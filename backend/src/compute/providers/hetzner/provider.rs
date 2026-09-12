use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use anyhow::{Result, anyhow, Context};
use async_trait::async_trait;
use dashmap::DashMap;

use crate::compute::{
    traits::{ComputeProvider, ProviderCapabilities, SessionHealth, RemoteExecutor},
    types::SessionStartResult,
    common::{git_ops::GitOps, ssh_keys::SshKeyManager, sshd::{SshdConfig, SshdLogLevel}, scripts, tproject},
};
use crate::models::{Session, SessionRequest};
use super::api::{HetznerApi, HetznerConfig, cloud_init_script};
use super::ssh_executor::SshExecutor;
use crate::compute::ssh_session_user;

#[derive(Debug, Clone)]
struct RemoteSession {
    server_id: u64,
    ip: String,
    session_sshd_port: u16,
}

#[derive(Debug)]
pub struct HetznerComputeProvider {
    config: HetznerConfig,
    api: HetznerApi,
    sessions: DashMap<String, RemoteSession>,
    keys: SshKeyManager,
}

impl HetznerComputeProvider {
    pub fn from_env(http: reqwest::Client) -> Result<Self> {
        let config = HetznerConfig::from_env()?;
        let api = HetznerApi::new(http, config.token.clone());
        Ok(Self { config, api, sessions: DashMap::new(), keys: SshKeyManager::new() })
    }

    fn admin_executor(&self, ip: &str) -> SshExecutor {
        let mut ex = SshExecutor::new(ip.to_string(), 22, "root".to_string());
        if let Ok(key) = std::env::var("HCLOUD_SSH_IDENTITY") {
            ex.identity_file = Some(key);
        }
        ex
    }

    async fn wait_ssh(&self, ip: &str, port: u16) -> Result<()> {
        for _ in 0..60 {
            let ex = SshExecutor::new(ip.to_string(), port, "root".to_string());
            if ex.exec_shell("true").await.map(|o| o.exit_status.success()).unwrap_or(false) {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        Err(anyhow!("timed out waiting for ssh {}:{}", ip, port))
    }

    /// Resolve the session mode, mirroring the local provider:
    /// explicit `collab` stays collab, `pair`/absent means pair.
    fn resolve_mode(mode: Option<&str>) -> Result<&'static str> {
        match mode {
            Some("collab") => Ok("collab"),
            Some("pair") | None => Ok("pair"),
            Some(other) => Err(anyhow!("Unknown mode: {}", other)),
        }
    }

    /// Shared preamble: workspace dirs, shallow clone, env resolution
    /// (including `t update` for tlang projects), and optional GitHub
    /// token injection for passwordless push.
    /// Returns `(root, repo_path, env_resolved)`.
    async fn remote_preamble(
        &self,
        ex: &dyn RemoteExecutor,
        session_id: &str,
        request: &SessionRequest,
    ) -> Result<(String, String, String)> {
        let root = format!("/home/{}/.steadystate/sessions/{}", ssh_session_user(), session_id);
        let repo_path = format!("{}/repo", root);
        ex.mkdir_p(PathBuf::from(&root).as_path(), 0o700).await?;
        ex.mkdir_p(PathBuf::from(&repo_path).as_path(), 0o700).await?;

        let clone_out = ex.exec_shell(&format!(
            "git clone --depth 1 {} '{}' 2>&1 || git -C '{}' pull --ff-only 2>&1",
            shell_quote(&request.repo_url), repo_path, repo_path
        )).await?;
        if !clone_out.exit_status.success() && !ex.exists(PathBuf::from(&repo_path).join(".git").as_path()).await? {
            return Err(anyhow!("remote clone failed: {}", clone_out.stderr));
        }

        let env_req = request.environment.as_deref().unwrap_or("auto");
        let env_resolved: String = if env_req == "auto" {
            if ex.exists(PathBuf::from(&repo_path).join("tproject.toml").as_path()).await? {
                "tproject".to_string()
            } else if ex.exists(PathBuf::from(&repo_path).join("flake.nix").as_path()).await? {
                "flake".to_string()
            } else {
                "noenv".to_string()
            }
        } else {
            env_req.to_string()
        };

        if env_resolved == "tproject" {
            tproject::ensure_nix(ex).await?;
            tproject::t_update(ex, PathBuf::from(&repo_path).as_path()).await?;
            let _ = tproject::check_min_version(ex, PathBuf::from(&repo_path).as_path()).await;
        }

        // Token-inject origin for passwordless push, same as local setups.
        if let Some(auth) = crate::compute::common::provider_config::extract_forge_config(request).as_ref() {
            crate::compute::common::provider_config::inject_token_auth(
                ex,
                PathBuf::from(&repo_path).as_path(),
                &request.repo_url,
                auth,
            ).await;
        }

        Ok((root, repo_path, env_resolved))
    }

    async fn remote_authorized_keys(
        &self,
        request: &SessionRequest,
    ) -> Vec<crate::compute::common::ssh_keys::AuthorizedKey> {
        let forge_auth = crate::compute::common::provider_config::extract_forge_config(request);
        let creator_login = forge_auth.as_ref().and_then(|f| f.login.clone());
        self.keys
            .build_authorized_keys_for_repo(
                creator_login.as_deref(),
                request.allowed_users.as_deref(),
                Some(&request.repo_url),
                forge_auth.as_ref(),
            )
            .await
    }

    async fn remote_setup(
        &self,
        ex: &dyn RemoteExecutor,
        public_ip: &str,
        session_id: &str,
        request: &SessionRequest,
    ) -> Result<SessionStartResult> {
        match Self::resolve_mode(request.mode.as_deref())? {
            "collab" => self.remote_setup_collab(ex, public_ip, session_id, request).await,
            _ => self.remote_setup_pair(ex, public_ip, session_id, request).await,
        }
    }

    async fn remote_setup_collab(
        &self,
        ex: &dyn RemoteExecutor,
        public_ip: &str,
        session_id: &str,
        request: &SessionRequest,
    ) -> Result<SessionStartResult> {
        let (root, repo_path, env_resolved) = self.remote_preamble(ex, session_id, request).await?;

        let git = GitOps::new(ex);
        let canonical = format!("{}/canonical", root);
        git.clone(&repo_path, &PathBuf::from(&canonical), None, None).await?;
        let branch_name = format!("{}_collab_{}", chrono::Local::now().format("%Y%m%d"), session_id);
        git.checkout_new_branch(&PathBuf::from(&canonical), &branch_name).await?;

        let authorized_keys = self.remote_authorized_keys(request).await;

        let bin = format!("{}/bin", root);
        ex.mkdir_p(PathBuf::from(&bin).as_path(), 0o755).await?;
        ex.write_file(PathBuf::from(format!("{}/sync-log", root)).as_path(), &[], 0o666).await?;
        ex.write_file(PathBuf::from(format!("{}/activity-log", root)).as_path(), &[], 0o666).await?;

        // Render wrapper with owned Strings (render copies immediately, avoid 'static leak).
        let repo_name = request.repo_url.split('/').last().map(|s| s.trim_end_matches(".git")).unwrap_or("repo").to_string();
        let template = scripts::collab_wrapper_script();
        // Build via temporary map of &str borrowing owned values.
        let wrapper = {
            let mut vars: HashMap<&str, &str> = HashMap::new();
            vars.insert("session_root", root.as_str());
            vars.insert("session_id", session_id);
            vars.insert("branch_name", branch_name.as_str());
            vars.insert("repo_name", repo_name.as_str());
            vars.insert("environment", env_resolved.as_str());
            vars.insert("flake_path", "$WORKTREE");
            template.render(&vars)
        };
        ex.write_file(PathBuf::from(format!("{}/bin/steadystate-wrapper", root)).as_path(), wrapper.as_bytes(), 0o755).await?;

        // Session info for dashboard.
        let forced_command = format!("{}/bin/steadystate-wrapper {{user}}", root);
        let (port, host_pub) = self.launch_remote_sshd(ex, &root, &authorized_keys, &forced_command).await?;
        let user = ssh_session_user();
        let invite = format!("ssh://{}@{}:{}", user, public_ip, port);
        let magic_link = format!(
            "steadystate://collab/{}?ssh={}&host_key={}",
            session_id,
            urlencoding::encode(&invite),
            urlencoding::encode(&host_pub)
        );
        let session_info = serde_json::json!({
            "magic_link": magic_link,
            "ssh_url": invite,
            "repo_name": repo_name,
        });
        ex.write_file(
            PathBuf::from(format!("{}/session-info.json", root)).as_path(),
            serde_json::to_string_pretty(&session_info)?.as_bytes(),
            0o644,
        ).await?;

        Ok(SessionStartResult {
            endpoint: Some(invite),
            magic_link: Some(magic_link),
            host_public_key: Some(host_pub),
        })
    }

    /// Materialize `{root}/flake` on the remote host for `noenv`/`python`,
    /// mirroring the local provider's `setup_environment`. Returns the
    /// flake path to bake into wrappers.
    async fn remote_env_flake(
        ex: &dyn RemoteExecutor,
        root: &str,
        repo_path: &str,
        env_resolved: &str,
    ) -> Result<String> {
        const NOENV_FLAKE_URL: &str = "https://raw.githubusercontent.com/The-Exact-Computing-Company/steadystate/main/backend/flakes/noenv";

        match env_resolved {
            "noenv" => {
                let flake_dest = format!("{}/flake", root);
                ex.mkdir_p(PathBuf::from(&flake_dest).as_path(), 0o755).await?;
                // Remote host has curl (installed by cloud-init).
                for file in ["flake.nix", "flake.lock"] {
                    let out = ex.exec_shell(&format!(
                        "curl -fsSL {}/{} -o '{}'",
                        NOENV_FLAKE_URL,
                        file,
                        format!("{}/{}", flake_dest, file),
                    )).await?;
                    if !out.exit_status.success() {
                        return Err(anyhow!("failed to fetch noenv {}: {}", file, out.stderr));
                    }
                }
                Ok(flake_dest)
            }
            "python" => {
                use crate::compute::common::python::{detect_python_version, generate_python_flake};
                let version = detect_python_version(ex, PathBuf::from(repo_path).as_path()).await?;
                let content = generate_python_flake(version);
                let flake_dest = format!("{}/flake", root);
                ex.mkdir_p(PathBuf::from(&flake_dest).as_path(), 0o755).await?;
                ex.write_file(
                    PathBuf::from(format!("{}/flake.nix", flake_dest)).as_path(),
                    content.as_bytes(),
                    0o644,
                ).await?;
                tracing::info!("Generated remote Python flake with {}", version.nix_attr());
                Ok(flake_dest)
            }
            _ => Ok("$REPO".to_string()),
        }
    }

    /// Pair mode: everyone shares one repo checkout inside a shared tmux
    /// session (via `pair-wrapper` as the SSH forced command). No canonical
    /// repo, no branches — mirrors the local pair flow.
    async fn remote_setup_pair(
        &self,
        ex: &dyn RemoteExecutor,
        public_ip: &str,
        session_id: &str,
        request: &SessionRequest,
    ) -> Result<SessionStartResult> {
        let (root, repo_path, env_resolved) = self.remote_preamble(ex, session_id, request).await?;

        let authorized_keys = self.remote_authorized_keys(request).await;

        let bin = format!("{}/bin", root);
        ex.mkdir_p(PathBuf::from(&bin).as_path(), 0o755).await?;
        ex.write_file(PathBuf::from(format!("{}/activity-log", root)).as_path(), &[], 0o666).await?;

        // Bake the env flake path into the wrapper (materializes {root}/flake
        // for noenv/python; other envs resolve at runtime against the checkout).
        let flake_path = Self::remote_env_flake(ex, &root, &repo_path, &env_resolved).await?;
        let template = scripts::pair_wrapper_script();
        let wrapper = {
            let mut vars: HashMap<&str, &str> = HashMap::new();
            vars.insert("session_root", root.as_str());
            vars.insert("session_id", session_id);
            vars.insert("environment", env_resolved.as_str());
            vars.insert("flake_path", flake_path.as_str());
            template.render(&vars)
        };
        ex.write_file(PathBuf::from(format!("{}/bin/pair-wrapper", root)).as_path(), wrapper.as_bytes(), 0o755).await?;

        let forced_command = format!("{}/bin/pair-wrapper {{user}}", root);
        let (port, host_pub) = self.launch_remote_sshd(ex, &root, &authorized_keys, &forced_command).await?;
        let user = ssh_session_user();
        let invite = format!("ssh://{}@{}:{}", user, public_ip, port);
        let magic_link = format!(
            "steadystate://pair/{}?ssh={}&host_key={}",
            session_id,
            urlencoding::encode(&invite),
            urlencoding::encode(&host_pub)
        );

        Ok(SessionStartResult {
            endpoint: Some(invite),
            magic_link: Some(magic_link),
            host_public_key: Some(host_pub),
        })
    }

    async fn launch_remote_sshd(
        &self,
        ex: &dyn RemoteExecutor,
        root: &str,
        authorized_keys: &[crate::compute::common::ssh_keys::AuthorizedKey],
        forced_command: &str,
    ) -> Result<(u16, String)> {
        let ssh_dir = format!("{}/ssh", root);
        ex.mkdir_p(PathBuf::from(&ssh_dir).as_path(), 0o700).await?;

        let host_key = format!("{}/host_key", ssh_dir);
        let keygen = ex.exec_shell(&format!(
            "[ -f {} ] || ssh-keygen -t ed25519 -f {} -N '' -q; cat {}.pub",
            shell_quote(&host_key), shell_quote(&host_key), shell_quote(&host_key)
        )).await?;
        if !keygen.exit_status.success() {
            return Err(anyhow!("remote host key generation failed: {}", keygen.stderr));
        }

        let auth_keys_path = format!("{}/authorized_keys", ssh_dir);
        let content = self.keys.generate_authorized_keys_file(authorized_keys, Some(forced_command));
        ex.write_file(PathBuf::from(&auth_keys_path).as_path(), content.as_bytes(), 0o600).await?;

        // Deterministic high port from root hash.
        let port: u16 = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            root.hash(&mut h);
            20000 + (h.finish() % 8000) as u16
        };

        let pid_file = format!("{}/sshd.pid", ssh_dir);
        let cfg = SshdConfig {
            port,
            host_key_path: PathBuf::from(&host_key),
            authorized_keys_path: PathBuf::from(&auth_keys_path),
            pid_file_path: PathBuf::from(&pid_file),
            log_level: SshdLogLevel::Info,
            permit_user_environment: true,
        };
        let cfg_path = format!("{}/sshd_config", ssh_dir);
        ex.write_file(PathBuf::from(&cfg_path).as_path(), cfg.generate().as_bytes(), 0o600).await?;

        let log_path = format!("{}/sshd.log", ssh_dir);
        let launch = ex.exec_shell(&format!(
            "nohup /usr/sbin/sshd -f {} -D -E {} >/dev/null 2>&1 & echo $!",
            shell_quote(&cfg_path), shell_quote(&log_path)
        )).await?;
        // Parse the pid to confirm the daemon actually started; the pid itself
        // is not tracked because deleting the server cleans up everything.
        let _pid: u32 = launch.stdout.trim().parse().context("parse remote sshd pid")?;

        let pubkey = ex.read_file(PathBuf::from(format!("{}.pub", host_key)).as_path()).await?;
        let pub_s = String::from_utf8(pubkey).context("host pubkey utf8")?;
        let host_pub = pub_s.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        Ok((port, host_pub))
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_mode_matches_local() {
        // Mirrors LocalComputeProvider::start_session dispatch.
        assert_eq!(HetznerComputeProvider::resolve_mode(Some("collab")).unwrap(), "collab");
        assert_eq!(HetznerComputeProvider::resolve_mode(Some("pair")).unwrap(), "pair");
        assert_eq!(HetznerComputeProvider::resolve_mode(None).unwrap(), "pair");
        assert!(HetznerComputeProvider::resolve_mode(Some("solo")).is_err());
        assert!(HetznerComputeProvider::resolve_mode(Some("")).is_err());
    }

    #[test]
    fn test_pair_wrapper_renders_without_placeholders() {
        let template = scripts::pair_wrapper_script();
        let mut vars: HashMap<&str, &str> = HashMap::new();
        vars.insert("session_root", "/home/steady/.steadystate/sessions/abc");
        vars.insert("session_id", "abc123");
        vars.insert("environment", "tproject");
        vars.insert("flake_path", "$REPO");
        let out = template.render(&vars);
        assert!(!out.contains("{{session_root}}"));
        assert!(!out.contains("{{session_id}}"));
        assert!(!out.contains("{{environment}}"));
        assert!(!out.contains("{{flake_path}}"));
        assert!(out.contains("tmux new-session -A"));
        // TMUX_SESSION is composed at runtime: pair-${SESSION_ID:0:8}.
        assert!(out.contains("SESSION_ID=\"abc123\""));
        assert!(out.contains("pair-${SESSION_ID:0:8}"));
    }
}

#[async_trait]
impl ComputeProvider for HetznerComputeProvider {
    fn id(&self) -> &'static str { "hetzner" }
    fn display_name(&self) -> &'static str { "Hetzner Cloud" }
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            supports_pair_mode: true,
            supports_collab_mode: true,
            supports_persistent_storage: false,
            supports_snapshots: false,
            max_session_duration: None,
            supported_environments: vec!["tproject".into(), "auto".into(), "flake".into(), "noenv".into(), "python".into(), "legacy-nix".into()],
        }
    }

    async fn start_session(&self, session_id: &str, request: &SessionRequest) -> Result<SessionStartResult> {
        let user = ssh_session_user();
        let short = &session_id[..8.min(session_id.len())];
        let name = format!("steady-{}", short);
        let server = self.api.create_server(&name, &self.config, Some(cloud_init_script(&user))).await?;
        let server = self.api.wait_running(server.id).await?;
        let ip = server.public_net.ipv4.ip.clone();
        self.wait_ssh(&ip, 22).await?;

        let admin = self.admin_executor(&ip);
        // Best-effort: ensure session user exists (cloud-init usually handles it).
        let _ = admin.exec_shell(&format!("id {} >/dev/null 2>&1 || useradd -m -s /bin/bash {}", user, user)).await;

        let result = match self.remote_setup(&admin, &ip, session_id, request).await {
            Ok(result) => result,
            Err(e) => {
                // The VM exists but was never recorded: delete it here or it
                // bills forever with no handle to clean it up.
                tracing::warn!(
                    "Setup failed for hetzner server {} ({}); deleting it: {:#}",
                    server.id, ip, e
                );
                if let Err(del_err) = self.api.delete_server(server.id).await {
                    tracing::error!(
                        "ORPHANED hetzner server {} ({}): setup failed ({:#}) and delete failed ({:#}). Delete it manually in hcloud.",
                        server.id, ip, e, del_err
                    );
                }
                return Err(e);
            }
        };

        // Record for terminate/health. On failure to parse, still record the
        // server id so terminate_session can always clean up the VM.
        let port = result.endpoint.as_ref()
            .and_then(|ep| ep.rsplit(':').next())
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(22);
        self.sessions.insert(session_id.to_string(), RemoteSession {
            server_id: server.id,
            ip: ip.clone(),
            session_sshd_port: port,
        });
        Ok(result)
    }

    async fn terminate_session(&self, session: &Session) -> Result<()> {
        if let Some((_, rs)) = self.sessions.remove(&session.id) {
            tracing::info!("Deleting hetzner server {} ({}:{})", rs.server_id, rs.ip, rs.session_sshd_port);
            self.api.delete_server(rs.server_id).await?;
        }
        Ok(())
    }

    async fn health_check(&self, session: &Session) -> Result<SessionHealth> {
        if let Some(rs) = self.sessions.get(&session.id) {
            match self.api.get_server(rs.server_id).await {
                Ok(s) if s.status == "running" => Ok(SessionHealth::Healthy),
                Ok(s) => Ok(SessionHealth::Unhealthy { reason: format!("server {} ({}:{}) status: {}", rs.server_id, rs.ip, rs.session_sshd_port, s.status) }),
                Err(e) => Ok(SessionHealth::Degraded { reason: format!("hcloud api for server {}: {:#}", rs.server_id, e) }),
            }
        } else {
            Ok(SessionHealth::Unknown)
        }
    }
}

// Keep Arc constructor helper for state registration.
impl HetznerComputeProvider {
    pub fn into_arc(http: reqwest::Client) -> Result<Arc<dyn ComputeProvider>> {
        Ok(Arc::new(Self::from_env(http)?) as Arc<dyn ComputeProvider>)
    }
}
