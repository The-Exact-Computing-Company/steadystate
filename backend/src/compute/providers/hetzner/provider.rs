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

    fn extract_github(request: &SessionRequest) -> (Option<String>, Option<String>) {
        if let Some(cfg) = &request.provider_config {
            if let Some(gh) = cfg.get("github") {
                #[derive(serde::Deserialize)]
                struct Gh { login: String, access_token: String }
                if let Ok(g) = serde_json::from_value::<Gh>(gh.clone()) {
                    return (Some(g.login), Some(g.access_token));
                }
            }
        }
        (None, None)
    }

    async fn remote_setup(
        &self,
        ex: &dyn RemoteExecutor,
        public_ip: &str,
        session_id: &str,
        request: &SessionRequest,
    ) -> Result<SessionStartResult> {
        let root = format!("/home/{}/.steadystate/sessions/{}", ssh_session_user(), session_id);
        let repo_path = format!("{}/repo", root);
        ex.mkdir_p(PathBuf::from(&root).as_path(), 0o700).await?;
        ex.mkdir_p(PathBuf::from(&repo_path).as_path(), 0o700).await?;

        let git = GitOps::new(ex);
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

        let canonical = format!("{}/canonical", root);
        git.clone(&repo_path, &PathBuf::from(&canonical), None, None).await?;
        let branch_name = format!("{}_collab_{}", chrono::Local::now().format("%Y%m%d"), session_id);
        git.checkout_new_branch(&PathBuf::from(&canonical), &branch_name).await?;

        let (creator_login, github_token) = Self::extract_github(request);
        let authorized_keys = self.keys
            .build_authorized_keys_for_repo(
                creator_login.as_deref(),
                request.allowed_users.as_deref(),
                Some(&request.repo_url),
                github_token.as_deref(),
            )
            .await;

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
        let (port, host_pub) = self.launch_remote_sshd(ex, &root, &authorized_keys).await?;
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

    async fn launch_remote_sshd(
        &self,
        ex: &dyn RemoteExecutor,
        root: &str,
        authorized_keys: &[crate::compute::common::ssh_keys::AuthorizedKey],
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
        let wrapper_tpl = format!("{}/bin/steadystate-wrapper {{user}}", root);
        let content = self.keys.generate_authorized_keys_file(authorized_keys, Some(&wrapper_tpl));
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

        let result = self.remote_setup(&admin, &ip, session_id, request).await?;

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
