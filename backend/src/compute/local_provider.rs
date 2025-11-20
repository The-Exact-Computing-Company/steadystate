// backend/src/compute/local_provider.rs

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use futures::StreamExt;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::{timeout, Duration};


use crate::compute::ComputeProvider;
use crate::models::{Session, SessionRequest, SessionState};

#[async_trait::async_trait]
pub trait CommandExecutor: Send + Sync + std::fmt::Debug {
    async fn run_status(&self, cmd: &str, args: &[&str]) -> Result<std::process::ExitStatus>;
    async fn run_capture(&self, cmd: &str, args: &[&str]) -> Result<(u32, Box<dyn tokio::io::AsyncRead + Unpin + Send>, Box<dyn tokio::io::AsyncRead + Unpin + Send>)>;
    async fn run_shell(&self, script: &str) -> Result<std::process::ExitStatus>;
}

#[derive(Debug, Clone)]
pub struct RealCommandExecutor;

#[async_trait::async_trait]
impl CommandExecutor for RealCommandExecutor {
    async fn run_status(&self, cmd: &str, args: &[&str]) -> Result<std::process::ExitStatus> {
        Command::new(cmd)
            .args(args)
            .stdin(std::process::Stdio::null())
            .process_group(0)
            .status()
            .await
            .context(format!("Failed to execute {}", cmd))
    }

    async fn run_capture(&self, cmd: &str, args: &[&str]) -> Result<(u32, Box<dyn tokio::io::AsyncRead + Unpin + Send>, Box<dyn tokio::io::AsyncRead + Unpin + Send>)> {
        let mut c = Command::new(cmd);
        c.args(args);
        c.stdin(std::process::Stdio::null());
        c.process_group(0);
        c.stdout(std::process::Stdio::piped());
        c.stderr(std::process::Stdio::piped());

        let mut child = c.spawn().context(format!("Failed to spawn {}", cmd))?;
        let pid = child.id().ok_or_else(|| anyhow!("Failed to get PID"))?;
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("Failed to capture stdout"))?;
        let stderr = child.stderr.take().ok_or_else(|| anyhow!("Failed to capture stderr"))?;
        
        Ok((pid, Box::new(stdout), Box::new(stderr)))
    }

    async fn run_shell(&self, script: &str) -> Result<std::process::ExitStatus> {
        Command::new("sh")
            .arg("-c")
            .arg(script)
            .stdin(std::process::Stdio::null())
            .process_group(0)
            .status()
            .await
            .context("Failed to execute shell script")
    }
}

#[derive(Debug)]
struct LocalSession {
    pid: u32,
    workspace_root: PathBuf,
}

#[derive(Debug, Default)]
pub struct LocalProviderState {
    live_sessions: DashMap<String, LocalSession>,
}

#[derive(Debug)]
pub struct LocalComputeProvider {
    flake_path: PathBuf,
    state: Arc<LocalProviderState>,
    executor: Box<dyn CommandExecutor>,
}

impl LocalComputeProvider {
    pub fn new(flake_path: PathBuf) -> Self {
        Self {
            flake_path,
            state: Arc::new(LocalProviderState::default()),
            executor: Box::new(RealCommandExecutor),
        }
    }

    /// Constructor for testing with a mock executor
    pub fn new_with_executor(flake_path: PathBuf, executor: Box<dyn CommandExecutor>) -> Self {
        Self {
            flake_path,
            state: Arc::new(LocalProviderState::default()),
            executor,
        }
    }

    fn create_workspace(&self, session_id: &str) -> Result<(PathBuf, PathBuf)> {
        let base = std::env::temp_dir()
            .join("steadystate")
            .join("sessions")
            .join(session_id);
        let repo_path = base.join("repo");
        
        std::fs::create_dir_all(&repo_path)
            .with_context(|| format!("Failed to create repo dir at {}", repo_path.display()))?;
            
        Ok((base, repo_path))
    }

    async fn ensure_nix_installed(&self) -> Result<()> {
        // 1. Check if nix is already in PATH
        let status = self.executor.run_status("sh", &["-c", "command -v nix >/dev/null 2>&1"]).await
            .context("Failed to check for nix")?;

        if status.success() {
            return Ok(());
        }

        tracing::info!("Nix not found; installing Lix...");
        
        // 2. Install Lix non-interactively
        let install_cmd = r#"curl --proto '=https' --tlsv1.2 -sSf -L https://install.lix.systems/lix | sh -s -- install --no-confirm"#;
        let status = self.executor.run_shell(install_cmd).await
            .context("Failed to spawn Lix installer")?;

        if !status.success() {
            return Err(anyhow!("Lix installer failed"));
        }
        
        tracing::info!("Lix installation completed successfully");
        Ok(())
    }

    async fn clone_repo(&self, repo_url: &str, dest: &Path) -> Result<()> {
        tracing::info!("Cloning repo {} into {}", repo_url, dest.display());
        
        let status = self.executor.run_status("git", &["clone", "--depth=1", repo_url, dest.to_str().unwrap()]).await
            .context("Failed to spawn git clone")?;

        if !status.success() {
            return Err(anyhow!("git clone failed for {}", repo_url));
        }
        Ok(())
    }

    async fn launch_upterm_in_noenv(
        &self,
        flake_path: &Path,
        working_dir: &Path,
        github_user: Option<&str>,
        allowed_users: Option<&[String]>,
        public: bool,
    ) -> Result<(u32, String)> {
        // We run upterm from the host (backend environment), which wraps the nix develop session.
        // This ensures upterm is found (since it's in the host env) and the user lands in the nix dev shell.
        
        // We use shell_escape to safely insert paths into the shell string.
        let safe_workdir = shell_escape::escape(working_dir.to_string_lossy().into());
        let safe_flake = shell_escape::escape(flake_path.to_string_lossy().into());
        
        // The command that upterm will run *inside* the session:
        // We use `bash` as the command inside nix develop to give an interactive shell.
        let session_cmd = format!("nix develop {}#default --command bash", safe_flake);
        let safe_session_cmd = shell_escape::escape(session_cmd.into());

        // Construct upterm host command
        let mut upterm_args = vec!["host".to_string()];
        
        // 1. Server configuration
        if let Ok(server) = std::env::var("STEADYSTATE_UPTERM_SERVER") {
            upterm_args.push("--server".to_string());
            upterm_args.push(server);
        }

        // 2. Authorization
        if !public {
            // If not public, we must have at least one authorized user (the creator)
            if let Some(user) = github_user {
                upterm_args.push("--github-user".to_string());
                upterm_args.push(user.to_string());
            }
            
            if let Some(users) = allowed_users {
                for user in users {
                    upterm_args.push("--github-user".to_string());
                    upterm_args.push(user.clone());
                }
            }
        }

        // 4. Force command
        upterm_args.push(format!("--force-command={}", safe_session_cmd));

        let upterm_cmd_str = upterm_args.join(" ");

        let full_cmd = format!(
            "cd {} && upterm {}",
            safe_workdir, upterm_cmd_str.strip_prefix("upterm ").unwrap_or(&upterm_cmd_str)
        );

        tracing::info!("Starting upterm session with command: {}", full_cmd);
        
        // Use setsid to detach from TTY and avoid SIGTTIN when running in background.
        // We use `setsid -w` to wait for the child, and we print the PID of the new session leader.
        let nix_wrapper = format!(
            r#"
            if [ -f /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
              . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
            fi
            echo "DEBUG: Wrapper started, running full_cmd..." >&2
            echo "DEBUG: PATH=$PATH" >&2
            unset SSH_ASKPASS
            unset DISPLAY
            unset SSH_AUTH_SOCK
            
            # Run with setsid to detach from TTY
            # We use sh -c to print the PID then exec upterm
            setsid -w sh -c 'echo "PID: $$"; {}'
            
            echo "DEBUG: full_cmd finished with exit code $?" >&2
            "#,
            full_cmd
        );
        
        tracing::info!("Spawning upterm command...");
        let (wrapper_pid, stdout, stderr) = self.executor.run_capture("sh", &["-c", &nix_wrapper]).await
            .context("Failed to spawn nix develop/upterm")?;

        tracing::info!("Upterm wrapper spawned with PID {}", wrapper_pid);

        // Spawn a task to log stderr
        let stderr_reader = BufReader::new(stderr);
        tokio::spawn(async move {
            let mut lines = tokio_stream::wrappers::LinesStream::new(stderr_reader.lines());
            while let Some(line_res) = lines.next().await {
                match line_res {
                    Ok(line) => eprintln!("UPTERM STDERR: {}", line),
                    Err(e) => eprintln!("Error reading upterm stderr: {}", e),
                }
            }
        });

        // We wait for the invite link to appear in stdout.
        let invite_result = timeout(Duration::from_secs(30), capture_upterm_invite(stdout)).await;

        match invite_result {
            Ok(Ok((captured_pid, invite))) => {
                // If we captured a PID from setsid, use it. Otherwise fall back to wrapper PID (less reliable for kill).
                let final_pid = captured_pid.unwrap_or(wrapper_pid);
                tracing::info!("Session ready. Wrapper PID: {}, Final PID: {}", wrapper_pid, final_pid);
                Ok((final_pid, invite))
            },
            Ok(Err(e)) => {
                tracing::error!("Upterm failed to provide invite: {:#}", e);
                let _ = self.kill_pid(wrapper_pid).await;
                Err(e)
            }
            Err(_) => {
                tracing::error!("Timed out waiting for upterm invite");
                let _ = self.kill_pid(wrapper_pid).await;
                Err(anyhow!("Timed out waiting for upterm invite"))
            }
        }
    }

    async fn kill_pid(&self, pid: u32) -> Result<()> {
        tracing::info!("Killing local session process with pid={}", pid);
        let cmd = format!("kill -TERM {}", pid);
        let status = self.executor.run_shell(&cmd).await
            .context("Failed to spawn kill")?;
            
        if !status.success() {
            tracing::warn!("kill returned non-zero for pid={}", pid);
        }
        Ok(())
    }
}









pub(crate) async fn capture_upterm_invite(stdout: impl tokio::io::AsyncRead + Unpin) -> Result<(Option<u32>, String)> {
    let reader = BufReader::new(stdout);
    let mut lines = tokio_stream::wrappers::LinesStream::new(reader.lines());

    let mut pid = None;

    while let Some(line_res) = lines.next().await {
        let line = line_res?;
        tracing::warn!(upterm_stdout = %line, "upterm stdout");
        let trimmed = line.trim();
        
        if trimmed.starts_with("PID: ") {
            if let Ok(p) = trimmed.strip_prefix("PID: ").unwrap_or("").trim().parse::<u32>() {
                tracing::info!("Captured upterm PID: {}", p);
                pid = Some(p);
            }
        } else if trimmed.starts_with("Invite: ssh") {
            tracing::info!("Captured upterm invite: {}", trimmed);
            return Ok((pid, trimmed.to_string()));
        } else if trimmed.starts_with("SSH Session:") {
            // Format: "SSH Session:            ssh ..."
            if let Some(ssh_cmd) = trimmed.strip_prefix("SSH Session:") {
                let ssh_cmd = ssh_cmd.trim();
                tracing::info!("Captured upterm invite: {}", ssh_cmd);
                return Ok((pid, ssh_cmd.to_string()));
            }
        }
    }
    Err(anyhow!("Upterm did not print an invite line"))
}



#[derive(Debug, serde::Deserialize)]
struct GitHubComputeConfig {
    login: String,
    access_token: String,
}

fn parse_github_repo(repo_url: &str) -> Option<(String, String)> {
    // Supports https://github.com/owner/repo(.git)
    let url = repo_url.strip_prefix("https://github.com/")?;
    let url = url.strip_suffix(".git").unwrap_or(url);
    let mut parts = url.split('/');
    let owner = parts.next()?.to_string();
    let repo = parts.next()?.to_string();
    Some((owner, repo))
}

async fn ensure_fork_and_clone(
    http: &reqwest::Client,
    gh: &GitHubComputeConfig,
    original_repo_url: &str,
    dest: &Path,
    executor: &dyn CommandExecutor,
) -> Result<()> {
    let (owner, repo) = parse_github_repo(original_repo_url)
        .ok_or_else(|| anyhow!("Unsupported GitHub repo URL: {}", original_repo_url))?;

    let user = &gh.login;

    // 1. Check if fork already exists
    let fork_url = format!("https://api.github.com/repos/{}/{}", user, repo);
    let resp = http
        .get(&fork_url)
        .bearer_auth(&gh.access_token)
        .header("User-Agent", "steadystate-backend/0.1")
        .send()
        .await?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        // 2. Create fork
        let create_url = format!("https://api.github.com/repos/{}/{}", owner, repo);
        tracing::info!("Creating fork of {}/{} for {}", owner, repo, user);

        let fork_resp = http
            .post(format!("{}/forks", create_url))
            .bearer_auth(&gh.access_token)
            .header("User-Agent", "steadystate-backend/0.1")
            .send()
            .await?
            .error_for_status()
            .context("Failed to create fork via GitHub API")?;

        tracing::debug!("Fork response: {:?}", fork_resp.status());

        // Simple backoff: give GitHub a moment to materialize the fork
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }

    // 3. Clone the *fork* into dest
    // Inject token into URL for authenticated clone
    let fork_clone_url = format!("https://x-access-token:{}@github.com/{}/{}.git", gh.access_token, user, repo);
    tracing::info!("Cloning fork {} into {}", fork_clone_url.replace(&gh.access_token, "***"), dest.display());
    
    let status = executor.run_status("git", &["clone", "--depth=1", &fork_clone_url, dest.to_str().unwrap()]).await
        .context("Failed to spawn git clone")?;

    if !status.success() {
        return Err(anyhow!("git clone failed for {}", fork_clone_url.replace(&gh.access_token, "***")));
    }

    // 4. Add upstream remote pointing at the original repo (best effort)
    let upstream_url = format!("https://github.com/{}/{}.git", owner, repo);
    let status = executor.run_status("git", &["-C", dest.to_str().unwrap(), "remote", "add", "upstream", &upstream_url]).await
        .context("Failed to add upstream remote")?;

    if !status.success() {
        tracing::warn!("git remote add upstream failed for {}", dest.display());
    }

    Ok(())
}

#[async_trait::async_trait]
impl ComputeProvider for LocalComputeProvider {
    fn id(&self) -> &'static str { "local" }

    async fn start_session(&self, session: &mut Session, request: &SessionRequest) -> Result<()> {
        tracing::info!("Starting local NOENV session: id={} repo={}", session.id, request.repo_url);
        
        self.ensure_nix_installed().await?;
        
        let (workspace_root, repo_path) = self.create_workspace(&session.id)?;
        
        // --- New: if GitHub config present, fork+clone. Otherwise, plain clone.
        if let Some(cfg) = &request.provider_config {
            if let Some(gh_val) = cfg.get("github") {
                if let Ok(gh) = serde_json::from_value::<GitHubComputeConfig>(gh_val.clone()) {
                    let http = reqwest::Client::new();
                    ensure_fork_and_clone(&http, &gh, &request.repo_url, &repo_path, self.executor.as_ref()).await?;
                } else {
                    self.clone_repo(&request.repo_url, &repo_path).await?;
                }
            } else {
                self.clone_repo(&request.repo_url, &repo_path).await?;
            }
        } else {
            self.clone_repo(&request.repo_url, &repo_path).await?;
        }
        
        // Extract GitHub login if available
        let mut github_login = None;
        if let Some(cfg) = &request.provider_config {
             if let Some(gh_val) = cfg.get("github") {
                if let Ok(gh) = serde_json::from_value::<GitHubComputeConfig>(gh_val.clone()) {
                    github_login = Some(gh.login);
                }
             }
        }

        let (pid, invite) = self.launch_upterm_in_noenv(
            &self.flake_path, 
            &repo_path,
            github_login.as_deref(),
            request.allowed_users.as_deref(),
            request.public
        ).await?;
        
        // Store session state (PID) so we can kill it later.
        self.state.live_sessions.insert(session.id.clone(), LocalSession { pid, workspace_root });
        
        // Update the session model that will be returned to the user.
        session.state = SessionState::Running;
        session.endpoint = Some(invite);
        
        Ok(())
    }

    async fn terminate_session(&self, session: &Session) -> Result<()> {
        tracing::info!("Terminating local NOENV session: id={}", session.id);
        
        if let Some((_, local_session)) = self.state.live_sessions.remove(&session.id) {
            if local_session.pid != 0 {
                let _ = self.kill_pid(local_session.pid).await;
            }
            if let Err(e) = std::fs::remove_dir_all(&local_session.workspace_root) {
                tracing::warn!("Failed to remove workspace at {}: {:#}", local_session.workspace_root.display(), e);
            }
        } else {
            tracing::warn!("terminate_session called, but no live session state found for id={}", session.id);
        }
        Ok(())
    }
}
