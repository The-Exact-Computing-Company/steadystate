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
    async fn run_capture(&self, cmd: &str, args: &[&str]) -> Result<(u32, Box<dyn tokio::io::AsyncRead + Unpin + Send>)>;
    async fn run_shell(&self, script: &str) -> Result<std::process::ExitStatus>;
}

#[derive(Debug, Clone)]
pub struct RealCommandExecutor;

#[async_trait::async_trait]
impl CommandExecutor for RealCommandExecutor {
    async fn run_status(&self, cmd: &str, args: &[&str]) -> Result<std::process::ExitStatus> {
        Command::new(cmd)
            .args(args)
            .status()
            .await
            .context(format!("Failed to execute {}", cmd))
    }

    async fn run_capture(&self, cmd: &str, args: &[&str]) -> Result<(u32, Box<dyn tokio::io::AsyncRead + Unpin + Send>)> {
        let mut c = Command::new(cmd);
        c.args(args);
        c.stdout(std::process::Stdio::piped());
        c.stderr(std::process::Stdio::piped()); // Capture stderr too if needed, or null it

        let mut child = c.spawn().context(format!("Failed to spawn {}", cmd))?;
        let pid = child.id().ok_or_else(|| anyhow!("Failed to get PID"))?;
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("Failed to capture stdout"))?;
        
        Ok((pid, Box::new(stdout)))
    }

    async fn run_shell(&self, script: &str) -> Result<std::process::ExitStatus> {
        Command::new("sh")
            .arg("-c")
            .arg(script)
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

    async fn launch_upterm_in_noenv(&self, flake_path: &Path, working_dir: &Path) -> Result<(u32, String)> {
        let inner_cmd = "upterm host --force-command=bash";
        
        // We use shell_escape to safely insert paths into the shell string.
        let safe_workdir = shell_escape::escape(working_dir.to_string_lossy().into());
        let safe_flake = shell_escape::escape(flake_path.to_string_lossy().into());
        
        let full_cmd = format!(
            "cd {} && nix develop {}#default --command {}",
            safe_workdir, safe_flake, inner_cmd
        );

        tracing::info!("Starting upterm session...");
        
        let nix_wrapper = format!(
            r#"
            if [ -f /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
              . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
            fi
            {}
            "#,
            full_cmd
        );
        
        let (pid, stdout) = self.executor.run_capture("sh", &["-c", &nix_wrapper]).await
            .context("Failed to spawn nix develop/upterm")?;

        // We wait for the invite link to appear in stdout.
        let invite = timeout(Duration::from_secs(30), capture_upterm_invite(stdout))
            .await
            .context("Timed out waiting for upterm invite")??;

        Ok((pid, invite))
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









async fn capture_upterm_invite(stdout: impl tokio::io::AsyncRead + Unpin) -> Result<String> {
    let reader = BufReader::new(stdout);
    let mut lines = tokio_stream::wrappers::LinesStream::new(reader.lines());

    while let Some(line_res) = lines.next().await {
        let line = line_res?;
        tracing::debug!(upterm_line = %line, "upterm stdout");
        if line.starts_with("Invite: ssh") {
            tracing::info!("Captured upterm invite: {}", line);
            return Ok(line);
        }
    }
    Err(anyhow!("Upterm did not print an invite line"))
}



#[async_trait::async_trait]
impl ComputeProvider for LocalComputeProvider {
    fn id(&self) -> &'static str { "local" }

    async fn start_session(&self, session: &mut Session, request: &SessionRequest) -> Result<()> {
        tracing::info!("Starting local NOENV session: id={} repo={}", session.id, request.repo_url);
        
        self.ensure_nix_installed().await?;
        
        let (workspace_root, repo_path) = self.create_workspace(&session.id)?;
        
        self.clone_repo(&request.repo_url, &repo_path).await?;
        
        let (pid, invite) = self.launch_upterm_in_noenv(&self.flake_path, &repo_path).await?;
        
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
