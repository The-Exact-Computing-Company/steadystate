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
}

impl LocalComputeProvider {
    pub fn new(flake_path: PathBuf) -> Self {
        Self {
            flake_path,
            state: Arc::new(LocalProviderState::default()),
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
}

/// Helper to wrap a command so it runs with the Nix profile sourced.
fn nix_shell_command(cmd: &str) -> Command {
    let mut c = Command::new("sh");
    let full = format!(
        r#"
        if [ -f /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
          . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
        fi
        {}
        "#,
        cmd
    );
    c.arg("-c").arg(full);
    c
}

async fn ensure_nix_installed() -> Result<()> {
    // 1. Check if nix is already in PATH
    let status = Command::new("sh")
        .arg("-c")
        .arg("command -v nix >/dev/null 2>&1")
        .status()
        .await
        .context("Failed to check for nix")?;

    if status.success() {
        return Ok(());
    }

    tracing::info!("Nix not found; installing Lix...");
    
    // 2. Install Lix non-interactively
    let install_cmd = r#"curl --proto '=https' --tlsv1.2 -sSf -L https://install.lix.systems/lix | sh -s -- install --no-confirm"#;
    let status = Command::new("sh")
        .arg("-c")
        .arg(install_cmd)
        .status()
        .await
        .context("Failed to spawn Lix installer")?;

    if !status.success() {
        return Err(anyhow!("Lix installer failed"));
    }
    
    tracing::info!("Lix installation completed successfully");
    Ok(())
}

async fn clone_repo(repo_url: &str, dest: &Path) -> Result<()> {
    tracing::info!("Cloning repo {} into {}", repo_url, dest.display());
    
    let status = Command::new("git")
        .arg("clone")
        .arg("--depth=1")
        .arg(repo_url)
        .arg(dest)
        .status()
        .await
        .context("Failed to spawn git clone")?;

    if !status.success() {
        return Err(anyhow!("git clone failed for {}", repo_url));
    }
    Ok(())
}

async fn launch_upterm_in_noenv(flake_path: &Path, working_dir: &Path) -> Result<(u32, String)> {
    let inner_cmd = "upterm host --force-command=bash";
    
    // We use shell_escape to safely insert paths into the shell string.
    let safe_workdir = shell_escape::escape(working_dir.to_string_lossy().into());
    let safe_flake = shell_escape::escape(flake_path.to_string_lossy().into());
    
    let full_cmd = format!(
        "cd {} && nix develop {}#default --command {}",
        safe_workdir, safe_flake, inner_cmd
    );

    tracing::info!("Starting upterm session...");
    
    let mut cmd = nix_shell_command(&full_cmd);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().context("Failed to spawn nix develop/upterm")?;
    let pid = child.id().ok_or_else(|| anyhow!("Failed to obtain PID of upterm process"))?;
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("Failed to capture upterm stdout"))?;

    // We wait for the invite link to appear in stdout.
    let invite = timeout(Duration::from_secs(30), capture_upterm_invite(stdout))
        .await
        .context("Timed out waiting for upterm invite")??;

    Ok((pid, invite))
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

async fn kill_pid(pid: u32) -> Result<()> {
    tracing::info!("Killing local session process with pid={}", pid);
    let cmd = format!("kill -TERM {}", pid);
    let status = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()
        .await
        .context("Failed to spawn kill")?;
        
    if !status.success() {
        tracing::warn!("kill returned non-zero for pid={}", pid);
    }
    Ok(())
}

#[async_trait::async_trait]
impl ComputeProvider for LocalComputeProvider {
    fn id(&self) -> &'static str { "local" }

    async fn start_session(&self, session: &mut Session, request: &SessionRequest) -> Result<()> {
        tracing::info!("Starting local NOENV session: id={} repo={}", session.id, request.repo_url);
        
        ensure_nix_installed().await?;
        
        let (workspace_root, repo_path) = self.create_workspace(&session.id)?;
        
        clone_repo(&request.repo_url, &repo_path).await?;
        
        let (pid, invite) = launch_upterm_in_noenv(&self.flake_path, &repo_path).await?;
        
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
                let _ = kill_pid(local_session.pid).await;
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
