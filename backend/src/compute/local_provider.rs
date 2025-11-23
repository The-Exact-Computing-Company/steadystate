// backend/src/compute/local_provider.rs

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use futures::StreamExt;
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncBufReadExt, BufReader, AsyncReadExt};
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use tracing::instrument;


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
    event_daemon_pid: Option<u32>,
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
        // ------------------------------------------------------------
        // FIX: Never put SSHD or session files under /tmp.
        // OpenSSH refuses host keys or configs under any insecure path.
        // Move session root to: $HOME/.steadystate/sessions/<session_id>
        // ------------------------------------------------------------

        let home = dirs::home_dir()
            .ok_or_else(|| anyhow!("No HOME directory found"))?;

        let base_root = std::env::var("STEADYSTATE_SESSION_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".steadystate").join("sessions"));

        // Ensure two-level dirs (~/.steadystate/sessions) exist and secure
        std::fs::create_dir_all(&base_root)
            .with_context(|| format!("Failed to create {:?}", base_root))?;
        
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&base_root, std::fs::Permissions::from_mode(0o700))
            .context("Failed to chmod session root directory")?;

        // Create this session's directory
        let base = base_root.join(session_id);
        std::fs::create_dir_all(&base)
            .with_context(|| format!("Failed to create {:?}", base))?;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))
            .context("Failed to chmod session directory")?;

        // Repo path inside session
        let repo_path = base.join("repo");
        std::fs::create_dir_all(&repo_path)
            .with_context(|| format!("Failed to create repo dir at {}", repo_path.display()))?;
        std::fs::set_permissions(&repo_path, std::fs::Permissions::from_mode(0o700))
            .context("Failed to chmod repo directory")?;

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

    async fn ensure_pijul_installed(&self) -> Result<()> {
        // 1. Check if pijul is already in PATH
        let status = self.executor.run_status("sh", &["-c", "command -v pijul >/dev/null 2>&1"]).await
            .context("Failed to check for pijul")?;

        if status.success() {
            return Ok(());
        }

        tracing::info!("Pijul not found; installing...");
        
        // 2. Install Pijul (using cargo for now, or a pre-built binary if available)
        // For reliability in this environment, let's assume cargo is available or try a static binary.
        // Since we are in a dev environment, let's try cargo install if cargo exists, else fail.
        
        let cargo_check = self.executor.run_status("sh", &["-c", "command -v cargo >/dev/null 2>&1"]).await?;
        if cargo_check.success() {
             let status = self.executor.run_status("cargo", &["install", "pijul"]).await
                .context("Failed to install pijul via cargo")?;
             if !status.success() {
                 return Err(anyhow!("Failed to install pijul via cargo"));
             }
             Ok(())
        } else {
            // Fallback: try to download a static binary or fail
            // For now, fail with a helpful message
            Err(anyhow!("Pijul not found and cargo not available to install it. Please install pijul."))
        }
    }

    async fn init_canonical_repo(&self, session_root: &Path, git_repo: &Path) -> Result<PathBuf> {
        let canonical_path = session_root.join("canonical-pijul");
        tracing::info!("Initializing canonical Pijul repository at {}", canonical_path.display());
        
        // Create canonical directory
        std::fs::create_dir_all(&canonical_path)
            .context("Failed to create canonical-pijul directory")?;
            
        // Copy files from git-repo (excluding .git)
        let status = std::process::Command::new("rsync")
            .args(&[
                "-a",
                "--exclude=.git",
                &format!("{}/", git_repo.display()),
                &format!("{}/", canonical_path.display()),
            ])
            .status()
            .context("Failed to run rsync")?;
            
        if !status.success() {
            return Err(anyhow!("rsync failed to copy files to canonical repo"));
        }
        
        // Setup isolated Pijul home directory
        let pijul_home = session_root.join("system-pijul-home");
        std::fs::create_dir_all(&pijul_home).context("Failed to create system pijul home")?;
        
        // Create Pijul config directories
        let config_dir = pijul_home.join(".config/pijul");
        std::fs::create_dir_all(&config_dir).context("Failed to create pijul config dir")?;
        
        // Create a minimal Pijul config file
        let config_content = r#"[author]
name = "System"
email = "system@steadystate.local"
"#;
        std::fs::write(config_dir.join("config.toml"), config_content)
            .context("Failed to write pijul config")?;
        
        // Generate SSH key for Pijul identity (Pijul uses SSH keys internally)
        let keys_dir = config_dir.join("keys");
        std::fs::create_dir_all(&keys_dir).context("Failed to create keys dir")?;
        
        let key_path = keys_dir.join("system");
        // We use Command directly here as we want to await output/status simply
        let keygen_status = Command::new("ssh-keygen")
            .args(&[
                "-t", "ed25519",
                "-f", key_path.to_str().unwrap(),
                "-N", "",
                "-C", "system@steadystate.local",
            ])
            .output()
            .await
            .context("Failed to generate SSH key for Pijul")?;
        
        if !keygen_status.status.success() {
            tracing::warn!("ssh-keygen failed, Pijul may require manual identity setup");
        }
        
        // Initialize Pijul repository with our isolated HOME
        let init_cmd = format!(
            "export HOME={} && \
             export XDG_CONFIG_HOME={}/.config && \
             cd {} && \
             pijul init",
            pijul_home.display(),
            pijul_home.display(),
            canonical_path.display()
        );
        
        let status = self.executor.run_status("sh", &["-c", &init_cmd]).await
            .context("Failed to run pijul init in canonical repo")?;
            
        if !status.success() {
            return Err(anyhow!("pijul init failed in canonical repo"));
        }
        
        // Add all files
        let add_cmd = format!(
            "export HOME={} && \
             export XDG_CONFIG_HOME={}/.config && \
             cd {} && \
             pijul add -r .",
            pijul_home.display(),
            pijul_home.display(),
            canonical_path.display()
        );
        
        let _ = self.executor.run_status("sh", &["-c", &add_cmd]).await;
        
        // Record initial state - use --author flag to bypass identity requirement
        let record_cmd = format!(
            "export HOME={} && \
             export XDG_CONFIG_HOME={}/.config && \
             cd {} && \
             pijul record -a -m 'Initial import from Git' --author 'System <system@steadystate.local>'",
            pijul_home.display(),
            pijul_home.display(),
            canonical_path.display()
        );
        
        // Use Command to capture output for debugging
        let record_output = Command::new("sh")
            .arg("-c")
            .arg(&record_cmd)
            .output()
            .await
            .context("Failed to record initial state")?;
            
        if !record_output.status.success() {
            let stderr = String::from_utf8_lossy(&record_output.stderr);
            let stdout = String::from_utf8_lossy(&record_output.stdout);
            tracing::warn!("Failed to record initial state. stdout: {}, stderr: {}", stdout, stderr);
            // Don't fail - the repo is initialized, just not recorded
        } else {
            tracing::info!("Successfully recorded initial state in canonical repo");
        }
        
        Ok(canonical_path)
    }

    fn install_steadystate_commands(&self, session_root: &Path) -> Result<()> {
        let bin_dir = session_root.join("bin");
        std::fs::create_dir_all(&bin_dir).context("Failed to create bin directory")?;
        
        // 1. Copy steadystate binary as steadystate-cli
        let current_exe = std::env::current_exe().context("Failed to get current executable path")?;
        let target = bin_dir.join("steadystate-cli");
        std::fs::copy(&current_exe, &target).context("Failed to copy steadystate binary")?;
        
        // 2. Create sync script
        let sync_script = r#"#!/bin/bash
set -e

USER_ID="${USER:-unknown}"
# Default to PWD if USER_WORKSPACE not set (fallback)
WORKSPACE="${USER_WORKSPACE:-$PWD}"
# We need to find session root if not set
if [ -z "$SESSION_ROOT" ]; then
    # Try to deduce from workspace path (assuming /tmp/steadystate/sessions/{id}/{user})
    SESSION_ROOT=$(dirname "$WORKSPACE")
fi

CANONICAL="${CANONICAL_REPO:-$SESSION_ROOT/canonical-pijul}"
ACTIVITY_LOG="${ACTIVITY_LOG:-$SESSION_ROOT/activity-log}"

log_activity() {
    local action="$1"
    if [ -f "$ACTIVITY_LOG" ]; then
        echo "$(date -Iseconds),$USER_ID,$action" >> "$ACTIVITY_LOG"
    fi
}

echo "Syncing changes..."
log_activity "syncing"

cd "$WORKSPACE"

# 1. Record local changes (if any)
if pijul add . >/dev/null 2>&1; then
    if pijul record -a -m "Changes by $USER_ID" --author "$USER_ID <$USER_ID@steadystate.local>" 2>&1 | grep -v "Nothing to record"; then
        echo "✓ Recorded your changes"
        log_activity "recorded"
    fi
fi

# 2. Pull from canonical
echo "Pulling changes from collaborators..."
if ! pijul pull canonical --all >/dev/null 2>&1; then
    echo "Warning: Pull may have conflicts, checking..."
fi

# 3. Check for conflicts
CONFLICTS=$(find . -type f ! -path './.pijul/*' -exec grep -l '<<<<<<<' {} \; 2>/dev/null || true)

if [ -n "$CONFLICTS" ]; then
    echo ""
    echo "⚠️  MERGE CONFLICTS DETECTED"
    echo ""
    echo "The following files have conflicts that need your attention:"
    echo ""
    
    for file in $CONFLICTS; do
        # Find first conflict line
        line=$(grep -n '<<<<<<<' "$file" | head -1 | cut -d: -f1)
        echo "  📝 $file (line $line)"
        
        # Log conflict
        log_activity "conflict:{\"file\":\"$file\",\"line\":$line}"
    done
    
    echo ""
    echo "Please:"
    echo "  1. Open the conflicted files"
    echo "  2. Look for conflict markers: <<<<<<<, =======, >>>>>>>"
    echo "  3. Edit to resolve conflicts"
    echo "  4. Save your changes"
    echo "  5. Run 'steadystate sync' again"
    echo ""
    
    exit 0
fi

# 4. Auto-record merge if needed
if [ -n "$(pijul diff 2>/dev/null)" ]; then
    pijul add . >/dev/null 2>&1 || true
    pijul record -a -m "Auto-merge by $USER_ID" --author "$USER_ID <$USER_ID@steadystate.local>" 2>&1 | grep -v "Nothing to record" || true
    echo "✓ Merged changes from collaborators"
fi

# 5. Push to canonical
if pijul push canonical >/dev/null 2>&1; then
    echo "✓ Pushed to canonical repository"
fi

# 6. Log sync completion
log_activity "synced"
echo ""
echo "✓ Sync complete!"
"#;

        let sync_path = bin_dir.join("steadystate-sync");
        std::fs::write(&sync_path, sync_script).context("Failed to write sync script")?;
        
        // Make executable
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sync_path, std::fs::Permissions::from_mode(0o755))?;
        
        // 3. Create wrapper script (steadystate)
        let wrapper_script = r#"#!/bin/bash
case "$1" in
    sync)
        exec steadystate-sync
        ;;
    diff)
        pijul diff
        ;;
    status)
        pijul status
        ;;
    finalize)
        # TODO: Implement finalize
        echo "Finalize not implemented yet"
        ;;
    *)
        # Fallback to real CLI or error
        if command -v steadystate-cli >/dev/null; then
            exec steadystate-cli "$@"
        else
            echo "Unknown command: $1"
            echo "Available: sync, diff, status"
            exit 1
        fi
        ;;
esac
"#;
        let wrapper_path = bin_dir.join("steadystate");
        std::fs::write(&wrapper_path, wrapper_script)?;
        std::fs::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755))?;
        

        Ok(())
    }


    async fn clone_repo(&self, repo_url: &str, dest: &Path) -> Result<()> {
        tracing::info!("Cloning repo {} into {}", repo_url, dest.display());
        
        let dest_str = dest.to_str().ok_or_else(|| anyhow!("Invalid path encoding for dest"))?;
        let status = self.executor.run_status("git", &["clone", "--depth=1", repo_url, dest_str]).await
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
        environment: Option<&str>,
        session_id: &str,
    ) -> Result<(u32, String)> {
        // We run upterm from the host (backend environment), which wraps the nix develop session.
        // This ensures upterm is found (since it's in the host env) and the user lands in the nix dev shell.
        
        // The command that upterm will run *inside* the session.
        // We want to run this command in the `working_dir`.
        // We will handle the directory change in the outer wrapper script.
        
        // We use shell_escape to safely insert paths into the shell string.
        let safe_workdir = shell_escape::escape(working_dir.to_string_lossy().into());
        // let safe_flake = shell_escape::escape(flake_path.to_string_lossy().into());
        
        // Choose flake/nix file based on --env flag
        let env_str = environment.unwrap_or("flake"); // Should be enforced by CLI, but default to flake
        
        let (cmd_prog, cmd_args) = if env_str == "noenv" {
            // Use curated minimal environment
            tracing::info!("Using --env=noenv: minimal curated environment");
            (
                "nix",
                vec![
                    "develop".to_string(),
                    "github:The-Exact-Computing-Company/steadystate?dir=backend/flakes/noenv".to_string(),
                    "--command".to_string(),
                    "bash".to_string(),
                ],
            )
        } else if env_str == "flake" {
            // Use repository's own flake
            tracing::info!("Using --env=flake: repository's flake.nix");
            let path_str = flake_path.to_string_lossy();
            let flake_ref = if path_str.starts_with("github:") {
                path_str.to_string()
            } else {
                // For local testing: point to repo's flake
                // Since we cd into working_dir in the wrapper script, we can just use "."
                ".".to_string()
            };
            (
                "nix",
                vec![
                    "develop".to_string(),
                    flake_ref,
                    "--command".to_string(),
                    "bash".to_string(),
                ],
            )
        } else if env_str.starts_with("legacy-nix") {
             // Handle legacy-nix (nix-shell)
             let filename = if env_str == "legacy-nix" {
                 "default.nix"
             } else {
                 // Parse legacy-nix[filename]
                 let start = env_str.find('[').unwrap_or(0) + 1;
                 let end = env_str.find(']').unwrap_or(env_str.len());
                 &env_str[start..end]
             };
             
             tracing::info!("Using --env={}: nix-shell {}", env_str, filename);
             (
                 "nix-shell",
                 vec![
                     filename.to_string(),
                     "--command".to_string(),
                     "bash".to_string(),
                 ],
             )
        } else {
            // Fallback (should be caught by CLI)
            tracing::warn!("Unknown environment: {}, defaulting to flake", env_str);
             (
                "nix",
                vec![
                    "develop".to_string(),
                    ".".to_string(),
                    "--command".to_string(),
                    "bash".to_string(),
                ],
            )
        };

        // Construct upterm host command
        let mut upterm_args = vec!["host".to_string()];
        
        // 1. Server configuration
        if let Ok(server) = std::env::var("STEADYSTATE_UPTERM_SERVER") {
            upterm_args.push("--server".to_string());
            upterm_args.push(server);
        }

        // Always accept connections automatically since we are running headless
        upterm_args.push("--accept".to_string());

        // 2. Authorization
        let authorized_keys = fetch_authorized_keys(github_user, allowed_users).await;
        
        // Write keys to a temporary file
        let key_file_path = format!("/tmp/steadystate_authorized_keys_{}", session_id);
        
        if let Ok(mut file) = std::fs::File::create(&key_file_path) {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            let _ = file.set_permissions(perms);
            
            use std::io::Write;
            for ak in &authorized_keys {
                if let Err(e) = writeln!(file, "{}", ak.key) {
                    tracing::error!("Failed to write key: {}", e);
                }
            }
        }
        
        upterm_args.push("--authorized-keys".to_string());
        upterm_args.push(key_file_path);

        // 5. Host command
        // upterm host [flags] -- <command> [args...]
        upterm_args.push("--".to_string());
        upterm_args.push(cmd_prog.to_string());
        for arg in cmd_args {
            upterm_args.push(arg);
        }

        tracing::info!("Upterm args: github_user={:?}, allowed_users={:?}, public={}", github_user, allowed_users, public);
        
        // Use setsid to detach from TTY and avoid SIGTTIN when running in background.
        // We use `setsid` to create a new session.
        // We pipe `tail -f /dev/null` to `upterm` to keep it alive (prevent EOF on stdin).
        // We use a wrapper shell script to handle the pipe and setsid while passing arguments safely.
        // We also cd into the working directory here.
        let wrapper_script = r#"
            if [ -f /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
              . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
            fi
            unset SSH_ASKPASS
            unset DISPLAY
            unset SSH_AUTH_SOCK
            
            WORK_DIR="$1"
            shift
            
            cd "$WORK_DIR" || exit 1
            
            # Execute setsid with a helper shell that sets up the pipe and executes the args
            # "$@" contains the upterm command and its arguments
            exec setsid sh -c 'echo "PID: $$"; tail -f /dev/null | exec "$@"' -- "$@"
        "#;
        
        // Convert args to &str
        let upterm_args_str: Vec<&str> = upterm_args.iter().map(|s| s.as_str()).collect();
        
        // Construct the full arguments for the outer sh
        // sh -c script -- workdir upterm [args...]
        let mut full_args = vec!["-c", wrapper_script, "--", safe_workdir.as_ref(), "upterm"];
        full_args.extend(upterm_args_str);
        
        tracing::info!("Spawning upterm command via wrapper...");
        let (wrapper_pid, stdout, stderr) = self.executor.run_capture("sh", &full_args).await
            .context("Failed to spawn upterm wrapper")?;

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
            Ok(Ok((captured_pid, invite, remaining_stdout))) => {
                // Spawn a task to continue draining stdout to prevent SIGPIPE
                tokio::spawn(async move {
                    let mut lines = tokio_stream::wrappers::LinesStream::new(remaining_stdout.lines());
                    while let Some(line_res) = lines.next().await {
                        match line_res {
                            Ok(line) => tracing::debug!(upterm_stdout = %line, "upterm stdout (post-invite)"),
                            Err(_) => break,
                        }
                    }
                });
                
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









pub(crate) async fn capture_upterm_invite(stdout: impl tokio::io::AsyncRead + Unpin + Send + 'static) -> Result<(Option<u32>, String, BufReader<Box<dyn tokio::io::AsyncRead + Unpin + Send>>)> {
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
            let remaining: Box<dyn tokio::io::AsyncRead + Unpin + Send> = Box::new(lines.into_inner().into_inner());
            return Ok((pid, trimmed.to_string(), BufReader::new(remaining)));
        } else if trimmed.starts_with("SSH Session:") {
            // Format: "SSH Session:            ssh ..."
            if let Some(ssh_cmd) = trimmed.strip_prefix("SSH Session:") {
                let ssh_cmd = ssh_cmd.trim();
                tracing::info!("Captured upterm invite: {}", ssh_cmd);
                let remaining: Box<dyn tokio::io::AsyncRead + Unpin + Send> = Box::new(lines.into_inner().into_inner());
                return Ok((pid, ssh_cmd.to_string(), BufReader::new(remaining)));
            }
        } else if line.contains("SSH Command:") {
            // New format (v0.18.0+): "│ ➤ SSH Command:   │ ssh ... │"
            // We look for "ssh " and take everything until the next "│" or end of line
            if let Some(idx) = line.find("ssh ") {
                let rest = &line[idx..];
                // If there's a trailing "│", strip it
                let ssh_cmd = if let Some(end_idx) = rest.find('│') {
                    rest[..end_idx].trim()
                } else {
                    rest.trim()
                };
                tracing::info!("Captured upterm invite (new format): {}", ssh_cmd);
                let remaining: Box<dyn tokio::io::AsyncRead + Unpin + Send> = Box::new(lines.into_inner().into_inner());
                return Ok((pid, ssh_cmd.to_string(), BufReader::new(remaining)));
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
    
    let dest_str = dest.to_str().ok_or_else(|| anyhow!("Invalid path encoding for dest"))?;
    let status = executor.run_status("git", &["clone", "--depth=1", &fork_clone_url, dest_str]).await
        .context("Failed to spawn git clone")?;

    if !status.success() {
        return Err(anyhow!("git clone failed for {}", fork_clone_url.replace(&gh.access_token, "***")));
    }

    // 4. Add upstream remote pointing at the original repo (best effort)
    let upstream_url = format!("https://github.com/{}/{}.git", owner, repo);
    let status = executor.run_status("git", &["-C", dest_str, "remote", "add", "upstream", &upstream_url]).await
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
        tracing::info!("Starting local session: id={} repo={}", session.id, request.repo_url);

        // Check mode
        if let Some(mode) = &request.mode {
            if mode != "pair" && mode != "collab" {
                return Err(anyhow!("Invalid mode: {}", mode));
            }
        }
        
        self.ensure_nix_installed().await?;
        if request.mode.as_deref() == Some("collab") {
            self.ensure_pijul_installed().await?;
        }
        
        let (workspace_root, repo_path) = self.create_workspace(&session.id)?;
        
        // --- GitHub Fork/Clone Logic ---
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

        // 4. Initialize Canonical Pijul Repo (if collab mode)
        let is_collab = request.mode.as_deref().unwrap_or("pair") == "collab";
        
        if is_collab {
            // Initialize canonical repo
            self.init_canonical_repo(&workspace_root, &repo_path).await?;
            
            // Install scripts
            self.install_steadystate_commands(&workspace_root)?;
            
            // Create logs
            std::fs::File::create(workspace_root.join("sync-log"))?;
            std::fs::File::create(workspace_root.join("activity-log"))?;
            
            // Start event daemon
            let event_daemon_pid = self.start_event_daemon(&workspace_root).await?;
            
            // 5. Launch SSHD for collaboration
            let (pid, invite) = self.launch_sshd_for_collab(
                &workspace_root,
                github_login.as_deref(),
                request.allowed_users.as_deref(),
                &session.id
            ).await?;
            
            // Store session info
            let local_session = LocalSession {
                pid,
                event_daemon_pid,
                workspace_root: workspace_root.clone(),
            };
            self.state.live_sessions.insert(session.id.clone(), local_session);
            
            session.state = SessionState::Running;
            session.endpoint = Some(invite.clone());
            
            // Generate Magic Link for Collab
            let magic_link = format!("steadystate://collab/{}?ssh={}", session.id, urlencoding::encode(&invite));
            session.magic_link = Some(magic_link);
            
        } else {
            // Legacy/Pair mode (Upterm)
            
            // Re-implement minimal pijul init for pair mode (inline)
            let init_cmd = format!("cd {} && pijul init", repo_path.display());
            self.executor.run_status("sh", &["-c", &init_cmd]).await?;
            let add_cmd = format!("cd {} && pijul add -r . 2>&1", repo_path.display());
            self.executor.run_status("sh", &["-c", &add_cmd]).await?;
            let record_cmd = format!(
                "cd {} && pijul record -a -m 'Initial import' --author 'System <system@steadystate.local>' 2>&1",
                repo_path.display()
            );
            self.executor.run_status("sh", &["-c", &record_cmd]).await?;
            
            // Launch Upterm
            // Launch Upterm
             let (pid, invite) = self.launch_upterm_in_noenv(
                &self.flake_path,
                &repo_path,
                github_login.as_deref(),
                request.allowed_users.as_deref(),
                request.public,
                request.environment.as_deref(),
                &session.id,
            ).await?;

            let local_session = LocalSession {
                pid,
                event_daemon_pid: None,
                workspace_root: repo_path,
            };
            self.state.live_sessions.insert(session.id.clone(), local_session);

            session.state = SessionState::Running;
            session.endpoint = Some(invite.clone());
            
            // Generate Magic Link for Pair
            let magic_link = format!("steadystate://pair/{}?ssh={}", session.id, urlencoding::encode(&invite));
            session.magic_link = Some(magic_link);
        }

        Ok(())
    }

    async fn terminate_session(&self, session: &Session) -> Result<()> {
        tracing::info!("Terminating local NOENV session: id={}", session.id);
        
        if let Some((_, local_session)) = self.state.live_sessions.remove(&session.id) {
            if local_session.pid != 0 {
                let _ = self.kill_pid(local_session.pid).await;
            }
            if let Some(ed_pid) = local_session.event_daemon_pid {
                let _ = self.kill_pid(ed_pid).await;
            }
            if let Err(e) = std::fs::remove_dir_all(&local_session.workspace_root) {
                tracing::warn!("Failed to remove workspace at {}: {:#}", local_session.workspace_root.display(), e);
            }
            let key_file_path = format!("/tmp/steadystate_authorized_keys_{}", session.id);
            if let Err(e) = std::fs::remove_file(&key_file_path) {
                tracing::warn!("Failed to remove key file at {}: {:#}", key_file_path, e);
            }
        } else {
            tracing::warn!("terminate_session called, but no live session state found for id={}", session.id);
        }
        Ok(())
    }


}

impl LocalComputeProvider {
    async fn start_event_daemon(&self, session_root: &Path) -> Result<Option<u32>> {
        tracing::info!("Starting event daemon for session: {}", session_root.display());
        
        // In a real deployment, we'd expect steady-eventd to be in PATH or relative to exe.
        // For dev, we can try to run it via cargo or look in target dir.
        
        let exe_path = std::env::current_exe()?;
        let bin_dir = exe_path.parent().unwrap();
        let daemon_path = bin_dir.join("steady-eventd");
        
        let cmd_path = if daemon_path.exists() {
            daemon_path
        } else {
            // Fallback for dev environment (running from source root?)
            // Try to find it in target/release or target/debug
            let mut p = std::env::current_dir()?.join("target/release/steady-eventd");
            if !p.exists() {
                p = std::env::current_dir()?.join("target/debug/steady-eventd");
            }
            p
        };
        
        if !cmd_path.exists() {
            tracing::warn!("steady-eventd binary not found at {}, skipping event daemon", cmd_path.display());
            return Ok(None);
        }

        let child = tokio::process::Command::new(cmd_path)
            .arg("--session-root")
            .arg(session_root)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .context("Failed to spawn steady-eventd")?;
            
        let pid = child.id();
        tracing::info!("Started steady-eventd with PID: {:?}", pid);
        
        Ok(pid)
    }

    async fn launch_sshd_for_collab(
        &self,
        session_root: &Path,
        github_user: Option<&str>,
        allowed_users: Option<&[String]>,
        session_id: &str,
    ) -> Result<(u32, String)> {
        use tokio::process::Command;
        use tokio::time::timeout;
        tracing::info!("Launching SSHD for collab session {}", session_id);

        // ------------------------------------------------------------
        // NEW: Create secure sshd runtime directory
        // ------------------------------------------------------------
        let sshd_dir = session_root.join("sshd");
        std::fs::create_dir_all(&sshd_dir)
            .context("Failed to create sshd directory")?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sshd_dir, std::fs::Permissions::from_mode(0o700))
            .context("Failed to chmod sshd directory")?;

        // 1. Generate Host Keys
        let host_key_path = sshd_dir.join("host_key");
        if !host_key_path.exists() {
            let key_str = host_key_path.to_string_lossy();
            let status = self.executor.run_status(
                "ssh-keygen", 
                &["-t", "ed25519", "-f", &key_str, "-N", ""]
            ).await.context("Failed to generate host key")?;
            
            if !status.success() {
                return Err(anyhow!("ssh-keygen failed"));
            }
        }
        
        // Ensure Host Key permissions are strict (0600)
        std::fs::set_permissions(&host_key_path, std::fs::Permissions::from_mode(0o600))
            .context("Failed to set host key permissions")?;

        // ------------------------------------------------------------
        // NEW: Paths for auth keys, config, logs, pid
        // ------------------------------------------------------------
        let auth_keys_path = sshd_dir.join("authorized_keys");
        let config_path = sshd_dir.join("sshd_config");
        let log_path = sshd_dir.join("sshd.log");
        let pid_path = sshd_dir.join("sshd.pid");

        // 2. Copy steadystate CLI binary to session bin
        let bin_dir = session_root.join("bin");
        std::fs::create_dir_all(&bin_dir).context("Failed to create bin dir")?;
        
        tracing::info!("Locating steadystate CLI binary...");
        
        let target_exe = bin_dir.join("steadystate");
        
        tokio::task::spawn_blocking(move || -> Result<()> {
            // Try to find steadystate CLI in the same directory as the backend first
            let current_exe = std::env::current_exe()?;
            let current_dir = current_exe.parent().ok_or_else(|| anyhow!("Failed to get current exe directory"))?;
            let mut cli_exe = current_dir.join("steadystate");
            
            // If not found, try to find it in PATH
            if !cli_exe.exists() {
                tracing::info!("steadystate binary not found in {:?}, searching PATH...", current_dir);
                if let Ok(output) = std::process::Command::new("which").arg("steadystate").output() {
                    if output.status.success() {
                        let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        let path = PathBuf::from(path_str);
                        if path.exists() {
                            cli_exe = path;
                        }
                    }
                }
            }
            
            if !cli_exe.exists() {
                return Err(anyhow!("steadystate CLI binary not found at {} or in PATH. Ensure it is built and available.", cli_exe.display()));
            }

            tracing::info!("Found steadystate CLI at: {:?}", cli_exe);
            std::fs::copy(&cli_exe, &target_exe).context("Failed to copy steadystate binary")?;
            Ok(())
        }).await??;
        
        tracing::info!("steadystate CLI binary copied successfully.");
        
        // 3. Prepare Authorized Keys with ForceCommand
        let authorized_keys = fetch_authorized_keys(github_user, allowed_users).await;
        
        if authorized_keys.is_empty() {
            return Err(anyhow!("No authorized keys found. Cannot start SSHD without at least one key."));
        }
        
        // ------------------------------------------------------------
        // FIX: wrapper script also lives in secure directory
        // ------------------------------------------------------------
        let wrapper_path = sshd_dir.join("wrapper.sh");
        
        // Generate port early so we can include it in the magic link
        let port = 20000 + (rand::random::<u16>() % 10000);
        let user = std::env::var("USER").unwrap_or("steadystate".into());
        let invite = format!("ssh://{}@localhost:{}", user, port);
        let magic_link = format!("steadystate://collab/{}?ssh={}", session_id, urlencoding::encode(&invite));
        
        // Use /usr/bin/env bash for portability (NixOS doesn't always have /bin/bash)
        let wrapper_content = format!(r#"#!/usr/bin/env bash
set -e

USER_ID="$1"
export REPO_ROOT="{session_root}"
export PATH="$REPO_ROOT/bin:$PATH"
ACTIVE_USERS_FILE="$REPO_ROOT/active-users"
ACTIVITY_LOG="$REPO_ROOT/activity-log"
SYNC_LOG="$REPO_ROOT/sync-log"
export ACTIVITY_LOG
export SYNC_LOG
export SESSION_ROOT="$REPO_ROOT"
export NOENV_FLAKE_PATH="{noenv_flake_path}"
export JWT_SECRET="{jwt_secret}"
export SESSION_ID="{session_id}"
export MAGIC_LINK="{magic_link}"

# Add user to active-users
echo "$USER_ID" >> "$ACTIVE_USERS_FILE"

# Cleanup function
cleanup() {{
    if [ -f "$ACTIVE_USERS_FILE" ]; then
        grep -v "^$USER_ID$" "$ACTIVE_USERS_FILE" > "$ACTIVE_USERS_FILE.tmp" 2>/dev/null || true
        mv "$ACTIVE_USERS_FILE.tmp" "$ACTIVE_USERS_FILE" 2>/dev/null || true
    fi
}}
trap cleanup EXIT

# Create worktree if not exists
WORKTREE="$REPO_ROOT/worktrees/$USER_ID"
if [ ! -d "$WORKTREE" ]; then
    echo "Creating workspace for $USER_ID..."
    mkdir -p "$REPO_ROOT/worktrees"
    
    # Clone from canonical repo
    pijul clone "$REPO_ROOT/canonical-pijul" "$WORKTREE" 2>&1 || {{
        echo "Failed to clone workspace"
        exit 1
    }}
fi

# Set HOME to workspace for isolation
export HOME="$WORKTREE"
export USER_WORKSPACE="$WORKTREE"
export CANONICAL_REPO="$REPO_ROOT/canonical-pijul"

cd "$WORKTREE" || exit 1

# Configure Pijul remote if not exists
if ! pijul remote 2>/dev/null | grep -q "canonical"; then
    echo "Adding canonical remote..."
    pijul remote add canonical "$CANONICAL_REPO" 2>&1 || true
fi

# Handle SSH_ORIGINAL_COMMAND
if [ -n "$SSH_ORIGINAL_COMMAND" ]; then
    exec bash -c "$SSH_ORIGINAL_COMMAND"
else
    # Default to shell
    cat << 'WELCOME'
╔════════════════════════════════════════════════════════════╗
║         Welcome to SteadyState Collaboration Mode          ║
╚════════════════════════════════════════════════════════════╝

Your workspace: $WORKTREE

Commands:
  steadystate sync      - Sync your changes
  steadystate diff      - Show changes
  steadystate status    - Check status

WELCOME
    
    exec bash -l
fi
"#, 
        session_root = session_root.display(),
        noenv_flake_path = self.flake_path.display(),
        jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "placeholder_secret".to_string()),
        session_id = session_id,
        magic_link = magic_link
        );

        std::fs::write(&wrapper_path, wrapper_content).context("Failed to write wrapper script")?;
        std::fs::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755))?;

        // Write authorized keys
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&auth_keys_path).context("Failed to create authorized_keys")?;
            std::fs::set_permissions(&auth_keys_path, std::fs::Permissions::from_mode(0o600))?;
            
            for ak in &authorized_keys {
                writeln!(file, "command=\"{} {}\" {}", wrapper_path.display(), ak.user, ak.key)?;
            }
        }

        // 4. Generate sshd_config with better settings
        // 4. Generate sshd_config with better settings
        // Port is already generated above
        
        // Find sshd path
        let sshd_path = if Path::new("/usr/sbin/sshd").exists() {
            "/usr/sbin/sshd".to_string()
        } else if Path::new("/usr/bin/sshd").exists() {
            "/usr/bin/sshd".to_string()
        } else {
            // Try to find absolute path using `which`
            match Command::new("which").arg("sshd").output().await {
                Ok(output) if output.status.success() => {
                    String::from_utf8_lossy(&output.stdout).trim().to_string()
                }
                _ => {
                    tracing::warn!("Could not find absolute path for sshd, using 'sshd'");
                    "sshd".to_string()
                }
            }
        };
        
        let sshd_config = format!(r#"# SteadyState SSH Configuration
Port {port}
ListenAddress 127.0.0.1
HostKey {host_key}
PidFile {pid}

# Authentication
PubkeyAuthentication yes
AuthorizedKeysFile {auth_keys}
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
PermitRootLogin no

# Security
StrictModes no
PermitUserEnvironment yes
UsePrivilegeSeparation no

# Logging
SyslogFacility USER
LogLevel DEBUG3

# Session
PrintMotd no
PrintLastLog no
AcceptEnv LANG LC_*

# Subsystems
Subsystem sftp internal-sftp
"#, 
            port = port,
            host_key = host_key_path.display(),
            auth_keys = auth_keys_path.display(),
            pid = pid_path.display()
        );

        std::fs::write(&config_path, sshd_config)?;
        
        tracing::info!("SSHD config written to: {}", config_path.display());
        tracing::info!("Using SSHD binary: {}", sshd_path);
        tracing::info!("Listening on port: {}", port);

        // 5. Test the config first
        let test_output = Command::new(&sshd_path)
            .args(&["-t", "-f", config_path.to_str().unwrap()])
            .output()
            .await
            .context("Failed to test sshd config")?;
        
        if !test_output.status.success() {
            let stderr = String::from_utf8_lossy(&test_output.stderr);
            tracing::error!("SSHD config test failed: {}", stderr);
            return Err(anyhow!("Invalid SSHD configuration: {}", stderr));
        }
        
        tracing::info!("SSHD config test passed");

        // 6. Spawn sshd with explicit paths and logging to file
        // -D: no detach
        // -E log_file: append debug logs to log_file
        let args = vec!["-f", config_path.to_str().unwrap(), "-D", "-E", log_path.to_str().unwrap()];

        tracing::info!("Spawning sshd: {} {}", sshd_path, args.join(" "));
        
        let (pid, stdout, stderr) = self.executor.run_capture(&sshd_path, &args).await
            .context("Failed to spawn sshd")?;

        tracing::info!("SSHD spawned with PID {}", pid);
        
        // Spawn stderr logger to capture immediate startup errors
        let stderr_reader = BufReader::new(stderr);
        let stderr_lines = Arc::new(Mutex::new(Vec::new()));
        let stderr_lines_clone = stderr_lines.clone();
        
        tokio::spawn(async move {
            let mut lines = tokio_stream::wrappers::LinesStream::new(stderr_reader.lines());
            while let Some(line_res) = lines.next().await {
                if let Ok(line) = line_res {
                    tracing::warn!("SSHD STDERR: {}", line);
                    stderr_lines_clone.lock().unwrap().push(line);
                }
            }
        });
        
        // Wait longer for sshd to start
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        
        // Check if process is still alive
        let check_cmd = format!("kill -0 {} 2>/dev/null", pid);
        match self.executor.run_status("sh", &["-c", &check_cmd]).await {
            Ok(status) if status.success() => {
                tracing::info!("SSHD process {} is running", pid);
            }
            _ => {
                tracing::error!("SSHD process {} died after launch", pid);
                
                // Collect captured stderr
                let captured_stderr = stderr_lines.lock().unwrap().join("\n");
                
                // Read the log file
                let log_content = std::fs::read_to_string(&log_path).unwrap_or_default();
                
                let error_msg = format!(
                    "SSHD process {} died immediately.\nCaptured STDERR:\n{}\nLog File Content:\n{}", 
                    pid, captured_stderr, log_content
                );
                
                tracing::error!("{}", error_msg);
                return Err(anyhow!(error_msg));
            }
        }

        // Try to connect to the port to verify it's listening
        let port_check = format!("nc -z localhost {} 2>/dev/null || (sleep 1 && nc -z localhost {})", port, port);
        match timeout(
            std::time::Duration::from_secs(5),
            self.executor.run_status("sh", &["-c", &port_check])
        ).await {
            Ok(Ok(status)) if status.success() => {
                tracing::info!("SSHD is listening on port {}", port);
            }
            _ => {
                tracing::warn!("Could not verify SSHD is listening on port {} (nc might not be available)", port);
                // Don't fail here, just warn
            }
        }

        // Use current user for invite link
        let current_user = std::env::var("USER").unwrap_or_else(|_| "steady".to_string());
        let hostname = "localhost";
        let invite = format!("ssh://{}@{}:{}", current_user, hostname, port);
        
        tracing::info!("SSHD ready. Connect with: {}", invite);
        
        Ok((pid, invite))
    }
}

struct AuthorizedKey {
    user: String,
    key: String,
}

async fn fetch_authorized_keys(github_user: Option<&str>, allowed_users: Option<&[String]>) -> Vec<AuthorizedKey> {
    tracing::info!("Starting fetch_authorized_keys");
    // Use a Set to deduplicate keys
    let mut unique_keys = std::collections::HashSet::new();
    let mut result = Vec::new();
    
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap_or_default();

    // 1. Add local keys
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    tracing::info!("fetch_authorized_keys: HOME={}", home);
    
    let local_key_paths = vec![
        format!("{}/.ssh/id_ed25519.pub", home),
        format!("{}/.ssh/id_rsa.pub", home),
    ];

    for path in local_key_paths {
        tracing::info!("Checking for local key at: {}", path);
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    if unique_keys.insert(trimmed.to_string()) {
                        result.push(AuthorizedKey { user: "host".to_string(), key: trimmed.to_string() });
                    }
                }
            }
            tracing::info!("Added local key from {}", path);
        } else {
            tracing::warn!("Could not read local key at {}", path);
        }
    }

    // 2. Fetch GitHub keys
    let mut users_to_fetch = Vec::new();
    if let Some(user) = github_user {
        users_to_fetch.push(user);
    }
    if let Some(users) = allowed_users {
        users_to_fetch.extend(users.iter().map(|s| s.as_str()));
    }

    tracing::info!("Fetching keys for users: {:?}", users_to_fetch);

    for user in users_to_fetch {
        let url = format!("https://github.com/{}.keys", user);
        tracing::info!("Fetching keys from {}", url);
        match client.get(&url).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(text) = resp.text().await {
                        let mut count = 0;
                        for line in text.lines() {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                                if unique_keys.insert(trimmed.to_string()) {
                                    result.push(AuthorizedKey { user: user.to_string(), key: trimmed.to_string() });
                                    count += 1;
                                }
                            }
                        }
                        tracing::info!("Fetched {} keys for GitHub user {}", count, user);
                    }
                } else {
                    tracing::warn!("Failed to fetch keys for {}: HTTP {}", user, resp.status());
                }
            }
            Err(e) => {
                tracing::warn!("Failed to fetch keys for {}: {}", user, e);
            }
        }
    }

    tracing::info!("fetch_authorized_keys completed. Found {} keys total.", result.len());
    result
}
