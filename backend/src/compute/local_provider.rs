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
            let mut perms = file.metadata().unwrap().permissions();
            perms.set_mode(0o600);
            let _ = file.set_permissions(perms);
            
            use std::io::Write;
            if let Err(e) = file.write_all(authorized_keys.as_bytes()) {
                tracing::error!("Failed to write authorized keys to file: {}", e);
            }
            let _ = file.write_all(b"\n");
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
            request.public,
            request.environment.as_deref(),
            &session.id,
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

async fn fetch_authorized_keys(github_user: Option<&str>, allowed_users: Option<&[String]>) -> String {
    // Use a Set to deduplicate keys
    let mut unique_keys = std::collections::HashSet::new();
    
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
                    unique_keys.insert(trimmed.to_string());
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

    for user in users_to_fetch {
        let url = format!("https://github.com/{}.keys", user);
        match client.get(&url).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(text) = resp.text().await {
                        for line in text.lines() {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                                unique_keys.insert(trimmed.to_string());
                            }
                        }
                        tracing::info!("Fetched keys for GitHub user {}", user);
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

    // Join all unique keys with newlines
    let result = unique_keys.into_iter().collect::<Vec<_>>().join("\n");
    result
}
