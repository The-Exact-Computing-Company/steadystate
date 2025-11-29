// cli/src/main.rs

//! SteadyState CLI - Manage reproducible development environments
//!
//! This CLI provides commands for authentication and session management.
//! See README.md for usage examples.

mod auth;
mod config;
mod session;
mod sync;
mod notify;
mod merge;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use reqwest::{Client, Url};
use serde::Serialize;
use tokio::time::Duration;
use tracing::{error, info, warn};

use auth::{
    UpResponse, delete_refresh_token, device_login, get_refresh_token, perform_refresh,
    request_with_auth,
};
use config::{BACKEND_URL, CLI_VERSION, HTTP_TIMEOUT_SECS, USER_AGENT};
use session::{read_session, remove_session};
use steadystate_common::types::SessionState;

#[derive(Parser)]
#[command(
    name = "steadystate",
    about = "SteadyState CLI — Exact reproducible dev envs",
    disable_version_flag = true,
    version = CLI_VERSION
)]
struct Cli {
    #[arg(long = "version", short = 'v')]
    version: bool,

    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start interactive login (device flow)
    Login {
        /// Authentication provider (e.g., github, gitlab, orchid, fake)
        #[arg(long, default_value = "github")]
        provider: String,
    },
    /// Show current logged-in user (if any)
    Whoami {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Refresh JWT using refresh token stored in keychain
    Refresh,
    /// Logout: revoke refresh token and clear local session
    Logout,
    /// Create a remote development session for the provided repository URL
    Up {
        /// Repository URL used for the remote session
        repo: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Allow specific GitHub users to connect. Defaults to all repository collaborators. Use "none" to restrict to host only.
        #[arg(long)]
        allow: Vec<String>,
        /// Make the session public (anyone with the link can connect)
        #[arg(long)]
        public: bool,
        /// Environment to load (e.g. "noenv")
        #[arg(long)]
        env: Option<String>,
        /// Session mode: "pair" or "collab"
        #[arg(long)]
        mode: Option<String>,
    },
    /// Join a remote session using a magic link or SSH URL
    Join {
        /// Magic link (steadystate://...) or SSH URL
        url: String,
    },
    /// Synchronize changes with other users (Collaboration Mode)
    Sync,
    /// Watch for sync events (Collaboration Mode)
    Watch,
    /// Show the working tree status
    Status,
    /// Show changes between the working tree and the last synced state
    Diff,
    /// Publish changes to the canonical repository (alias for sync)
    Publish,
}

#[derive(Serialize)]
struct WhoamiOutput {
    logged_in: bool,
    login: Option<String>,
    jwt_expires_at: Option<u64>,
}

async fn whoami(json_output: bool) -> Result<()> {
    match read_session(None).await {
        Ok(sess) => {
            if json_output {
                let output = WhoamiOutput {
                    logged_in: true,
                    login: Some(sess.login.clone()),
                    jwt_expires_at: sess.jwt_exp,
                };
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Logged in as: {}", sess.login);
                if let Some(exp) = sess.jwt_exp {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("System time is before UNIX EPOCH")
                        .as_secs();
                    if exp > now {
                        let remaining = exp - now;
                        println!("JWT expires in: {}s", remaining);
                    } else {
                        println!("JWT expired (will auto-refresh on next use)");
                    }
                }
            }
            Ok(())
        }
        Err(_) => {
            if json_output {
                let output = WhoamiOutput {
                    logged_in: false,
                    login: None,
                    jwt_expires_at: None,
                };
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("No active session found. Run 'steadystate login' first.");
            }
            Ok(())
        }
    }
}

async fn logout(client: &Client) -> Result<()> {
    let session = match read_session(None).await {
        Ok(s) => s,
        Err(_) => {
            println!("No active session");
            return Ok(());
        }
    };
    let username = session.login.clone();

    if let Some(refresh) = get_refresh_token(&username, None).await? {
        let url = format!("{}/auth/revoke", &*BACKEND_URL);
        match auth::send_with_retries(|| {
            client
                .post(&url)
                .json(&serde_json::json!({ "refresh_token": refresh.clone() }))
        })
        .await
        {
            Ok(resp) if resp.status().is_success() => {
                info!("Refresh token revoked on server");
            }
            Ok(resp) => {
                warn!("Server revoke returned status: {}", resp.status());
            }
            Err(e) => {
                warn!("Failed to revoke on server: {:#}", e);
            }
        }
    }

    let _ = delete_refresh_token(&username, None).await;
    let _ = remove_session(None).await;
    println!("Logged out (local tokens removed).");
    Ok(())
}

async fn up(client: &Client, repo: String, json: bool, allow: Vec<String>, public: bool, env: Option<String>, mode: Option<String>) -> Result<()> {
    Url::parse(&repo).context(
        "Invalid repository URL. Provide a fully-qualified URL (e.g. https://github.com/user/repo).",
    )?;

    // Validate --env flag
    let env_val = match env {
        Some(e) => e,
        None => {
            eprintln!("Error: --env flag is required.");
            eprintln!("Valid options:");
            eprintln!("  --env=noenv                 Use minimal curated environment");
            eprintln!("  --env=flake                 Use repository's flake.nix");
            eprintln!("  --env=legacy-nix            Use default.nix (nix-shell)");
            eprintln!("  --env=legacy-nix[filename]  Use specified nix file (nix-shell)");
            return Ok(());
        }
    };

    // Check if env is valid
    let is_valid = env_val == "noenv" ||
                   env_val == "flake" ||
                   env_val == "legacy-nix" ||
                   (env_val.starts_with("legacy-nix[") && env_val.ends_with("]"));

    if !is_valid {
        eprintln!("Error: Invalid --env option: {}", env_val);
        eprintln!("Valid options:");
        eprintln!("  --env=noenv                 Use minimal curated environment");
        eprintln!("  --env=flake                 Use repository's flake.nix");
        eprintln!("  --env=legacy-nix            Use default.nix (nix-shell)");
        eprintln!("  --env=legacy-nix[filename]  Use specified nix file (nix-shell)");
        return Ok(());
    }

    // Validate --mode flag
    let mode_val = match mode {
        Some(m) => m,
        None => {
            eprintln!("Error: --mode flag is required.");
            eprintln!("Valid options:");
            eprintln!("  --mode=pair    Pair programming mode (Upterm)");
            eprintln!("  --mode=collab  Collaboration mode (SSH)");
            return Ok(());
        }
    };

    if mode_val != "pair" && mode_val != "collab" {
        eprintln!("Error: Invalid --mode option: {}", mode_val);
        eprintln!("Valid options:");
        eprintln!("  --mode=pair    Pair programming mode (Upterm)");
        eprintln!("  --mode=collab  Collaboration mode (SSH)");
        return Ok(());
    }

    let payload = serde_json::json!({
        "repo_url": repo,
        "allowed_users": if allow.is_empty() { None } else { Some(allow.clone()) },
        "public": public,
        "environment": env_val,
        "mode": mode_val
    });

    let resp: UpResponse = request_with_auth(
        client,
        |c, jwt| {
            c.post(format!("{}/sessions", &*BACKEND_URL))
                .bearer_auth(jwt)
                .json(&payload)
        },
        None,
    )
    .await?;

    let mut final_endpoint = resp.endpoint.clone();
    let mut final_host_key = resp.host_public_key.clone();


    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        println!("✅ Session created: {}", resp.id);
        
        // Poll until the session is ready or fails
        if resp.endpoint.is_none() && resp.state == SessionState::Provisioning {
            println!("⏳ Provisioning session...");
            
            let mut attempts = 0;
            let max_attempts = 60; // 60 * 1s = 1 minute timeout
            
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                attempts += 1;
                
                let status: UpResponse = request_with_auth( // Assuming UpResponse can also be used for status
                    client,
                    |c, jwt| {
                        c.get(format!("{}/sessions/{}", &*BACKEND_URL, resp.id))
                            .bearer_auth(jwt)
                    },
                    None,
                )
                .await?;
                
                match status.state {
                    SessionState::Running => {
                        final_endpoint = status.endpoint;
                        final_host_key = status.host_public_key;
                        let final_magic_link = status.magic_link; // Update magic link from status
                        
                        if let Some(endpoint) = &final_endpoint {
                            println!("✅ Session ready!");
                            println!("SSH: {}", endpoint);
                            if let Some(link) = &final_magic_link {
                                println!("Magic Link: {}", link);
                            }
                        } else {
                            println!("⚠️  Session is running but no endpoint available");
                        }
                        break;
                    }
                    SessionState::Failed => {
                        println!("❌ Session provisioning failed");
                        if let Some(msg) = status.message {
                            println!("Error: {}", msg);
                        }
                        return Err(anyhow::anyhow!("Session provisioning failed"));
                    }
                    SessionState::Provisioning => {
                        if attempts >= max_attempts {
                            println!("⏱️  Timed out waiting for session. Check status later with:");
                            println!("  curl -H 'Authorization: Bearer <token>' {}/sessions/{}", &*BACKEND_URL, resp.id);
                            break;
                        }
                        // Continue polling
                    }
                    other => {
                        println!("Session state: {:?}", other);
                    }
                }
            }
        } else if let Some(endpoint) = &resp.endpoint {
            println!("✅ Session ready!");
            println!("SSH: {}", endpoint);
            if let Some(link) = &resp.magic_link { // Print initial magic link if available
                println!("Magic Link: {}", link);
            }
        }

        // Launch dashboard if in collab mode and we have an endpoint
        if mode_val == "collab" {
            if let Some(endpoint) = final_endpoint {
                println!("Launching dashboard...");
                // Parse endpoint to get host/port/user
                // Endpoint is ssh://steady@host:port
                // We want to run: ssh -t -p port steady@host "steadystate watch"
                
                if let Ok(url) = Url::parse(&endpoint) {
                    let host = url.host_str().unwrap_or("localhost");
                    let port = url.port().unwrap_or(22);
                    let user = url.username();
                    
                    let mut args = vec![
                        "-p".to_string(),
                        port.to_string(),
                        "-t".to_string(), // Force PTY for TUI
                    ];
                    
                    if let Some(host_key) = final_host_key {
                        let known_hosts = format!("[{}]:{} {}", host, port, host_key);
                        let known_hosts_path = format!("/tmp/steadystate-{}-known_hosts", resp.id);
                        std::fs::write(&known_hosts_path, known_hosts)?;
                        
                        args.extend([
                            "-o".to_string(), format!("UserKnownHostsFile={}", known_hosts_path),
                            "-o".to_string(), "StrictHostKeyChecking=yes".to_string(),
                        ]);
                    } else {
                        args.extend([
                            "-o".to_string(), "StrictHostKeyChecking=no".to_string(),
                            "-o".to_string(), "UserKnownHostsFile=/dev/null".to_string(),
                        ]);
                    }
                    
                    let target = if !user.is_empty() {
                        format!("{}@{}", user, host)
                    } else {
                        host.to_string()
                    };
                    args.push(target);
                    
                    // Command to run
                    args.push("steadystate watch".to_string());
                    
                    println!("Connecting to dashboard...");
                    use std::os::unix::process::CommandExt;
                    let err = std::process::Command::new("ssh")
                        .args(&args)
                        .exec();
                    return Err(anyhow::anyhow!("Failed to execute ssh: {}", err));
                }
            }
        }
    }

    Ok(())
}

async fn join(url_str: String) -> Result<()> {
    if url_str.starts_with("steadystate://") {
        let url = Url::parse(&url_str).context("Failed to parse magic link")?;
        
        let mode = url.host_str().ok_or_else(|| anyhow::anyhow!("Invalid magic link: missing mode"))?;
        
        match mode {
            "pair" => {
                // Extract upterm param
                let mut pairs = url.query_pairs();
                let upterm_url = pairs
                    .find(|(key, _)| key == "upterm")
                    .map(|(_, val)| val.to_string())
                    .ok_or_else(|| anyhow::anyhow!("Invalid pair link: missing 'upterm' parameter"))?;
                
                println!("Joining pair session...");
                println!("Connecting to: {}", upterm_url);
                
                // Execute ssh
                let up_url = Url::parse(&upterm_url).context("Failed to parse upterm URL")?;
                let host = up_url.host_str().ok_or_else(|| anyhow::anyhow!("Missing host in upterm URL"))?;
                let port = up_url.port().unwrap_or(22);
                let user = up_url.username();
                
                let mut args = vec![
                    "-p".to_string(),
                    port.to_string(),
                    "-o".to_string(),
                    "StrictHostKeyChecking=no".to_string(), // For ephemeral hosts
                    "-o".to_string(),
                    "UserKnownHostsFile=/dev/null".to_string(),
                    "-t".to_string(), // Force PTY
                ];
                
                if !user.is_empty() {
                    args.push(format!("{}@{}", user, host));
                } else {
                    args.push(host.to_string());
                }
                
                use std::os::unix::process::CommandExt;
                let err = std::process::Command::new("ssh")
                    .args(&args)
                    .exec();
                    
                return Err(anyhow::anyhow!("Failed to execute ssh: {}", err));
            }
            "collab" => {
                // Extract ssh param
                let mut pairs = url.query_pairs();
                let ssh_url = pairs
                    .find(|(key, _)| key == "ssh")
                    .map(|(_, val)| val.to_string())
                    .ok_or_else(|| anyhow::anyhow!("Invalid collab link: missing 'ssh' parameter"))?;
                
                let host_key = pairs
                    .find(|(key, _)| key == "host_key")
                    .map(|(_, val)| val.to_string());
                
                println!("Joining collaboration session...");
                println!("Connecting to: {}", ssh_url);
                
                // Execute ssh
                let up_url = Url::parse(&ssh_url).context("Failed to parse SSH URL")?;
                let host = up_url.host_str().ok_or_else(|| anyhow::anyhow!("Missing host in SSH URL"))?;
                let port = up_url.port().unwrap_or(22);
                let user = up_url.username();
                
                let mut args = vec![
                    "-p".to_string(),
                    port.to_string(),
                ];

                if let Some(key) = host_key {
                    // We don't have session ID easily here, use random or hash of url
                    use std::collections::hash_map::DefaultHasher;
                    use std::hash::{Hash, Hasher};
                    let mut hasher = DefaultHasher::new();
                    url_str.hash(&mut hasher);
                    let session_id = format!("{:x}", hasher.finish());

                    let known_hosts = format!("[{}]:{} {}", host, port, key);
                    let known_hosts_path = format!("/tmp/steadystate-{}-known_hosts", session_id);
                    std::fs::write(&known_hosts_path, known_hosts)?;
                    
                    args.extend([
                        "-o".to_string(), format!("UserKnownHostsFile={}", known_hosts_path),
                        "-o".to_string(), "StrictHostKeyChecking=yes".to_string(),
                    ]);
                } else {
                    args.extend([
                        "-o".to_string(), "StrictHostKeyChecking=no".to_string(),
                        "-o".to_string(), "UserKnownHostsFile=/dev/null".to_string(),
                    ]);
                }

                args.push("-t".to_string()); // Force PTY
                
                if !user.is_empty() {
                    args.push(format!("{}@{}", user, host));
                } else {
                    args.push(host.to_string());
                }

                // Inject username if available
                let shell_cmd = if let Ok(session) = crate::session::read_session(None).await {
                    format!("export STEADYSTATE_USERNAME={}; exec $SHELL -l", session.login)
                } else {
                    "exec $SHELL -l".to_string()
                };
                args.push(shell_cmd);
                
                use std::os::unix::process::CommandExt;
                let err = std::process::Command::new("ssh")
                    .args(&args)
                    .exec();
                    
                return Err(anyhow::anyhow!("Failed to execute ssh: {}", err));
            }
            _ => {
                return Err(anyhow::anyhow!("Unknown mode: {}", mode));
            }
        }
    } else {
        // Legacy/Direct SSH URL
        println!("Joining via direct SSH...");
        
        if url_str.starts_with("ssh://") {
             let up_url = Url::parse(&url_str).context("Failed to parse SSH URL")?;
             let host = up_url.host_str().ok_or_else(|| anyhow::anyhow!("Missing host in SSH URL"))?;
             let port = up_url.port().unwrap_or(22);
             let user = up_url.username();
             
             let mut args = vec![
                "-p".to_string(),
                port.to_string(),
                "-t".to_string(),
            ];
             
             if !user.is_empty() {
                args.push(format!("{}@{}", user, host));
            } else {
                args.push(host.to_string());
            }
            
            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new("ssh")
                .args(&args)
                .exec();
            return Err(anyhow::anyhow!("Failed to execute ssh: {}", err));
        } else {
            // Assume it's valid ssh arg
             use std::os::unix::process::CommandExt;
            let err = std::process::Command::new("ssh")
                .arg(&url_str)
                .exec();
            return Err(anyhow::anyhow!("Failed to execute ssh: {}", err));
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    if std::env::var("RUST_LOG")
        .ok()
        .map(|value| value.to_lowercase().contains("debug"))
        .unwrap_or(false)
    {
        eprintln!(
            "⚠️ Debug logging is enabled; JWTs and refresh tokens may appear in logs. Proceed carefully."
        );
    }

    let cli = Cli::parse();

    if cli.version {
        println!("SteadyState CLI version {}", CLI_VERSION);
        return Ok(());
    }

    let cmd = match cli.cmd {
        Some(cmd) => cmd,
        None => {
            Cli::command().print_help().ok();
            println!();
            return Ok(());
        }
    };

    // Condition: disable connection pooling during integration tests.
    let mut builder = Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS));

    if std::env::var("STEADYSTATE_BACKEND").is_ok() {
        builder = builder
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(None);
    }

    let client = builder.build().context("create http client")?;

    match cmd {
        Commands::Login { provider } => {
            if let Err(e) = device_login(&client, &provider).await.context(
                "Failed to reach backend. Check network connectivity and the STEADYSTATE_BACKEND environment variable.",
            ) {
                error!("login failed: {:#}", e);
                std::process::exit(1);
            }
        }
        Commands::Whoami { json } => {
            if let Err(e) = whoami(json).await {
                error!("whoami failed: {:#}", e);
                std::process::exit(1);
            }
        }
        Commands::Refresh => match perform_refresh(&client, None, None).await {
            Ok(_) => println!("Token refreshed."),
            Err(e) => {
                error!("refresh failed: {:#}", e);
                std::process::exit(1);
            }
        },
        Commands::Logout => {
            if let Err(e) = logout(&client).await {
                error!("logout failed: {:#}", e);
                std::process::exit(1);
            }
        }
        Commands::Up { repo, json, allow, public, env, mode } => {
            if let Err(e) = up(&client, repo, json, allow, public, env, mode).await {
                let msg = format!("{:#}", e);
                let usage_error = msg.contains("Invalid repository URL.");

                if usage_error {
                    println!("{}", msg);
                } else {
                    eprintln!("up failed: {}", msg);
                }

                std::process::exit(1);
            }
        }
        Commands::Join { url } => {
             if let Err(e) = join(url).await {
                eprintln!("join failed: {:#}", e);
                std::process::exit(1);
            }
        }
        Commands::Sync => {
            if let Err(e) = sync::sync().await {
                eprintln!("sync failed: {:#}", e);
                std::process::exit(1);
            }
        }
        Commands::Watch => {
            if let Err(e) = notify::watch() {
                eprintln!("watch failed: {:#}", e);
                std::process::exit(1);
            }
        }
        Commands::Status => {
            if let Err(e) = sync::status_command().await {
                eprintln!("status failed: {:#}", e);
                std::process::exit(1);
            }
        }
        Commands::Diff => {
            if let Err(e) = sync::diff_command().await {
                eprintln!("diff failed: {:#}", e);
                std::process::exit(1);
            }
        }
        Commands::Publish => {
            if let Err(e) = sync::publish_command().await {
                eprintln!("publish failed: {:#}", e);
                std::process::exit(1);
            }
        }
    }

    Ok(())
} 
