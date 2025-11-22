// cli/src/main.rs

//! SteadyState CLI - Manage reproducible development environments
//!
//! This CLI provides commands for authentication and session management.
//! See README.md for usage examples.

mod auth;
mod config;
mod session;

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
        /// Allow specific GitHub users to connect (can be used multiple times)
        #[arg(long)]
        allow: Vec<String>,
        /// Make the session public (anyone with the link can connect)
        #[arg(long)]
        public: bool,
        /// Environment to load (e.g. "noenv")
        #[arg(long)]
        env: Option<String>,
    },
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
                        .unwrap()
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

    if let Some(refresh) = get_refresh_token(&username).await? {
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

    let _ = delete_refresh_token(&username).await;
    let _ = remove_session(None).await;
    println!("Logged out (local tokens removed).");
    Ok(())
}

async fn up(client: &Client, repo: String, json: bool, allow: Vec<String>, public: bool, env: Option<String>) -> Result<()> {
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

    let payload = serde_json::json!({
        "repo_url": repo,
        "allowed_users": if allow.is_empty() { None } else { Some(allow.clone()) },
        "public": public,
        "environment": env_val
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

    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        println!("✅ Session created: {}", resp.id);
        
        // Poll until the session is ready or fails
        if resp.endpoint.is_none() && resp.state == "Provisioning" {
            println!("⏳ Provisioning session...");
            
            let mut attempts = 0;
            let max_attempts = 60; // 60 * 2s = 2 minutes timeout
            
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                attempts += 1;
                
                let status: UpResponse = request_with_auth(
                    client,
                    |c, jwt| {
                        c.get(format!("{}/sessions/{}", &*BACKEND_URL, resp.id))
                            .bearer_auth(jwt)
                    },
                    None,
                )
                .await?;
                
                match status.state.as_str() {
                    "Running" => {
                        if let Some(endpoint) = status.endpoint {
                            println!("✅ Session ready!");
                            println!("SSH: {}", endpoint);
                        } else {
                            println!("⚠️  Session is running but no endpoint available");
                        }
                        break;
                    }
                    "Failed" => {
                        println!("❌ Session provisioning failed");
                        if let Some(msg) = status.message {
                            println!("Error: {}", msg);
                        }
                        return Err(anyhow::anyhow!("Session provisioning failed"));
                    }
                    "Provisioning" => {
                        if attempts >= max_attempts {
                            println!("⏱️  Timed out waiting for session. Check status later with:");
                            println!("  curl -H 'Authorization: Bearer <token>' {}/sessions/{}", &*BACKEND_URL, resp.id);
                            break;
                        }
                        // Continue polling
                    }
                    other => {
                        println!("Session state: {}", other);
                    }
                }
            }
        } else if let Some(endpoint) = resp.endpoint {
            println!("SSH: {}", endpoint);
        }
    }

    Ok(())
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
        Commands::Refresh => match perform_refresh(&client, None).await {
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
        Commands::Up { repo, json, allow, public, env } => {
            if let Err(e) = up(&client, repo, json, allow, public, env).await {
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
    }

    Ok(())
} 
