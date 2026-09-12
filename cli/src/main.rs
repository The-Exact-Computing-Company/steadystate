// cli/src/main.rs

//! SteadyState CLI - Manage reproducible development environments
//!
//! This CLI provides commands for authentication and session management.
//! See README.md for usage examples.

mod auth;
mod config;
mod merge;
mod notify;
mod session;
mod sync;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use reqwest::{Client, Url};
use serde::Serialize;
use tokio::time::Duration;
use tracing::{error, info, warn};

use auth::{
    UpResponse, delete_refresh_token, device_login, get_access_token, get_refresh_token,
    perform_refresh, request_with_auth,
};
use config::{BACKEND_URL, CLI_VERSION, HTTP_TIMEOUT_SECS, JWT_REFRESH_BUFFER_SECS, USER_AGENT};
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
    /// Start interactive login (device flow, PAT, or OIDC browser flow)
    Login {
        /// Authentication provider (e.g., github, gitlab, oidc, fake)
        #[arg(long, default_value = "github")]
        provider: String,
        /// PAT for providers without a device flow (gitlab). Falls back to
        /// GITLAB_TOKEN env, then an interactive hidden prompt.
        #[arg(long)]
        token: Option<String>,
        /// OIDC: print the URL and paste the redirect instead of opening
        /// a browser + localhost listener (headless/SSH sessions).
        #[arg(long)]
        no_browser: bool,
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
        /// Environment to load (e.g. "noenv")
        #[arg(long)]
        env: Option<String>,
        /// Session mode: "pair" or "collab"
        #[arg(long)]
        mode: Option<String>,
        /// Compute provider: "local" or "hetzner"
        #[arg(long)]
        provider: Option<String>,
        /// Session lifetime (e.g. 12h, 90m, 2d, 3600). Clamped to the
        /// server max; defaults to the server default (48h).
        #[arg(long)]
        ttl: Option<String>,
        /// Forge PAT attached to the session for collaborator lookup and
        /// token-injected clone. Needed for SSO logins (no forge token
        /// stored). Falls back to FORGE_TOKEN env.
        #[arg(long)]
        forge_token: Option<String>,
    },
    /// Join a remote session using a magic link or SSH URL
    Join {
        /// Magic link (steadystate://...) or SSH URL
        url: String,
    },
    /// Open a dashboard to monitor a session
    #[command(alias = "dash")]
    Dashboard {
        /// The magic link to the session
        magic_link: String,
    },
    /// Show who last modified lines in a file (git blame)
    Credit {
        /// The file to check
        file: String,
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
    /// Terminate a session by ID (or magic link)
    Down {
        /// Session ID or steadystate:// magic link
        target: String,
    },
    /// List your sessions
    List {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Extend a session's lifetime by ID (or magic link)
    Extend {
        /// Session ID or steadystate:// magic link
        target: String,
        /// Additional lifetime (e.g. 12h, 90m, 2d, 3600). Added to the
        /// current expiry, clamped to the server max. Defaults to the
        /// server default TTL when omitted.
        #[arg(long)]
        ttl: Option<String>,
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
                println!(
                    "Logged in as: {} (via {})",
                    sess.login,
                    sess.provider_or_default()
                );
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

    if let Err(e) = delete_refresh_token(&username, None).await {
        eprintln!("Warning: Failed to delete refresh token: {}", e);
    }
    // Also remove the forge access token (PAT/OAuth); otherwise a later
    // `up` would still send a credential after logout.
    if let Err(e) = auth::delete_access_token(&username, None).await {
        eprintln!("Warning: Failed to delete access token: {}", e);
    }
    if let Err(e) = remove_session(None).await {
        eprintln!("Warning: Failed to remove session file: {}", e);
    }
    println!("Logged out (local tokens removed).");
    Ok(())
}

/// Extract a session ID from a raw ID or a steadystate:// magic link.
fn session_id_from_target(target: &str) -> Result<String> {
    let t = target.trim();
    if let Some(_rest) = t.strip_prefix("steadystate://") {
        let url = Url::parse(t).context("Failed to parse magic link")?;
        let id = url
            .path_segments()
            .and_then(|mut c| c.next())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("Magic link has no session ID"))?;
        return Ok(id.to_string());
    }
    if t.contains("://") {
        anyhow::bail!("Expected a session ID or steadystate:// magic link, got URL");
    }
    if t.is_empty() {
        anyhow::bail!("Empty session target");
    }
    Ok(t.to_string())
}

/// Render expiry epoch seconds as relative human text.
fn format_expiry(expires_at: Option<u64>) -> String {
    match expires_at {
        None => "never".to_string(),
        Some(exp) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if exp <= now {
                "expired".to_string()
            } else {
                let d = exp - now;
                if d >= 3600 {
                    format!("in {}h", d / 3600)
                } else if d >= 60 {
                    format!("in {}m", d / 60)
                } else {
                    format!("in {}s", d)
                }
            }
        }
    }
}

fn short_repo_name(repo_url: Option<&String>) -> &str {
    repo_url
        .map(|u| u.rsplit('/').next().unwrap_or(u).trim_end_matches(".git"))
        .filter(|s| !s.is_empty())
        .unwrap_or("-")
}

/// Render last-activity epoch seconds as idle text (`5m`, `2h`, `—`).
fn format_idle(last_activity_at: Option<u64>) -> String {
    match last_activity_at {
        None => "—".to_string(),
        Some(t) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // Clock skew (activity in the future) reads as just-now.
            let idle = now.saturating_sub(t);
            if idle < 60 {
                "now".to_string()
            } else if idle < 3600 {
                format!("{}m", idle / 60)
            } else if idle < 86_400 {
                format!("{}h", idle / 3600)
            } else {
                format!("{}d", idle / 86_400)
            }
        }
    }
}

async fn down(client: &Client, target: String) -> Result<()> {
    let id = session_id_from_target(&target)?;

    // Authenticated DELETE (request_with_auth expects a JSON body, but
    // DELETE answers 202 with none — so authenticate manually here).
    let session = read_session(None)
        .await
        .context("Not logged in. Please run 'steadystate login' first.")?;
    let mut jwt = session.jwt.clone();
    if session.is_near_expiry(JWT_REFRESH_BUFFER_SECS) {
        jwt = perform_refresh(client, Some(session.login.clone()), None)
            .await
            .context("Session expired and refresh failed")?
            .jwt;
    }

    let url = format!("{}/sessions/{}", &*BACKEND_URL, id);
    let resp = auth::send_with_retries(|| client.delete(&url).bearer_auth(&jwt)).await?;

    match resp.status().as_u16() {
        202 => println!("Session {} termination requested.", id),
        404 => println!("No such session: {} (already gone?)", id),
        403 => anyhow::bail!("Not allowed: only the session creator can terminate it."),
        401 => anyhow::bail!("Session expired or revoked. Run 'steadystate login' again."),
        s => anyhow::bail!("Terminate failed with status {}", s),
    }
    Ok(())
}

/// Extends a session's lifetime (POST /sessions/{id}/extend).
async fn extend(client: &Client, target: String, ttl: Option<String>) -> Result<()> {
    let id = session_id_from_target(&target)?;

    let ttl_secs = match ttl.as_deref() {
        None => None,
        Some(s) => Some(parse_duration_secs(s).with_context(|| {
            format!(
                "Invalid --ttl option '{}'. Examples: --ttl=12h, --ttl=90m, --ttl=2d, --ttl=3600",
                s
            )
        })?),
    };

    // Manual auth (like `down`) so 403/404 get distinct, actionable messages
    // instead of request_with_auth's generic failure.
    let session = read_session(None)
        .await
        .context("Not logged in. Please run 'steadystate login' first.")?;
    let mut jwt = session.jwt.clone();
    if session.is_near_expiry(JWT_REFRESH_BUFFER_SECS) {
        jwt = perform_refresh(client, Some(session.login.clone()), None)
            .await
            .context("Session expired and refresh failed")?
            .jwt;
    }

    let url = format!("{}/sessions/{}/extend", &*BACKEND_URL, id);
    let body = serde_json::json!({ "ttl_secs": ttl_secs });
    let resp = auth::send_with_retries(|| client.post(&url).bearer_auth(&jwt).json(&body))
        .await
        .context("extend request failed")?;

    match resp.status().as_u16() {
        200 => {}
        404 => anyhow::bail!("No such session: {} (already gone?)", id),
        403 => anyhow::bail!("Not allowed: only the session creator can extend it."),
        409 => anyhow::bail!("Session is terminating or terminated and cannot be extended."),
        401 => anyhow::bail!("Session expired or revoked. Run 'steadystate login' again."),
        s => anyhow::bail!("Extend failed with status {}", s),
    }

    let info: UpResponse = resp.json().await.context("parse extend response")?;
    println!("✅ Session {} extended.", id);
    println!("   New expiry: {}", format_expiry(info.expires_at));
    Ok(())
}

async fn list_sessions(client: &Client, json: bool) -> Result<()> {
    let sessions: Vec<UpResponse> = request_with_auth(
        client,
        |c, jwt| {
            c.get(format!("{}/sessions", &*BACKEND_URL))
                .bearer_auth(jwt)
        },
        None,
    )
    .await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&sessions)?);
        return Ok(());
    }
    if sessions.is_empty() {
        println!("No sessions. Create one with 'steadystate up ...'.");
        return Ok(());
    }
    println!(
        "{:<10} {:<12} {:<8} {:<10} {:<8} REPO",
        "ID", "STATE", "PROVIDER", "EXPIRES", "IDLE"
    );
    for s in &sessions {
        println!(
            "{:<10} {:<12} {:<8} {:<10} {:<8} {}",
            s.id.chars().take(8).collect::<String>(),
            s.state.as_str(),
            s.compute_provider.as_deref().unwrap_or("-"),
            format_expiry(s.expires_at),
            format_idle(s.last_activity_at),
            short_repo_name(s.repo_url.as_ref()),
        );
    }
    Ok(())
}

/// Arguments for `steadystate up`, grouped to keep the signature manageable.
struct UpArgs {
    repo: String,
    json: bool,
    allow: Vec<String>,
    env: Option<String>,
    mode: Option<String>,
    provider: Option<String>,
    ttl: Option<String>,
    forge_token: Option<String>,
}

const ENV_HELP: &str = "Environment to load (only 'tproject' is supported now).
  --env=tproject              T-lang project (tproject.toml -> t update -> nix develop)";

const MODE_HELP: &str = "\
Valid --mode options:
  --mode=pair    Pair programming mode (Tmux)
  --mode=collab  Collaboration mode (SSH)";

/// Single-quote a string for safe interpolation into a remote shell command.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Write a 0600 known_hosts file for a session and return its path.
/// The path is derived from a hash of `seed` (never the raw, server- or
/// magic-link-controlled id), so it cannot traverse out of /tmp or be
/// symlink-squatted predictably. `host_key` is validated as a single
/// `type base64` pair so embedded newlines cannot inject extra entries.
fn write_known_hosts(
    prefix: &str,
    seed: &str,
    host: &str,
    port: u16,
    host_key: &str,
) -> Result<String> {
    let cleaned = host_key.trim();
    if cleaned.contains(['\n', '\r']) {
        anyhow::bail!("Refusing host key containing newlines");
    }
    let mut parts = cleaned.split_whitespace();
    let (ktype, kb64) = match (parts.next(), parts.next()) {
        (Some(a), Some(b)) => (a, b),
        _ => anyhow::bail!("Malformed host key in magic link"),
    };
    if !(ktype.starts_with("ssh-") || ktype.starts_with("ecdsa-")) {
        anyhow::bail!("Unsupported host key type: {}", ktype);
    }

    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    let path = format!(
        "/tmp/steadystate-{}-{:x}-known_hosts",
        prefix,
        hasher.finish()
    );
    let content = format!("[{}]:{} {} {}\n", host, port, ktype, kb64);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(&path)
        .with_context(|| format!("create {}", path))?
        .write_all(content.as_bytes())
        .with_context(|| format!("write {}", path))?;
    Ok(path)
}

/// Parse a human duration into seconds: plain seconds (`3600`) or a
/// number with one suffix (`90s`, `90m`, `12h`, `2d`, `1w`).
/// Rejects empty input, unknown suffixes, and zero.
fn parse_duration_secs(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty duration");
    }
    let (num_part, mult) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => (
            &s[..s.len() - 1],
            match c {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86_400,
                'w' => 604_800,
                other => anyhow::bail!("unknown duration suffix '{}' (use s, m, h, d, w)", other),
            },
        ),
        _ => (s, 1),
    };
    let n: u64 = num_part
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration number in '{}'", s))?;
    let secs = n.checked_mul(mult).context("duration out of range")?;
    if secs == 0 {
        anyhow::bail!("duration must be positive");
    }
    Ok(secs)
}

async fn up(client: &Client, args: UpArgs) -> Result<()> {
    let UpArgs {
        repo,
        json,
        allow,
        env,
        mode,
        provider,
        ttl,
        forge_token,
    } = args;

    Url::parse(&repo).context(
        "Invalid repository URL. Provide a fully-qualified URL (e.g. https://github.com/user/repo).",
    )?;

    // Validate --env (required, must be "tproject").
    let env_val = env.ok_or_else(|| anyhow::anyhow!("--env flag is required.\n{}", ENV_HELP))?;
    if env_val != "tproject" {
        anyhow::bail!("Invalid --env option: {}\n{}", env_val, ENV_HELP);
    }

    // Validate --mode (required).
    let mode_val =
        mode.ok_or_else(|| anyhow::anyhow!("--mode flag is required.\n{}", MODE_HELP))?;
    if mode_val != "pair" && mode_val != "collab" {
        anyhow::bail!("Invalid --mode option: {}\n{}", mode_val, MODE_HELP);
    }

    // Validate --provider (optional, defaults to the backend default).
    let provider_val: Option<String> = match provider.as_deref() {
        None => None,
        Some("local") | Some("hetzner") => provider.clone(),
        Some(other) => {
            anyhow::bail!(
                "Invalid --provider option: {}\nValid options:\n  --provider=local    Run on this machine\n  --provider=hetzner  Provision a Hetzner Cloud server",
                other
            );
        }
    };

    // Parse --ttl (optional). The server clamps to its max.
    let ttl_secs: Option<u64> = match ttl.as_deref() {
        None => None,
        Some(s) => Some(parse_duration_secs(s).with_context(|| {
            format!(
                "Invalid --ttl option '{}'. Examples: --ttl=12h, --ttl=90m, --ttl=2d, --ttl=3600",
                s
            )
        })?),
    };

    // Get credentials to send with request.
    // OIDC sessions carry no forge token (SSO identity only), so the access
    // token is optional here; --forge-token can still attach one.
    let session = read_session(None)
        .await
        .context("Not logged in. Please run 'steadystate login' first.")?;

    let access_token = get_access_token(&session.login, None)
        .await?
        .filter(|t| !t.trim().is_empty());

    let session_provider = session.provider_or_default().to_string();
    let mut provider_creds = serde_json::Map::new();
    provider_creds.insert(
        "login".to_string(),
        serde_json::Value::String(session.login.clone()),
    );
    if let Some(t) = access_token {
        provider_creds.insert("access_token".to_string(), serde_json::Value::String(t));
    }
    let mut provider_config = serde_json::Map::new();
    provider_config.insert(session_provider, serde_json::Value::Object(provider_creds));

    // Forge token bridge for SSO (or cross-forge) sessions: attaches a
    // GitHub/GitLab PAT used for collaborator lookup + token-injected clone.
    // --forge-token wins, FORGE_TOKEN env is the fallback.
    let forge_token = forge_token.filter(|t| !t.trim().is_empty()).or_else(|| {
        std::env::var("FORGE_TOKEN")
            .ok()
            .filter(|t| !t.trim().is_empty())
    });
    if let Some(ft) = forge_token {
        let forge = if repo.to_lowercase().contains("gitlab") {
            "gitlab"
        } else {
            "github"
        };
        let mut forge_creds = serde_json::Map::new();
        forge_creds.insert(
            "login".to_string(),
            serde_json::Value::String(session.login.clone()),
        );
        forge_creds.insert(
            "access_token".to_string(),
            serde_json::Value::String(ft.trim().to_string()),
        );
        provider_config.insert(forge.to_string(), serde_json::Value::Object(forge_creds));
    }

    let payload = serde_json::json!({
        "repo_url": repo,
        "allowed_users": if allow.is_empty() { None } else { Some(allow.clone()) },
        "environment": env_val,
        "mode": mode_val,
        "provider": provider_val,
        "ttl_secs": ttl_secs,
        "provider_config": provider_config,
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

                let status: UpResponse = request_with_auth(
                    // Assuming UpResponse can also be used for status
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
                            if mode_val == "pair" {
                                println!("✅ Session ready!");
                                println!();
                                println!("SteadyState Pair Programming Session");
                                println!("Session ID: {}", resp.id);
                                let repo_name = repo
                                    .split('/')
                                    .next_back()
                                    .unwrap_or(&repo)
                                    .trim_end_matches(".git");
                                println!("Repository: {}", repo_name);
                                if let Some(link) = &final_magic_link {
                                    println!("Join with:       steadystate join \"{}\"", link);
                                }
                                println!("To join with ssh: {}", endpoint);
                            } else {
                                println!("✅ Session ready!");
                                println!("SSH: {}", endpoint);
                                if let Some(link) = &final_magic_link {
                                    println!("Magic Link: {}", link);
                                }
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
                        // Keep polling; the shared timeout check below bounds it.
                    }
                    other => {
                        println!("Session state: {:?}", other);
                    }
                }

                // Unconditional timeout: never loop forever on an unknown or
                // stuck state.
                if attempts >= max_attempts {
                    println!(
                        "⏱️  Timed out waiting for session {}. Check status later with `steadystate list`.",
                        resp.id
                    );
                    return Err(anyhow::anyhow!(
                        "Timed out waiting for session {} to become ready",
                        resp.id
                    ));
                }
            }
        } else if let Some(endpoint) = &resp.endpoint {
            if mode_val == "pair" {
                println!("✅ Session ready!");
                println!();
                println!("SteadyState Pair Programming Session");
                println!("Session ID: {}", resp.id);
                let repo_name = repo
                    .split('/')
                    .next_back()
                    .unwrap_or(&repo)
                    .trim_end_matches(".git");
                println!("Repository: {}", repo_name);
                if let Some(link) = &resp.magic_link {
                    println!("Join with:       steadystate join \"{}\"", link);
                }
                println!("To join with ssh: {}", endpoint);
            } else {
                println!("✅ Session ready!");
                println!("SSH: {}", endpoint);
                if let Some(link) = &resp.magic_link {
                    // Print initial magic link if available
                    println!("Magic Link: {}", link);
                }
            }
        }

        // Launch dashboard if in collab mode and we have an endpoint
        if mode_val == "collab"
            && let Some(endpoint) = final_endpoint
        {
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
                    let known_hosts_path =
                        write_known_hosts("dash", &resp.id, host, port, &host_key)?;
                    args.extend([
                        "-o".to_string(),
                        format!("UserKnownHostsFile={}", known_hosts_path),
                        "-o".to_string(),
                        "StrictHostKeyChecking=yes".to_string(),
                    ]);
                } else {
                    args.extend([
                        "-o".to_string(),
                        "StrictHostKeyChecking=no".to_string(),
                        "-o".to_string(),
                        "UserKnownHostsFile=/dev/null".to_string(),
                    ]);
                }

                let target = if !user.is_empty() {
                    format!("{}@{}", user, host)
                } else {
                    host.to_string()
                };
                // `--` ends ssh option parsing so a hostile host/user
                // cannot smuggle an ssh flag.
                args.push("--".to_string());
                args.push(target);

                // Command to run
                args.push("steadystate watch".to_string());

                println!("Connecting to dashboard...");
                use std::os::unix::process::CommandExt;
                let err = std::process::Command::new("ssh").args(&args).exec();
                return Err(anyhow::anyhow!("Failed to execute ssh: {}", err));
            }
        }
    }

    Ok(())
}

async fn join(url_str: String) -> Result<()> {
    if url_str.starts_with("steadystate://") {
        let url = Url::parse(&url_str).context("Failed to parse magic link")?;

        let mode = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid magic link: missing mode"))?;

        match mode {
            "pair" | "collab" => {
                // Both modes now use SSH!
                let mut pairs = url.query_pairs();
                let ssh_url = pairs
                    .find(|(key, _)| key == "ssh")
                    .map(|(_, val)| val.to_string())
                    .or_else(|| {
                        // Backward compat for old pair links (though they won't work with new backend)
                        pairs = url.query_pairs();
                        pairs
                            .find(|(key, _)| key == "upterm")
                            .map(|(_, val)| val.to_string())
                    })
                    .ok_or_else(|| anyhow::anyhow!("Invalid link: missing 'ssh' parameter"))?;

                // Reset iterator for host_key
                let mut pairs = url.query_pairs();
                let host_key = pairs
                    .find(|(key, _)| key == "host_key")
                    .map(|(_, val)| val.to_string());

                println!("Joining {} session...", mode);
                println!("Connecting to: {}", ssh_url);

                // Execute ssh
                let up_url = Url::parse(&ssh_url).context("Failed to parse SSH URL")?;
                let host = up_url
                    .host_str()
                    .ok_or_else(|| anyhow::anyhow!("Missing host in SSH URL"))?;
                let port = up_url.port().unwrap_or(22);
                let user = up_url.username();

                let mut args = vec!["-p".to_string(), port.to_string()];

                if let Some(key) = host_key {
                    let known_hosts_path = write_known_hosts("join", &url_str, host, port, &key)?;
                    args.extend([
                        "-o".to_string(),
                        format!("UserKnownHostsFile={}", known_hosts_path),
                        "-o".to_string(),
                        "StrictHostKeyChecking=yes".to_string(),
                    ]);
                } else {
                    args.extend([
                        "-o".to_string(),
                        "StrictHostKeyChecking=no".to_string(),
                        "-o".to_string(),
                        "UserKnownHostsFile=/dev/null".to_string(),
                    ]);
                }

                args.push("-t".to_string()); // Force PTY

                // `--` ends ssh option parsing so a hostile host/user cannot
                // smuggle an ssh flag through the magic link.
                args.push("--".to_string());
                if !user.is_empty() {
                    args.push(format!("{}@{}", user, host));
                } else {
                    args.push(host.to_string());
                }

                // Inject username if available (shell-quoted: the login comes
                // from a user-editable session file).
                let shell_cmd = if let Ok(session) = crate::session::read_session(None).await {
                    format!(
                        "export STEADYSTATE_USERNAME={}; exec $SHELL -l",
                        shell_quote(&session.login)
                    )
                } else {
                    "exec $SHELL -l".to_string()
                };
                args.push(shell_cmd);

                use std::os::unix::process::CommandExt;
                let err = std::process::Command::new("ssh").args(&args).exec();

                Err(anyhow::anyhow!("Failed to execute ssh: {}", err))
            }
            _ => Err(anyhow::anyhow!("Unknown mode: {}", mode)),
        }
    } else {
        // Legacy/Direct SSH URL
        println!("Joining via direct SSH...");

        if url_str.starts_with("ssh://") {
            let up_url = Url::parse(&url_str).context("Failed to parse SSH URL")?;
            let host = up_url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("Missing host in SSH URL"))?;
            let port = up_url.port().unwrap_or(22);
            let user = up_url.username();

            let mut args = vec!["-p".to_string(), port.to_string(), "-t".to_string()];

            if !user.is_empty() {
                args.push(format!("{}@{}", user, host));
            } else {
                args.push(host.to_string());
            }

            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new("ssh").args(&args).exec();
            Err(anyhow::anyhow!("Failed to execute ssh: {}", err))
        } else {
            // Assume it's valid ssh arg
            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new("ssh").arg(&url_str).exec();
            Err(anyhow::anyhow!("Failed to execute ssh: {}", err))
        }
    }
}

async fn open_dashboard(link: &str) -> Result<()> {
    // Parse the magic link
    let url = Url::parse(link).context("Invalid magic link format")?;

    // Extract session info from the link
    // Format: steadystate://collab/{session_id}?ssh={ssh_url}&host_key={key}

    if url.scheme() != "steadystate" {
        return Err(anyhow::anyhow!(
            "Invalid magic link: expected steadystate:// scheme"
        ));
    }

    let path_segments: Vec<&str> = url.path_segments().map(|c| c.collect()).unwrap_or_default();

    if path_segments.is_empty() {
        return Err(anyhow::anyhow!("Invalid magic link: missing session ID"));
    }

    let _session_id = path_segments[0];
    let mode = url.host_str().unwrap_or("collab");

    if mode != "collab" {
        return Err(anyhow::anyhow!(
            "Dashboard is only available for collab mode sessions"
        ));
    }

    // Parse query parameters
    let params: std::collections::HashMap<_, _> = url.query_pairs().collect();

    let ssh_url = params
        .get("ssh")
        .ok_or_else(|| anyhow::anyhow!("Magic link missing SSH URL"))?;

    let host_key = params.get("host_key").map(|s| s.to_string());

    // Parse SSH URL
    let ssh_parsed = Url::parse(ssh_url).context("Invalid SSH URL in magic link")?;

    let host = ssh_parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("SSH URL missing host"))?;
    let port = ssh_parsed.port().unwrap_or(22);
    let user = ssh_parsed.username();

    println!("Opening dashboard...");
    println!("Connecting to: {}:{}", host, port);

    // Build SSH command
    let mut args = vec![
        "-p".to_string(),
        port.to_string(),
        "-t".to_string(), // Force PTY for TUI
    ];

    // Handle host key verification
    if let Some(key) = host_key {
        let known_hosts_path = write_known_hosts("dash", link, host, port, &key)?;
        args.extend([
            "-o".to_string(),
            format!("UserKnownHostsFile={}", known_hosts_path),
            "-o".to_string(),
            "StrictHostKeyChecking=yes".to_string(),
        ]);
    } else {
        // No host key provided - warn but allow connection
        eprintln!("⚠️  Warning: No host key in magic link, skipping verification");
        args.extend([
            "-o".to_string(),
            "StrictHostKeyChecking=no".to_string(),
            "-o".to_string(),
            "UserKnownHostsFile=/dev/null".to_string(),
        ]);
    }

    // `--` ends ssh option parsing before the destination so a hostile
    // host/user cannot smuggle an ssh flag through the magic link.
    args.push("--".to_string());
    let target = if !user.is_empty() {
        format!("{}@{}", user, host)
    } else {
        host.to_string()
    };
    args.push(target);

    // Inject username if available so the dashboard knows who we are
    // (shell-quoted: the login comes from a user-editable session file).
    if let Ok(session) = crate::session::read_session(None).await {
        args.push(format!(
            "export STEADYSTATE_USERNAME={}; steadystate watch",
            shell_quote(&session.login)
        ));
    } else {
        args.push("steadystate watch".to_string());
    }

    // Execute SSH (replaces current process)
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new("ssh").args(&args).exec();

    Err(anyhow::anyhow!("Failed to execute ssh: {}", err))
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
        builder = builder.pool_max_idle_per_host(0).pool_idle_timeout(None);
    }

    let client = builder.build().context("create http client")?;

    match cmd {
        Commands::Login {
            provider,
            token,
            no_browser,
        } => {
            // GitLab has no OAuth device flow: authenticate with a PAT.
            // OIDC likewise: browser + localhost callback instead.
            let login_result = if provider == "gitlab" {
                match auth::resolve_pat(
                    token,
                    "GITLAB_TOKEN",
                    "GitLab Personal Access Token (read_user scope): ",
                ) {
                    Ok(pat) => auth::token_login(&client, &provider, &pat).await,
                    Err(e) => Err(e),
                }
            } else if provider == "oidc" {
                if token.is_some() {
                    Err(anyhow::anyhow!(
                        "--token is for --provider=gitlab; oidc uses the browser flow"
                    ))
                } else {
                    auth::oidc_login(&client, no_browser).await
                }
            } else if token.is_some() {
                Err(anyhow::anyhow!(
                    "--token is only used with --provider=gitlab; '{}' uses the device flow",
                    provider
                ))
            } else {
                device_login(&client, &provider).await
            };
            if let Err(e) = login_result.context(
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
        Commands::Up {
            repo,
            json,
            allow,
            env,
            mode,
            provider,
            ttl,
            forge_token,
        } => {
            if let Err(e) = up(
                &client,
                UpArgs {
                    repo,
                    json,
                    allow,
                    env,
                    mode,
                    provider,
                    ttl,
                    forge_token,
                },
            )
            .await
            {
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
        Commands::Dashboard { magic_link } => {
            if let Err(e) = open_dashboard(&magic_link).await {
                eprintln!("Failed to open dashboard: {:#}", e);
                std::process::exit(1);
            }
        }
        Commands::Credit { file } => {
            if let Err(e) = sync::credit_command(&file).await {
                eprintln!("credit failed: {:#}", e);
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
        Commands::Down { target } => {
            if let Err(e) = down(&client, target).await {
                eprintln!("down failed: {:#}", e);
                std::process::exit(1);
            }
        }
        Commands::List { json } => {
            if let Err(e) = list_sessions(&client, json).await {
                eprintln!("list failed: {:#}", e);
                std::process::exit(1);
            }
        }
        Commands::Extend { target, ttl } => {
            if let Err(e) = extend(&client, target, ttl).await {
                eprintln!("extend failed: {:#}", e);
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_secs() {
        assert_eq!(parse_duration_secs("3600").unwrap(), 3600);
        assert_eq!(parse_duration_secs("90s").unwrap(), 90);
        assert_eq!(parse_duration_secs("90m").unwrap(), 5400);
        assert_eq!(parse_duration_secs("12h").unwrap(), 43200);
        assert_eq!(parse_duration_secs("48h").unwrap(), 172800);
        assert_eq!(parse_duration_secs("2d").unwrap(), 172800);
        assert_eq!(parse_duration_secs("1w").unwrap(), 604800);
        assert_eq!(parse_duration_secs("  30m  ").unwrap(), 1800);

        for bad in ["", "0", "0h", "abc", "10x", "h", "-5m", "1.5h"] {
            assert!(parse_duration_secs(bad).is_err(), "{}", bad);
        }
    }

    #[test]
    fn test_session_id_from_target() {
        assert_eq!(session_id_from_target("abc123").unwrap(), "abc123");
        assert_eq!(session_id_from_target("  abc123  ").unwrap(), "abc123");
        assert_eq!(
            session_id_from_target("steadystate://collab/abc123?ssh=x").unwrap(),
            "abc123"
        );
        assert_eq!(
            session_id_from_target("steadystate://pair/xyz").unwrap(),
            "xyz"
        );
        assert!(session_id_from_target("steadystate://collab/").is_err());
        assert!(session_id_from_target("ssh://steady@host:2222").is_err());
        assert!(session_id_from_target("").is_err());
    }

    #[test]
    fn test_format_expiry() {
        assert_eq!(format_expiry(None), "never");
        assert_eq!(format_expiry(Some(1)), "expired");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(format_expiry(Some(now + 90)), "in 1m");
        assert_eq!(format_expiry(Some(now + 7200)), "in 2h");
        assert_eq!(format_expiry(Some(now + 45)), "in 45s");
    }

    #[test]
    fn test_short_repo_name() {
        assert_eq!(
            short_repo_name(Some(&"https://github.com/org/repo.git".to_string())),
            "repo"
        );
        assert_eq!(
            short_repo_name(Some(&"https://gitlab.com/group/sub/proj".to_string())),
            "proj"
        );
        assert_eq!(short_repo_name(None), "-");
    }

    #[test]
    fn test_format_idle() {
        assert_eq!(format_idle(None), "—");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(format_idle(Some(now)), "now");
        assert_eq!(format_idle(Some(now + 60)), "now");
        assert_eq!(format_idle(Some(now - 300)), "5m");
        assert_eq!(format_idle(Some(now - 7200)), "2h");
        assert_eq!(format_idle(Some(now - 90000)), "1d");
    }
}
