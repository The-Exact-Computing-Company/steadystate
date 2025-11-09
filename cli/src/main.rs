use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dirs::config_dir;
use jwt_simple::prelude::*;
use keyring::Entry;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};
use tokio::{select, signal, task, time};
use tracing::{debug, error, info, warn};

const SERVICE_NAME: &str = "steadystate";
const BACKEND_ENV: &str = "STEADYSTATE_BACKEND"; // e.g. https://api.steadystate.dev
const DEFAULT_BACKEND: &str = "http://localhost:8080";
const JWT_REFRESH_BUFFER_SECS: u64 = 60;

#[derive(Parser)]
#[command(name = "steadystate", about = "SteadyState CLI — Exact reproducible dev envs")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start interactive login (device flow)
    Login,
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
}

#[derive(Deserialize)]
struct DeviceResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Deserialize)]
struct PollResponse {
    status: Option<String>,
    jwt: Option<String>,
    refresh_token: Option<String>,
    refresh_expires_at: Option<u64>,
    login: Option<String>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Session {
    login: String,
    jwt: String,
    jwt_exp: Option<u64>, // epoch seconds
}

#[derive(Serialize)]
struct WhoamiOutput {
    logged_in: bool,
    login: Option<String>,
    jwt_expires_at: Option<u64>,
}

fn backend_url() -> String {
    std::env::var(BACKEND_ENV).unwrap_or_else(|_| DEFAULT_BACKEND.to_string())
}

async fn cfg_dir() -> Result<PathBuf> {
    let mut p = config_dir().context("could not determine config directory")?;
    p.push("steadystate");
    tokio::fs::create_dir_all(&p)
        .await
        .context("create config dir")?;
    Ok(p)
}

async fn session_file() -> Result<PathBuf> {
    Ok(cfg_dir().await?.join("session.json"))
}

async fn write_session(session: &Session) -> Result<()> {
    let p = session_file().await?;
    let data = serde_json::to_vec_pretty(session)?;
    // Write with temp file then atomically rename
    let tmp = p.with_extension("tmp");
    tokio::fs::write(&tmp, &data)
        .await
        .context("write session tmp file")?;
    // set strict permissions on unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .await
            .ok(); // non-fatal if fails
    }
    tokio::fs::rename(tmp, &p)
        .await
        .context("rename session file")?;
    Ok(())
}

async fn read_session() -> Result<Session> {
    let p = session_file().await?;
    let bytes = tokio::fs::read(&p)
        .await
        .context("read session file")?;
    let s: Session = serde_json::from_slice(&bytes).context("parse session json")?;
    Ok(s)
}

async fn remove_session() -> Result<()> {
    let p = session_file().await?;
    // Just attempt removal, ignore NotFound
    match tokio::fs::remove_file(p).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("remove session file"),
    }
}

// Keychain helpers (blocking; run in spawn_blocking)
async fn store_refresh_token(username: &str, token: &str) -> Result<()> {
    let username = username.to_string();
    let token = token.to_string();
    task::spawn_blocking(move || -> Result<()> {
        let entry = Entry::new(SERVICE_NAME, &username)
            .map_err(|e| anyhow::anyhow!("keyring entry creation failed: {}", e))?;
        entry
            .set_password(&token)
            .map_err(|e| anyhow::anyhow!("keyring set_password failed: {}", e))?;
        Ok(())
    })
    .await?
}

async fn get_refresh_token(username: &str) -> Result<Option<String>> {
    let username = username.to_string();
    task::spawn_blocking(move || -> Result<Option<String>> {
        let entry = Entry::new(SERVICE_NAME, &username)
            .map_err(|e| anyhow::anyhow!("keyring entry creation failed: {}", e))?;
        match entry.get_password() {
            Ok(tok) => Ok(Some(tok)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => {
                warn!("keyring get_password error: {}", err);
                Ok(None)
            }
        }
    })
    .await?
}

async fn delete_refresh_token(username: &str) -> Result<()> {
    let username = username.to_string();
    task::spawn_blocking(move || -> Result<()> {
        if let Ok(entry) = Entry::new(SERVICE_NAME, &username) {
            let _ = entry.delete_credential();
        }
        Ok(())
    })
    .await?
}

fn extract_exp_from_jwt(jwt: &str) -> Option<u64> {
    // JWT format is: header.payload.signature
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        warn!("Invalid JWT format");
        return None;
    }
    
    // Decode the payload (second part) using base64url decoding
    let payload_bytes = match Base64UrlSafeNoPadding::decode_to_vec(parts[1], None) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!("Failed to decode JWT payload: {:?}", e);
            return None;
        }
    };
    
    // Parse the JSON payload to extract 'exp' claim
    match serde_json::from_slice::<serde_json::Value>(&payload_bytes) {
        Ok(payload) => payload.get("exp").and_then(|v| v.as_u64()),
        Err(e) => {
            warn!("Failed to parse JWT payload: {}", e);
            None
        }
    }
}

async fn device_login(client: &Client) -> Result<()> {
    let url = format!("{}/auth/device", backend_url());
    let resp = client
        .post(&url)
        .send()
        .await
        .context("request device code from backend")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("device code request failed ({}): {}", status, body);
    }

    let dr: DeviceResponse = resp.json().await.context("parse device response")?;

    println!("Open the verification URL and enter the code:");
    println!("\n  {}\n", dr.verification_uri);
    println!("Code: {}\n", dr.user_code);

    // Try to open browser; non-fatal if fails
    if let Err(e) = open::that(&dr.verification_uri) {
        debug!("open browser failed: {}", e);
    }

    let poll_url = format!("{}/auth/poll", backend_url());
    let interval = dr.interval.unwrap_or(5);
    let device_code = dr.device_code.clone();
    let expires_in = dr.expires_in;
    let start = tokio::time::Instant::now();

    println!("Waiting for authorization (press Ctrl+C to cancel)...");

    let mut poll_interval = time::interval(Duration::from_secs(interval));
    poll_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        select! {
            _ = signal::ctrl_c() => {
                println!("\nCancelled by user");
                return Ok(());
            }
            _ = poll_interval.tick() => {
                // Check expiry
                if start.elapsed().as_secs() > expires_in {
                    anyhow::bail!("device code expired");
                }

                let poll = client
                    .get(&poll_url)
                    .query(&[("device_code", &device_code)])
                    .send()
                    .await
                    .context("poll request failed")?;

                // If pending, backend returns 202
                if poll.status().as_u16() == 202 {
                    continue;
                }

                let out: PollResponse = poll.json().await.context("parse poll response")?;

                if let Some(status) = out.status.as_deref() {
                    match status {
                        "pending" => continue,
                        "complete" => {
                            let jwt = out.jwt.context("server did not return jwt")?;
                            let refresh = out.refresh_token.context("no refresh token returned")?;
                            let login = out.login.context("no login returned")?;
                            
                            // store refresh token in keychain
                            store_refresh_token(&login, &refresh).await?;
                            
                            // write session file with jwt + expiry
                            let jwt_exp = extract_exp_from_jwt(&jwt);
                            let session = Session {
                                login: login.clone(),
                                jwt: jwt.clone(),
                                jwt_exp,
                            };
                            write_session(&session).await?;
                            println!("✅ Logged in as {}", login);
                            return Ok(());
                        }
                        other => {
                            warn!("unexpected status: {}", other);
                            continue;
                        }
                    }
                } else if let Some(err) = out.error {
                    match err.as_str() {
                        "authorization_pending" => continue,
                        "slow_down" => {
                            // Adjust interval for next iteration
                            poll_interval = time::interval(Duration::from_secs(interval + 5));
                            poll_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
                            continue;
                        }
                        "access_denied" => {
                            anyhow::bail!("authorization denied by user");
                        }
                        _ => {
                            anyhow::bail!("authorization error: {}", err);
                        }
                    }
                }
            }
        }
    }
}

async fn perform_refresh(client: &Client) -> Result<String> {
    // read session for username
    let session = read_session()
        .await
        .context("no existing session; run `steadystate login`")?;
    
    let username = session.login.clone();
    let refresh = get_refresh_token(&username).await?.ok_or_else(|| {
        anyhow::anyhow!("no refresh token in keychain; run `steadystate login` again")
    })?;

    let url = format!("{}/auth/refresh", backend_url());
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "refresh_token": refresh }))
        .send()
        .await
        .context("auth/refresh request failed")?;

    if resp.status().as_u16() == 401 {
        // refresh invalid: remove keychain entry and session
        let _ = delete_refresh_token(&username).await;
        let _ = remove_session().await;
        anyhow::bail!("refresh token invalid; you must run `steadystate login` again");
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("refresh failed ({}): {}", status, body);
    }

    let body: serde_json::Value = resp.json().await.context("parse refresh response")?;
    let jwt = body
        .get("jwt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no jwt in refresh response"))?
        .to_string();

    // update stored session
    let jwt_exp = extract_exp_from_jwt(&jwt);
    let new_session = Session {
        login: username.clone(),
        jwt: jwt.clone(),
        jwt_exp,
    };
    write_session(&new_session).await?;
    Ok(jwt)
}

/// Generic helper to make an authenticated request; refreshes JWT proactively when near expiry.
async fn request_with_auth<T, F>(client: &Client, builder_fn: F) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    F: Fn(&Client, &str) -> reqwest::RequestBuilder,
{
    // read session
    let session = read_session()
        .await
        .context("no session found; please login")?;
    let mut jwt = session.jwt.clone();
    
    // check expiry within buffer window
    let mut need_refresh = false;
    if let Some(exp) = session.jwt_exp {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if exp <= now + JWT_REFRESH_BUFFER_SECS {
            need_refresh = true;
        }
    }
    
    if need_refresh {
        info!("JWT near expiry, refreshing proactively");
        jwt = perform_refresh(client).await?;
    }

    let req = builder_fn(client, &jwt);
    let resp = req.send().await.context("request failed")?;
    
    // if 401, try one refresh and retry once
    if resp.status().as_u16() == 401 {
        info!("Got 401, attempting token refresh");
        jwt = perform_refresh(client).await?;
        let req2 = builder_fn(client, &jwt);
        let resp2 = req2.send().await.context("request retry failed")?;
        
        if !resp2.status().is_success() {
            let status = resp2.status();
            let body = resp2.text().await.unwrap_or_default();
            anyhow::bail!("request failed after retry ({}): {}", status, body);
        }
        
        let body = resp2.json::<T>().await.context("parse response")?;
        return Ok(body);
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("request failed ({}): {}", status, body);
    }
    
    let body = resp.json::<T>().await.context("parse response")?;
    Ok(body)
}

async fn whoami(json_output: bool) -> Result<()> {
    match read_session().await {
        Ok(sess) => {
            if json_output {
                let output = WhoamiOutput {
                    logged_in: true,
                    login: Some(sess.login),
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
                println!("Not logged in. Run `steadystate login`");
            }
            Ok(())
        }
    }
}

async fn logout(client: &Client) -> Result<()> {
    // read session for username and maybe JWT
    let session = match read_session().await {
        Ok(s) => s,
        Err(_) => {
            println!("No active session");
            return Ok(());
        }
    };
    let username = session.login.clone();
    
    // attempt to revoke on backend if refresh token exists
    if let Some(refresh) = get_refresh_token(&username).await? {
        let url = format!("{}/auth/revoke", backend_url());
        match client
            .post(&url)
            .json(&serde_json::json!({ "refresh_token": refresh }))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                info!("Refresh token revoked on server");
            }
            Ok(resp) => {
                warn!("Server revoke returned status: {}", resp.status());
            }
            Err(e) => {
                warn!("Failed to revoke on server: {}", e);
            }
        }
    }
    
    // delete local artifacts
    let _ = delete_refresh_token(&username).await;
    let _ = remove_session().await;
    println!("Logged out (local tokens removed).");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Init tracing subscriber (RUST_LOG controls level)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();
    let client = Client::builder()
        .user_agent("SteadyStateCLI/0.1")
        .timeout(Duration::from_secs(30))
        .build()
        .context("create http client")?;

    match cli.cmd {
        Commands::Login => {
            if let Err(e) = device_login(&client).await {
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
        Commands::Refresh => match perform_refresh(&client).await {
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
    }

    Ok(())
}
