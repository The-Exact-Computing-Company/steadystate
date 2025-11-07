use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dirs::config_dir;
use jwt_simple::prelude::UnvalidatedToken;
use keyring::Entry;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};
use tokio::{signal, task, time};
use tracing::{debug, error, info, warn};

const SERVICE_NAME: &str = "steadystate";
const BACKEND_ENV: &str = "STEADYSTATE_BACKEND"; // e.g. https://api.steadystate.dev
const DEFAULT_BACKEND: &str = "http://localhost:8080";

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
    Whoami,
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

fn backend_url() -> String {
    std::env::var(BACKEND_ENV).unwrap_or_else(|_| DEFAULT_BACKEND.to_string())
}

async fn cfg_dir() -> Result<PathBuf> {
    let mut p = config_dir().context("could not determine config directory")?;
    p.push("steadystate");
    tokio::fs::create_dir_all(&p).await.context("create config dir")?;
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
    tokio::fs::write(&tmp, &data).await.context("write session tmp file")?;
    // set strict permissions on unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .await
            .ok(); // non-fatal if fails
    }
    tokio::fs::rename(tmp, &p).await.context("rename session file")?;
    Ok(())
}

async fn read_session() -> Result<Session> {
    let p = session_file().await?;
    let bytes = tokio::fs::read(&p).await.context("read session file")?;
    let s: Session = serde_json::from_slice(&bytes).context("parse session json")?;
    Ok(s)
}

async fn remove_session() -> Result<()> {
    let p = session_file().await?;
    if p.exists() {
        let _ = tokio::fs::remove_file(p).await;
    }
    Ok(())
}

// Keychain helpers (blocking; run in spawn_blocking)
async fn store_refresh_token(username: &str, token: &str) -> Result<()> {
    let username = username.to_string();
    let token = token.to_string();
    task::spawn_blocking(move || -> Result<()> {
        let entry = Entry::new(SERVICE_NAME, &username);
        entry
            .set_password(&token)
            .map_err(|e| anyhow::anyhow!("keyring set_password failed: {}", e))?;
        Ok(())
    })
    .await??
}

async fn get_refresh_token(username: &str) -> Result<Option<String>> {
    let username = username.to_string();
    let res = task::spawn_blocking(move || -> Result<Option<String>> {
        let entry = Entry::new(SERVICE_NAME, &username);
        match entry.get_password() {
            Ok(tok) => Ok(Some(tok)),
            Err(err) => {
                // key not found or other keyring error - treat as None, but surface debug
                debug!("keyring get_password err: {}", err);
                Ok(None)
            }
        }
    })
    .await?;
    res
}

async fn delete_refresh_token(username: &str) -> Result<()> {
    let username = username.to_string();
    let _ = task::spawn_blocking(move || -> Result<()> {
        let entry = Entry::new(SERVICE_NAME, &username);
        // ignore error if not present
        let _ = entry.delete_password();
        Ok(())
    })
    .await?;
    Ok(())
}

fn extract_exp_from_jwt(jwt: &str) -> Option<u64> {
    // Use jwt-simple UnvalidatedToken to read claims without verifying signature.
    match UnvalidatedToken::from_str(jwt) {
        Ok(t) => match t.claims() {
            Ok(claims) => claims.exp().map(|ts| ts as u64),
            Err(_) => None,
        },
        Err(_) => None,
    }
}

async fn device_login(client: &Client) -> Result<()> {
    let url = format!("{}/auth/device", backend_url());
    let resp = client
        .post(&url)
        .send()
        .await
        .context("request device code from backend")?;
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

    loop {
        // cancel on ctrl-c
        if signal::ctrl_c().now_or_never().is_some() {
            println!("Cancelled by user");
            return Ok(());
        }

        let poll = client
            .get(&poll_url)
            .query(&[("device_code", &device_code)])
            .send()
            .await
            .context("poll request failed")?;

        // If pending, backend returns 202
        if poll.status().as_u16() == 202 {
            // sleep respecting interval
            time::sleep(Duration::from_secs(interval)).await;
            // check expiry
            if start.elapsed().as_secs() > expires_in + 5 {
                anyhow::bail!("device code expired");
            }
            continue;
        }

        let out: PollResponse = poll.json().await.context("parse poll response")?;

        if let Some(status) = out.status.as_deref() {
            match status {
                "pending" => {
                    time::sleep(Duration::from_secs(interval)).await;
                    continue;
                }
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
                    time::sleep(Duration::from_secs(interval)).await;
                    continue;
                }
            }
        } else if let Some(err) = out.error {
            match err.as_str() {
                "authorization_pending" => {
                    time::sleep(Duration::from_secs(interval)).await;
                    continue;
                }
                "slow_down" => {
                    time::sleep(Duration::from_secs(interval + 5)).await;
                    continue;
                }
                "access_denied" => {
                    anyhow::bail!("authorization denied by user");
                }
                _ => {
                    anyhow::bail!("authorization error: {}", err);
                }
            }
        } else {
            time::sleep(Duration::from_secs(interval)).await;
        }
    }
}

async fn perform_refresh(client: &Client) -> Result<String> {
    // read session for username
    let session = match read_session().await {
        Ok(s) => s,
        Err(e) => anyhow::bail!("no existing session; run `steadystate login`: {}", e),
    };
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
        delete_refresh_token(&username).await.ok();
        remove_session().await.ok();
        anyhow::bail!("refresh token invalid; you must run `steadystate login` again");
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
/// `builder_fn` is a closure that receives (&Client, &str, &str jwt) -> reqwest::RequestBuilder
async fn request_with_auth<T, F>(client: &Client, builder_fn: F) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    F: Fn(&Client, &str) -> reqwest::RequestBuilder,
{
    // read session
    let session = read_session().await.context("no session found; please login")?;
    let mut jwt = session.jwt.clone();
    // check expiry within 60s
    let mut need_refresh = false;
    if let Some(exp) = session.jwt_exp {
        let now = chrono::Utc::now().timestamp() as u64;
        if exp <= now + 60 {
            need_refresh = true;
        }
    }
    if need_refresh {
        jwt = perform_refresh(client).await?;
    }

    let req = builder_fn(client, &jwt);
    let resp = req.send().await.context("request failed")?;
    if resp.status().is_client_error() {
        // if 401, try one refresh and retry once
        if resp.status().as_u16() == 401 {
            jwt = perform_refresh(client).await?;
            let req2 = builder_fn(client, &jwt);
            let resp2 = req2.send().await.context("request retry failed")?;
            resp2.error_for_status_ref().context("error status after retry")?;
            let body = resp2.json::<T>().await.context("parse response")?;
            return Ok(body);
        }
    }
    resp.error_for_status().context("request returned error status")?;
    let body = resp.json::<T>().await.context("parse response")?;
    Ok(body)
}

async fn whoami() -> Result<()> {
    match read_session().await {
        Ok(sess) => {
            println!("Logged in as: {}", sess.login);
            Ok(())
        }
        Err(_) => {
            println!("Not logged in. Run `steadystate login`");
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
        let _ = client
            .post(&url)
            .json(&serde_json::json!({ "refresh_token": refresh }))
            .send()
            .await; // ignore errors
    }
    // delete local artifacts
    delete_refresh_token(&username).await.ok();
    remove_session().await.ok();
    println!("Logged out (local tokens removed).");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Init tracing subscriber (RUST_LOG controls level)
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let client = Client::builder()
        .user_agent("SteadyStateCLI/0.1")
        .build()
        .context("create http client")?;

    match cli.cmd {
        Commands::Login => {
            if let Err(e) = device_login(&client).await {
                error!("login failed: {:#}", e);
                std::process::exit(1);
            }
        }
        Commands::Whoami => {
            if let Err(e) = whoami().await {
                error!("whoami failed: {:#}", e);
                std::process::exit(1);
            }
        }
        Commands::Refresh => {
            match perform_refresh(&client).await {
                Ok(_) => println!("Token refreshed."),
                Err(e) => {
                    error!("refresh failed: {:#}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Logout => {
            if let Err(e) = logout(&client).await {
                error!("logout failed: {:#}", e);
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
