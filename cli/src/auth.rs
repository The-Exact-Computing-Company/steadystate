use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use jwt_simple::prelude::*;
use keyring::Entry;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::{select, signal, time};
use tracing::{debug, info, warn};

use crate::config::{
    backend_url, DEVICE_POLL_MAX_INTERVAL_SECS, DEVICE_POLL_REQUEST_TIMEOUT_SECS,
    JWT_REFRESH_BUFFER_SECS, MAX_NETWORK_RETRIES, RETRY_DELAY_MS, SERVICE_NAME,
};
use crate::session::{get_cfg_dir, read_session, remove_session, write_session, Session};

//
// =====================================================
// Types
// =====================================================
//

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

#[derive(Deserialize, Serialize)]
pub struct UpResponse {
    pub id: String,
    pub ssh_url: String,
}

//
// =====================================================
// Device Login
// =====================================================
//

pub async fn device_login(client: &Client) -> Result<()> {
    let url = format!("{}/auth/device", backend_url());
    let resp = send_with_retries(|| client.post(&url)).await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("device code request failed ({}): {}", status, body);
    }

    let dr: DeviceResponse = resp.json().await.context("parse device response")?;

    println!("Open the verification URL and enter the code:");
    println!("\n  {}\n", dr.verification_uri);
    println!("Code: {}\n", dr.user_code);

    if let Err(e) = open::that(&dr.verification_uri) {
        warn!("open browser failed: {}", e);
    }

    let poll_url = format!("{}/auth/poll", backend_url());
    let interval = dr.interval.unwrap_or(5).max(1);
    let max_interval_secs = DEVICE_POLL_MAX_INTERVAL_SECS.max(interval);
    let device_code = dr.device_code.clone();
    let expires_in = dr.expires_in;

    println!("Waiting for authorization (press Ctrl+C to cancel)...");

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠚", "⠞", "⠖", "⠦", "⠴", "⠲", "⠳", "⠓"]),
    );
    spinner.enable_steady_tick(Duration::from_millis(120));
    let start = Instant::now();

    let poll_loop = async {
        let mut current_interval_secs = interval;

        loop {
            spinner.set_message(format!(
                "Authorizing... {}s elapsed",
                start.elapsed().as_secs()
            ));

            select! {
                _ = signal::ctrl_c() => {
                    spinner.finish_and_clear();
                    println!("\nCancelled by user");
                    return Ok(());
                }

                _ = time::sleep(Duration::from_secs(current_interval_secs)) => {
                    let poll = send_with_retries(|| {
                        client
                            .get(&poll_url)
                            .query(&[("device_code", device_code.clone())])
                            .timeout(Duration::from_secs(DEVICE_POLL_REQUEST_TIMEOUT_SECS))
                    })
                    .await
                    .context("poll request failed")?;

                    if poll.status().as_u16() == 202 {
                        current_interval_secs = current_interval_secs
                            .saturating_mul(3)
                            .saturating_div(2)
                            .clamp(interval, max_interval_secs);
                        continue;
                    }

                    let out: PollResponse = poll.json().await.context("parse poll response")?;

                    if let Some(status) = out.status.as_deref() {
                        match status {
                            "pending" => {
                                current_interval_secs = current_interval_secs
                                    .saturating_mul(3)
                                    .saturating_div(2)
                                    .clamp(interval, max_interval_secs);
                                continue;
                            }
                            "complete" => {
                                spinner.finish_and_clear();

                                let jwt = out.jwt.context("server did not return jwt")?;
                                let refresh = out.refresh_token.context("no refresh token")?;
                                let login = out.login.context("no login returned")?;

                                store_refresh_token(&login, &refresh).await?;
                                write_session(&Session::new(login.clone(), jwt.clone()), None).await?;

                                println!("✅ Logged in as {}", login);
                                return Ok(());
                            }
                            other => {
                                warn!("unexpected status: {}", other);
                                continue;
                            }
                        }
                    }

                    if let Some(err) = out.error {
                        spinner.finish_and_clear();
                        match err.as_str() {
                            "authorization_pending" => continue,
                            "slow_down" => {
                                current_interval_secs =
                                    (current_interval_secs + 5).clamp(interval, max_interval_secs);
                                continue;
                            }
                            "access_denied" => anyhow::bail!("authorization denied by user"),
                            _ => anyhow::bail!("authorization error: {}", err),
                        }
                    }
                }
            }
        }
    };

    match time::timeout(Duration::from_secs(expires_in), poll_loop).await {
        Ok(r) => r,
        Err(_) => {
            spinner.finish_and_clear();
            anyhow::bail!("device code expired")
        }
    }
}

//
// =====================================================
// Refresh Token
// =====================================================
//

pub async fn perform_refresh(client: &Client, override_dir: Option<&PathBuf>) -> Result<String> {
    let session = read_session(override_dir)
        .await
        .context("No active session found. Run 'steadystate login' first.")?;

    let username = session.login.clone();

    let refresh = get_refresh_token(&username)
        .await?
        .ok_or_else(|| anyhow!("no refresh token in keychain; run `steadystate login` again"))?;

    let url = format!("{}/auth/refresh", backend_url());

    let resp = send_with_retries(|| {
        client.post(&url).json(&serde_json::json!({
            "refresh_token": refresh.clone()
        }))
    })
    .await
    .context("auth/refresh request failed")?;

    // 401 means expired refresh token
    if resp.status().as_u16() == 401 {
        let _ = delete_refresh_token(&username).await;
        let _ = remove_session(override_dir).await;
        anyhow::bail!("Refresh token expired. Run 'steadystate login' again.");
    }

    if !resp.status().is_success() {
        let status = resp.status();
        if tracing::enabled!(tracing::Level::DEBUG) {
            if let Ok(body) = resp.text().await {
                debug!("refresh failed body: {}", body);
            }
        }
        anyhow::bail!("refresh failed with status {}", status);
    }

    let json: serde_json::Value = resp.json().await.context("parse refresh response")?;
    let jwt = json
        .get("jwt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("no jwt in refresh response"))?
        .to_string();

    let new_sess = Session::new(username.clone(), jwt.clone());
    write_session(&new_sess, override_dir).await?;

    Ok(jwt)
}

//
// =====================================================
// Authenticated Request Wrapper
// =====================================================
//

pub async fn request_with_auth<T, F>(
    client: &Client,
    builder_fn: F,
    override_dir: Option<&PathBuf>,
) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    F: Fn(&Client, &str) -> reqwest::RequestBuilder,
{
    let session = read_session(override_dir)
        .await
        .context("No active session found. Run 'steadystate login' first.")?;

    let mut jwt = session.jwt.clone();

    if session.is_near_expiry(JWT_REFRESH_BUFFER_SECS) {
        info!("JWT near expiry, refreshing proactively");
        jwt = perform_refresh(client, override_dir).await?;
    }

    // First attempt
    let resp = send_with_retries(|| builder_fn(client, &jwt)).await?;

    // On 401 → try refresh
    if resp.status().as_u16() == 401 {
        info!("Got 401, attempting token refresh");

        jwt = perform_refresh(client, override_dir).await?;
        time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;

        let resp2 = send_with_retries(|| builder_fn(client, &jwt)).await?;

        if !resp2.status().is_success() {
            let status = resp2.status();
            if tracing::enabled!(tracing::Level::DEBUG) {
                if let Ok(body) = resp2.text().await {
                    debug!("request retry body: {}", body);
                }
            }
            anyhow::bail!("request failed after retry with status {}", status);
        }

        return Ok(resp2.json::<T>().await.context("parse response")?);
    }

    // Other non-success error
    if !resp.status().is_success() {
        let status = resp.status();
        if tracing::enabled!(tracing::Level::DEBUG) {
            if let Ok(body) = resp.text().await {
                debug!("request body: {}", body);
            }
        }
        anyhow::bail!("request failed with status {}", status);
    }

    Ok(resp.json::<T>().await.context("parse response")?)
}

//
// =====================================================
// JWT expiry decoder
// =====================================================
//

pub fn extract_exp_from_jwt(jwt: &str) -> Option<u64> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        warn!("Invalid JWT format");
        return None;
    }

    let payload_bytes =
        Base64UrlSafeNoPadding::decode_to_vec(parts[1], None).unwrap_or_else(|e| {
            warn!("Failed to decode JWT payload: {:?}", e);
            Vec::new()
        });

    if payload_bytes.is_empty() {
        return None;
    }

    let json: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    json.get("exp")?.as_u64()
}

//
// =====================================================
// Fake-keychain fallback
// =====================================================
//

fn fake_keychain_path(username: &str, cfg_dir: &Path) -> PathBuf {
    cfg_dir.join("keychain").join(format!("{}.json", username))
}

async fn write_fake_key(username: &str, token: &str) -> Result<()> {
    let cfg = get_cfg_dir(None).await?;
    let kc = cfg.join("keychain");
    tokio::fs::create_dir_all(&kc).await?;

    let path = fake_keychain_path(username, &cfg);
    let json = serde_json::json!({ "token": token });

    tokio::fs::write(&path, serde_json::to_vec_pretty(&json)?)
        .await
        .context("write fake keychain")?;

    Ok(())
}

async fn read_fake_key(username: &str) -> Result<Option<String>> {
    let cfg = get_cfg_dir(None).await?;
    let path = fake_keychain_path(username, &cfg);

    if !path.exists() {
        return Ok(None);
    }

    let bytes = tokio::fs::read(&path).await?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)?;
    Ok(json.get("token").and_then(|v| v.as_str().map(|s| s.to_string())))
}

async fn delete_fake_key(username: &str) -> Result<()> {
    let cfg = get_cfg_dir(None).await?;
    let path = fake_keychain_path(username, &cfg);

    let _ = tokio::fs::remove_file(&path).await;
    Ok(())
}

//
// =====================================================
// Public Keychain API (real + fallback)
// =====================================================
//

pub async fn store_refresh_token(username: &str, token: &str) -> Result<()> {
    if token.is_empty() {
        return Err(anyhow!("refresh token cannot be empty"));
    }

    // Try OS keychain first
    let entry = Entry::new(SERVICE_NAME, username);
    match entry {
        Ok(e) => {
            if let Err(err) = e.set_password(token) {
                warn!("OS keychain set_password failed: {} — using fallback", err);
                write_fake_key(username, token).await?;
            }
        }
        Err(err) => {
            warn!("OS keychain unavailable: {} — using fallback", err);
            write_fake_key(username, token).await?;
        }
    }

    Ok(())
}

pub async fn get_refresh_token(username: &str) -> Result<Option<String>> {
    // Try real keychain
    let entry = Entry::new(SERVICE_NAME, username);
    match entry {
        Ok(e) => match e.get_password() {
            Ok(tok) => return Ok(Some(tok)),
            Err(keyring::Error::NoEntry) => {} // fall through to fake
            Err(err) => warn!("OS keychain get_password failed: {}", err),
        },
        Err(err) => warn!("OS keychain unavailable: {}", err),
    }

    // Fallback
    read_fake_key(username).await
}

pub async fn delete_refresh_token(username: &str) -> Result<()> {
    // Best effort: delete from OS keychain
    if let Ok(e) = Entry::new(SERVICE_NAME, username) {
        let _ = e.delete_credential();
    }

    // Delete fallback
    delete_fake_key(username).await
}

//
// =====================================================
// Retry wrapper
// =====================================================
//

pub(crate) async fn send_with_retries<F>(mut make: F) -> Result<reqwest::Response>
where
    F: FnMut() -> reqwest::RequestBuilder,
{
    let mut delay = Duration::from_millis(RETRY_DELAY_MS);

    for attempt in 1..=MAX_NETWORK_RETRIES {
        let req = make();

        match req.send().await {
            Ok(resp) => return Ok(resp),
            Err(err) if attempt < MAX_NETWORK_RETRIES && (err.is_timeout() || err.is_connect()) => {
                warn!(
                    "network request failed (attempt {} of {}): {}",
                    attempt, MAX_NETWORK_RETRIES, err
                );
                time::sleep(delay).await;
                delay = delay.saturating_mul(2);
            }
            Err(err) => return Err(err.into()),
        }
    }

    unreachable!("retry loop must return early");
}
