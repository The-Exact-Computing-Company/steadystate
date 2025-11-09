use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use jwt_simple::prelude::*;
use keyring::Entry;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::{select, signal, time};
use tracing::{debug, info, warn};

use crate::config::{
    BACKEND_URL, DEVICE_POLL_MAX_INTERVAL_SECS, DEVICE_POLL_REQUEST_TIMEOUT_SECS,
    JWT_REFRESH_BUFFER_SECS, MAX_NETWORK_RETRIES, RETRY_DELAY_MS, SERVICE_NAME,
};
use crate::session::{Session, read_session, remove_session, write_session};

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

/// Initiates OAuth device flow authentication.
pub async fn device_login(client: &Client) -> Result<()> {
    let url = format!("{}/auth/device", &*BACKEND_URL);
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

    let poll_url = format!("{}/auth/poll", &*BACKEND_URL);
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
                                let refresh = out
                                    .refresh_token
                                    .context("no refresh token returned")?;
                                let login = out.login.context("no login returned")?;

                                store_refresh_token(&login, &refresh).await?;

                                let session = Session::new(login.clone(), jwt.clone());
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
                            "authorization_pending" => {
                                current_interval_secs = current_interval_secs
                                    .saturating_mul(3)
                                    .saturating_div(2)
                                    .clamp(interval, max_interval_secs);
                                continue;
                            }
                            "slow_down" => {
                                current_interval_secs = (current_interval_secs + 5)
                                    .clamp(interval, max_interval_secs);
                                continue;
                            }
                            "access_denied" => {
                                spinner.finish_and_clear();
                                anyhow::bail!("authorization denied by user");
                            }
                            _ => {
                                spinner.finish_and_clear();
                                anyhow::bail!("authorization error: {}", err);
                            }
                        }
                    }
                }
            }
        }
    };

    match time::timeout(Duration::from_secs(expires_in), poll_loop).await {
        Ok(res) => res,
        Err(_) => {
            spinner.finish_and_clear();
            anyhow::bail!("device code expired")
        }
    }
}

/// Refreshes JWT using stored refresh token.
pub async fn perform_refresh(client: &Client) -> Result<String> {
    let session = read_session()
        .await
        .context("No active session found. Run 'steadystate login' first.")?;

    let username = session.login.clone();
    let refresh = get_refresh_token(&username).await?.ok_or_else(|| {
        anyhow::anyhow!("no refresh token in keychain; run `steadystate login` again")
    })?;

    let url = format!("{}/auth/refresh", &*BACKEND_URL);
    let resp = send_with_retries(|| {
        client
            .post(&url)
            .json(&serde_json::json!({ "refresh_token": refresh.clone() }))
    })
    .await
    .context("auth/refresh request failed")?;

    if resp.status().as_u16() == 401 {
        let _ = delete_refresh_token(&username).await;
        let _ = remove_session().await;
        anyhow::bail!("Refresh token expired. Run 'steadystate login' to authenticate again.");
    }

    if !resp.status().is_success() {
        let status = resp.status();
        // Debug logs may include sensitive response bodies (JWTs).
        if tracing::enabled!(tracing::Level::DEBUG) {
            if let Ok(body) = resp.text().await {
                debug!("refresh failed body: {}", body);
            }
        }
        anyhow::bail!("refresh failed with status {}", status);
    }

    let body: serde_json::Value = resp.json().await.context("parse refresh response")?;
    let jwt = body
        .get("jwt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no jwt in refresh response"))?
        .to_string();

    let new_session = Session::new(username.clone(), jwt.clone());
    write_session(&new_session).await?;
    Ok(jwt)
}

/// Makes authenticated request with automatic token refresh.
pub async fn request_with_auth<T, F>(client: &Client, builder_fn: F) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    F: Fn(&Client, &str) -> reqwest::RequestBuilder,
{
    let session = read_session()
        .await
        .context("No active session found. Run 'steadystate login' first.")?;
    let mut jwt = session.jwt.clone();

    if session.is_near_expiry(JWT_REFRESH_BUFFER_SECS) {
        info!("JWT near expiry, refreshing proactively");
        jwt = perform_refresh(client).await?;
    }

    let resp = send_with_retries(|| builder_fn(client, &jwt)).await?;

    if resp.status().as_u16() == 401 {
        info!("Got 401, attempting token refresh");
        jwt = perform_refresh(client).await?;
        time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
        let resp2 = send_with_retries(|| builder_fn(client, &jwt)).await?;

        if !resp2.status().is_success() {
            let status = resp2.status();
            // Debug logs may include sensitive response bodies (JWTs).
            if tracing::enabled!(tracing::Level::DEBUG) {
                if let Ok(body) = resp2.text().await {
                    debug!("request retry body: {}", body);
                }
            }
            anyhow::bail!("request failed after retry with status {}", status);
        }

        let body = resp2.json::<T>().await.context("parse response")?;
        return Ok(body);
    }

    if !resp.status().is_success() {
        let status = resp.status();
        // Debug logs may include sensitive response bodies (JWTs).
        if tracing::enabled!(tracing::Level::DEBUG) {
            if let Ok(body) = resp.text().await {
                debug!("request body: {}", body);
            }
        }
        anyhow::bail!("request failed with status {}", status);
    }

    let body = resp.json::<T>().await.context("parse response")?;
    Ok(body)
}

/// Extracts expiry timestamp from JWT (no signature verification).
pub fn extract_exp_from_jwt(jwt: &str) -> Option<u64> {
    // Note: This only extracts expiry for refresh logic. JWT signature is validated server-side.
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        warn!("Invalid JWT format");
        return None;
    }

    let payload_bytes = match Base64UrlSafeNoPadding::decode_to_vec(parts[1], None) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!("Failed to decode JWT payload: {:?}", e);
            return None;
        }
    };

    match serde_json::from_slice::<serde_json::Value>(&payload_bytes) {
        Ok(payload) => match payload.get("exp") {
            Some(value) => match value.as_u64() {
                Some(exp) => Some(exp),
                None => {
                    warn!("JWT exp claim is not a positive integer");
                    None
                }
            },
            None => {
                warn!("JWT missing exp claim");
                None
            }
        },
        Err(e) => {
            warn!("Failed to parse JWT payload: {}", e);
            None
        }
    }
}

/// Stores refresh token in the OS keychain.
pub async fn store_refresh_token(username: &str, token: &str) -> Result<()> {
    let username = username.to_string();
    let token = token.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let entry = Entry::new(SERVICE_NAME, &username)
            .map_err(|e| anyhow::anyhow!("keyring entry creation failed: {}", e))?;
        entry
            .set_password(&token)
            .map_err(|e| anyhow::anyhow!("keyring set_password failed: {}", e))?;
        Ok(())
    })
    .await?
}

/// Retrieves refresh token from keychain if present.
pub async fn get_refresh_token(username: &str) -> Result<Option<String>> {
    let username = username.to_string();
    tokio::task::spawn_blocking(move || -> Result<Option<String>> {
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

/// Deletes refresh token from keychain if present.
pub async fn delete_refresh_token(username: &str) -> Result<()> {
    let username = username.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        if let Ok(entry) = Entry::new(SERVICE_NAME, &username) {
            let _ = entry.delete_credential();
        }
        Ok(())
    })
    .await?
}

pub(crate) async fn send_with_retries<F>(mut make_request: F) -> Result<reqwest::Response>
where
    F: FnMut() -> reqwest::RequestBuilder,
{
    let mut delay = Duration::from_millis(RETRY_DELAY_MS);
    for attempt in 1..=MAX_NETWORK_RETRIES {
        let builder = make_request();
        match builder.send().await {
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

    unreachable!("retry loop should return before exhausting attempts");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_jwt(payload: serde_json::Value) -> String {
        let header = Base64UrlSafeNoPadding::encode_to_string(r#"{"alg":"none"}"#.as_bytes())
            .expect("encode header");
        let payload_str = serde_json::to_string(&payload).unwrap();
        let payload_enc = Base64UrlSafeNoPadding::encode_to_string(payload_str.as_bytes())
            .expect("encode payload");
        format!("{}.{}.", header, payload_enc)
    }

    #[tokio::test]
    async fn test_extract_exp_from_valid_jwt() {
        let jwt = build_jwt(serde_json::json!({ "exp": 1_700_000_000 }));
        assert_eq!(extract_exp_from_jwt(&jwt), Some(1_700_000_000));
    }

    #[tokio::test]
    async fn test_extract_exp_handles_invalid_jwt() {
        let jwt = "invalid";
        assert_eq!(extract_exp_from_jwt(jwt), None);
    }

    #[tokio::test]
    async fn test_extract_exp_missing_claim() {
        let jwt = build_jwt(serde_json::json!({"sub": "abc" }));
        assert_eq!(extract_exp_from_jwt(&jwt), None);
    }

    #[tokio::test]
    async fn test_extract_exp_expired_token() {
        let jwt = build_jwt(serde_json::json!({"exp": 1 }));
        assert_eq!(extract_exp_from_jwt(&jwt), Some(1));
    }
}
