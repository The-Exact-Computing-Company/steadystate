use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use jwt_simple::prelude::*;
use keyring::Entry;
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::{select, signal, time};
use tracing::{info, warn};

use crate::config::{
    BACKEND_URL, DEVICE_POLL_MAX_INTERVAL_SECS, DEVICE_POLL_REQUEST_TIMEOUT_SECS,
    JWT_REFRESH_BUFFER_SECS, MAX_NETWORK_RETRIES, RETRY_DELAY_MS, SERVICE_NAME,
};
use crate::session::{read_session, remove_session, write_session, Session};

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
    login: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct UpResponse {
    pub id: String,
    pub ssh_url: String,
}

/// Initiates OAuth device flow authentication.
pub async fn device_login(client: &Client, provider: &str) -> Result<()> {
    // Backend: POST /auth/device?provider={provider}
    let url = format!("{}/auth/device?provider={}", &*BACKEND_URL, provider);
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
    let start = std::time::Instant::now();

    // --- Main polling loop -------------------------------------------------
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
                    // Backend now expects POST with JSON { "device_code": ... }
                    let poll = send_with_retries(|| {
                        client
                            .post(&poll_url)
                            .json(&serde_json::json!({ "device_code": device_code.clone() }))
                            .timeout(Duration::from_secs(DEVICE_POLL_REQUEST_TIMEOUT_SECS))
                    })
                    .await
                    .context("poll request failed")?;

                    if !poll.status().is_success() {
                        let status = poll.status();
                        let body = poll.text().await.unwrap_or_default();
                        anyhow::bail!("poll request failed ({}): {}", status, body);
                    }

                    let out: PollResponse = poll.json().await.context("parse poll response")?;

                    match out.status.as_deref() {
                        Some("complete") => {
                            // Success: backend returns jwt, refresh_token, login
                            spinner.finish_and_clear();
                            let jwt = out.jwt.context("server did not return jwt")?;
                            let refresh = out.refresh_token.context("no refresh token returned")?;
                            let login = out.login.context("no login returned")?;

                            store_refresh_token(&login, &refresh).await?;

                            let session = Session::new(login.clone(), jwt.clone());
                            write_session(&session, None).await?;
                            println!("✅ Logged in as {}", login);
                            return Ok(());
                        }
                        Some("pending") => {
                            // Still waiting. Maybe slow_down hint.
                            if let Some(err) = out.error.as_deref() {
                                match err {
                                    "slow_down" => {
                                        current_interval_secs =
                                            (current_interval_secs + 5).clamp(interval, max_interval_secs);
                                    }
                                    // You can extend with more non-fatal hints later.
                                    other => {
                                        spinner.finish_and_clear();
                                        anyhow::bail!("Authorization error: {}", other);
                                    }
                                }
                            }
                            // Otherwise: keep polling with current interval.
                        }
                        None => {
                            if let Some(err) = out.error {
                                spinner.finish_and_clear();
                                anyhow::bail!("Authorization error: {}", err);
                            } else {
                                spinner.finish_and_clear();
                                anyhow::bail!("Unexpected poll response: missing status");
                            }
                        }
                        Some(other) => {
                            spinner.finish_and_clear();
                            anyhow::bail!("Unexpected poll status: {}", other);
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
            anyhow::bail!("Device code expired.")
        }
    }
}

// =======================================================================
// REFACTORED AUTHENTICATION LOGIC
// =======================================================================

#[derive(Debug, Deserialize)]
pub struct RefreshResponse {
    pub jwt: String,
}

/// Refreshes JWT using stored refresh token.
pub async fn perform_refresh(client: &Client, login_override: Option<String>) -> Result<RefreshResponse> {
    let username = match login_override {
        Some(login) => login,
        None => {
            read_session(None)
                .await
                .context("No active session found. Run 'steadystate login' first.")?
                .login
        }
    };

    let refresh = get_refresh_token(&username)
        .await?
        .ok_or_else(|| anyhow!("No refresh token found. Run `steadystate login` again."))?;

    let url = format!("{}/auth/refresh", &*BACKEND_URL);
    let resp = send_with_retries(|| {
        client
            .post(&url)
            .json(&serde_json::json!({ "refresh_token": refresh }))
    })
    .await
    .context("auth/refresh request failed")?;

    if resp.status().as_u16() == 401 {
        let _ = delete_refresh_token(&username).await;
        let _ = remove_session(None).await;
        anyhow::bail!(
            "Refresh token has expired or been revoked. Run 'steadystate login' to authenticate again."
        );
    }

    if !resp.status().is_success() {
        anyhow::bail!("Refresh failed with status {}", resp.status());
    }

    let refresh_resp: RefreshResponse = resp.json().await.context("parse refresh response")?;

    let new_session = Session::new(username, refresh_resp.jwt.clone());
    write_session(&new_session, None).await?;

    Ok(refresh_resp)
}

/// Perform an authenticated request with correct semantics:
///
/// 1. If JWT is expired locally → proactively refresh.
/// 2. Call API.
/// 3. If API returns 401 → treat as fatal, advise user to log in again.
pub async fn request_with_auth<T, F>(
    client: &Client,
    builder_fn: F,
    _override_dir: Option<&PathBuf>, // Kept for API compatibility if needed elsewhere
) -> Result<T>
where
    T: DeserializeOwned,
    F: Fn(&Client, &str) -> reqwest::RequestBuilder,
{
    // Step 1: Load session
    let session = read_session(None)
        .await
        .context("No active session. Run `steadystate login` first.")?;
    let mut jwt = session.jwt.clone();

    // Step 2: If JWT is near expiry → refresh proactively
    if session.is_near_expiry(JWT_REFRESH_BUFFER_SECS) {
        info!("JWT has expired or is near expiry, refreshing proactively");
        let refresh_resp = perform_refresh(client, Some(session.login))
            .await
            .context("Session expired and refresh failed")?;
        jwt = refresh_resp.jwt;
    }

    // Step 3: Perform the authenticated request
    let resp = send_with_retries(|| builder_fn(client, &jwt))
        .await
        .context("API request failed")?;

    // Step 4: If backend returns 401 → fail clearly, do not retry
    if resp.status().as_u16() == 401 {
        anyhow::bail!(
            "Your session has expired or been revoked. Run `steadystate login` again."
        );
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("API request failed with status {}: {}", status, body);
    }

    // Step 5: Parse and return
    Ok(resp
        .json::<T>()
        .await
        .context("Failed to parse server response")?)
}

// =======================================================================
// UNCHANGED HELPERS
// =======================================================================

/// Extracts expiry timestamp from JWT (no signature verification).
pub fn extract_exp_from_jwt(jwt: &str) -> Option<u64> {
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
        Ok(payload) => payload.get("exp").and_then(|v| v.as_u64()),
        Err(e) => {
            warn!("Failed to parse JWT payload: {}", e);
            None
        }
    }
}

/// Stores refresh token in the OS keychain.
pub async fn store_refresh_token(username: &str, token: &str) -> Result<()> {
    if token.is_empty() {
        return Err(anyhow!("refresh token cannot be empty"));
    }
    let username = username.to_string();
    let token = token.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let entry = Entry::new(SERVICE_NAME, &username).context("keyring entry creation failed")?;
        entry
            .set_password(&token)
            .context("keyring set_password failed")?;
        Ok(())
    })
    .await?
}

/// Retrieves refresh token from keychain if present.
pub async fn get_refresh_token(username: &str) -> Result<Option<String>> {
    let username = username.to_string();
    tokio::task::spawn_blocking(move || -> Result<Option<String>> {
        let entry = Entry::new(SERVICE_NAME, &username).context("keyring entry creation failed")?;
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
    use tempfile::{tempdir, TempDir};

    struct TestContext {
        _dir: TempDir,
        path: PathBuf,
    }

    impl TestContext {
        fn new() -> Self {
            let dir = tempdir().expect("create tempdir");
            let path = dir.path().to_path_buf();
            Self { _dir: dir, path }
        }
    }

    #[tokio::test]
    async fn test_perform_refresh_without_session() {
        let _ctx = TestContext::new();
        let client = Client::builder().pool_max_idle_per_host(0).build().unwrap();

        let result = perform_refresh(&client, None).await;
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(err_msg.contains("No active session found. Run 'steadystate login' first."));
    }

    #[tokio::test]
    async fn test_perform_refresh_without_refresh_token() {
        let ctx = TestContext::new();
        let client = Client::builder().pool_max_idle_per_host(0).build().unwrap();

        let session = Session::new("test_user".to_string(), "fake_jwt".to_string());
        write_session(&session, Some(&ctx.path))
            .await
            .expect("write session");

        let result = perform_refresh(&client, Some("test_user".to_string())).await;
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(err_msg.contains("No refresh token found"));

        let _ = crate::session::remove_session(Some(&ctx.path)).await;
    }
    }
