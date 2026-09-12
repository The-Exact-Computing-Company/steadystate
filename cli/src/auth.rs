use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use indicatif::{ProgressBar, ProgressStyle};
use jwt_simple::prelude::*;
use keyring::Entry;
use reqwest::Client;
use serde::{Deserialize, de::DeserializeOwned};
use tokio::{select, signal, time};
use tracing::{info, warn};

use crate::config::{
    BACKEND_URL, DEVICE_POLL_MAX_INTERVAL_SECS, DEVICE_POLL_REQUEST_TIMEOUT_SECS,
    JWT_REFRESH_BUFFER_SECS, MAX_NETWORK_RETRIES, RETRY_DELAY_MS, SERVICE_NAME,
};
use crate::session::{Session, read_session, remove_session, write_session};
use steadystate_common::types::{DeviceFlowResponse, SessionInfo};

type DeviceResponse = DeviceFlowResponse;

#[derive(Deserialize)]
struct PollResponse {
    status: Option<String>,
    jwt: Option<String>,
    refresh_token: Option<String>,
    pub login: Option<String>,
    pub provider_access_token: Option<String>,
    pub error: Option<String>,
}

pub type UpResponse = SessionInfo;

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
    let interval = dr.interval.max(1);
    let max_interval_secs = DEVICE_POLL_MAX_INTERVAL_SECS.max(interval);
    let device_code = dr.device_code.clone();
    let expires_in = dr.expires_in;

    println!("Waiting for authorization (press Ctrl+C to cancel)...");

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner} {msg}")
            .expect("Progress bar template is valid")
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

                            store_refresh_token(&login, &refresh, None).await?;

                            if let Some(token) = out.provider_access_token {
                                store_access_token(&login, &token, None).await?;
                            }

                            let session = Session::with_provider(login.clone(), jwt.clone(), Some(provider.to_string()));
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

/// PAT login for providers without a device flow (GitLab).
/// Posts the token to POST /auth/token and stores the resulting session
/// exactly like the device flow does.
pub async fn token_login(client: &Client, provider: &str, token: &str) -> Result<()> {
    if token.trim().is_empty() {
        anyhow::bail!(
            "Empty token. Create one at your GitLab profile → Access Tokens (needs read_user scope; read_api for collaborator lookup)."
        );
    }
    let url = format!("{}/auth/token", &*BACKEND_URL);
    let resp = send_with_retries(|| {
        client.post(&url).json(&serde_json::json!({
            "provider": provider,
            "token": token.trim(),
        }))
    })
    .await
    .context("token login request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("token login failed ({}): {}", status, body);
    }

    let out: PollResponse = resp.json().await.context("parse token login response")?;
    let jwt = out.jwt.context("server did not return jwt")?;
    let refresh = out.refresh_token.context("no refresh token returned")?;
    let login = out.login.context("no login returned")?;

    store_refresh_token(&login, &refresh, None).await?;
    let session = Session::with_provider(login.clone(), jwt, Some(provider.to_string()));
    write_session(&session, None).await?;
    println!("✅ Logged in as {} (via {})", login, provider);
    Ok(())
}

/// Resolve a PAT from `--token`, `GITLAB_TOKEN`, or an interactive hidden prompt.
pub fn resolve_pat(flag: Option<String>, env_var: &str, prompt: &str) -> Result<String> {
    if let Some(t) = flag {
        return Ok(t);
    }
    if let Ok(t) = std::env::var(env_var)
        && !t.trim().is_empty() {
            return Ok(t);
        }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        anyhow::bail!(
            "No token provided. Pass --token, set {} or run interactively.",
            env_var
        );
    }
    rpassword::prompt_password(prompt).context("read token from terminal")
}

// =======================================================================
// OIDC LOGIN (browser + localhost callback, RFC 8252 native-app style)
// =======================================================================

/// Generate a PKCE verifier/challenge pair (S256).
/// Returns `(verifier, challenge)`; the verifier stays on this machine.
pub fn pkce_pair() -> (String, String) {
    use base64::Engine as _;
    use rand::RngCore;
    use sha2::{Digest, Sha256};
    let mut bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    (verifier, challenge)
}

/// Pull `code` and `state` out of a redirect target: either a full URL
/// (pasted from the browser) or a bare `?code=..&state=..` query string.
pub fn parse_callback_target(target: &str) -> Result<(String, String)> {
    let params = callback_params(target)?;
    let code = params
        .get("code")
        .filter(|s| !s.is_empty())
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!("Redirect has no ?code= parameter (access denied or IdP error?)")
        })?;
    let state = params
        .get("state")
        .filter(|s| !s.is_empty())
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Redirect has no ?state= parameter"))?;
    Ok((code, state))
}

/// Parse the query half of a redirect target into a map (code optional —
/// the backend's authorization URL carries `state` but no `code` yet).
pub fn callback_params(target: &str) -> Result<std::collections::HashMap<String, String>> {
    let query = if let Some(q) = target.split_once('?') {
        q.1.to_string()
    } else if target.contains('=') {
        target.to_string()
    } else {
        anyhow::bail!("No query string in redirect target");
    };
    Ok(url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect())
}

#[derive(Deserialize)]
struct OidcStartOut {
    key: String,
    auth_url: String,
    expires_in: u64,
}

/// OIDC login: PKCE start, browser round-trip via a localhost listener
/// (or pasted redirect with `no_browser`), then completion + session store.
pub async fn oidc_login(client: &Client, no_browser: bool) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let (verifier, challenge) = pkce_pair();

    // Bind localhost first so the redirect_uri is known before start.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind localhost callback listener")?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}/callback",
        listener.local_addr()?.port()
    );

    let start_url = format!("{}/auth/oidc/start", &*BACKEND_URL);
    let resp = send_with_retries(|| {
        client.post(&start_url).json(&serde_json::json!({
            "code_challenge": challenge,
            "redirect_uri": redirect_uri,
        }))
    })
    .await
    .context("OIDC start request failed")?;
    if resp.status().as_u16() == 503 {
        anyhow::bail!("OIDC is not configured on this backend (OIDC_ISSUER/ID/SECRET).");
    }
    if !resp.status().is_success() {
        anyhow::bail!(
            "OIDC start failed ({}): {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let start: OidcStartOut = resp.json().await.context("parse OIDC start response")?;

    // The backend minted `state` inside auth_url; the echo must match it.
    let expected_state = callback_params(&start.auth_url)?
        .get("state")
        .filter(|s| !s.is_empty())
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Backend returned an authorization URL without ?state="))?;

    println!("Open this URL in your browser:\n\n  {}\n", start.auth_url);
    if !no_browser
        && let Err(e) = open::that(&start.auth_url) {
            warn!("open browser failed: {}", e);
        }

    let (code, echo_state) = if no_browser {
        println!("After approving, paste the full localhost redirect URL here:");
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)
            .context("read redirect URL")?;
        parse_callback_target(line.trim())?
    } else {
        println!("Waiting for the browser callback (press Ctrl+C to cancel)...");
        let (mut stream, _) = tokio::time::timeout(
            Duration::from_secs(start.expires_in.max(60)),
            listener.accept(),
        )
        .await
        .context("Timed out waiting for the browser callback")?
        .context("localhost callback accept failed")?;
        let mut reader = tokio::io::BufReader::new(&mut stream);
        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .await
            .context("read callback request")?;
        let target = request_line
            .split_whitespace()
            .nth(1)
            .context("malformed callback request line")?;
        let parsed = parse_callback_target(target);
        let body = "<html><body>Login received — return to the terminal.</body></html>";
        let _ = stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await;
        parsed?
    };

    if echo_state != expected_state {
        anyhow::bail!("State mismatch in OIDC callback (possible CSRF) — aborting.");
    }

    let complete_url = format!("{}/auth/oidc/complete", &*BACKEND_URL);
    let resp = send_with_retries(|| {
        client.post(&complete_url).json(&serde_json::json!({
            "key": start.key,
            "code": code,
            "verifier": verifier,
            "state": echo_state,
        }))
    })
    .await
    .context("OIDC complete request failed")?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "OIDC complete failed ({}): {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let out: PollResponse = resp.json().await.context("parse OIDC complete response")?;
    let jwt = out.jwt.context("server did not return jwt")?;
    let refresh = out.refresh_token.context("no refresh token returned")?;
    let login = out.login.context("no login returned")?;

    store_refresh_token(&login, &refresh, None).await?;
    let session = Session::with_provider(login.clone(), jwt, Some("oidc".to_string()));
    write_session(&session, None).await?;
    println!("✅ Logged in as {} (via oidc)", login);
    Ok(())
}

// =======================================================================
// REFACTORED AUTHENTICATION LOGIC
// =======================================================================

#[derive(Debug, Deserialize)]
pub struct RefreshResponse {
    pub jwt: String,
}

/// Refreshes JWT using stored refresh token.
pub async fn perform_refresh(
    client: &Client,
    login_override: Option<String>,
    override_dir: Option<&PathBuf>,
) -> Result<RefreshResponse> {
    // Load the cached session when available so provider attribution
    // (github vs gitlab) survives refreshes.
    let cached = read_session(override_dir).await.ok();
    let username = match login_override {
        Some(login) => login,
        None => cached
            .as_ref()
            .map(|s| s.login.clone())
            .context("No active session found. Run 'steadystate login' first.")?,
    };

    let refresh = get_refresh_token(&username, override_dir)
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
        if let Err(e) = delete_refresh_token(&username, override_dir).await {
            eprintln!("Warning: Failed to delete refresh token: {}", e);
        }
        let _ = remove_session(override_dir).await;
        anyhow::bail!(
            "Refresh token has expired or been revoked. Run 'steadystate login' to authenticate again."
        );
    }

    if !resp.status().is_success() {
        anyhow::bail!("Refresh failed with status {}", resp.status());
    }

    let refresh_resp: RefreshResponse = resp.json().await.context("parse refresh response")?;

    let provider = cached.as_ref().and_then(|s| s.provider.clone());
    let new_session = Session::with_provider(username, refresh_resp.jwt.clone(), provider);
    write_session(&new_session, override_dir).await?;

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
        let refresh_resp = perform_refresh(client, Some(session.login), _override_dir)
            .await
            .context("Session expired and refresh failed")?;
        jwt = refresh_resp.jwt;
    }

    // Step 3: Perform the authenticated request
    let resp = send_with_retries(|| builder_fn(client, &jwt))
        .await
        .context("API request failed")?;

    // Step 4: If backend returns 401 → fail clearly, do not retry
    // Step 4: If backend returns 401 → fail clearly, do not retry
    if resp.status().as_u16() == 401 {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Your session has expired or been revoked. Run `steadystate login` again.\nServer says: {}",
            body
        );
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("API request failed with status {}: {}", status, body);
    }

    // Step 5: Parse and return
    resp
        .json::<T>()
        .await
        .context("Failed to parse server response")
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

/// Helper to check for mock keyring environment variable
fn get_mock_keyring_path(username: &str) -> Option<PathBuf> {
    std::env::var("STEADYSTATE_KEYRING_DIR")
        .ok()
        .map(|d| PathBuf::from(d).join(format!("{}.keyring", username)))
}

const KEYRING_TIMEOUT_MS: u64 = 2000;

/// Helper to get the fallback file path for the refresh token
async fn get_fallback_token_path(override_dir: Option<&PathBuf>) -> Result<PathBuf> {
    let base_dir = crate::session::get_cfg_dir(override_dir).await?;
    Ok(base_dir.join("credentials"))
}

/// Stores refresh token in the OS keychain (with timeout) or fallback file.
pub async fn store_refresh_token(
    username: &str,
    token: &str,
    override_dir: Option<&PathBuf>,
) -> Result<()> {
    if token.is_empty() {
        return Err(anyhow!("refresh token cannot be empty"));
    }

    // Check for mock keyring first
    if let Some(path) = get_mock_keyring_path(username) {
        return std::fs::write(path, token).context("failed to write mock keyring");
    }

    let use_keyring = std::env::var("STEADYSTATE_NO_KEYRING").is_err();

    if use_keyring {
        let username = username.to_string();
        let token_val = token.to_string();

        // Try keyring with timeout
        let keyring_result = time::timeout(
            Duration::from_millis(KEYRING_TIMEOUT_MS),
            tokio::task::spawn_blocking(move || {
                let entry =
                    Entry::new(SERVICE_NAME, &username).context("keyring entry creation failed")?;
                entry
                    .set_password(&token_val)
                    .context("keyring set_password failed")
            }),
        )
        .await;

        match keyring_result {
            Ok(Ok(Ok(_))) => return Ok(()),
            Ok(Ok(Err(e))) => warn!("Keyring error: {}. Falling back to file storage.", e),
            Ok(Err(e)) => warn!(
                "Keyring task join error: {}. Falling back to file storage.",
                e
            ),
            Err(_) => warn!("Keyring operation timed out. Falling back to file storage."),
        }
    } else {
        info!("STEADYSTATE_NO_KEYRING set, skipping system keyring.");
    }

    // Fallback: Write to file
    let path = get_fallback_token_path(override_dir).await?;
    tokio::fs::write(&path, token)
        .await
        .context("failed to write fallback token file")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await
        {
            warn!("Failed to set strict permissions on token file: {}", e);
        }
    }

    Ok(())
}

/// Retrieves refresh token from keychain (with timeout) or fallback file.
pub async fn get_refresh_token(
    username: &str,
    override_dir: Option<&PathBuf>,
) -> Result<Option<String>> {
    // Check for mock keyring first
    if let Some(path) = get_mock_keyring_path(username) {
        if path.exists() {
            return std::fs::read_to_string(path)
                .map(Some)
                .context("failed to read mock keyring");
        } else {
            return Ok(None);
        }
    }

    let use_keyring = std::env::var("STEADYSTATE_NO_KEYRING").is_err();

    if use_keyring {
        let username = username.to_string();

        // Try keyring with timeout
        let keyring_result = time::timeout(
            Duration::from_millis(KEYRING_TIMEOUT_MS),
            tokio::task::spawn_blocking(move || {
                let entry =
                    Entry::new(SERVICE_NAME, &username).context("keyring entry creation failed")?;
                match entry.get_password() {
                    Ok(tok) => Ok(Some(tok)),
                    Err(keyring::Error::NoEntry) => Ok(None),
                    Err(e) => Err(e).context("keyring get_password failed"),
                }
            }),
        )
        .await;

        match keyring_result {
            Ok(Ok(Ok(Some(token)))) => return Ok(Some(token)),
            Ok(Ok(Ok(None))) => {
                // Keyring worked but no token. Check fallback file just in case?
                // Usually if we use keyring we stick to it, but if user switched envs...
                // Let's check fallback file if keyring is empty.
            }
            Ok(Ok(Err(e))) => warn!("Keyring error: {}. Checking fallback file.", e),
            Ok(Err(e)) => warn!("Keyring task join error: {}. Checking fallback file.", e),
            Err(_) => warn!("Keyring operation timed out. Checking fallback file."),
        }
    }

    // Fallback: Read from file
    let path = get_fallback_token_path(override_dir).await?;
    if path.exists() {
        let token = tokio::fs::read_to_string(path)
            .await
            .context("failed to read fallback token file")?;
        if !token.trim().is_empty() {
            return Ok(Some(token));
        }
    }

    Ok(None)
}

/// Deletes refresh token from keychain (with timeout) and fallback file.
pub async fn delete_refresh_token(username: &str, override_dir: Option<&PathBuf>) -> Result<()> {
    // Check for mock keyring first
    if let Some(path) = get_mock_keyring_path(username) {
        if path.exists() {
            std::fs::remove_file(path).context("failed to delete mock keyring")?;
        }
        return Ok(());
    }

    let use_keyring = std::env::var("STEADYSTATE_NO_KEYRING").is_err();

    if use_keyring {
        let username = username.to_string();

        // Try keyring with timeout
        let _ = time::timeout(
            Duration::from_millis(KEYRING_TIMEOUT_MS),
            tokio::task::spawn_blocking(move || {
                if let Ok(entry) = Entry::new(SERVICE_NAME, &username) {
                    let _ = entry.delete_credential();
                }
            }),
        )
        .await;
    }

    // Always try to delete fallback file too
    let path = get_fallback_token_path(override_dir).await?;
    if path.exists() {
        tokio::fs::remove_file(path)
            .await
            .context("failed to delete fallback token file")?;
    }

    Ok(())
}

/// Helper to get the fallback file path for the access token
async fn get_access_token_path(override_dir: Option<&PathBuf>) -> Result<PathBuf> {
    let base_dir = crate::session::get_cfg_dir(override_dir).await?;
    Ok(base_dir.join("provider_token"))
}

/// Stores access token in the OS keychain (with timeout) or fallback file.
pub async fn store_access_token(
    username: &str,
    token: &str,
    override_dir: Option<&PathBuf>,
) -> Result<()> {
    if token.is_empty() {
        return Err(anyhow!("access token cannot be empty"));
    }

    // Check for mock keyring first
    if let Some(path) = get_mock_keyring_path(&format!("{}_access", username)) {
        return std::fs::write(path, token).context("failed to write mock keyring");
    }

    let use_keyring = std::env::var("STEADYSTATE_NO_KEYRING").is_err();

    if use_keyring {
        let username = format!("{}_access", username);
        let token_val = token.to_string();

        // Try keyring with timeout
        let keyring_result = time::timeout(
            Duration::from_millis(KEYRING_TIMEOUT_MS),
            tokio::task::spawn_blocking(move || {
                let entry =
                    Entry::new(SERVICE_NAME, &username).context("keyring entry creation failed")?;
                entry
                    .set_password(&token_val)
                    .context("keyring set_password failed")
            }),
        )
        .await;

        match keyring_result {
            Ok(Ok(Ok(_))) => return Ok(()),
            Ok(Ok(Err(e))) => warn!("Keyring error: {}. Falling back to file storage.", e),
            Ok(Err(e)) => warn!(
                "Keyring task join error: {}. Falling back to file storage.",
                e
            ),
            Err(_) => warn!("Keyring operation timed out. Falling back to file storage."),
        }
    }

    // Fallback: Write to file
    let path = get_access_token_path(override_dir).await?;
    tokio::fs::write(&path, token)
        .await
        .context("failed to write access token file")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await
        {
            warn!("Failed to set strict permissions on token file: {}", e);
        }
    }

    Ok(())
}

/// Retrieves access token from keychain (with timeout) or fallback file.
pub async fn get_access_token(
    username: &str,
    override_dir: Option<&PathBuf>,
) -> Result<Option<String>> {
    // Check for mock keyring first
    if let Some(path) = get_mock_keyring_path(&format!("{}_access", username)) {
        if path.exists() {
            return std::fs::read_to_string(path)
                .map(Some)
                .context("failed to read mock keyring");
        } else {
            return Ok(None);
        }
    }

    let use_keyring = std::env::var("STEADYSTATE_NO_KEYRING").is_err();

    if use_keyring {
        let username = format!("{}_access", username);

        // Try keyring with timeout
        let keyring_result = time::timeout(
            Duration::from_millis(KEYRING_TIMEOUT_MS),
            tokio::task::spawn_blocking(move || {
                let entry =
                    Entry::new(SERVICE_NAME, &username).context("keyring entry creation failed")?;
                match entry.get_password() {
                    Ok(tok) => Ok(Some(tok)),
                    Err(keyring::Error::NoEntry) => Ok(None),
                    Err(e) => Err(e).context("keyring get_password failed"),
                }
            }),
        )
        .await;

        match keyring_result {
            Ok(Ok(Ok(Some(token)))) => return Ok(Some(token)),
            Ok(Ok(Ok(None))) => {}
            Ok(Ok(Err(e))) => warn!("Keyring error: {}. Checking fallback file.", e),
            Ok(Err(e)) => warn!("Keyring task join error: {}. Checking fallback file.", e),
            Err(_) => warn!("Keyring operation timed out. Checking fallback file."),
        }
    }

    // Fallback: Read from file
    let path = get_access_token_path(override_dir).await?;
    if path.exists() {
        let token = tokio::fs::read_to_string(path)
            .await
            .context("failed to read access token file")?;
        if !token.trim().is_empty() {
            return Ok(Some(token));
        }
    }

    Ok(None)
}

/// Deletes access token from keychain (with timeout) and fallback file.
pub async fn delete_access_token(username: &str, override_dir: Option<&PathBuf>) -> Result<()> {
    // Check for mock keyring first
    if let Some(path) = get_mock_keyring_path(&format!("{}_access", username)) {
        if path.exists() {
            std::fs::remove_file(path).context("failed to delete mock keyring")?;
        }
        return Ok(());
    }

    let use_keyring = std::env::var("STEADYSTATE_NO_KEYRING").is_err();

    if use_keyring {
        let username = format!("{}_access", username);

        // Try keyring with timeout
        let _ = time::timeout(
            Duration::from_millis(KEYRING_TIMEOUT_MS),
            tokio::task::spawn_blocking(move || {
                if let Ok(entry) = Entry::new(SERVICE_NAME, &username) {
                    let _ = entry.delete_credential();
                }
            }),
        )
        .await;
    }

    // Always try to delete fallback file too
    let path = get_access_token_path(override_dir).await?;
    if path.exists() {
        tokio::fs::remove_file(path)
            .await
            .context("failed to delete access token file")?;
    }

    Ok(())
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
    Err(anyhow::anyhow!(
        "Max retries ({}) exceeded",
        MAX_NETWORK_RETRIES
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{TempDir, tempdir};

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

        let result = perform_refresh(&client, None, Some(&_ctx.path)).await;
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

        let result = perform_refresh(&client, Some("test_user".to_string()), Some(&ctx.path)).await;
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(err_msg.contains("No refresh token found"));

        let _ = crate::session::remove_session(Some(&ctx.path)).await;
    }

    #[test]
    fn test_resolve_pat_flag_wins() {
        let out = resolve_pat(
            Some("flag-token".to_string()),
            "STEADYSTATE_TEST_PAT_A",
            "prompt: ",
        )
        .unwrap();
        assert_eq!(out, "flag-token");
    }

    #[test]
    fn test_resolve_pat_env_fallback() {
        // SAFETY: unique var name, no other test touches it.
        unsafe { std::env::set_var("STEADYSTATE_TEST_PAT_B", "env-token") };
        let out = resolve_pat(None, "STEADYSTATE_TEST_PAT_B", "prompt: ").unwrap();
        unsafe { std::env::remove_var("STEADYSTATE_TEST_PAT_B") };
        assert_eq!(out, "env-token");
    }

    #[test]
    fn test_resolve_pat_errors_without_input() {
        // In the test harness stdin is not a terminal, so this must fail
        // instead of blocking on a prompt.
        let err = resolve_pat(None, "STEADYSTATE_TEST_PAT_MISSING", "prompt: ").unwrap_err();
        assert!(format!("{:#}", err).contains("STEADYSTATE_TEST_PAT_MISSING"));
    }

    #[test]
    fn test_pkce_pair_challenge_matches_verifier() {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let (verifier, challenge) = pkce_pair();
        assert!(!verifier.is_empty() && !challenge.is_empty());
        // RFC 7636 test-style recomputation: challenge == BASE64URL(SHA256(verifier)).
        let recomputed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, recomputed);
        // Uniqueness across generations.
        assert_ne!(pkce_pair().0, verifier);
    }

    #[test]
    fn test_parse_callback_target() {
        let (code, state) =
            parse_callback_target("http://127.0.0.1:54321/callback?code=abc123&state=xyz").unwrap();
        assert_eq!((code.as_str(), state.as_str()), ("abc123", "xyz"));

        // Bare query strings (SSH-pasted redirects) work too.
        let (code, _) = parse_callback_target("code=only-code&state=s").unwrap();
        assert_eq!(code, "only-code");

        assert!(parse_callback_target("http://127.0.0.1:1/callback").is_err());
        assert!(parse_callback_target("http://x/cb?code=a").is_err());
        assert!(parse_callback_target("http://x/cb?error=access_denied").is_err());
    }

    #[test]
    fn test_callback_params_state_without_code() {
        // The backend's authorization URL carries state but no code yet.
        let params =
            callback_params("https://sso.example.com/authorize?response_type=code&state=st4te")
                .unwrap();
        assert_eq!(params.get("state").map(String::as_str), Some("st4te"));
        assert!(!params.contains_key("code"));
    }
}
