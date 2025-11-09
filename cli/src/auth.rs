use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result}; // Added `anyhow` for the new error
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
use crate::session::{read_session, remove_session, write_session, Session};

// ... (The file is identical from here down to `store_refresh_token`)
// ... (No changes needed in device_login, perform_refresh, request_with_auth, etc.)

// --- SNIP --- //

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
    // ** THE FIX IS HERE **
    // Enforce that empty tokens are invalid at the application level.
    if token.is_empty() {
        return Err(anyhow!("refresh token cannot be empty"));
    }

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


// --- SNIP --- //

// ... (The rest of the file, including all tests, remains unchanged)
// ... (The `test_keychain_store_empty_token` test will now pass everywhere because our function now correctly returns an error)

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

    fn build_jwt(payload: serde_json::Value) -> String {
        let header = Base64UrlSafeNoPadding::encode_to_string(r#"{"alg":"none"}"#.as_bytes())
            .expect("encode header");
        let payload_str = serde_json::to_string(&payload).unwrap();
        let payload_enc = Base64UrlSafeNoPadding::encode_to_string(payload_str.as_bytes())
            .expect("encode payload");
        format!("{}.{}.", header, payload_enc)
    }

    // ============================================================================
    // JWT Extraction Tests
    // ============================================================================

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

    #[tokio::test]
    async fn test_extract_exp_with_string_exp() {
        let jwt = build_jwt(serde_json::json!({"exp": "not_a_number" }));
        assert_eq!(extract_exp_from_jwt(&jwt), None);
    }

    #[tokio::test]
    async fn test_extract_exp_with_negative_exp() {
        let jwt = build_jwt(serde_json::json!({"exp": -1 }));
        assert_eq!(extract_exp_from_jwt(&jwt), None);
    }

    #[tokio::test]
    async fn test_extract_exp_with_zero_exp() {
        let jwt = build_jwt(serde_json::json!({"exp": 0 }));
        assert_eq!(extract_exp_from_jwt(&jwt), Some(0));
    }

    #[tokio::test]
    async fn test_extract_exp_with_max_u64() {
        let jwt = build_jwt(serde_json::json!({"exp": u64::MAX }));
        assert_eq!(extract_exp_from_jwt(&jwt), Some(u64::MAX));
    }

    #[tokio::test]
    async fn test_extract_exp_with_malformed_base64() {
        let jwt = "header.!!!invalid_base64!!!.signature";
        assert_eq!(extract_exp_from_jwt(jwt), None);
    }

    #[tokio::test]
    async fn test_extract_exp_with_empty_payload() {
        let jwt = build_jwt(serde_json::json!({}));
        assert_eq!(extract_exp_from_jwt(&jwt), None);
    }

    #[tokio::test]
    async fn test_extract_exp_with_too_few_parts() {
        let jwt = "header.payload";
        assert_eq!(extract_exp_from_jwt(jwt), None);
    }

    #[tokio::test]
    async fn test_extract_exp_with_empty_string() {
        let jwt = "";
        assert_eq!(extract_exp_from_jwt(jwt), None);
    }

    // ============================================================================
    // Keychain Tests
    // ============================================================================

    #[tokio::test]
    async fn test_keychain_store_and_retrieve() {
        let _ctx = TestContext::new();
        let username = "test_user";
        let token = "test_token_123";

        store_refresh_token(username, token)
            .await
            .expect("store token");
        let retrieved = get_refresh_token(username)
            .await
            .expect("get token")
            .expect("token present");

        assert_eq!(retrieved, token);

        delete_refresh_token(username)
            .await
            .expect("delete token");
    }

    #[tokio::test]
    async fn test_keychain_get_nonexistent() {
        let _ctx = TestContext::new();
        let username = "nonexistent_user_xyz";

        let result = get_refresh_token(username).await.expect("get token");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_keychain_delete_nonexistent() {
        let _ctx = TestContext::new();
        let username = "nonexistent_user_abc";

        let result = delete_refresh_token(username).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_keychain_overwrite_token() {
        let _ctx = TestContext::new();
        let username = "overwrite_user";

        store_refresh_token(username, "token1")
            .await
            .expect("store token1");
        store_refresh_token(username, "token2")
            .await
            .expect("store token2");

        let retrieved = get_refresh_token(username)
            .await
            .expect("get token")
            .expect("token present");

        assert_eq!(retrieved, "token2");

        delete_refresh_token(username)
            .await
            .expect("delete token");
    }

    #[tokio::test]
    async fn test_keychain_store_empty_token() {
        let _ctx = TestContext::new();
        let username = "empty_token_user";

        // Keyring doesn't support empty passwords on some backends.
        // We enforce this rule in our function, so it should always fail.
        let result = store_refresh_token(username, "").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_keychain_store_special_chars() {
        let _ctx = TestContext::new();
        let username = "special_chars_user";
        let token = "token!@#$%^&*(){}[]|\\:;\"'<>,.?/~`";

        store_refresh_token(username, token)
            .await
            .expect("store special token");
        let retrieved = get_refresh_token(username)
            .await
            .expect("get token")
            .expect("token present");

        assert_eq!(retrieved, token);

        delete_refresh_token(username)
            .await
            .expect("delete token");
    }

    #[tokio::test]
    async fn test_keychain_multiple_users() {
        let _ctx = TestContext::new();

        store_refresh_token("user1", "token1")
            .await
            .expect("store user1");
        store_refresh_token("user2", "token2")
            .await
            .expect("store user2");
        store_refresh_token("user3", "token3")
            .await
            .expect("store user3");

        let tok1 = get_refresh_token("user1")
            .await
            .expect("get user1")
            .expect("user1 present");
        let tok2 = get_refresh_token("user2")
            .await
            .expect("get user2")
            .expect("user2 present");
        let tok3 = get_refresh_token("user3")
            .await
            .expect("get user3")
            .expect("user3 present");

        assert_eq!(tok1, "token1");
        assert_eq!(tok2, "token2");
        assert_eq!(tok3, "token3");

        delete_refresh_token("user1").await.expect("delete user1");
        delete_refresh_token("user2").await.expect("delete user2");
        delete_refresh_token("user3").await.expect("delete user3");
    }

    #[tokio::test]
    async fn test_keychain_delete_then_get() {
        let _ctx = TestContext::new();
        let username = "delete_then_get_user";

        store_refresh_token(username, "token")
            .await
            .expect("store token");
        delete_refresh_token(username)
            .await
            .expect("delete token");

        let result = get_refresh_token(username).await.expect("get token");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_keychain_store_very_long_token() {
        let _ctx = TestContext::new();
        let username = "long_token_user";
        let token = "a".repeat(10_000);

        store_refresh_token(username, &token)
            .await
            .expect("store long token");
        let retrieved = get_refresh_token(username)
            .await
            .expect("get token")
            .expect("token present");

        assert_eq!(retrieved, token);

        delete_refresh_token(username)
            .await
            .expect("delete token");
    }

    // ============================================================================
    // Integration Tests
    // ============================================================================

    #[tokio::test]
    async fn test_perform_refresh_without_session() {
        let ctx = TestContext::new();
        let client = Client::new();

        let result = perform_refresh(&client, Some(&ctx.path)).await;
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(err_msg.contains("No active session found"));
    }

    #[tokio::test]
    async fn test_perform_refresh_without_refresh_token() {
        let ctx = TestContext::new();
        let client = Client::new();

        let session = Session::new("test_user".to_string(), "fake_jwt".to_string());
        write_session(&session, Some(&ctx.path))
            .await
            .expect("write session");

        let result = perform_refresh(&client, Some(&ctx.path)).await;
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(err_msg.contains("no refresh token"));

        // Clean up
        let _ = crate::session::remove_session(Some(&ctx.path)).await;
    }
}
