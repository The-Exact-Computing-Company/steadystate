// backend/src/routes/auth.rs

use std::sync::Arc;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use tracing::{info, warn};

use crate::jwt::CustomClaims;
use crate::{
    auth::provider::DevicePollOutcome,
    models::*,
    state::AppState,
};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/device", post(device_start))
        .route("/poll", post(poll))
        .route("/token", post(token_login))
        .route("/refresh", post(refresh))
        .route("/revoke", post(revoke))
        .route("/me", get(me))
}

/// Initiates the device flow authentication process.
///
/// # Arguments
/// * `state` - The application state.
/// * `q` - Query parameters containing the provider ID (default: "github").
///
/// # Returns
/// * `200 OK` with the device code and user code.
/// * `400 Bad Request` if the provider is invalid.
/// * `500 Internal Server Error` if the flow fails.
pub async fn device_start(
    State(state): State<Arc<AppState>>,
    Query(q): Query<DeviceQuery>,
) -> Result<Json<DeviceStartResponse>, (StatusCode, Json<serde_json::Value>)> {
    let provider_id = ProviderId::from(q.provider.as_deref().unwrap_or("github"));

    let provider = state.get_or_create_provider(&provider_id).await
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))))?;

    let start = provider.start_device_flow().await
        .map_err(internal)?;

    state.device_pending.insert(start.device_code.clone(), PendingDevice {
        provider: q.provider.unwrap_or("github".into()).into(),
        device_code: start.device_code.clone(),
        user_code: start.user_code.clone(),
        verification_uri: start.verification_uri.clone(),
        interval: start.interval,
        created_at: now(),
    });

    Ok(Json(start))
}

/// Polls the status of a pending device flow authentication.
///
/// # Arguments
/// * `state` - The application state.
/// * `q` - JSON body containing the device code.
///
/// # Returns
/// * `200 OK` with the poll status (pending, complete, slow_down) and tokens if complete.
/// * `500 Internal Server Error` if the provider lookup fails.
pub async fn poll(
    State(state): State<Arc<AppState>>,
    Json(q): Json<PollQuery>,
) -> Result<Json<PollOut>, (StatusCode, Json<serde_json::Value>)> {
    let pending = match state.device_pending.get(&q.device_code) {
        Some(e) => e,
        None => {
            return Ok(Json(PollOut {
                status: None,
                jwt: None,
                refresh_token: None,
                login: None,
                provider_access_token: None,
                error: Some("invalid_device_code".into()),
            }))
        }
    };
    let provider_id = pending.provider.clone();
    drop(pending);

    let provider = match state.get_or_create_provider(&provider_id).await {
        Ok(p) => p,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })))),
    };

    match provider.poll_device_flow(&q.device_code).await {
        Ok(DevicePollOutcome::Complete { identity, provider_access_token }) => {
            info!(
                "device flow complete for {} via {}",
                identity.login,
                provider_id.as_str()
            );

            state.device_pending.remove(&q.device_code);

            let jwt = state
                .jwt
                .sign(&identity.login, provider_id.as_str())
                .map_err(internal)?;
            let refresh_token = state.issue_refresh_token(identity.login.clone(), provider_id);

            if let Some(ref token) = provider_access_token {
                state.provider_tokens.insert(
                    (identity.provider.clone(), identity.login.clone()),
                    token.clone()
                );
                if let Err(e) = state.save_tokens() {
                    warn!("Failed to persist tokens: {}", e);
                }
            }

            Ok(Json(PollOut {
                status: Some("complete".into()),
                jwt: Some(jwt),
                refresh_token: Some(refresh_token),
                login: Some(identity.login),
                provider_access_token: provider_access_token.clone(),
                error: None,
            }))
        }
        Ok(DevicePollOutcome::Pending) => {
            info!("poll pending for provider '{}'", provider_id.as_str());
            Ok(Json(PollOut {
                status: Some("pending".into()),
                jwt: None, refresh_token: None, login: None,
                provider_access_token: None,
                error: None,
            }))
        },
        Ok(DevicePollOutcome::SlowDown) => {
            info!("poll slow_down for provider '{}'", provider_id.as_str());
            Ok(Json(PollOut {
                status: Some("pending".into()),
                jwt: None, refresh_token: None, login: None,
                provider_access_token: None,
                error: Some("slow_down".into()),
            }))
        },
        Err(e) => {
            warn!("poll error for provider '{}': {}", provider_id.as_str(), e);
            Ok(Json(PollOut {
                status: None,
                jwt: None,
                refresh_token: None,
                login: None,
                provider_access_token: None,
                error: Some(e.to_string()),
            }))
        }
    }
}


/// PAT login for providers without an OAuth device flow (GitLab).
///
/// # Arguments
/// * `state` - The application state.
/// * `inp` - JSON body with `provider` (currently only "gitlab") and `token`.
///
/// # Returns
/// * `200 OK` with JWT + refresh token (same shape as a completed poll).
/// * `400 Bad Request` for providers that have a device flow.
/// * `401 Unauthorized` if the token is rejected by the provider.
pub async fn token_login(
    State(state): State<Arc<AppState>>,
    Json(inp): Json<TokenIn>,
) -> Result<Json<PollOut>, (StatusCode, Json<serde_json::Value>)> {
    let provider_name = inp.provider.as_deref().unwrap_or("gitlab");
    if provider_name != "gitlab" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("provider '{}' uses the device flow; use POST /auth/device instead", provider_name) })),
        ));
    }

    let validated = validate_gitlab_token(&state, &inp.token).await
        .map_err(|e| (StatusCode::UNAUTHORIZED, Json(json!({ "error": e.to_string() }))))?;

    let jwt = state
        .jwt
        .sign(&validated.login, "gitlab")
        .map_err(internal)?;
    let refresh_token = state.issue_refresh_token(validated.login.clone(), ProviderId::from("gitlab"));

    state.provider_tokens.insert(
        ("gitlab".to_string(), validated.login.clone()),
        inp.token.trim().to_string(),
    );
    if let Err(e) = state.save_tokens() {
        warn!("Failed to persist tokens: {}", e);
    }

    info!("PAT login complete for {} via gitlab", validated.login);
    Ok(Json(PollOut {
        status: Some("complete".into()),
        jwt: Some(jwt),
        refresh_token: Some(refresh_token),
        login: Some(validated.login),
        provider_access_token: None,
        error: None,
    }))
}

async fn validate_gitlab_token(
    state: &Arc<AppState>,
    token: &str,
) -> anyhow::Result<crate::auth::provider::UserIdentity> {
    use crate::auth::gitlab::GitLabAuth;
    // Build a short-lived instance from env (same config the factory uses);
    // avoids downcasting the trait object.
    let base = crate::auth::gitlab::base_url_from_env()?;
    GitLabAuth::new(state.http.clone(), base)
        .validate_token(token)
        .await
}
/// Refreshes an access token using a refresh token.
///
/// # Arguments
/// * `state` - The application state.
/// * `inp` - JSON body containing the refresh token.
///
/// # Returns
/// * `200 OK` with a new JWT.
/// * `401 Unauthorized` if the refresh token is invalid or expired.
pub async fn refresh(
    State(state): State<Arc<AppState>>,
    Json(inp): Json<RefreshIn>,
) -> Result<Json<RefreshOut>, (StatusCode, Json<serde_json::Value>)> {
    let rec = state
        .refresh_store
        .get(&inp.refresh_token)
        .map(|e| e.clone())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid refresh token" }))))?;

    if now() >= rec.expires_at {
        state.revoke_refresh_token(&inp.refresh_token);
        return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": "refresh expired" }))));
    }

    let jwt = state
        .jwt
        .sign(&rec.login, rec.provider.as_str())
        .map_err(internal)?;

    Ok(Json(RefreshOut {
        jwt,
        refresh_expires_at: Some(rec.expires_at),
    }))
}


/// Revokes a refresh token.
///
/// # Arguments
/// * `state` - The application state.
/// * `inp` - JSON body containing the refresh token.
///
/// # Returns
/// * `200 OK` with `{"revoked": true}`.
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    Json(inp): Json<RevokeIn>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state.revoke_refresh_token(&inp.refresh_token);
    Ok(Json(json!({ "revoked": true })))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("System time is before UNIX EPOCH").as_secs()
}

fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })))
}

/// Returns the current user's claims.
///
/// # Arguments
/// * `claims` - The JWT claims extracted from the Authorization header.
///
/// # Returns
/// * `200 OK` with the claims JSON.
pub async fn me(
    claims: CustomClaims,
) -> Json<CustomClaims> {
    Json(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::lock_test_env;

    /// Spin up a mock GitLab `/api/v4/user` endpoint.
    /// `ok=true` returns a user for any token; otherwise 401.
    async fn mock_gitlab(ok: bool) -> String {
        let app = axum::Router::new().route(
            "/api/v4/user",
            axum::routing::get(move || async move {
                if ok {
                    (
                        axum::http::StatusCode::OK,
                        axum::Json(serde_json::json!({
                            "id": 42,
                            "username": "gluser",
                            "email": "gl@example.com",
                        })),
                    )
                } else {
                    (
                        axum::http::StatusCode::UNAUTHORIZED,
                        axum::Json(serde_json::json!({ "message": "401 Unauthorized" })),
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock gitlab");
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock gitlab");
        });
        base
    }

    async fn test_state_with_gitlab(base: &str) -> TestEnv {
        let guard = lock_test_env();
        let saved: Vec<(String, Option<String>)> =
            ["JWT_SECRET", "NOENV_FLAKE_PATH", "STEADYSTATE_DB_PATH", "GITLAB_URL", "HCLOUD_TOKEN"]
                .iter()
                .map(|k| (k.to_string(), std::env::var(k).ok()))
                .collect();
        // SAFETY: serialized by the shared test-env lock; restored on drop.
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-for-token-tests");
            std::env::set_var("NOENV_FLAKE_PATH", "/tmp/dummy-flake");
            std::env::set_var("STEADYSTATE_DB_PATH", ":memory:");
            std::env::set_var("GITLAB_URL", base);
            std::env::remove_var("HCLOUD_TOKEN");
        }
        let state = AppState::try_new().await.expect("test AppState");
        TestEnv { state, saved, _guard: guard }
    }

    /// Holds test env overrides until the end of the test, then restores.
    struct TestEnv {
        state: Arc<AppState>,
        saved: Vec<(String, Option<String>)>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            // SAFETY: still holding the shared lock.
            unsafe {
                for (k, old) in self.saved.drain(..) {
                    match old {
                        Some(v) => std::env::set_var(&k, v),
                        None => std::env::remove_var(&k),
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn token_login_gitlab_complete() {
        let base = mock_gitlab(true).await;
        let env = test_state_with_gitlab(&base).await;
        let state = env.state.clone();

        let out = token_login(
            State(state.clone()),
            Json(TokenIn { provider: Some("gitlab".to_string()), token: "glpat-xxx".to_string() }),
        )
        .await
        .expect("token login")
        .0;
        assert_eq!(out.status.as_deref(), Some("complete"));
        assert_eq!(out.login.as_deref(), Some("gluser"));
        assert!(out.jwt.is_some());
        assert!(out.refresh_token.is_some());

        // Refresh token is usable for JWT refresh (proves persistence path).
        let stored: Vec<_> = state.refresh_store.iter().map(|e| e.key().clone()).collect();
        assert_eq!(stored.len(), 1);
    }

    #[tokio::test]
    async fn token_login_rejects_device_flow_providers() {
        let base = mock_gitlab(true).await;
        let env = test_state_with_gitlab(&base).await;
        let state = env.state.clone();

        let err = token_login(
            State(state),
            Json(TokenIn { provider: Some("github".to_string()), token: "x".to_string() }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn token_login_bad_pat_is_401() {
        let base = mock_gitlab(false).await;
        let env = test_state_with_gitlab(&base).await;
        let state = env.state.clone();

        let err = token_login(
            State(state),
            Json(TokenIn { provider: None, token: "bogus".to_string() }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }
}
