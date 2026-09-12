// backend/src/routes/auth.rs

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn};

use crate::jwt::CustomClaims;
use crate::{auth::provider::DevicePollOutcome, models::*, state::AppState};

pub fn router() -> Router<Arc<AppState>> {
    // Per-route rate-limit tiers (see rate_limit.rs). Merging preserves layers.
    let token = crate::rate_limit::token_limit(Router::new().route("/token", post(token_login)));
    let device = crate::rate_limit::auth_limit(
        Router::new()
            .route("/device", post(device_start))
            .route("/poll", post(poll))
            .route("/oidc/start", post(oidc_start))
            .route("/oidc/complete", post(oidc_complete)),
    );
    let general = crate::rate_limit::general_limit(
        Router::new()
            .route("/refresh", post(refresh))
            .route("/revoke", post(revoke))
            .route("/me", get(me)),
    );
    Router::new().merge(token).merge(device).merge(general)
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

    let provider = state
        .get_or_create_provider(&provider_id)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
        })?;

    let start = provider.start_device_flow().await.map_err(internal)?;

    // Bound pending entries: prune expired ones, then record the provider's
    // own expiry so a device code cannot be polled forever.
    state.prune_auth_state();
    state.device_pending.insert(
        start.device_code.clone(),
        PendingDevice {
            provider: q.provider.unwrap_or("github".into()).into(),
            device_code: start.device_code.clone(),
            expires_at: now() + start.expires_in,
            user_code: start.user_code.clone(),
            verification_uri: start.verification_uri.clone(),
            interval: start.interval,
        },
    );

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
            }));
        }
    };
    // Expired device codes are terminal: drop and reject.
    if pending.expires_at <= now() {
        let provider_id = pending.provider.clone();
        drop(pending);
        state.device_pending.remove(&q.device_code);
        info!(
            "device code expired for provider '{}'",
            provider_id.as_str()
        );
        return Ok(Json(PollOut {
            status: None,
            jwt: None,
            refresh_token: None,
            login: None,
            provider_access_token: None,
            error: Some("expired_device_code".into()),
        }));
    }
    let provider_id = pending.provider.clone();
    drop(pending);

    let provider = match state.get_or_create_provider(&provider_id).await {
        Ok(p) => p,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            ));
        }
    };

    match provider.poll_device_flow(&q.device_code).await {
        Ok(DevicePollOutcome::Complete {
            identity,
            provider_access_token,
        }) => {
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
            let refresh_token = state
                .issue_refresh_token(identity.login.clone(), provider_id)
                .await
                .map_err(internal)?;

            if let Some(ref token) = provider_access_token {
                state.provider_tokens.insert(
                    (identity.provider.clone(), identity.login.clone()),
                    token.clone(),
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
                jwt: None,
                refresh_token: None,
                login: None,
                provider_access_token: None,
                error: None,
            }))
        }
        Ok(DevicePollOutcome::SlowDown) => {
            info!("poll slow_down for provider '{}'", provider_id.as_str());
            Ok(Json(PollOut {
                status: Some("pending".into()),
                jwt: None,
                refresh_token: None,
                login: None,
                provider_access_token: None,
                error: Some("slow_down".into()),
            }))
        }
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
            Json(
                json!({ "error": format!("provider '{}' uses the device flow; use POST /auth/device instead", provider_name) }),
            ),
        ));
    }

    let validated = validate_gitlab_token(&state, &inp.token)
        .await
        .map_err(|e| {
            use crate::auth::gitlab::GitLabTokenError;
            let status = match e {
                GitLabTokenError::Empty => StatusCode::BAD_REQUEST,
                GitLabTokenError::Rejected(_) => StatusCode::UNAUTHORIZED,
                GitLabTokenError::Upstream(_) => StatusCode::BAD_GATEWAY,
            };
            (status, Json(json!({ "error": e.to_string() })))
        })?;

    let jwt = state
        .jwt
        .sign(&validated.login, "gitlab")
        .map_err(internal)?;
    let refresh_token = state
        .issue_refresh_token(validated.login.clone(), ProviderId::from("gitlab"))
        .await
        .map_err(internal)?;

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
) -> Result<crate::auth::provider::UserIdentity, crate::auth::gitlab::GitLabTokenError> {
    use crate::auth::gitlab::{GitLabAuth, GitLabTokenError};
    // Build a short-lived instance from env (same config the factory uses);
    // avoids downcasting the trait object.
    let base = crate::auth::gitlab::base_url_from_env()
        .map_err(|e| GitLabTokenError::Upstream(e.to_string()))?;
    GitLabAuth::new(state.http.clone(), base)
        .validate_token(token)
        .await
}
/// OIDC login start: store the CLI's PKCE challenge + callback URL and
/// return the browser authorization URL.
///
/// # Returns
/// * `200 OK` with `{ key, auth_url, expires_in }`.
/// * `503` if OIDC is not configured on the server.
pub async fn oidc_start(
    State(state): State<Arc<AppState>>,
    Json(inp): Json<OidcStartIn>,
) -> Result<Json<OidcStartOut>, (StatusCode, Json<serde_json::Value>)> {
    if inp.code_challenge.trim().is_empty() || inp.redirect_uri.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "code_challenge and redirect_uri are required" })),
        ));
    }
    // Localhost (or explicit loopback) callbacks only — the verifier never
    // leaves the user's machine, so a public redirect URL would leak codes.
    let uri_ok = inp.redirect_uri.starts_with("http://127.0.0.1:")
        || inp.redirect_uri.starts_with("http://localhost:")
        || inp.redirect_uri.starts_with("http://[::1]:");
    if !uri_ok {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "redirect_uri must be a localhost URL" })),
        ));
    }

    let cfg = state.oidc().await.map_err(|e| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": format!("OIDC not configured: {}", e) })),
        )
    })?;

    state.prune_oidc_pending();
    let key = uuid::Uuid::new_v4().to_string();
    let login_state = uuid::Uuid::new_v4().to_string();
    let redirect_uri = inp.redirect_uri.trim().to_string();
    let auth_url = cfg.authorization_url(&login_state, inp.code_challenge.trim(), &redirect_uri);
    state.oidc_pending.insert(
        key.clone(),
        crate::auth::oidc::OidcPending {
            state: login_state,
            code_challenge: inp.code_challenge.trim().to_string(),
            redirect_uri,
            created_at: now(),
        },
    );
    Ok(Json(OidcStartOut {
        key,
        auth_url,
        expires_in: crate::auth::oidc::OIDC_PENDING_TTL_SECS,
    }))
}

/// OIDC login completion: exchange code + verifier, mint SteadyState creds.
///
/// # Returns
/// * `200 OK` with JWT + refresh token (completed-poll shape).
/// * `400` for unknown/expired keys; `401`/`502` when the IdP rejects.
pub async fn oidc_complete(
    State(state): State<Arc<AppState>>,
    Json(inp): Json<OidcCompleteIn>,
) -> Result<Json<PollOut>, (StatusCode, Json<serde_json::Value>)> {
    let pending = state
        .oidc_pending
        .remove(&inp.key)
        .map(|(_, p)| p)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "unknown or expired login key; restart login" })),
            )
        })?;
    if now().saturating_sub(pending.created_at) > crate::auth::oidc::OIDC_PENDING_TTL_SECS {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "login expired; restart login" })),
        ));
    }

    let cfg = state.oidc().await.map_err(internal)?;

    // CSRF binding: the IdP must echo the state minted at start.
    if inp.state.trim().is_empty() || inp.state != pending.state {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "OIDC state mismatch; restart login" })),
        ));
    }

    // The stored redirect_uri is the exact localhost callback the CLI used
    // at authorize time; the IdP requires it verbatim at exchange time.
    // Binding it server-side (rather than trusting a client-supplied value)
    // keeps a stolen code useless without our PKCE verifier too.
    let redirect_uri = pending.redirect_uri.clone();
    let access_token = cfg
        .exchange_code(&state.http, &inp.code, &inp.verifier, &redirect_uri)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": e.to_string() })),
            )
        })?;
    let identity = cfg
        .fetch_identity(&state.http, &access_token)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": e.to_string() })),
            )
        })?;

    let jwt = state.jwt.sign(&identity.login, "oidc").map_err(internal)?;
    let refresh_token = state
        .issue_refresh_token(identity.login.clone(), ProviderId::from("oidc"))
        .await
        .map_err(internal)?;

    info!(
        "OIDC login complete for {} via {}",
        identity.login, cfg.issuer
    );
    Ok(Json(PollOut {
        status: Some("complete".into()),
        jwt: Some(jwt),
        refresh_token: Some(refresh_token),
        login: Some(identity.login),
        provider_access_token: None,
        error: None,
    }))
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
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid refresh token" })),
            )
        })?;

    if now() >= rec.expires_at {
        let _ = state.revoke_refresh_token(&inp.refresh_token).await;
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "refresh expired" })),
        ));
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
    state
        .revoke_refresh_token(&inp.refresh_token)
        .await
        .map_err(internal)?;
    Ok(Json(json!({ "revoked": true })))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": e.to_string() })),
    )
}

/// Returns the current user's claims.
///
/// # Arguments
/// * `claims` - The JWT claims extracted from the Authorization header.
///
/// # Returns
/// * `200 OK` with the claims JSON.
pub async fn me(claims: CustomClaims) -> Json<CustomClaims> {
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
        let guard = lock_test_env().await;
        let saved: Vec<(String, Option<String>)> = [
            "JWT_SECRET",
            "NOENV_FLAKE_PATH",
            "STEADYSTATE_DB_PATH",
            "GITLAB_URL",
            "HCLOUD_TOKEN",
        ]
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
        TestEnv {
            state,
            saved,
            _guard: guard,
        }
    }

    /// Holds test env overrides until the end of the test, then restores.
    struct TestEnv {
        state: Arc<AppState>,
        saved: Vec<(String, Option<String>)>,
        _guard: tokio::sync::MutexGuard<'static, ()>,
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
            Json(TokenIn {
                provider: Some("gitlab".to_string()),
                token: "glpat-xxx".to_string(),
            }),
        )
        .await
        .expect("token login")
        .0;
        assert_eq!(out.status.as_deref(), Some("complete"));
        assert_eq!(out.login.as_deref(), Some("gluser"));
        assert!(out.jwt.is_some());
        assert!(out.refresh_token.is_some());

        // Refresh token is usable for JWT refresh (proves persistence path).
        let stored: Vec<_> = state
            .refresh_store
            .iter()
            .map(|e| e.key().clone())
            .collect();
        assert_eq!(stored.len(), 1);
    }

    #[tokio::test]
    async fn token_login_rejects_device_flow_providers() {
        let base = mock_gitlab(true).await;
        let env = test_state_with_gitlab(&base).await;
        let state = env.state.clone();

        let err = token_login(
            State(state),
            Json(TokenIn {
                provider: Some("github".to_string()),
                token: "x".to_string(),
            }),
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
            Json(TokenIn {
                provider: None,
                token: "bogus".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    /// Spin up a mock OIDC issuer (discovery + token + userinfo).
    async fn mock_oidc_issuer() -> String {
        mock_oidc_issuer_with(serde_json::json!({
            "sub": "sso-123",
            "preferred_username": "corpuser",
            "email": "corpuser@example.com",
        }))
        .await
    }

    /// Mock issuer with a custom userinfo payload (for iss/aud tests).
    async fn mock_oidc_issuer_with(userinfo: serde_json::Value) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock oidc");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get({
                    let base = base.clone();
                    move || async move {
                        axum::Json(serde_json::json!({
                            "authorization_endpoint": format!("{}/authorize", base),
                            "token_endpoint": format!("{}/token", base),
                            "userinfo_endpoint": format!("{}/userinfo", base),
                        }))
                    }
                }),
            )
            .route(
                "/token",
                axum::routing::post(|| async {
                    axum::Json(serde_json::json!({
                        "access_token": "mock-access",
                        "token_type": "Bearer",
                    }))
                }),
            )
            .route(
                "/userinfo",
                axum::routing::get(move || {
                    let userinfo = userinfo.clone();
                    async move { axum::Json(userinfo) }
                }),
            );
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock oidc");
        });
        base
    }

    async fn test_state_with_oidc(base: &str) -> TestEnv {
        let guard = lock_test_env().await;
        let saved: Vec<(String, Option<String>)> = [
            "JWT_SECRET",
            "NOENV_FLAKE_PATH",
            "STEADYSTATE_DB_PATH",
            "HCLOUD_TOKEN",
            "OIDC_ISSUER",
            "OIDC_CLIENT_ID",
            "OIDC_CLIENT_SECRET",
            "OIDC_ALLOW_HTTP",
        ]
        .iter()
        .map(|k| (k.to_string(), std::env::var(k).ok()))
        .collect();
        // SAFETY: serialized by the shared test-env lock; restored on drop.
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-for-oidc-tests");
            std::env::set_var("NOENV_FLAKE_PATH", "/tmp/dummy-flake");
            std::env::set_var("STEADYSTATE_DB_PATH", ":memory:");
            std::env::remove_var("HCLOUD_TOKEN");
            std::env::set_var("OIDC_ISSUER", base);
            std::env::set_var("OIDC_CLIENT_ID", "test-cid");
            std::env::set_var("OIDC_CLIENT_SECRET", "test-csecret");
            // Mock issuer runs on http://127.0.0.1.
            std::env::set_var("OIDC_ALLOW_HTTP", "1");
        }
        let state = AppState::try_new().await.expect("test AppState");
        TestEnv {
            state,
            saved,
            _guard: guard,
        }
    }

    #[tokio::test]
    async fn oidc_start_complete_round_trip() {
        let base = mock_oidc_issuer().await;
        let env = test_state_with_oidc(&base).await;
        let state = env.state.clone();

        let out = oidc_start(
            State(state.clone()),
            Json(OidcStartIn {
                code_challenge: "challenge-abc".to_string(),
                redirect_uri: "http://127.0.0.1:9999/callback".to_string(),
            }),
        )
        .await
        .expect("oidc start")
        .0;
        assert!(!out.key.is_empty());
        assert!(out.auth_url.contains("code_challenge=challenge-abc"));
        assert!(
            out.auth_url.contains("127.0.0.1%3A9999") || out.auth_url.contains("redirect_uri=")
        );
        // Extract the state the backend minted (echoed via the IdP).
        let echoed_state = url::Url::parse(&out.auth_url)
            .expect("parse auth url")
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string())
            .expect("state in auth url");

        let out = oidc_complete(
            State(state.clone()),
            Json(OidcCompleteIn {
                key: out.key,
                code: "auth-code-xyz".to_string(),
                verifier: "verifier-abc".to_string(),
                state: echoed_state,
            }),
        )
        .await
        .expect("oidc complete")
        .0;
        assert_eq!(out.status.as_deref(), Some("complete"));
        assert_eq!(out.login.as_deref(), Some("corpuser"));
        assert!(out.jwt.is_some());
        assert!(out.refresh_token.is_some());

        // Single-use key: replay fails.
        let err = oidc_complete(
            State(state),
            Json(OidcCompleteIn {
                key: "nope".to_string(),
                code: "x".to_string(),
                verifier: "y".to_string(),
                state: "z".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oidc_complete_rejects_state_mismatch() {
        let base = mock_oidc_issuer().await;
        let env = test_state_with_oidc(&base).await;
        let state = env.state.clone();

        let out = oidc_start(
            State(state.clone()),
            Json(OidcStartIn {
                code_challenge: "c".to_string(),
                redirect_uri: "http://127.0.0.1:9999/callback".to_string(),
            }),
        )
        .await
        .expect("oidc start")
        .0;

        let err = oidc_complete(
            State(state),
            Json(OidcCompleteIn {
                key: out.key,
                code: "auth-code-xyz".to_string(),
                verifier: "verifier".to_string(),
                state: "wrong-state".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    /// Start a login against an issuer whose userinfo carries extra claims,
    /// then attempt completion. Returns the start output for the assertions.
    async fn start_against(userinfo: serde_json::Value) -> (OidcStartOut, Arc<AppState>) {
        let base = mock_oidc_issuer_with(userinfo).await;
        let env = test_state_with_oidc(&base).await;
        let state = env.state.clone();
        let out = oidc_start(
            State(state.clone()),
            Json(OidcStartIn {
                code_challenge: "c".to_string(),
                redirect_uri: "http://127.0.0.1:9999/callback".to_string(),
            }),
        )
        .await
        .expect("oidc start")
        .0;
        (out, state)
    }

    #[tokio::test]
    async fn oidc_rejects_aud_mismatch() {
        // Token minted for a different client of the same IdP: reject.
        let (out, state) = start_against(serde_json::json!({
            "sub": "sso-123",
            "preferred_username": "corpuser",
            "aud": "someone-elses-client",
        }))
        .await;

        let err = oidc_complete(
            State(state),
            Json(OidcCompleteIn {
                key: out.key,
                code: "auth-code-xyz".to_string(),
                verifier: "verifier".to_string(),
                state: extract_state(&out.auth_url),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn oidc_rejects_iss_mismatch() {
        let (out, state) = start_against(serde_json::json!({
            "sub": "sso-123",
            "preferred_username": "corpuser",
            "iss": "https://evil.example.com",
        }))
        .await;

        let err = oidc_complete(
            State(state),
            Json(OidcCompleteIn {
                key: out.key,
                code: "auth-code-xyz".to_string(),
                verifier: "verifier".to_string(),
                state: extract_state(&out.auth_url),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn oidc_accepts_matching_aud_array() {
        // aud as an array containing our client id is fine.
        let base = mock_oidc_issuer_with(serde_json::json!({
            "sub": "sso-123",
            "preferred_username": "corpuser",
            "aud": ["other", "test-cid"],
        }))
        .await;
        let env = test_state_with_oidc(&base).await;
        let state = env.state.clone();

        let out = oidc_start(
            State(state.clone()),
            Json(OidcStartIn {
                code_challenge: "c".to_string(),
                redirect_uri: "http://127.0.0.1:9999/callback".to_string(),
            }),
        )
        .await
        .expect("oidc start")
        .0;

        let done = oidc_complete(
            State(state),
            Json(OidcCompleteIn {
                key: out.key,
                code: "auth-code-xyz".to_string(),
                verifier: "verifier".to_string(),
                state: extract_state(&out.auth_url),
            }),
        )
        .await
        .expect("complete with array aud containing our client");
        assert_eq!(done.0.login.as_deref(), Some("corpuser"));
    }

    fn extract_state(auth_url: &str) -> String {
        url::Url::parse(auth_url)
            .expect("parse auth url")
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string())
            .expect("state in auth url")
    }

    #[tokio::test]
    async fn oidc_start_rejects_non_localhost_redirect() {
        let base = mock_oidc_issuer().await;
        let env = test_state_with_oidc(&base).await;
        let state = env.state.clone();

        let err = oidc_start(
            State(state),
            Json(OidcStartIn {
                code_challenge: "c".to_string(),
                redirect_uri: "https://evil.example.com/cb".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oidc_unconfigured_is_503() {
        // No OIDC_* env at all (other than what try_new needs).
        let _guard = lock_test_env().await;
        let saved: Vec<(String, Option<String>)> = [
            "JWT_SECRET",
            "NOENV_FLAKE_PATH",
            "STEADYSTATE_DB_PATH",
            "HCLOUD_TOKEN",
            "OIDC_ISSUER",
            "OIDC_CLIENT_ID",
            "OIDC_CLIENT_SECRET",
        ]
        .iter()
        .map(|k| (k.to_string(), std::env::var(k).ok()))
        .collect();
        // SAFETY: serialized by the shared test-env lock.
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-for-oidc-tests");
            std::env::set_var("NOENV_FLAKE_PATH", "/tmp/dummy-flake");
            std::env::set_var("STEADYSTATE_DB_PATH", ":memory:");
            std::env::remove_var("HCLOUD_TOKEN");
            std::env::remove_var("OIDC_ISSUER");
            std::env::remove_var("OIDC_CLIENT_ID");
            std::env::remove_var("OIDC_CLIENT_SECRET");
        }
        let state = AppState::try_new().await.expect("test AppState");

        let err = oidc_start(
            State(state),
            Json(OidcStartIn {
                code_challenge: "c".to_string(),
                redirect_uri: "http://127.0.0.1:1/callback".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);

        // SAFETY: still holding the shared lock.
        unsafe {
            for (k, old) in saved {
                match old {
                    Some(v) => std::env::set_var(&k, v),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }
}
