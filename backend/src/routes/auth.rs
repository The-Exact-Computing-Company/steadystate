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
        _device_code: start.device_code.clone(),
        _user_code: start.user_code.clone(),
        _verification_uri: start.verification_uri.clone(),
        _interval: start.interval,
        _created_at: now(),
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

            if let Some(token) = provider_access_token {
                state.provider_tokens.insert(
                    (identity.provider.clone(), identity.login.clone()),
                    token
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
                error: None,
            }))
        }
        Ok(DevicePollOutcome::Pending) => {
            info!("poll pending for provider '{}'", provider_id.as_str());
            Ok(Json(PollOut {
                status: Some("pending".into()),
                jwt: None, refresh_token: None, login: None,
                error: None,
            }))
        },
        Ok(DevicePollOutcome::SlowDown) => {
            info!("poll slow_down for provider '{}'", provider_id.as_str());
            Ok(Json(PollOut {
                status: Some("pending".into()),
                jwt: None, refresh_token: None, login: None,
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
                error: Some(e.to_string()),
            }))
        }
    }
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
        state.refresh_store.remove(&inp.refresh_token);
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
    state.refresh_store.remove(&inp.refresh_token);
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
