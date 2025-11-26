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

pub async fn device_start(
    State(state): State<Arc<AppState>>,
    Query(q): Query<DeviceQuery>,
) -> Result<Json<DeviceStartResponse>, (StatusCode, String)> {
    let provider_id = ProviderId::from(q.provider.as_deref().unwrap_or("github"));

    let provider = state.get_or_create_provider(&provider_id).await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

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

pub async fn poll(
    State(state): State<Arc<AppState>>,
    Json(q): Json<PollQuery>,
) -> Result<Json<PollOut>, (StatusCode, String)> {
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
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
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
        Ok(DevicePollOutcome::Pending) => Ok(Json(PollOut {
            status: Some("pending".into()),
            jwt: None, refresh_token: None, login: None,
            error: None,
        })),
        Ok(DevicePollOutcome::SlowDown) => Ok(Json(PollOut {
            status: Some("pending".into()),
            jwt: None, refresh_token: None, login: None,
            error: Some("slow_down".into()),
        })),
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


pub async fn refresh(
    State(state): State<Arc<AppState>>,
    Json(inp): Json<RefreshIn>,
) -> Result<Json<RefreshOut>, (StatusCode, String)> {
    let rec = state
        .refresh_store
        .get(&inp.refresh_token)
        .map(|e| e.clone())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid refresh token".into()))?;

    if now() >= rec.expires_at {
        state.refresh_store.remove(&inp.refresh_token);
        return Err((StatusCode::UNAUTHORIZED, "refresh expired".into()));
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


pub async fn revoke(
    State(state): State<Arc<AppState>>,
    Json(inp): Json<RevokeIn>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    state.refresh_store.remove(&inp.refresh_token);
    Ok(Json(json!({ "revoked": true })))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("System time is before UNIX EPOCH").as_secs()
}

fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

pub async fn me(
    claims: CustomClaims,
) -> Json<CustomClaims> {
    Json(claims)
}
