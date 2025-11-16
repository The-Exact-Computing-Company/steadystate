// backend/src/routes/auth.rs

use axum::{
    extract::{Query, State},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use tracing::{info, warn};

use crate::{
    models::*,
    state::AppState,
};


pub fn router() -> Router<std::sync::Arc<AppState>> {
    Router::new()
        .route("/device", post(device_start))
        .route("/poll", post(poll))
        .route("/refresh", post(refresh))
        .route("/revoke", post(revoke))
        .route("/me", get(me))
}

pub async fn device_start(
    State(state): State<std::sync::Arc<AppState>>,
    Query(q): Query<DeviceQuery>,
) -> Result<Json<DeviceStartResponse>, (axum::http::StatusCode, String)> {
    let provider_name = q.provider.as_deref().and_then(ProviderName::parse)
        .unwrap_or(ProviderName::GitHub);
    
    // Lazily get or create the provider. This is the key change.
    let provider = state.get_or_create_provider(provider_name)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;

    let start = provider.start_device_flow().await
        .map_err(internal)?;

    state.device_pending.insert(start.device_code.clone(), PendingDevice {
        provider: provider_name,
        device_code: start.device_code.clone(),
        user_code: start.user_code.clone(),
        verification_uri: start.verification_uri.clone(),
        interval: start.interval,
        created_at: now(),
    });

    Ok(Json(start))
}

pub async fn poll(
    State(state): State<std::sync::Arc<AppState>>,
    Json(q): Json<PollQuery>,
) -> Result<Json<PollOut>, (axum::http::StatusCode, String)> {
    let entry = match state.device_pending.get(&q.device_code) {
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

    let provider_name = entry.provider;
    // Release the read guard before we potentially mutate the map.
    drop(entry);
    
    // Lazily get the provider again. It should be cached now.
    let provider = match state.get_or_create_provider(provider_name) {
        Ok(p) => p,
        Err(e) => return Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };

    // Try to exchange device_code for identity.
    match provider.poll_device_flow(&q.device_code).await {
        Ok(identity) => {
            info!(
                "device flow complete for {} via {}",
                identity.login,
                provider_name.as_str()
            );

            state.device_pending.remove(&q.device_code);

            let jwt = state
                .jwt
                .sign(&identity.login, provider_name.as_str())
                .map_err(internal)?;
            let refresh_token = state.issue_refresh_token(identity.login.clone(), provider_name);

            Ok(Json(PollOut {
                status: Some("complete".into()),
                jwt: Some(jwt),
                refresh_token: Some(refresh_token),
                login: Some(identity.login),
                error: None,
            }))
        }
        Err(e) => {
            let msg = e.to_string();
            let lower = msg.to_lowercase();

            if lower.contains("authorization_pending") ||
                lower.contains("authorization request is still pending") {
                    return Ok(Json(PollOut {
                        status: Some("pending".into()),
                        jwt: None, refresh_token: None, login: None,
                        error: None,
                    }));
                }

            if lower.contains("slow_down") {
                return Ok(Json(PollOut {
                    status: Some("pending".into()),
                    jwt: None, refresh_token: None, login: None,
                    error: Some("slow_down".into()),
                }));
            }

            warn!("poll error: {msg}");
            Ok(Json(PollOut {
                status: None,
                jwt: None,
                refresh_token: None,
                login: None,
                error: Some(msg),
            }))
        }
    }
}


pub async fn refresh(
    State(state): State<std::sync::Arc<AppState>>,
    Json(inp): Json<RefreshIn>,
) -> Result<Json<RefreshOut>, (axum::http::StatusCode, String)> {
    let Some(rec) = state
        .refresh_store
        .get(&inp.refresh_token)
        .map(|e| e.clone())
    else {
        return Err((
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid refresh token".into(),
        ));
    };

    if now() >= rec.expires_at {
        state.refresh_store.remove(&inp.refresh_token);
        return Err((
            axum::http::StatusCode::UNAUTHORIZED,
            "refresh expired".into(),
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


pub async fn revoke(
    State(state): State<std::sync::Arc<AppState>>,
    Json(inp): Json<RevokeIn>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    state.refresh_store.remove(&inp.refresh_token);
    Ok(Json(json!({ "revoked": true })))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn internal<E: std::fmt::Display>(e: E) -> (axum::http::StatusCode, String) {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

pub async fn me(
    State(state): State<std::sync::Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {

    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or((axum::http::StatusCode::UNAUTHORIZED, "Missing Authorization header".into()))?
        .to_str()
        .map_err(|_| (axum::http::StatusCode::BAD_REQUEST, "Invalid Authorization header".into()))?;

    if !auth.starts_with("Bearer ") {
        return Err((axum::http::StatusCode::BAD_REQUEST, "Expected Bearer token".into()));
    }

    let token = &auth["Bearer ".len()..];

    let claims = state
        .jwt
        .verify(token)
        .map_err(|e| (axum::http::StatusCode::UNAUTHORIZED, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "login": claims.sub,
        "provider": claims.provider,
        "issuer": claims.iss,
        "exp": claims.exp,
    })))
}
