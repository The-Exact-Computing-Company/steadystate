// backend/src/rate_limit.rs
//
// Per-IP rate limiting for the auth API via tower_governor.
//
// Tiers (requests/minute per client IP, replenished steadily):
// - token endpoints (POST /auth/token): strict — PATs are bearer secrets
//   and this route is otherwise an unthrottled validation oracle.
// - device flow (POST /auth/device, POST /auth/poll): moderate — poll
//   loops legitimately hit /poll every few seconds.
// - everything else under /auth: lenient.
//
// Any tier can be disabled by setting its env var to 0 (useful in tests).
// Limits are approximate token-bucket tiers, not exact fixed windows.
//
// NOTE on keying: by default, keys are peer IPs (ConnectInfo). Behind a
// reverse proxy every client shares the proxy's IP unless you set
// `RATE_LIMIT_TRUST_FORWARDED`, which switches to the `Forwarded` /
// `X-Forwarded-For` / `X-Real-IP` headers. ONLY enable that when a trusted
// proxy in front of the backend strips or overwrites those headers on
// client traffic — otherwise clients can spoof header-based keys and
// sidestep the per-IP limits entirely.

use std::sync::Arc;

use axum::Router;
use tower_governor::{
    GovernorError, governor::GovernorConfigBuilder, key_extractor::PeerIpKeyExtractor,
};

use crate::state::AppState;

pub const DEFAULT_TOKEN_PER_MIN: u64 = 5;
pub const DEFAULT_AUTH_PER_MIN: u64 = 30;
pub const DEFAULT_GENERAL_PER_MIN: u64 = 120;

fn env_per_min(name: &str, def: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(def)
}

/// Whether to key rate limits on proxy-forwarded client IPs instead of the
/// peer address. Only safe behind a proxy that controls those headers.
pub fn trust_forwarded() -> bool {
    matches!(
        std::env::var("RATE_LIMIT_TRUST_FORWARDED")
            .unwrap_or_default()
            .to_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    )
}

pub fn token_per_min() -> u64 {
    env_per_min("RATE_LIMIT_TOKEN_PER_MIN", DEFAULT_TOKEN_PER_MIN)
}

pub fn auth_per_min() -> u64 {
    env_per_min("RATE_LIMIT_AUTH_PER_MIN", DEFAULT_AUTH_PER_MIN)
}

pub fn general_per_min() -> u64 {
    env_per_min("RATE_LIMIT_DEFAULT_PER_MIN", DEFAULT_GENERAL_PER_MIN)
}

fn json_error_handler(err: GovernorError) -> axum::response::Response {
    use axum::response::IntoResponse;
    let (status, msg, wait) = match err {
        GovernorError::TooManyRequests { wait_time, .. } => (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            format!("rate limited, retry in {}s", wait_time),
            Some(wait_time),
        ),
        other => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            other.to_string(),
            None,
        ),
    };
    let mut resp = (status, axum::Json(serde_json::json!({ "error": msg }))).into_response();
    if let Some(w) = wait
        && let Ok(v) = w.to_string().parse()
    {
        resp.headers_mut().insert("retry-after", v);
    }
    resp
}

/// Apply a ~`per_min` requests/minute per-IP limit to a router.
/// `per_min == 0` disables the tier (router returned unchanged).
fn limit(router: Router<Arc<AppState>>, per_min: u64) -> Router<Arc<AppState>> {
    if per_min == 0 {
        return router;
    }
    // One token every 60/per_min seconds, bucket capacity = per_min.
    let period_ms = (60_000 / per_min).max(1);
    let burst = per_min.min(u32::MAX as u64) as u32;

    if trust_forwarded() {
        use tower_governor::key_extractor::SmartIpKeyExtractor;
        let config = Arc::new(
            GovernorConfigBuilder::default()
                .key_extractor(SmartIpKeyExtractor)
                .per_millisecond(period_ms)
                .burst_size(burst.max(1))
                .error_handler(json_error_handler)
                .finish()
                .expect("non-zero governor period and burst"),
        );
        router.layer(tower_governor::GovernorLayer { config })
    } else {
        let config = Arc::new(
            GovernorConfigBuilder::default()
                .per_millisecond(period_ms)
                .burst_size(burst.max(1))
                .key_extractor(PeerIpKeyExtractor)
                .error_handler(json_error_handler)
                .finish()
                .expect("non-zero governor period and burst"),
        );
        router.layer(tower_governor::GovernorLayer { config })
    }
}

/// Strict tier for POST /auth/token (env `RATE_LIMIT_TOKEN_PER_MIN`).
pub fn token_limit(router: Router<Arc<AppState>>) -> Router<Arc<AppState>> {
    limit(router, token_per_min())
}

/// Moderate tier for the device flow (env `RATE_LIMIT_AUTH_PER_MIN`).
pub fn auth_limit(router: Router<Arc<AppState>>) -> Router<Arc<AppState>> {
    limit(router, auth_per_min())
}

/// Lenient tier for refresh/revoke/me (env `RATE_LIMIT_DEFAULT_PER_MIN`).
pub fn general_limit(router: Router<Arc<AppState>>) -> Router<Arc<AppState>> {
    limit(router, general_per_min())
}
