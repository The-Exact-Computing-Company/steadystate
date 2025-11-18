// backend/src/routes/sessions.rs

use std::sync::Arc;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, delete},
    Json, Router,
};
use uuid::Uuid;

use crate::{
    jwt::CustomClaims,
    models::{Session, SessionInfo, SessionRequest, SessionState},
    state::AppState,
};

// --- CHANGE IS HERE ---
// The router should not have a state generic. It will be added in `main.rs`.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", post(create_session))
        .route("/:id", get(get_session_status))
        .route("/:id", delete(terminate_session))
}
// ... (rest of the file is unchanged)
