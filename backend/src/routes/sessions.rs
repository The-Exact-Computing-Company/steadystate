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

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", post(create_session))
        .route("/:id", get(get_session_status))
        .route("/:id", delete(terminate_session))
}

/// The main async task that performs the long-running provisioning.
async fn run_provisioning(
    app_state: Arc<AppState>,
    session_id: String,
    request: SessionRequest,
) {
    let provider_id = {
        let session = app_state.sessions.get(&session_id).unwrap();
        session.compute_provider.clone()
    };

    let provider = app_state.compute_providers.get(&provider_id).unwrap().clone();

    // The actual work happens here.
    let result = {
        let mut session = app_state.sessions.get_mut(&session_id).unwrap();
        provider.start_session(&mut session, &request).await
    };

    // Update the session based on the result.
    if let Err(e) = result {
        tracing::error!("Provisioning failed for session {}: {:#}", session_id, e);
        let mut session = app_state.sessions.get_mut(&session_id).unwrap();
        session.state = SessionState::Failed;
        session.error_message = Some(format!("{:#}", e));
        session.updated_at = std::time::SystemTime::now();
    }
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    claims: CustomClaims,
    Json(request): Json<SessionRequest>,
) -> (StatusCode, Json<SessionInfo>) {
    let session_id = Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now();

    let session = Session {
        id: session_id.clone(),
        state: SessionState::Provisioning,
        repo_url: request.repo_url.clone(),
        branch: request.branch.clone(),
        environment: request.environment.clone(),
        endpoint: None,
        compute_provider: state.default_compute_provider.clone(),
        creator_login: claims.sub,
        created_at: now,
        updated_at: now,
        error_message: None,
    };

    let session_info = SessionInfo::from(&session);
    state.sessions.insert(session_id.clone(), session);

    // Spawn the background task to do the actual work.
    tokio::spawn(run_provisioning(state, session_id, request));

    (StatusCode::ACCEPTED, Json(session_info))
}

async fn get_session_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<SessionInfo>, StatusCode> {
    match state.sessions.get(&id) {
        Some(session) => Ok(Json(SessionInfo::from(&*session))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn terminate_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> StatusCode {
    if let Some(mut session) = state.sessions.get_mut(&id) {
        session.state = SessionState::Terminating;
        let provider = state.compute_providers.get(&session.compute_provider).unwrap().clone();
        
        // Spawn termination as a background task as well.
        let session_clone = session.clone();
        tokio::spawn(async move {
            if let Err(e) = provider.terminate_session(&session_clone).await {
                tracing::error!("Failed to terminate session {}: {:#}", id, e);
                // Optionally update session to Failed here.
            }
        });
        
        StatusCode::ACCEPTED
    } else {
        StatusCode::NOT_FOUND
    }
}
