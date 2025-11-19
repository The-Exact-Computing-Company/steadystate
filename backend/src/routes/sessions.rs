// backend/src/routes/sessions.rs

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
    compute::ComputeProvider,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_session))
        .route("/{id}", get(get_session_status))
        .route("/{id}", delete(terminate_session))
}

async fn run_provisioning(
    app_state: AppState,
    session_id: String,
    request: SessionRequest,
) {
    // 1. Retrieve the provider ID
    let provider_id = if let Some(session) = app_state.sessions.get(&session_id) {
        session.compute_provider.clone()
    } else {
        return; 
    };

    // 2. Get the provider (map is now wrapped in Arc, so access is cheap)
    let provider = if let Some(p) = app_state.compute_providers.get(&provider_id) {
        p.clone()
    } else {
        tracing::error!("Provider '{}' not found", provider_id);
        return;
    };

    // 3. Do the work
    let result = if let Some(mut session_entry) = app_state.sessions.get_mut(&session_id) {
        provider.start_session(&mut session_entry, &request).await
    } else {
        return;
    };

    // 4. Handle failure
    if let Err(e) = result {
        tracing::error!("Provisioning failed for session {}: {:#}", session_id, e);
        if let Some(mut session) = app_state.sessions.get_mut(&session_id) {
            session.state = SessionState::Failed;
            session.error_message = Some(format!("{:#}", e));
            session.updated_at = std::time::SystemTime::now();
        }
    }
}

async fn create_session(
    State(state): State<AppState>,
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
        // FIX IS HERE: Access default_compute_provider via config
        compute_provider: state.config.default_compute_provider.clone(),
        creator_login: claims.sub,
        created_at: now,
        updated_at: now,
        error_message: None,
    };

    let session_info = SessionInfo::from(&session);
    
    state.sessions.insert(session_id.clone(), session);

    // state is cheap to clone now
    tokio::spawn(run_provisioning(state.clone(), session_id, request));

    (StatusCode::ACCEPTED, Json(session_info))
}

async fn get_session_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SessionInfo>, StatusCode> {
    match state.sessions.get(&id) {
        Some(session) => Ok(Json(SessionInfo::from(&*session))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn terminate_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> StatusCode {
    if let Some(mut session) = state.sessions.get_mut(&id) {
        session.state = SessionState::Terminating;
        
        if let Some(provider) = state.compute_providers.get(&session.compute_provider) {
            let provider = provider.clone();
            let session_clone = session.clone();
            
            tokio::spawn(async move {
                if let Err(e) = provider.terminate_session(&session_clone).await {
                    tracing::error!("Failed to terminate session {}: {:#}", id, e);
                }
            });
        }
        StatusCode::ACCEPTED
    } else {
        StatusCode::NOT_FOUND
    }
}
