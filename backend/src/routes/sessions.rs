// backend/src/routes/sessions.rs

use std::sync::Arc;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, delete},
    Json, Router,
};
use uuid::Uuid;
use serde_json::json;

use crate::{
    jwt::CustomClaims,
    models::{Session, SessionInfo, SessionRequest, SessionState},
    state::AppState,
};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", post(create_session))
        .route("/{id}", get(get_session_status))
        .route("/{id}", delete(terminate_session))
}

async fn run_provisioning(
    app_state: Arc<AppState>,
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

    // 3. Do the work (release lock first!)
    // We clone request data needed for provisioning if necessary, but here we pass the whole request.
    
    // Release the lock by not holding a reference to session_entry across the await point.
    // We already have provider_id and provider.
    
    let result = provider.start_session(&session_id, &request).await;

    // 4. Handle result
    if let Some(mut session) = app_state.sessions.get_mut(&session_id) {
        match result {
            Ok(start_result) => {
                session.state = SessionState::Running;
                session.endpoint = start_result.endpoint;
                session.magic_link = start_result.magic_link;
                session.host_public_key = start_result.host_public_key;
                session.updated_at = std::time::SystemTime::now();
                tracing::info!("Session {} provisioned successfully", session_id);
            }
            Err(e) => {
                tracing::error!("Provisioning failed for session {}: {:#}", session_id, e);
                session.state = SessionState::Failed;
                session.error_message = Some(format!("{:#}", e));
                session.updated_at = std::time::SystemTime::now();
            }
        }
    } else {
        tracing::warn!("Session {} disappeared after provisioning", session_id);
    }
}

/// Creates a new session.
///
/// # Arguments
/// * `state` - The application state.
/// * `claims` - The JWT claims of the user creating the session.
/// * `request` - JSON body containing session details (repo URL, branch, etc.).
///
/// # Returns
/// * `202 Accepted` with the initial session info.
async fn create_session(
    State(state): State<Arc<AppState>>,
    claims: CustomClaims,
    Json(mut request): Json<SessionRequest>,
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
        creator_login: claims.sub.clone(),
        created_at: now,
        updated_at: now,
        error_message: None,
        magic_link: None,
        host_public_key: None,
    };

    let session_info = SessionInfo::from(&session);
    
    state.sessions.insert(session_id.clone(), session);
    tracing::info!("Session {} inserted into map, total sessions: {}", session_id, state.sessions.len());

    // --- Inject GitHub token if available ---
    if claims.provider == "github" {
        if let Some(token) = state
            .provider_tokens
            .get(&("github".to_string(), claims.sub.clone()))
        {
            request.provider_config = Some(serde_json::json!({
                "github": {
                    "login": claims.sub,
                    "access_token": token.value().clone(),
                }
            }));
        }
    }

    // state is cheap to clone now
    tokio::spawn(run_provisioning(state.clone(), session_id, request));

    (StatusCode::ACCEPTED, Json(session_info))
}

/// Retrieves the status of a session.
///
/// # Arguments
/// * `state` - The application state.
/// * `id` - The session ID.
///
/// # Returns
/// * `200 OK` with the session info.
/// * `404 Not Found` if the session does not exist.
async fn get_session_status(
    State(state): State<Arc<AppState>>,
    _claims: CustomClaims,
    Path(id): Path<String>,
) -> Result<Json<SessionInfo>, (StatusCode, Json<serde_json::Value>)> {
    tracing::info!("GET /sessions/{}, total sessions in map: {}", id, state.sessions.len());
    match state.sessions.get(&id) {
        Some(session) => {
            tracing::info!("Found session {} in state {:?}", id, session.state);
            Ok(Json(SessionInfo::from(&*session)))
        }
        None => {
            tracing::warn!("Session {} not found in map", id);
            Err((StatusCode::NOT_FOUND, Json(json!({ "error": "Session not found" }))))
        }
    }
}

/// Terminates a session.
///
/// # Arguments
/// * `state` - The application state.
/// * `id` - The session ID.
///
/// # Returns
/// * `202 Accepted` if termination was initiated.
/// * `404 Not Found` if the session does not exist.
async fn terminate_session(
    State(state): State<Arc<AppState>>,
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
