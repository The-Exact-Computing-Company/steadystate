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
        drop(session);
        app_state.persist_session(&session_id);
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

    let requested_provider = request.provider.clone()
        .map(|p| p.trim().to_lowercase())
        .filter(|p| !p.is_empty());
    let compute_provider = match requested_provider {
        Some(p) if state.compute_providers.contains_key(&p) => p,
        Some(p) => {
            tracing::warn!("Unknown compute provider '{}', falling back to '{}'", p, state.config.default_compute_provider);
            state.config.default_compute_provider.clone()
        }
        None => state.config.default_compute_provider.clone(),
    };

    // Per-user live-session cap (cost control, chiefly for cloud providers).
    // A cap of 0 disables the limit.
    if state.config.max_sessions_per_user > 0
        && state.live_session_count(&claims.sub) >= state.config.max_sessions_per_user
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(SessionInfo {
                id: String::new(),
                state: SessionState::Failed,
                endpoint: None,
                compute_provider: None,
                message: Some(format!(
                    "Session limit reached ({} live sessions). Terminate one with DELETE /sessions/{{id}} first.",
                    state.config.max_sessions_per_user
                )),
                magic_link: None,
                host_public_key: None,
                expires_at: None,
            }),
        );
    }

    let ttl = state.session_ttl(request.ttl_secs);
    let expires_at = now + std::time::Duration::from_secs(ttl);
    tracing::info!(
        "Session {} requested ttl {:?}, granted {}s",
        session_id,
        request.ttl_secs,
        ttl
    );

    let session = Session {
        id: session_id.clone(),
        state: SessionState::Provisioning,
        repo_url: request.repo_url.clone(),
        branch: request.branch.clone(),
        environment: request.environment.clone(),
        endpoint: None,
        compute_provider,
        creator_login: claims.sub.clone(),
        created_at: now,
        updated_at: now,
        error_message: None,
        magic_link: None,
        host_public_key: None,
        expires_at: Some(expires_at),
    };

    let session_info = SessionInfo::from(&session);
    
    state.sessions.insert(session_id.clone(), session);
    state.persist_session(&session_id);
    tracing::info!("Session {} inserted into map, total sessions: {}", session_id, state.sessions.len());

    // --- Inject the caller's forge token (github PAT/OAuth or gitlab PAT) ---
    // Keyed by the JWT's provider claim, so any auth provider works here.
    if let Some(token) = state
        .provider_tokens
        .get(&(claims.provider.clone(), claims.sub.clone()))
    {
        let mut creds = serde_json::Map::new();
        creds.insert("login".to_string(), serde_json::Value::String(claims.sub.clone()));
        creds.insert(
            "access_token".to_string(),
            serde_json::Value::String(token.value().clone()),
        );
        let mut outer = serde_json::Map::new();
        outer.insert(claims.provider.clone(), serde_json::Value::Object(creds));
        request.provider_config = Some(serde_json::Value::Object(outer));
    }

    // state is cheap to clone now
    tokio::spawn(run_provisioning(state.clone(), session_id, request));

    (StatusCode::ACCEPTED, Json(session_info))
}

/// Retrieves the status of a session.
///
/// Any authenticated user may poll lifecycle state, but only the creator
/// sees connection secrets (`endpoint`, `magic_link`, `host_public_key`).
/// Joining uses the out-of-band magic link directly, so redaction breaks
/// no collaborator flow.
///
/// # Arguments
/// * `state` - The application state.
/// * `claims` - The JWT claims of the caller.
/// * `id` - The session ID.
///
/// # Returns
/// * `200 OK` with the session info (redacted for non-creators).
/// * `404 Not Found` if the session does not exist.
async fn get_session_status(
    State(state): State<Arc<AppState>>,
    claims: CustomClaims,
    Path(id): Path<String>,
) -> Result<Json<SessionInfo>, (StatusCode, Json<serde_json::Value>)> {
    tracing::info!("GET /sessions/{}, total sessions in map: {}", id, state.sessions.len());
    match state.sessions.get(&id) {
        Some(session) => {
            tracing::info!("Found session {} in state {:?}", id, session.state);
            let info = SessionInfo::from(&*session);
            if session.creator_login == claims.sub {
                Ok(Json(info))
            } else {
                Ok(Json(info.redacted()))
            }
        }
        None => {
            tracing::warn!("Session {} not found in map", id);
            Err((StatusCode::NOT_FOUND, Json(json!({ "error": "Session not found" }))))
        }
    }
}

/// Terminates a session.
///
/// Requires a valid JWT, and only the session creator may terminate it.
///
/// # Arguments
/// * `state` - The application state.
/// * `claims` - The JWT claims of the caller.
/// * `id` - The session ID.
///
/// # Returns
/// * `202 Accepted` if termination was initiated.
/// * `403 Forbidden` if the caller did not create the session.
/// * `404 Not Found` if the session does not exist.
async fn terminate_session(
    State(state): State<Arc<AppState>>,
    claims: CustomClaims,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    // 404 first so session IDs are not enumerable via 403-vs-404.
    let creator = match state.sessions.get(&id) {
        Some(session) => session.creator_login.clone(),
        None => return Err((StatusCode::NOT_FOUND, Json(json!({ "error": "Session not found" })))),
    };
    if creator != claims.sub {
        return Err((StatusCode::FORBIDDEN, Json(json!({ "error": "Only the session creator can terminate it" }))));
    }

    terminate_inner(&state, &id).await
}

/// Shared termination core: mark Terminating, persist, and spawn provider
/// cleanup (which records Terminated/Failed on completion).
/// Used by DELETE (after the ownership check above) and by the reaper,
/// which needs no caller auth — expiry is server policy.
pub(crate) async fn terminate_inner(
    state: &Arc<AppState>,
    id: &str,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    if let Some(mut session) = state.sessions.get_mut(id) {
        session.state = SessionState::Terminating;
        session.updated_at = std::time::SystemTime::now();
        let session_clone = session.clone();
        let owned_id = id.to_string();
        drop(session);

        // Persist the Terminating state before spawning cleanup.
        state.persist_session(&owned_id);

        if let Some(provider) = state.compute_providers.get(&session_clone.compute_provider) {
            let provider = provider.clone();
            let bg_state = state.clone();
            tokio::spawn(async move {
                match provider.terminate_session(&session_clone).await {
                    Ok(()) => {
                        if let Some(mut s) = bg_state.sessions.get_mut(&owned_id) {
                            s.state = SessionState::Terminated;
                            s.updated_at = std::time::SystemTime::now();
                        }
                        bg_state.persist_session(&owned_id);
                    }
                    Err(e) => {
                        tracing::error!("Failed to terminate session {}: {:#}", owned_id, e);
                        if let Some(mut s) = bg_state.sessions.get_mut(&owned_id) {
                            s.state = SessionState::Failed;
                            s.error_message = Some(format!("terminate failed: {:#}", e));
                            s.updated_at = std::time::SystemTime::now();
                        }
                        bg_state.persist_session(&owned_id);
                    }
                }
            });
        }
        Ok(StatusCode::ACCEPTED)
    } else {
        Err((StatusCode::NOT_FOUND, Json(json!({ "error": "Session not found" }))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Session;
    use crate::state::lock_test_env;

    /// Minimal AppState for route tests: in-memory SQLite, dummy secrets.
    /// Env is saved, overridden, and restored under the shared test lock,
    /// so parallel env-mutating tests cannot observe intermediate values.
    async fn test_state() -> Arc<AppState> {
        let _guard = lock_test_env();
        let saved: Vec<(String, Option<String>)> = [
            "JWT_SECRET",
            "NOENV_FLAKE_PATH",
            "STEADYSTATE_DB_PATH",
            "HCLOUD_TOKEN",
            "STEADYSTATE_DEFAULT_SESSION_TTL_SECS",
            "STEADYSTATE_MAX_SESSION_TTL_SECS",
            "STEADYSTATE_MAX_SESSIONS_PER_USER",
        ]
            .iter()
            .map(|k| (k.to_string(), std::env::var(k).ok()))
            .collect();
        // SAFETY: serialized by the shared test-env lock.
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-for-route-tests");
            std::env::set_var("NOENV_FLAKE_PATH", "/tmp/dummy-flake");
            std::env::set_var("STEADYSTATE_DB_PATH", ":memory:");
            std::env::remove_var("HCLOUD_TOKEN");
            std::env::set_var("STEADYSTATE_DEFAULT_SESSION_TTL_SECS", "3600");
            std::env::set_var("STEADYSTATE_MAX_SESSION_TTL_SECS", "7200");
            std::env::set_var("STEADYSTATE_MAX_SESSIONS_PER_USER", "2");
        }
        let state = AppState::try_new().await.expect("test AppState");
        // SAFETY: still holding the shared lock; nothing after try_new reads env.
        unsafe {
            for (k, old) in saved {
                match old {
                    Some(v) => std::env::set_var(&k, v),
                    None => std::env::remove_var(&k),
                }
            }
        }
        state
    }

    fn seed_session(state: &Arc<AppState>, id: &str, creator: &str) {
        let now = std::time::SystemTime::now();
        state.sessions.insert(id.to_string(), Session {
            id: id.to_string(),
            state: SessionState::Running,
            repo_url: "https://github.com/user/repo".to_string(),
            branch: None,
            environment: None,
            endpoint: Some("ssh://steady@host:2222".to_string()),
            compute_provider: "local".to_string(),
            creator_login: creator.to_string(),
            created_at: now,
            updated_at: now,
            error_message: None,
            magic_link: Some("steadystate://collab/sess?ssh=x".to_string()),
            host_public_key: Some("ssh-ed25519 AAAA".to_string()),
            expires_at: None,
        });
    }

    fn claims(login: &str) -> CustomClaims {
        CustomClaims { sub: login.to_string(), provider: "github".to_string() }
    }

    #[tokio::test]
    async fn terminate_unknown_id_is_404() {
        let state = test_state().await;
        let err = terminate_session(State(state), claims("alice"), Path("nope".to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn terminate_non_creator_is_403_and_keeps_session() {
        let state = test_state().await;
        seed_session(&state, "sess-1", "alice");
        let err = terminate_session(State(state.clone()), claims("bob"), Path("sess-1".to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        let s = state.sessions.get("sess-1").unwrap();
        assert_eq!(s.state, SessionState::Running);
    }

    #[tokio::test]
    async fn terminate_creator_is_accepted_then_terminated() {
        let state = test_state().await;
        seed_session(&state, "sess-2", "alice");
        let status = terminate_session(State(state.clone()), claims("alice"), Path("sess-2".to_string()))
            .await
            .unwrap();
        assert_eq!(status, StatusCode::ACCEPTED);

        // Local provider has no live handle for the seed, so cleanup resolves
        // immediately; poll for the spawned task to record Terminated.
        let mut final_state = SessionState::Terminating;
        for _ in 0..50 {
            if let Some(s) = state.sessions.get("sess-2") {
                final_state = s.state.clone();
                if final_state == SessionState::Terminated {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(final_state, SessionState::Terminated);

        // And the durable store agrees (restart would rehydrate Terminated).
        let saved = state.storage.load_sessions().unwrap();
        let rec = saved.iter().find(|s| s.id == "sess-2").unwrap();
        assert_eq!(rec.state, SessionState::Terminated);
    }

    fn create_req(ttl_secs: Option<u64>) -> SessionRequest {
        SessionRequest {
            repo_url: "https://github.com/user/repo".to_string(),
            branch: None,
            environment: None,
            provider: None,
            provider_config: None,
            allowed_users: None,
            public: false,
            mode: Some("pair".to_string()),
            ttl_secs,
        }
    }

    fn expires_in_secs(info: &SessionInfo) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        info.expires_at.expect("create sets expiry") - now
    }

    #[tokio::test]
    async fn create_applies_default_ttl() {
        // test_state pins default=3600, max=7200.
        let state = test_state().await;
        let (status, Json(info)) =
            create_session(State(state), claims("alice"), Json(create_req(None))).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let remaining = expires_in_secs(&info);
        assert!(remaining <= 3600 && remaining > 3500, "{}", remaining);
    }

    #[tokio::test]
    async fn create_clamps_over_max_ttl() {
        let state = test_state().await;
        let (status, Json(info)) =
            create_session(State(state), claims("alice"), Json(create_req(Some(999_999)))).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let remaining = expires_in_secs(&info);
        assert!(remaining <= 7200 && remaining > 7100, "{}", remaining);
    }

    #[tokio::test]
    async fn create_enforces_per_user_cap() {
        // test_state pins max 2 live sessions per user.
        let state = test_state().await;
        seed_session(&state, "cap-1", "alice");
        seed_session(&state, "cap-2", "alice");
        seed_session(&state, "other-1", "bob");

        let (status, _) =
            create_session(State(state.clone()), claims("alice"), Json(create_req(None))).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

        // Under the cap (bob has 1) still works.
        let (status, _) =
            create_session(State(state), claims("bob"), Json(create_req(None))).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn status_creator_sees_full_info() {
        let state = test_state().await;
        seed_session(&state, "sess-9", "alice");
        let Json(info) =
            get_session_status(State(state), claims("alice"), Path("sess-9".to_string()))
                .await
                .unwrap();
        assert_eq!(info.state, SessionState::Running);
        assert!(info.magic_link.is_some());
        assert!(info.endpoint.is_some());
        assert!(info.host_public_key.is_some());
    }

    #[tokio::test]
    async fn status_non_creator_is_redacted() {
        let state = test_state().await;
        seed_session(&state, "sess-9", "alice");
        let Json(info) =
            get_session_status(State(state), claims("mallory"), Path("sess-9".to_string()))
                .await
                .unwrap();
        // Lifecycle visible, connection secrets hidden.
        assert_eq!(info.state, SessionState::Running);
        assert_eq!(info.id, "sess-9");
        assert_eq!(info.magic_link, None);
        assert_eq!(info.endpoint, None);
        assert_eq!(info.host_public_key, None);
    }

    #[tokio::test]
    async fn status_unknown_id_is_404() {
        let state = test_state().await;
        let err = get_session_status(State(state), claims("alice"), Path("nope".to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }
}
