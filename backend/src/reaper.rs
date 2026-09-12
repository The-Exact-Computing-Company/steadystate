// backend/src/reaper.rs
//
// Background expiry enforcement: periodically terminate Running sessions
// past their `expires_at`. This is the cost-control backstop — without it,
// forgotten sessions (especially Hetzner VMs, billed hourly) run forever.
//
// Only Running sessions are reaped: Provisioning sessions may just be slow
// (cloud-init + nix builds take minutes), and Failed sessions are left for
// manual inspection (failed Hetzner provisioning cleans up its own VM
// best-effort in the provider).

use std::sync::Arc;
use std::time::Duration;

use crate::models::SessionState;
use crate::routes::sessions::terminate_inner;
use crate::state::AppState;

/// Sweep interval. Expiry precision is minute-scale by design; a tight
/// loop would only add lock contention on the session map.
pub const REAP_INTERVAL_SECS: u64 = 60;

/// Run the reap loop forever. Spawn once from `main`.
pub async fn run_forever(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(REAP_INTERVAL_SECS));
    loop {
        interval.tick().await;
        let reaped = reap_once(&state).await;
        if reaped > 0 {
            tracing::info!("Reaper terminated {} expired session(s)", reaped);
        }
    }
}

/// One sweep: terminate every Running session past expiry.
/// Returns the number of sessions sent to termination.
/// Legacy records without `expires_at` are never reaped.
pub async fn reap_once(state: &Arc<AppState>) -> usize {
    let now = std::time::SystemTime::now();
    let expired: Vec<String> = state
        .sessions
        .iter()
        .filter(|e| {
            e.state == SessionState::Running
                && e.expires_at.map(|exp| exp <= now).unwrap_or(false)
        })
        .map(|e| e.id.clone())
        .collect();

    let mut reaped = 0;
    for id in expired {
        match terminate_inner(state, &id).await {
            Ok(_) => {
                tracing::info!("Reaper: expired session {} sent to termination", id);
                reaped += 1;
            }
            Err((status, _)) => {
                tracing::warn!("Reaper: failed to terminate {} ({})", id, status);
            }
        }
    }
    reaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Session;
    use crate::state::lock_test_env;

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
            std::env::set_var("JWT_SECRET", "test-secret-for-reaper-tests");
            std::env::set_var("NOENV_FLAKE_PATH", "/tmp/dummy-flake");
            std::env::set_var("STEADYSTATE_DB_PATH", ":memory:");
            std::env::remove_var("HCLOUD_TOKEN");
            std::env::set_var("STEADYSTATE_DEFAULT_SESSION_TTL_SECS", "3600");
            std::env::set_var("STEADYSTATE_MAX_SESSION_TTL_SECS", "7200");
            std::env::set_var("STEADYSTATE_MAX_SESSIONS_PER_USER", "10");
        }
        let state = AppState::try_new().await.expect("test AppState");
        // SAFETY: still holding the shared lock; nothing below reads env.
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

    fn seed(state: &Arc<AppState>, id: &str, st: SessionState, expires: Option<std::time::SystemTime>) {
        let now = std::time::SystemTime::now();
        state.sessions.insert(
            id.to_string(),
            Session {
                id: id.to_string(),
                state: st,
                repo_url: "https://github.com/u/r".to_string(),
                branch: None,
                environment: None,
                endpoint: None,
                compute_provider: "local".to_string(),
                creator_login: "alice".to_string(),
                created_at: now,
                updated_at: now,
                error_message: None,
                magic_link: None,
                host_public_key: None,
                expires_at: expires,
            },
        );
    }

    #[tokio::test]
    async fn reaps_only_expired_running() {
        let state = test_state().await;
        let past = std::time::SystemTime::now() - Duration::from_secs(10);
        let future = std::time::SystemTime::now() + Duration::from_secs(3600);

        seed(&state, "expired", SessionState::Running, Some(past));
        seed(&state, "live", SessionState::Running, Some(future));
        seed(&state, "legacy", SessionState::Running, None);
        seed(&state, "provisioning", SessionState::Provisioning, Some(past));

        assert_eq!(reap_once(&state).await, 1);

        // Local provider has no live handle: cleanup resolves immediately.
        let mut final_state = SessionState::Terminating;
        for _ in 0..50 {
            if let Some(s) = state.sessions.get("expired") {
                final_state = s.state.clone();
                if final_state == SessionState::Terminated {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(final_state, SessionState::Terminated);
        assert_eq!(state.sessions.get("live").unwrap().state, SessionState::Running);
        assert_eq!(state.sessions.get("legacy").unwrap().state, SessionState::Running);
        assert_eq!(
            state.sessions.get("provisioning").unwrap().state,
            SessionState::Provisioning
        );
    }

    #[test]
    fn ttl_policy_defaults() {
        assert_eq!(
            crate::state::DEFAULT_SESSION_TTL_SECS,
            48 * 3600,
            "default session lifetime is 48h"
        );
    }
}
