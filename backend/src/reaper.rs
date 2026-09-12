// backend/src/reaper.rs
//
// Background expiry enforcement: terminate Running sessions that are past
// their lifetime (`expires_at`) or idle (no observed activity older than
// the idle TTL). This is the cost-control backstop — without it, forgotten
// sessions (especially Hetzner VMs, billed hourly) run forever.
//
// Only Running sessions are reaped: Provisioning sessions may just be slow
// (cloud-init + nix builds take minutes), and Failed sessions are left for
// manual inspection (failed Hetzner provisioning cleans up its own VM
// best-effort in the provider).
//
// Activity signals (per provider): live SSH connections, attached tmux
// clients, sync/activity log mtimes. Unobservable sessions (e.g. after a
// backend restart wiped live handles) fall back to creation time, so
// abandoned-but-unobservable sessions still die on the idle clock.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::models::{Session, SessionState};
use crate::routes::sessions::terminate_inner;
use crate::state::AppState;

/// Sweep interval. Expiry precision is minute-scale by design; a tight
/// loop would only add lock contention on the session map.
pub const REAP_INTERVAL_SECS: u64 = 60;

/// Provisioning sessions older than this are declared failed: cloud-init +
/// nix builds take minutes, never tens of minutes. Stuck rows would
/// otherwise live forever and permanently consume per-user cap.
pub const PROVISIONING_TIMEOUT_SECS: u64 = 30 * 60;

/// Terminal sessions are retained this long for inspection/debugging before
/// the reaper deletes their rows.
pub const TERMINAL_SESSION_RETENTION_SECS: u64 = 7 * 24 * 3600;

/// Run the reap loop forever. Spawn once from `main`.
pub async fn run_forever(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(REAP_INTERVAL_SECS));
    loop {
        interval.tick().await;
        let reaped = reap_once(&state).await;
        if reaped > 0 {
            tracing::info!("Reaper terminated {} expired session(s)", reaped);
        }
        // Keep the live maps and the DB bounded.
        state.prune_auth_state();
        match state
            .storage
            .clone()
            .prune_terminal_sessions_async(TERMINAL_SESSION_RETENTION_SECS)
            .await
        {
            Ok(0) => {}
            Ok(n) => tracing::info!("Reaper pruned {} terminal session(s)", n),
            Err(e) => tracing::warn!("Failed to prune terminal sessions: {:#}", e),
        }
    }
}

/// Idle duration of a session at `now`, resolving the freshest signal:
/// stored activity refreshed from the provider, else the stored value,
/// else creation time (covers legacy rows and unobservable sessions).
/// Returns `None` when provider signals fail: unknown must *defer* the
/// idle reap (a broken signal must never accelerate killing), while
/// lifetime expiry still applies.
async fn idle_for(state: &Arc<AppState>, session: &Session, now: SystemTime) -> Option<Duration> {
    let mut best = session.last_activity_at;
    if let Some(provider) = state.compute_providers.get(&session.compute_provider) {
        match provider.last_activity(session).await {
            Ok(Some(signal)) => {
                if best.map(|b| signal > b).unwrap_or(true) {
                    best = Some(signal);
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    "Activity signal failed for {}; skipping idle reap this round: {:#}",
                    session.id,
                    e
                );
                return None;
            }
        }
    }
    // Persist fresher observations so GET/list show them.
    if best != session.last_activity_at {
        if let Some(mut s) = state.sessions.get_mut(&session.id) {
            s.last_activity_at = best;
        }
        state.persist_session(&session.id).await;
    }
    let baseline = best.or(Some(session.created_at)).unwrap_or(now);
    Some(now.duration_since(baseline).unwrap_or(Duration::ZERO))
}

fn humandur(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 86_400 {
        format!("{}d", s / 86_400)
    } else if s >= 3600 {
        format!("{}h", s / 3600)
    } else if s >= 60 {
        format!("{}m", s / 60)
    } else {
        format!("{}s", s)
    }
}

/// One sweep: terminate every Running session past lifetime expiry or the
/// idle timeout, and fail Provisioning sessions stuck past the provisioning
/// timeout. Returns the number of sessions sent to termination.
/// Legacy records without `expires_at` are never lifetime-reaped.
pub async fn reap_once(state: &Arc<AppState>) -> usize {
    let now = SystemTime::now();
    let idle_ttl = Duration::from_secs(state.config.idle_ttl_secs);
    let prov_timeout = Duration::from_secs(PROVISIONING_TIMEOUT_SECS);

    // Snapshot first to keep map borrows short.
    let running: Vec<String> = state
        .sessions
        .iter()
        .filter(|e| e.state == SessionState::Running)
        .map(|e| e.id.clone())
        .collect();
    let provisioning: Vec<(String, SystemTime)> = state
        .sessions
        .iter()
        .filter(|e| e.state == SessionState::Provisioning)
        .map(|e| (e.id.clone(), e.created_at))
        .collect();

    let mut reaped = 0;
    for id in running {
        let Some(session) = state.sessions.get(&id).map(|e| e.clone()) else {
            continue;
        };
        let lifetime_due = session.expires_at.map(|exp| exp <= now).unwrap_or(false);

        // Unknown signals defer: only a *known* idle duration kills.
        let idle_due = if state.config.idle_ttl_secs == 0 {
            false
        } else {
            matches!(idle_for(state, &session, now).await, Some(d) if d >= idle_ttl)
        };

        if !lifetime_due && !idle_due {
            continue;
        }
        if idle_due && !lifetime_due {
            let idle = idle_for(state, &session, now)
                .await
                .unwrap_or(Duration::ZERO);
            let reason = format!("terminated: idle for {}", humandur(idle));
            tracing::info!("Reaper: session {} {}", id, reason);
            if let Some(mut s) = state.sessions.get_mut(&id) {
                s.error_message = Some(reason);
            }
            state.persist_session(&id).await;
        }
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

    // Stuck provisioning: fail them so they stop consuming cap. Provider
    // cleanup runs best-effort through terminate_inner (a terminate without
    // a live handle is a safe no-op at record level; workspace/VM leftovers
    // are handled by provider best-effort paths).
    for (id, created_at) in provisioning {
        if now.duration_since(created_at).unwrap_or(Duration::ZERO) < prov_timeout {
            continue;
        }
        tracing::warn!(
            "Reaper: session {} stuck Provisioning past {:?}; failing it",
            id,
            prov_timeout
        );
        if let Some(mut s) = state.sessions.get_mut(&id) {
            s.error_message = Some(format!(
                "provisioning timed out after {:?}; retry with a fresh session",
                prov_timeout
            ));
        }
        state.persist_session(&id).await;
        if terminate_inner(state, &id).await.is_ok() {
            reaped += 1;
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
        let _guard = lock_test_env().await;
        let saved: Vec<(String, Option<String>)> = [
            "JWT_SECRET",
            "NOENV_FLAKE_PATH",
            "STEADYSTATE_DB_PATH",
            "HCLOUD_TOKEN",
            "STEADYSTATE_DEFAULT_SESSION_TTL_SECS",
            "STEADYSTATE_MAX_SESSION_TTL_SECS",
            "STEADYSTATE_MAX_SESSIONS_PER_USER",
            "STEADYSTATE_IDLE_TTL_SECS",
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
            std::env::set_var("STEADYSTATE_IDLE_TTL_SECS", "60");
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

    fn seed(
        state: &Arc<AppState>,
        id: &str,
        st: SessionState,
        expires: Option<std::time::SystemTime>,
        last_activity: Option<std::time::SystemTime>,
    ) {
        seed_created(
            state,
            id,
            st,
            expires,
            last_activity,
            std::time::SystemTime::now(),
        );
    }

    fn seed_created(
        state: &Arc<AppState>,
        id: &str,
        st: SessionState,
        expires: Option<std::time::SystemTime>,
        last_activity: Option<std::time::SystemTime>,
        created: std::time::SystemTime,
    ) {
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
                created_at: created,
                updated_at: created,
                error_message: None,
                magic_link: None,
                host_public_key: None,
                expires_at: expires,
                last_activity_at: last_activity,
            },
        );
    }

    fn ago(secs: u64) -> SystemTime {
        SystemTime::now() - Duration::from_secs(secs)
    }

    fn future(secs: u64) -> SystemTime {
        SystemTime::now() + Duration::from_secs(secs)
    }

    async fn wait_terminated(state: &Arc<AppState>, id: &str) {
        // Local provider has no live handle for seeds, so cleanup resolves
        // immediately; poll for the spawned task to record Terminated.
        for _ in 0..50 {
            if let Some(s) = state.sessions.get(id)
                && s.state == SessionState::Terminated
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("{} was not terminated", id);
    }

    #[tokio::test]
    async fn reaps_only_expired_running() {
        let state = test_state().await;
        let past = ago(10);
        let future = future(3600);

        // idle_ttl=60: give these fresh activity so only lifetime matters.
        let now = SystemTime::now();
        seed(
            &state,
            "expired",
            SessionState::Running,
            Some(past),
            Some(now),
        );
        seed(
            &state,
            "live",
            SessionState::Running,
            Some(future),
            Some(now),
        );
        seed(&state, "legacy", SessionState::Running, None, Some(now));
        seed(
            &state,
            "provisioning",
            SessionState::Provisioning,
            Some(past),
            Some(now),
        );

        assert_eq!(reap_once(&state).await, 1);
        wait_terminated(&state, "expired").await;

        assert_eq!(
            state.sessions.get("live").unwrap().state,
            SessionState::Running
        );
        assert_eq!(
            state.sessions.get("legacy").unwrap().state,
            SessionState::Running
        );
        assert_eq!(
            state.sessions.get("provisioning").unwrap().state,
            SessionState::Provisioning
        );
    }

    #[tokio::test]
    async fn reaps_idle_sessions_with_reason() {
        // idle_ttl=60, lifetimes far in the future: only idleness kills.
        let state = test_state().await;
        let future = future(3600);

        seed(
            &state,
            "idle",
            SessionState::Running,
            Some(future),
            Some(ago(3600)),
        );
        seed(
            &state,
            "active",
            SessionState::Running,
            Some(future),
            Some(SystemTime::now()),
        );
        // Legacy row without activity falls back to creation time (now) -> kept.
        seed(
            &state,
            "legacy-idle",
            SessionState::Running,
            Some(future),
            None,
        );

        assert_eq!(reap_once(&state).await, 1);
        wait_terminated(&state, "idle").await;

        let msg = state
            .sessions
            .get("idle")
            .unwrap()
            .error_message
            .clone()
            .unwrap_or_default();
        assert!(msg.starts_with("terminated: idle for"), "{}", msg);

        assert_eq!(
            state.sessions.get("active").unwrap().state,
            SessionState::Running
        );
        assert_eq!(
            state.sessions.get("legacy-idle").unwrap().state,
            SessionState::Running
        );
    }

    #[tokio::test]
    async fn idle_disabled_keeps_idle_sessions() {
        let mut state = test_state().await;
        Arc::get_mut(&mut state)
            .expect("fresh Arc has one strong ref")
            .config
            .idle_ttl_secs = 0;
        seed(
            &state,
            "idle",
            SessionState::Running,
            Some(future(3600)),
            Some(ago(3600)),
        );
        assert_eq!(reap_once(&state).await, 0);
        assert_eq!(
            state.sessions.get("idle").unwrap().state,
            SessionState::Running
        );
    }

    #[tokio::test]
    async fn fails_stuck_provisioning() {
        let state = test_state().await;
        seed_created(
            &state,
            "stuck",
            SessionState::Provisioning,
            None,
            Some(SystemTime::now()),
            ago(3600),
        );
        seed_created(
            &state,
            "fresh-prov",
            SessionState::Provisioning,
            None,
            Some(SystemTime::now()),
            ago(10),
        );
        assert_eq!(reap_once(&state).await, 1);
        wait_terminated(&state, "stuck").await;
        let stuck = state.sessions.get("stuck").unwrap();
        assert!(
            stuck
                .error_message
                .as_deref()
                .unwrap_or_default()
                .contains("provisioning timed out"),
            "{:?}",
            stuck.error_message
        );
        assert_eq!(
            state.sessions.get("fresh-prov").unwrap().state,
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
        assert_eq!(
            crate::state::DEFAULT_IDLE_TTL_SECS,
            2 * 3600,
            "default idle timeout is 2h"
        );
    }

    #[test]
    fn test_humandur() {
        assert_eq!(humandur(Duration::from_secs(30)), "30s");
        assert_eq!(humandur(Duration::from_secs(90)), "1m");
        assert_eq!(humandur(Duration::from_secs(7200)), "2h");
        assert_eq!(humandur(Duration::from_secs(90000)), "1d");
    }
}
