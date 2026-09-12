use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::compute::traits::RemoteExecutor;

/// Activity signals for idle reaping, read through any `RemoteExecutor`
/// (local or over SSH).
///
/// Sources, in priority order:
/// 1. `active-users` non-empty (collab): someone is connected *right now*.
/// 2. Attached tmux clients (pair): `tmux list-clients -t pair-<id8>`.
/// 3. `sync-log` / `activity-log` mtimes: last sync or connection.
/// Anything unobservable yields `None` and the reaper falls back to the
/// session's creation time.

/// tmux session name for a pair session (mirrors pair-wrapper's
/// `TMUX_SESSION="pair-${SESSION_ID:0:8}"`).
pub fn tmux_session_name(session_id: &str) -> String {
    let short: String = session_id.chars().take(8).collect();
    format!("pair-{}", short)
}

/// True when an `active-users` file lists at least one connected user.
pub fn active_users_present(content: &str) -> bool {
    content.lines().any(|l| !l.trim().is_empty())
}

/// True when `tmux list-clients` output shows at least one client line.
pub fn tmux_clients_present(list_clients_stdout: &str) -> bool {
    list_clients_stdout.lines().any(|l| !l.trim().is_empty())
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

async fn file_content_nonempty(executor: &dyn RemoteExecutor, path: &Path) -> bool {
    match executor.read_file(path).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes)
            .lines()
            .any(|l| !l.trim().is_empty()),
        Err(_) => false,
    }
}

async fn path_mtime(executor: &dyn RemoteExecutor, path: &Path) -> Option<SystemTime> {
    let out = executor
        .exec_shell(&format!(
            "stat -c %Y {}",
            shell_quote(&path.to_string_lossy())
        ))
        .await
        .ok()?;
    if !out.exit_status.success() {
        return None;
    }
    out.stdout
        .trim()
        .parse::<u64>()
        .ok()
        .map(|s| UNIX_EPOCH + Duration::from_secs(s))
}

async fn tmux_has_clients(executor: &dyn RemoteExecutor, tmux_session: &str) -> bool {
    match executor
        .exec_shell(&format!(
            "tmux list-clients -t {} 2>/dev/null",
            shell_quote(tmux_session)
        ))
        .await
    {
        Ok(out) => out.exit_status.success() && tmux_clients_present(&out.stdout),
        Err(_) => false,
    }
}

/// Newest observed activity under a session root, or `None` when nothing
/// is observable. Never fails hard — individual signal errors collapse
/// to `None` so one broken signal cannot kill a live session.
///
/// tmux names use only the first 8 id chars, so a (rare) cross-session
/// prefix collision can only *delay* reaping, never cause a live kill.
pub async fn latest_activity(
    executor: &dyn RemoteExecutor,
    session_root: &Path,
    session_id: &str,
) -> Option<SystemTime> {
    if file_content_nonempty(executor, &session_root.join("active-users")).await {
        return Some(SystemTime::now());
    }
    if tmux_has_clients(executor, &tmux_session_name(session_id)).await {
        return Some(SystemTime::now());
    }
    let mut latest = None;
    for log in ["sync-log", "activity-log"] {
        if let Some(m) = path_mtime(executor, &session_root.join(log)).await {
            latest = Some(latest.map_or(m, |cur: SystemTime| cur.max(m)));
        }
    }
    latest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tmux_session_name() {
        assert_eq!(tmux_session_name("abcdef123456"), "pair-abcdef12");
        assert_eq!(tmux_session_name("abc"), "pair-abc");
    }

    #[test]
    fn test_active_users_present() {
        assert!(active_users_present("alice\nbob\n"));
        assert!(active_users_present("  alice  \n"));
        assert!(!active_users_present(""));
        assert!(!active_users_present("\n  \n"));
    }

    #[test]
    fn test_tmux_clients_present() {
        // Helper only ever sees stdout (stderr is dev-nulled by the caller);
        // absence is signaled by exit status there, not by this function.
        assert!(tmux_clients_present("/dev/pts/0: 0 [80x24 xterm] (utf8)\n"));
        assert!(!tmux_clients_present(""));
        assert!(!tmux_clients_present("  \n"));
    }
}
