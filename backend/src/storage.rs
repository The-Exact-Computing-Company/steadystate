// backend/src/storage.rs
//
// SQLite-backed durable storage for sessions and refresh tokens.
// The in-memory DashMaps in AppState remain the live store; this module
// is the write-through backing store + startup rehydration source.
//
// Design notes:
// - Single `rusqlite::Connection` behind a std Mutex. Critical sections are
//   short and never hold across `.await`, so this cannot block the runtime
//   for longer than one small SQL statement.
// - `SystemTime` is stored as seconds since the Unix epoch (INTEGER).
// - Schema is created idempotently (`CREATE TABLE IF NOT EXISTS`) so old
//   database files keep working across upgrades that only add columns via
//   separate migrations (none yet).

use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};

use crate::models::{RefreshRecord, Session, SessionState};

pub struct Storage {
    conn: Mutex<rusqlite::Connection>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
    id               TEXT PRIMARY KEY,
    state            TEXT NOT NULL,
    repo_url         TEXT NOT NULL,
    branch           TEXT,
    environment      TEXT,
    compute_provider TEXT NOT NULL,
    creator_login    TEXT NOT NULL,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    error_message    TEXT,
    endpoint         TEXT,
    magic_link       TEXT,
    host_public_key  TEXT,
    expires_at       INTEGER
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token      TEXT PRIMARY KEY,
    login      TEXT NOT NULL,
    provider   TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
"#;

fn unix_secs(t: std::time::SystemTime) -> i64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn system_time(secs: i64) -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs.max(0) as u64)
}

fn state_to_str(s: &SessionState) -> &'static str {
    // SessionState has as_str() in steadystate-common; match explicitly so a
    // new variant fails compilation here instead of silently persisting wrong.
    match s {
        SessionState::Provisioning => "Provisioning",
        SessionState::Running => "Running",
        SessionState::Terminating => "Terminating",
        SessionState::Terminated => "Terminated",
        SessionState::Failed => "Failed",
    }
}

fn state_from_str(s: &str) -> SessionState {
    match s {
        "Running" => SessionState::Running,
        "Terminating" => SessionState::Terminating,
        "Terminated" => SessionState::Terminated,
        "Failed" => SessionState::Failed,
        _ => SessionState::Provisioning,
    }
}

impl Storage {
    fn new(conn: rusqlite::Connection) -> Result<Self> {
        conn.execute_batch(SCHEMA).context("init storage schema")?;
        // Migration for databases created before expiry tracking existed.
        // Fails with "duplicate column" on new DBs — that error is expected
        // and ignored; any other error is surfaced.
        match conn.execute("ALTER TABLE sessions ADD COLUMN expires_at INTEGER", []) {
            Ok(_) => tracing::info!("Migrated sessions table: added expires_at"),
            Err(e) => {
                let msg = e.to_string();
                if !msg.contains("duplicate column") {
                    return Err(e).context("migrate sessions table");
                }
            }
        }
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Open (creating parents as needed) the database file.
    /// The special path `:memory:` opens a transient in-memory database.
    pub fn open(path: &Path) -> Result<Self> {
        if path.as_os_str() == ":memory:" {
            return Self::new(
                rusqlite::Connection::open_in_memory().context("open in-memory sqlite")?,
            );
        }        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create db parent dir {}", parent.display()))?;
        }
        let conn = rusqlite::Connection::open(path)
            .with_context(|| format!("open sqlite db {}", path.display()))?;
        Self::new(conn)
    }

    /// In-memory database, used by tests.
    pub fn open_in_memory() -> Result<Self> {
        Self::new(rusqlite::Connection::open_in_memory().context("open in-memory sqlite")?)
    }

    // --- sessions ---

    pub fn save_session(&self, s: &Session) -> Result<()> {
        let conn = self.conn.lock().expect("storage mutex poisoned");
        conn.execute(
            r#"INSERT INTO sessions
               (id, state, repo_url, branch, environment, compute_provider,
                creator_login, created_at, updated_at,
                error_message, endpoint, magic_link, host_public_key, expires_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
               ON CONFLICT(id) DO UPDATE SET
                 state=excluded.state, repo_url=excluded.repo_url,
                 branch=excluded.branch, environment=excluded.environment,
                 compute_provider=excluded.compute_provider,
                 creator_login=excluded.creator_login,
                 created_at=excluded.created_at, updated_at=excluded.updated_at,
                 error_message=excluded.error_message, endpoint=excluded.endpoint,
                 magic_link=excluded.magic_link,
                 host_public_key=excluded.host_public_key,
                 expires_at=excluded.expires_at"#,
            rusqlite::params![
                s.id,
                state_to_str(&s.state),
                s.repo_url,
                s.branch,
                s.environment,
                s.compute_provider,
                s.creator_login,
                unix_secs(s.created_at),
                unix_secs(s.updated_at),
                s.error_message,
                s.endpoint,
                s.magic_link,
                s.host_public_key,
                s.expires_at.map(unix_secs),
            ],
        )
        .context("save session")?;
        Ok(())
    }

    pub fn load_sessions(&self) -> Result<Vec<Session>> {
        let conn = self.conn.lock().expect("storage mutex poisoned");
        let mut stmt = conn.prepare(
            r#"SELECT id, state, repo_url, branch, environment, compute_provider,
                      creator_login, created_at, updated_at,
                      error_message, endpoint, magic_link, host_public_key, expires_at
               FROM sessions"#,
        )?;
        let rows = stmt.query_map([], |row| {
            let expires_raw: Option<i64> = row.get(13)?;
            Ok(Session {
                id: row.get(0)?,
                state: state_from_str(&row.get::<_, String>(1)?),
                repo_url: row.get(2)?,
                branch: row.get(3)?,
                environment: row.get(4)?,
                compute_provider: row.get(5)?,
                creator_login: row.get(6)?,
                created_at: system_time(row.get(7)?),
                updated_at: system_time(row.get(8)?),
                error_message: row.get(9)?,
                endpoint: row.get(10)?,
                magic_link: row.get(11)?,
                host_public_key: row.get(12)?,
                expires_at: expires_raw.map(system_time),
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>().context("load sessions")
    }

    pub fn delete_session(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("storage mutex poisoned");
        conn.execute("DELETE FROM sessions WHERE id = ?1", [id])
            .context("delete session")?;
        Ok(())
    }

    // --- refresh tokens ---

    pub fn save_refresh(&self, token: &str, rec: &RefreshRecord) -> Result<()> {
        let conn = self.conn.lock().expect("storage mutex poisoned");
        conn.execute(
            r#"INSERT INTO refresh_tokens (token, login, provider, expires_at)
               VALUES (?1, ?2, ?3, ?4)
               ON CONFLICT(token) DO UPDATE SET
                 login=excluded.login, provider=excluded.provider,
                 expires_at=excluded.expires_at"#,
            rusqlite::params![token, rec.login, rec.provider.as_str(), rec.expires_at as i64],
        )
        .context("save refresh token")?;
        Ok(())
    }

    pub fn load_refresh(&self) -> Result<Vec<(String, RefreshRecord)>> {
        let conn = self.conn.lock().expect("storage mutex poisoned");
        let mut stmt = conn.prepare("SELECT token, login, provider, expires_at FROM refresh_tokens")?;
        let rows = stmt.query_map([], |row| {
            let token: String = row.get(0)?;
            let rec = RefreshRecord {
                login: row.get(1)?,
                provider: row.get::<_, String>(2)?.into(),
                expires_at: row.get::<_, i64>(3)? as u64,
            };
            Ok((token, rec))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>().context("load refresh tokens")
    }

    pub fn delete_refresh(&self, token: &str) -> Result<()> {
        let conn = self.conn.lock().expect("storage mutex poisoned");
        conn.execute("DELETE FROM refresh_tokens WHERE token = ?1", [token])
            .context("delete refresh token")?;
        Ok(())
    }

    /// Remove expired refresh tokens; returns rows removed.
    pub fn prune_expired_refresh(&self, now: u64) -> Result<usize> {
        let conn = self.conn.lock().expect("storage mutex poisoned");
        let n = conn
            .execute("DELETE FROM refresh_tokens WHERE expires_at <= ?1", [now as i64])
            .context("prune expired refresh tokens")?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ProviderId;

    fn test_session(id: &str) -> Session {
        let now = std::time::SystemTime::now();
        Session {
            id: id.to_string(),
            state: SessionState::Running,
            repo_url: "https://github.com/user/repo".to_string(),
            branch: Some("main".to_string()),
            environment: Some("tproject".to_string()),
            endpoint: Some("ssh://steady@host:2222".to_string()),
            compute_provider: "local".to_string(),
            creator_login: "alice".to_string(),
            created_at: now,
            updated_at: now,
            error_message: None,
            magic_link: Some("steadystate://collab/abc".to_string()),
            host_public_key: Some("ssh-ed25519 AAAA".to_string()),
            expires_at: Some(now + std::time::Duration::from_secs(3600)),
        }
    }

    #[test]
    fn test_session_round_trip() {
        let db = Storage::open_in_memory().unwrap();
        let mut s = test_session("s1");
        db.save_session(&s).unwrap();

        let loaded = db.load_sessions().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "s1");
        assert_eq!(loaded[0].state, SessionState::Running);
        assert_eq!(loaded[0].creator_login, "alice");
        assert_eq!(loaded[0].magic_link.as_deref(), Some("steadystate://collab/abc"));
        assert!(loaded[0].expires_at.is_some());

        // Upsert updates state.
        s.state = SessionState::Terminated;
        s.error_message = Some("bye".to_string());
        db.save_session(&s).unwrap();
        let loaded = db.load_sessions().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].state, SessionState::Terminated);
        assert_eq!(loaded[0].error_message.as_deref(), Some("bye"));

        db.delete_session("s1").unwrap();
        assert!(db.load_sessions().unwrap().is_empty());
    }

    #[test]
    fn test_migration_adds_expires_to_old_db() {
        // Simulate a database file written before expiry tracking: same
        // table minus the expires_at column, with one row in it.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"CREATE TABLE sessions (
                id TEXT PRIMARY KEY, state TEXT NOT NULL, repo_url TEXT NOT NULL,
                branch TEXT, environment TEXT, compute_provider TEXT NOT NULL,
                creator_login TEXT NOT NULL, created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL, error_message TEXT, endpoint TEXT,
                magic_link TEXT, host_public_key TEXT
            );
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token TEXT PRIMARY KEY, login TEXT NOT NULL,
                provider TEXT NOT NULL, expires_at INTEGER NOT NULL
            );
            INSERT INTO sessions (id, state, repo_url, compute_provider, creator_login, created_at, updated_at)
            VALUES ('legacy-1', 'Running', 'https://github.com/u/r', 'local', 'bob', 1, 2);"#,
        )
        .unwrap();
        let db = Storage::new(conn).unwrap();

        let loaded = db.load_sessions().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "legacy-1");
        // Pre-expiry rows load with no expiry (treated as non-expiring legacy).
        assert_eq!(loaded[0].expires_at, None);

        // And new writes to the migrated table carry expiry.
        db.save_session(&test_session("new-1")).unwrap();
        let loaded = db.load_sessions().unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.iter().find(|r| r.id == "new-1").unwrap().expires_at.is_some());
    }

    #[test]
    fn test_state_round_trip_all_variants() {
        let db = Storage::open_in_memory().unwrap();
        let states = [
            SessionState::Provisioning,
            SessionState::Running,
            SessionState::Terminating,
            SessionState::Terminated,
            SessionState::Failed,
        ];
        for (i, st) in states.iter().enumerate() {
            let mut s = test_session(&format!("s{}", i));
            s.state = st.clone();
            db.save_session(&s).unwrap();
        }
        let mut loaded = db.load_sessions().unwrap();
        loaded.sort_by(|a, b| a.id.cmp(&b.id));
        for (i, st) in states.iter().enumerate() {
            assert_eq!(&loaded[i].state, st, "variant {:?}", st);
        }
    }

    #[test]
    fn test_refresh_round_trip_and_prune() {
        let db = Storage::open_in_memory().unwrap();
        let rec = RefreshRecord {
            login: "alice".to_string(),
            provider: ProviderId::from("github"),
            expires_at: 9_999_999_999,
        };
        db.save_refresh("tok1", &rec).unwrap();
        db.save_refresh("tok-old", &RefreshRecord { expires_at: 1, ..rec.clone() }).unwrap();

        let loaded = db.load_refresh().unwrap();
        assert_eq!(loaded.len(), 2);

        let pruned = db.prune_expired_refresh(100).unwrap();
        assert_eq!(pruned, 1);
        let loaded = db.load_refresh().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, "tok1");
        assert_eq!(loaded[0].1.login, "alice");

        db.delete_refresh("tok1").unwrap();
        assert!(db.load_refresh().unwrap().is_empty());
    }
}
