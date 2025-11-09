use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::task;
use tracing::warn;

use crate::auth::extract_exp_from_jwt;
use crate::config::{CONFIG_OVERRIDE_ENV, SERVICE_NAME};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Session {
    pub login: String,
    pub jwt: String,
    pub jwt_exp: Option<u64>, // epoch seconds
}

impl Session {
    pub fn new(login: String, jwt: String) -> Self {
        let jwt_exp = extract_exp_from_jwt(&jwt);
        Self {
            login,
            jwt,
            jwt_exp,
        }
    }

    pub fn is_near_expiry(&self, buffer_secs: u64) -> bool {
        if let Some(exp) = self.jwt_exp {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            exp <= now + buffer_secs
        } else {
            false
        }
    }
}

pub async fn cfg_dir() -> Result<PathBuf> {
    if let Ok(override_dir) = std::env::var(CONFIG_OVERRIDE_ENV) {
        let mut p = PathBuf::from(override_dir);
        tokio::fs::create_dir_all(&p)
            .await
            .context("create override config dir")?;
        p.push(SERVICE_NAME);
        tokio::fs::create_dir_all(&p)
            .await
            .context("create service config dir")?;
        return Ok(p);
    }

    let mut p = dirs::config_dir().context("could not determine config directory")?;
    p.push(SERVICE_NAME);
    tokio::fs::create_dir_all(&p)
        .await
        .context("create config dir")?;
    Ok(p)
}

pub async fn session_file() -> Result<PathBuf> {
    Ok(cfg_dir().await?.join("session.json"))
}

pub async fn write_session(session: &Session) -> Result<()> {
    let path = session_file().await?;
    let data = serde_json::to_vec_pretty(session)?;
    let path_clone = path.clone();
    let data_clone = data.clone();

    task::spawn_blocking(move || -> Result<()> {
        use fs2::FileExt;
        use std::fs::OpenOptions;
        use std::io::{Seek, SeekFrom, Write};

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&path_clone)
            .context("open session file")?;

        file.try_lock_exclusive().context("lock session file")?;

        file.set_len(0).context("truncate session file")?;
        file.seek(SeekFrom::Start(0)).context("seek session file")?;
        file.write_all(&data_clone).context("write session file")?;
        file.sync_all().context("sync session file")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                std::fs::set_permissions(&path_clone, std::fs::Permissions::from_mode(0o600))
            {
                warn!("Failed to set strict permissions on session file: {}", e);
            }
        }

        Ok(())
    })
    .await??;

    Ok(())
}

pub async fn read_session() -> Result<Session> {
    let path = session_file().await?;
    let bytes = tokio::fs::read(&path).await.context("read session file")?;
    let session: Session = serde_json::from_slice(&bytes).context("parse session json")?;
    Ok(session)
}

pub async fn remove_session() -> Result<()> {
    let path = session_file().await?;
    match tokio::fs::remove_file(path).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("remove session file"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use std::sync::Mutex;
    use tempfile::tempdir;

    static TEST_GUARD: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    struct TestContext {
        _guard: std::sync::MutexGuard<'static, ()>,
        _dir: tempfile::TempDir,
    }

    impl TestContext {
        fn new() -> Self {
            let guard = TEST_GUARD.lock().unwrap();
            let dir = tempdir().expect("create tempdir");
            unsafe {
                std::env::set_var(CONFIG_OVERRIDE_ENV, dir.path().to_str().unwrap());
            }
            Self {
                _guard: guard,
                _dir: dir,
            }
        }
    }

    impl Drop for TestContext {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var(CONFIG_OVERRIDE_ENV);
            }
        }
    }

    #[tokio::test]
    async fn test_write_read_cycle() {
        let ctx = TestContext::new();
        let session = Session {
            login: "user".into(),
            jwt: "token".into(),
            jwt_exp: Some(42),
        };

        write_session(&session).await.unwrap();
        let loaded = read_session().await.unwrap();
        assert_eq!(loaded.login, session.login);
        assert_eq!(loaded.jwt, session.jwt);
        assert_eq!(loaded.jwt_exp, session.jwt_exp);
        drop(ctx);
    }

    #[tokio::test]
    async fn test_remove_missing_session_ok() {
        let ctx = TestContext::new();
        remove_session().await.unwrap();
        drop(ctx);
    }
}
