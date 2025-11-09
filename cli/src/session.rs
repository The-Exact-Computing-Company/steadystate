use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
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

pub async fn get_cfg_dir(override_dir: Option<&PathBuf>) -> Result<PathBuf> {
    let base_dir = match override_dir {
        Some(p) => p.clone(),
        None => {
            if let Ok(override_env) = std::env::var(CONFIG_OVERRIDE_ENV) {
                PathBuf::from(override_env)
            } else {
                dirs::config_dir().context("could not determine config directory")?
            }
        }
    };

    let mut p = base_dir;
    p.push(SERVICE_NAME);
    tokio::fs::create_dir_all(&p)
        .await
        .context("create service config dir")?;
    Ok(p)
}


pub async fn session_file(override_dir: Option<&PathBuf>) -> Result<PathBuf> {
    Ok(get_cfg_dir(override_dir).await?.join("session.json"))
}

pub async fn write_session(session: &Session, override_dir: Option<&PathBuf>) -> Result<()> {
    let path = session_file(override_dir).await?;
    let data = serde_json::to_vec_pretty(session)?;

    tokio::fs::write(&path, &data)
        .await
        .context("write session file")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await
        {
            warn!("Failed to set strict permissions on session file: {}", e);
        }
    }

    Ok(())
}

pub async fn read_session(override_dir: Option<&PathBuf>) -> Result<Session> {
    let path = session_file(override_dir).await?;
    let bytes = tokio::fs::read(&path).await.context("read session file")?;
    let session: Session = serde_json::from_slice(&bytes).context("parse session json")?;
    Ok(session)
}

pub async fn remove_session(override_dir: Option<&PathBuf>) -> Result<()> {
    let path = session_file(override_dir).await?;
    match tokio::fs::remove_file(path).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("remove session file"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, TempDir};

    struct TestContext {
        // This holds the temporary directory, which is automatically deleted when TestContext goes out of scope.
        _dir: TempDir,
        // We store the path for easy access in tests.
        path: PathBuf,
    }

    impl TestContext {
        fn new() -> Self {
            let dir = tempdir().expect("create tempdir");
            let path = dir.path().to_path_buf();
            // No more environment variables! No more unsafe! No more Mutex!
            Self { _dir: dir, path }
        }
    }

    #[tokio::test]
    async fn test_write_read_cycle() {
        let ctx = TestContext::new();
        
        // Ensure no session exists by passing the temp directory path.
        remove_session(Some(&ctx.path)).await.unwrap();
        
        let session = Session {
            login: "test_user".into(),
            jwt: "fake_jwt".into(),
            jwt_exp: Some(42),
        };
        
        // Pass the temp directory path to the function being tested.
        write_session(&session, Some(&ctx.path)).await.unwrap();
        
        // Pass the temp directory path to read from the correct location.
        let loaded = read_session(Some(&ctx.path)).await.unwrap();
        
        assert_eq!(loaded.login, session.login);
        assert_eq!(loaded.jwt, session.jwt);
        assert_eq!(loaded.jwt_exp, session.jwt_exp);
    }

    #[tokio::test]
    async fn test_remove_missing_session_ok() {
        let ctx = TestContext::new();
        // Pass the temp directory path to ensure we operate in the isolated test environment.
        remove_session(Some(&ctx.path)).await.unwrap();
    }
}
