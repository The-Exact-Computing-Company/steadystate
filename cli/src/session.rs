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
    /// Auth provider id ("github", "gitlab", ...). Absent in sessions
    /// written before provider tracking existed — treated as "github".
    #[serde(default)]
    pub provider: Option<String>,
}

impl Session {
    pub fn new(login: String, jwt: String) -> Self {
        Self::with_provider(login, jwt, None)
    }

    pub fn with_provider(login: String, jwt: String, provider: Option<String>) -> Self {
        let jwt_exp = extract_exp_from_jwt(&jwt);
        Self {
            login,
            jwt,
            jwt_exp,
            provider,
        }
    }

    /// Provider id, defaulting to "github" for legacy session files.
    pub fn provider_or_default(&self) -> &str {
        self.provider.as_deref().unwrap_or("github")
    }

    pub fn is_near_expiry(&self, buffer_secs: u64) -> bool {
        if let Some(exp) = self.jwt_exp {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("System time is before UNIX EPOCH")
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
    use tempfile::{TempDir, tempdir};

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
    async fn test_is_near_expiry_true_when_within_buffer() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let exp = now + 30; // expires in 30 seconds
        let session = Session {
            login: "u".into(),
            jwt: "t".into(),
            provider: None,
            jwt_exp: Some(exp),
        };

        assert!(session.is_near_expiry(60)); // buffer 60s → should return true
    }

    #[tokio::test]
    async fn test_is_near_expiry_false_when_outside_buffer() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let exp = now + 300; // expires in 5 minutes
        let session = Session {
            login: "u".into(),
            jwt: "t".into(),
            provider: None,
            jwt_exp: Some(exp),
        };

        assert!(!session.is_near_expiry(60)); // buffer 60s → should return false
    }

    #[tokio::test]
    async fn test_is_near_expiry_none_expiry_means_false() {
        let session = Session {
            login: "u".into(),
            jwt: "t".into(),
            provider: None,
            jwt_exp: None,
        };

        assert!(!session.is_near_expiry(60));
    }

    #[tokio::test]
    async fn test_is_near_expiry_exact_boundary() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let exp = now + 60;
        let session = Session {
            login: "u".into(),
            jwt: "t".into(),
            provider: None,
            jwt_exp: Some(exp),
        };

        // Expiration equals now + buffer → treat as near expiry
        assert!(session.is_near_expiry(60));
    }

    #[tokio::test]
    async fn test_write_read_cycle() {
        let ctx = TestContext::new();

        // Ensure no session exists by passing the temp directory path.
        remove_session(Some(&ctx.path)).await.unwrap();

        let session = Session {
            login: "test_user".into(),
            jwt: "fake_jwt".into(),
            provider: None,
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

    #[test]
    fn test_provider_defaults_to_github() {
        let legacy = Session {
            login: "u".into(),
            jwt: "t".into(),
            jwt_exp: None,
            provider: None,
        };
        assert_eq!(legacy.provider_or_default(), "github");

        let gl = Session::with_provider("u".into(), "t".into(), Some("gitlab".into()));
        assert_eq!(gl.provider_or_default(), "gitlab");

        // Legacy JSON without the provider key still parses.
        let parsed: Session =
            serde_json::from_str(r#"{"login":"u","jwt":"t","jwt_exp":null}"#).unwrap();
        assert_eq!(parsed.provider_or_default(), "github");
    }
}
