// backend/src/state.rs

use anyhow::{Context, Result, anyhow};
use dashmap::DashMap;
use reqwest::Client;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::info;
use uuid::Uuid;

use crate::auth;
use crate::auth::oidc::OidcPending;
use crate::auth::provider::{AuthProviderDyn, AuthProviderFactoryDyn};
use crate::compute::{
    ComputeProvider, HetznerComputeProvider, LocalComputeProvider, LocalProviderConfig,
};
use crate::jwt::JwtKeys;
use crate::models::{PendingDevice, ProviderId, RefreshRecord, Session};
use crate::storage::Storage;

pub type SessionStore = DashMap<String, Session>;

const DEFAULT_DEVICE_POLL_INTERVAL: u64 = 15;
const DEFAULT_JWT_TTL: u64 = 900; // 15 minutes
const DEFAULT_REFRESH_TTL: u64 = 14 * 24 * 3600; // 14 days
/// Default session lifetime: 48h. Sessions are reaped past expiry.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 48 * 3600;
/// Upper bound for requested lifetimes: 7 days. 0 = no upper bound.
pub const DEFAULT_MAX_SESSION_TTL_SECS: u64 = 7 * 24 * 3600;
/// Max live (Provisioning/Running) sessions per user. 0 = unlimited.
pub const DEFAULT_MAX_SESSIONS_PER_USER: usize = 5;
/// Idle timeout: Running sessions with no observed activity older than this
/// are reaped. 0 disables idle reaping (lifetime expiry still applies).
pub const DEFAULT_IDLE_TTL_SECS: u64 = 2 * 3600;
const HTTP_POOL_MAX_IDLE_PER_HOST: usize = 8;

// --- Centralized Configuration ---
#[derive(Clone)]
pub struct Config {
    // Auth Keys
    pub enable_fake_auth: bool,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    #[allow(dead_code)]
    pub gitlab_client_id: Option<String>,
    #[allow(dead_code)]
    pub gitlab_client_secret: Option<String>,

    // Timeouts & TTLs
    #[allow(dead_code)]
    pub device_poll_interval: u64,
    pub jwt_ttl_secs: u64,
    pub refresh_ttl_secs: u64,
    pub default_session_ttl_secs: u64,
    pub max_session_ttl_secs: u64,
    pub max_sessions_per_user: usize,
    pub idle_ttl_secs: u64,

    // Compute
    pub default_compute_provider: String,

    // Storage
    pub db_path: std::path::PathBuf,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            enable_fake_auth: std::env::var("ENABLE_FAKE_AUTH").is_ok(),
            github_client_id: std::env::var("GITHUB_CLIENT_ID").ok(),
            github_client_secret: std::env::var("GITHUB_CLIENT_SECRET").ok(),
            gitlab_client_id: std::env::var("GITLAB_CLIENT_ID").ok(),
            gitlab_client_secret: std::env::var("GITLAB_CLIENT_SECRET").ok(),

            device_poll_interval: std::env::var("DEVICE_POLL_MAX_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_DEVICE_POLL_INTERVAL),
            jwt_ttl_secs: std::env::var("JWT_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_JWT_TTL),
            refresh_ttl_secs: std::env::var("REFRESH_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_REFRESH_TTL),
            default_session_ttl_secs: std::env::var("STEADYSTATE_DEFAULT_SESSION_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_SESSION_TTL_SECS),
            max_session_ttl_secs: std::env::var("STEADYSTATE_MAX_SESSION_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_MAX_SESSION_TTL_SECS),
            max_sessions_per_user: std::env::var("STEADYSTATE_MAX_SESSIONS_PER_USER")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_MAX_SESSIONS_PER_USER),
            idle_ttl_secs: std::env::var("STEADYSTATE_IDLE_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_IDLE_TTL_SECS),

            default_compute_provider: std::env::var("STEADYSTATE_PROVIDER")
                .unwrap_or_else(|_| "local".to_string()),

            db_path: std::env::var("STEADYSTATE_DB_PATH")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| {
                    dirs::home_dir()
                        .expect("HOME not set")
                        .join(".steadystate")
                        .join("steadystate.db")
                }),
        })
    }
}

// --- AppState Definition ---
// Derived Clone is now efficient because complex types are wrapped in Arc/DashMap.
#[derive(Clone)]
pub struct AppState {
    pub http: Client,
    pub jwt: JwtKeys,
    pub config: Config,

    // Auth state
    pub device_pending: Arc<DashMap<String, PendingDevice>>,
    pub oidc_pending: Arc<DashMap<String, OidcPending>>,
    pub refresh_store: Arc<DashMap<String, RefreshRecord>>,
    pub providers: Arc<DashMap<ProviderId, AuthProviderDyn>>,
    pub provider_factories: Arc<DashMap<String, AuthProviderFactoryDyn>>,
    // Lazily-initialized OIDC config (discovery runs once; restart to reload).
    pub oidc_config: Arc<tokio::sync::OnceCell<Arc<crate::auth::oidc::OidcConfig>>>,
    // Key: (provider, login) -> access_token
    pub provider_tokens: Arc<DashMap<(String, String), String>>,

    // Compute & Session state
    pub sessions: SessionStore,
    // Map is wrapped in Arc to allow cheap cloning of AppState
    pub compute_providers: Arc<HashMap<String, Arc<dyn ComputeProvider>>>,

    // Durable backing store (SQLite). DashMaps above stay the live store.
    pub storage: Arc<Storage>,
    /// Per-user creation mutexes: held across cap-check + insert so
    /// concurrent creates cannot jointly exceed the per-user cap (TOCTOU).
    /// Entries are never removed (one small mutex per user seen); the
    /// memory cost is negligible next to a session.
    pub creation_locks: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl AppState {
    pub async fn try_new() -> anyhow::Result<Arc<Self>> {
        // 1. Load Config first to fail fast on missing env vars
        let config = Config::from_env()?;

        tracing::info!(
            "Durable storage: {}. Device-flow pending entries stay in-memory; \
             live compute handles (PIDs, SSH) do not survive restarts.",
            config.db_path.display(),
        );

        let http = Client::builder()
            .user_agent("steadystate-backend/0.1")
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(HTTP_POOL_MAX_IDLE_PER_HOST)
            .build()
            .context("build reqwest client")?;

        let secret = std::env::var("JWT_SECRET").context("JWT_SECRET not set")?;
        let issuer = std::env::var("JWT_ISSUER").unwrap_or("steadystate".into());
        let jwt = JwtKeys::new(&secret, &issuer, config.jwt_ttl_secs);

        // 2. Setup Compute Providers
        let mut compute_providers = HashMap::<String, Arc<dyn ComputeProvider>>::new();

        // Initialize local provider using config path
        let provider_config = LocalProviderConfig {
            session_root: std::env::var("STEADYSTATE_SESSION_ROOT")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| {
                    dirs::home_dir()
                        .expect("HOME not set")
                        .join(".steadystate")
                        .join("sessions")
                }),
        };
        let local_provider = Arc::new(LocalComputeProvider::new(provider_config));
        compute_providers.insert(local_provider.id().to_string(), local_provider);

        // Initialize hetzner provider if configured (HCLOUD_TOKEN present).
        match HetznerComputeProvider::into_arc(http.clone()) {
            Ok(h) => {
                tracing::info!("Hetzner compute provider enabled");
                compute_providers.insert(h.id().to_string(), h);
            }
            Err(e) => {
                tracing::info!("Hetzner provider disabled: {:#}", e);
            }
        }

        // 2b. Open durable storage and rehydrate live maps.
        // Live provider handles (PIDs, SSH) cannot survive a restart, so
        // resumed sessions report Unknown health until re-provisioned —
        // but their records, endpoints and magic links are preserved.
        // Transient states cannot survive either: no provisioning or
        // termination task exists anymore, so Provisioning/Terminating rows
        // are failed explicitly (never silently stuck, never resurrected).
        // Activity observations are clamped to restart time: post-restart we
        // cannot observe anything, so every resumed session gets one full
        // idle TTL of grace instead of being reaped on stale signals.
        let storage = Arc::new(Storage::open(&config.db_path)?);
        let sessions = SessionStore::new();
        match storage.load_sessions() {
            Ok(saved) => {
                let boot = std::time::SystemTime::now();
                let mut fixed = 0;
                for mut s in saved {
                    let mut touched = false;
                    if matches!(
                        s.state,
                        crate::models::SessionState::Provisioning
                            | crate::models::SessionState::Terminating
                    ) {
                        tracing::warn!(
                            "Session {} was {:?} across a restart; marking Failed",
                            s.id,
                            s.state
                        );
                        s.state = crate::models::SessionState::Failed;
                        s.error_message = Some(
                            "Backend restarted mid-transition; provisioning/termination did not complete. Retry or terminate again.".to_string(),
                        );
                        s.updated_at = boot;
                        touched = true;
                    }
                    if s.last_activity_at.map(|a| a < boot).unwrap_or(true) {
                        s.last_activity_at = Some(boot);
                        touched = true;
                    }
                    if touched {
                        fixed += 1;
                        if let Err(e) = storage.save_session(&s) {
                            tracing::warn!("Failed to persist fixed session {}: {:#}", s.id, e);
                        }
                    }
                    sessions.insert(s.id.clone(), s);
                }
                tracing::info!(
                    "Rehydrated {} session(s) from {} ({} transitioned)",
                    sessions.len(),
                    config.db_path.display(),
                    fixed
                );
            }
            Err(e) => tracing::warn!(
                "Failed to load sessions from {}: {:#}",
                config.db_path.display(),
                e
            ),
        }
        let refresh_store = Arc::new(DashMap::new());
        match storage.load_refresh() {
            Ok(tokens) => {
                let now = now();
                let mut live = 0;
                for (token, rec) in tokens {
                    if rec.expires_at > now {
                        refresh_store.insert(token, rec);
                        live += 1;
                    }
                }
                // Drop expired rows so the table does not grow forever.
                if let Ok(pruned) = storage.prune_expired_refresh(now)
                    && pruned > 0
                {
                    tracing::info!("Pruned {} expired refresh token(s)", pruned);
                }
                tracing::info!("Rehydrated {} live refresh token(s)", live);
            }
            Err(e) => tracing::warn!("Failed to load refresh tokens: {:#}", e),
        }

        // 3. Build State
        let state = Arc::new(Self {
            http,
            jwt,
            config,
            device_pending: Arc::new(DashMap::new()),
            oidc_pending: Arc::new(DashMap::new()),
            refresh_store,
            providers: Arc::new(DashMap::new()),
            provider_factories: Arc::new(DashMap::new()),
            provider_tokens: Arc::new(load_tokens()),
            sessions,
            compute_providers: Arc::new(compute_providers),
            storage,
            oidc_config: Arc::new(tokio::sync::OnceCell::new()),
            creation_locks: Arc::new(DashMap::new()),
        });

        // 4. Register Auth Providers
        auth::register_builtin_providers(&state);

        Ok(state)
    }

    pub fn register_provider_factory(&self, factory: AuthProviderFactoryDyn) {
        self.provider_factories
            .insert(factory.id().to_string(), factory);
    }

    pub async fn get_or_create_provider(&self, id: &ProviderId) -> Result<AuthProviderDyn> {
        if let Some(provider) = self.providers.get(id) {
            return Ok(provider.clone());
        }

        info!(
            "Initializing auth provider for the first time: {}",
            id.as_str()
        );

        let key = id.as_str();
        let factory = self
            .provider_factories
            .get(key)
            .ok_or_else(|| anyhow!("Unknown or unsupported auth provider: '{}'", key))?
            .clone();

        let provider = factory.build(self).await?;
        self.providers.insert(id.clone(), provider.clone());
        Ok(provider)
    }

    /// Issue a refresh token, persisting it before returning. Hard error on
    /// storage failure (with the in-memory entry rolled back) so a caller
    /// never hands out a token that would vanish on restart.
    pub async fn issue_refresh_token(&self, login: String, provider: ProviderId) -> Result<String> {
        let token = Uuid::new_v4().to_string();
        let expires_at = now() + self.config.refresh_ttl_secs;

        let rec = RefreshRecord {
            login,
            provider,
            expires_at,
        };
        self.storage
            .clone()
            .save_refresh_async(token.clone(), rec.clone())
            .await
            .context("persist refresh token")?;
        self.refresh_store.insert(token.clone(), rec);
        Ok(token)
    }

    /// Effective lifetime in seconds for a create request: the requested
    /// TTL clamped to the server max, or the server default when absent.
    /// A max of 0 disables the upper bound.
    pub fn session_ttl(&self, requested: Option<u64>) -> u64 {
        let ttl = requested.unwrap_or(self.config.default_session_ttl_secs);
        if self.config.max_session_ttl_secs == 0 {
            ttl
        } else {
            ttl.min(self.config.max_session_ttl_secs)
        }
    }

    /// Count of the user's live (Provisioning/Running) sessions,
    /// used for per-user cap enforcement.
    pub fn live_session_count(&self, login: &str) -> usize {
        use crate::models::SessionState;
        self.sessions
            .iter()
            .filter(|e| {
                e.creator_login == login
                    && matches!(e.state, SessionState::Provisioning | SessionState::Running)
            })
            .count()
    }

    /// Lock serializing one user's session creation (cap-check + insert).
    /// Returned guard must be held across both operations.
    pub fn creation_lock(&self, login: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.creation_locks
            .entry(login.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Write-through persistence for one session record, off the async
    /// runtime. Best-effort: the in-memory map is the source of truth for
    /// the live process, and a storage outage degrades to in-memory
    /// behavior rather than failing the request that triggered the write.
    pub async fn persist_session(&self, id: &str) {
        if let Some(s) = self.sessions.get(id) {
            let owned = s.clone();
            drop(s);
            if let Err(e) = self.storage.clone().save_session_async(owned).await {
                tracing::error!("Failed to persist session {}: {:#}", id, e);
            }
        }
    }

    /// Load (once) the OIDC configuration, running discovery on first use.
    /// Returns a 503-style error when OIDC is not configured.
    pub async fn oidc(&self) -> anyhow::Result<Arc<crate::auth::oidc::OidcConfig>> {
        self.oidc_config
            .get_or_try_init(|| async {
                let cfg = crate::auth::oidc::OidcConfig::from_env(&self.http).await?;
                Ok::<_, anyhow::Error>(Arc::new(cfg))
            })
            .await
            .cloned()
    }

    /// Remove expired OIDC pending logins. Called lazily on start/complete.
    pub fn prune_oidc_pending(&self) {
        let cutoff = now().saturating_sub(crate::auth::oidc::OIDC_PENDING_TTL_SECS);
        self.oidc_pending.retain(|_, p| p.created_at >= cutoff);
    }

    /// Remove expired device-flow pending logins and refresh tokens from the
    /// in-memory maps (the DB side is pruned by the reaper). Called lazily
    /// from auth routes; keeps the maps bounded without a background task.
    pub fn prune_auth_state(&self) {
        let cutoff = now();
        self.device_pending.retain(|_, p| p.expires_at > cutoff);
        self.refresh_store.retain(|_, r| r.expires_at > cutoff);
        self.prune_oidc_pending();
    }

    /// Remove a refresh token from both live and durable stores.
    /// On storage failure the live entry is restored and an error returned,
    /// so memory and disk never disagree about whether a token is revoked
    /// (a restart must not resurrect a revoked token).
    pub async fn revoke_refresh_token(&self, token: &str) -> Result<()> {
        let removed = self.refresh_store.remove(token).map(|(_, v)| v);
        if let Err(e) = self
            .storage
            .clone()
            .delete_refresh_async(token.to_string())
            .await
        {
            if let Some(rec) = removed {
                self.refresh_store.insert(token.to_string(), rec);
            }
            return Err(e).context("delete refresh token from storage");
        }
        Ok(())
    }
    pub fn save_tokens(&self) -> Result<()> {
        let home = std::env::var("HOME").context("HOME not set")?;
        let dir = std::path::PathBuf::from(home).join(".steadystate");
        std::fs::create_dir_all(&dir)?;

        let mut map = HashMap::new();
        for item in self.provider_tokens.iter() {
            let (key, value) = item.pair();
            // key is (provider, login)
            map.insert(format!("{}:{}", key.0, key.1), value.clone());
        }

        let json = serde_json::to_string_pretty(&map)?;
        let file_path = dir.join("tokens.json");
        write_private_file(&file_path, json.as_bytes())?;
        Ok(())
    }
}

/// Write a file with 0600 permissions from creation (not after), so forge
/// tokens are never briefly world-readable regardless of umask.
fn write_private_file(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    f.write_all(contents)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn load_tokens() -> DashMap<(String, String), String> {
    let dash = DashMap::new();
    if let Ok(home) = std::env::var("HOME") {
        let file_path = std::path::PathBuf::from(home)
            .join(".steadystate")
            .join("tokens.json");
        if file_path.exists()
            && let Ok(content) = std::fs::read_to_string(file_path)
            && let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&content)
        {
            for (k, v) in map {
                if let Some((provider, login)) = k.split_once(':') {
                    dash.insert((provider.to_string(), login.to_string()), v);
                }
            }
            info!("Loaded {} tokens from disk", dash.len());
        }
    }
    dash
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("System time is before UNIX EPOCH")
        .as_secs()
}

/// Process-wide lock serializing tests that mutate process environment.
/// Env vars are global mutable state; without this, parallel tests that
/// set/remove vars (e.g. `HCLOUD_TOKEN`, `JWT_SECRET`) race each other.
/// A tokio mutex (not std) so holding it across `.await` is correct.
/// Poison-tolerant: a panicking test must not cascade into the rest.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
pub(crate) async fn lock_test_env() -> tokio::sync::MutexGuard<'static, ()> {
    TEST_ENV_LOCK.lock().await
}
