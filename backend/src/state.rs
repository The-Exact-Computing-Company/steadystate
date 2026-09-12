// backend/src/state.rs

use std::{collections::HashMap, sync::Arc, time::Duration};
use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use reqwest::Client;
use tracing::info;
use uuid::Uuid;

use crate::auth;
use crate::auth::provider::{AuthProviderDyn, AuthProviderFactoryDyn};
use crate::compute::{ComputeProvider, LocalComputeProvider, LocalProviderConfig, HetznerComputeProvider};
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
    #[allow(dead_code)]
    pub orchid_client_id: Option<String>,
    #[allow(dead_code)]
    pub orchid_client_secret: Option<String>,
    
    // Timeouts & TTLs
    #[allow(dead_code)]
    pub device_poll_interval: u64,
    pub jwt_ttl_secs: u64,
    pub refresh_ttl_secs: u64,
    pub default_session_ttl_secs: u64,
    pub max_session_ttl_secs: u64,
    pub max_sessions_per_user: usize,

    // Compute
    pub noenv_flake_path: String,
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
            orchid_client_id: std::env::var("ORCHID_CLIENT_ID").ok(),
            orchid_client_secret: std::env::var("ORCHID_CLIENT_SECRET").ok(),
            
            device_poll_interval: std::env::var("DEVICE_POLL_MAX_INTERVAL_SECS")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_DEVICE_POLL_INTERVAL),
            jwt_ttl_secs: std::env::var("JWT_TTL_SECS")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_JWT_TTL),
            refresh_ttl_secs: std::env::var("REFRESH_TTL_SECS")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_REFRESH_TTL),
            default_session_ttl_secs: std::env::var("STEADYSTATE_DEFAULT_SESSION_TTL_SECS")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_SESSION_TTL_SECS),
            max_session_ttl_secs: std::env::var("STEADYSTATE_MAX_SESSION_TTL_SECS")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_MAX_SESSION_TTL_SECS),
            max_sessions_per_user: std::env::var("STEADYSTATE_MAX_SESSIONS_PER_USER")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_MAX_SESSIONS_PER_USER),
            
            noenv_flake_path: std::env::var("NOENV_FLAKE_PATH")
                .context("NOENV_FLAKE_PATH must be set")?,
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
    pub refresh_store: Arc<DashMap<String, RefreshRecord>>,
    pub providers: Arc<DashMap<ProviderId, AuthProviderDyn>>,
    pub provider_factories: Arc<DashMap<String, AuthProviderFactoryDyn>>,
    // Key: (provider, login) -> access_token
    pub provider_tokens: Arc<DashMap<(String, String), String>>,

    // Compute & Session state
    pub sessions: SessionStore,
    // Map is wrapped in Arc to allow cheap cloning of AppState
    pub compute_providers: Arc<HashMap<String, Arc<dyn ComputeProvider>>>,

    // Durable backing store (SQLite). DashMaps above stay the live store.
    pub storage: Arc<Storage>,
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
                .unwrap_or_else(|_| dirs::home_dir().expect("HOME not set").join(".steadystate").join("sessions")),
            flake_path: config.noenv_flake_path.clone().into(),
        };
        let local_provider = Arc::new(LocalComputeProvider::new(provider_config, http.clone()));
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
        let storage = Arc::new(Storage::open(&config.db_path)?);
        let sessions = SessionStore::new();
        match storage.load_sessions() {
            Ok(saved) => {
                for s in saved {
                    sessions.insert(s.id.clone(), s);
                }
                tracing::info!("Rehydrated {} session(s) from {}", sessions.len(), config.db_path.display());
            }
            Err(e) => tracing::warn!("Failed to load sessions from {}: {:#}", config.db_path.display(), e),
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
                if let Ok(pruned) = storage.prune_expired_refresh(now) {
                    if pruned > 0 {
                        tracing::info!("Pruned {} expired refresh token(s)", pruned);
                    }
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
            refresh_store,
            providers: Arc::new(DashMap::new()),
            provider_factories: Arc::new(DashMap::new()),
            provider_tokens: Arc::new(load_tokens()),
            sessions,
            compute_providers: Arc::new(compute_providers),
            storage,
        });

        // 4. Register Auth Providers
        auth::register_builtin_providers(&state);

        Ok(state)
    }
    
    pub fn register_provider_factory(&self, factory: AuthProviderFactoryDyn) {
        self.provider_factories.insert(factory.id().to_string(), factory);
    }

    pub async fn get_or_create_provider(&self, id: &ProviderId) -> Result<AuthProviderDyn> {
        if let Some(provider) = self.providers.get(id) {
            return Ok(provider.clone());
        }

        info!("Initializing auth provider for the first time: {}", id.as_str());
        
        let key = id.as_str();
        let factory = self.provider_factories
            .get(key)
            .ok_or_else(|| anyhow!("Unknown or unsupported auth provider: '{}'", key))?
            .clone();

        let provider = factory.build(self).await?;
        self.providers.insert(id.clone(), provider.clone());
        Ok(provider)
    }

    pub fn issue_refresh_token(&self, login: String, provider: ProviderId) -> String {
        let token = Uuid::new_v4().to_string();

        // Use cached TTL from config
        let expires_at = now() + self.config.refresh_ttl_secs;

        let rec = RefreshRecord {
            login,
            provider,
            expires_at,
        };
        self.refresh_store.insert(token.clone(), rec.clone());
        if let Err(e) = self.storage.save_refresh(&token, &rec) {
            tracing::warn!("Failed to persist refresh token: {:#}", e);
        }

        token
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

    /// Write-through persistence for one session record.
    /// Best-effort: logs on failure so storage outages degrade to
    /// in-memory behavior instead of failing requests.
    pub fn persist_session(&self, id: &str) {
        if let Some(s) = self.sessions.get(id) {
            let owned = s.clone();
            drop(s);
            if let Err(e) = self.storage.save_session(&owned) {
                tracing::warn!("Failed to persist session {}: {:#}", id, e);
            }
        }
    }

    /// Remove a refresh token from both live and durable stores.
    pub fn revoke_refresh_token(&self, token: &str) {
        self.refresh_store.remove(token);
        if let Err(e) = self.storage.delete_refresh(token) {
            tracing::warn!("Failed to delete persisted refresh token: {:#}", e);
        }
    }
    pub fn save_tokens(&self) -> Result<()> {
        let home = std::env::var("HOME").context("HOME not set")?;
        let dir = std::path::PathBuf::from(home).join(".steadystate");
        std::fs::create_dir_all(&dir)?;
        let file_path = dir.join("tokens.json");

        let mut map = HashMap::new();
        for item in self.provider_tokens.iter() {
            let (key, value) = item.pair();
            // key is (provider, login)
            map.insert(format!("{}:{}", key.0, key.1), value.clone());
        }

        let json = serde_json::to_string_pretty(&map)?;
        std::fs::write(file_path, json)?;
        Ok(())
    }
}

fn load_tokens() -> DashMap<(String, String), String> {

    let dash = DashMap::new();
    if let Ok(home) = std::env::var("HOME") {
        let file_path = std::path::PathBuf::from(home).join(".steadystate").join("tokens.json");
        if file_path.exists() {
            if let Ok(content) = std::fs::read_to_string(file_path) {
                if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&content) {
                    for (k, v) in map {
                        if let Some((provider, login)) = k.split_once(':') {
                            dash.insert((provider.to_string(), login.to_string()), v);
                        }
                    }
                    info!("Loaded {} tokens from disk", dash.len());
                }
            }
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
/// Poison-tolerant: a panicking test must not cascade into the rest.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn lock_test_env() -> std::sync::MutexGuard<'static, ()> {
    TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
} 
