// backend/src/state.rs

use std::{collections::HashMap, sync::Arc, time::Duration};
use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use reqwest::Client;
use tracing::info;
use uuid::Uuid;

use crate::auth;
use crate::auth::provider::{AuthProviderDyn, AuthProviderFactoryDyn};
use crate::compute::local_provider::LocalComputeProvider;
use crate::compute::ComputeProvider;
use crate::jwt::JwtKeys;
use crate::models::{PendingDevice, ProviderId, RefreshRecord, Session};

pub type SessionStore = DashMap<String, Session>;

// --- Centralized Configuration ---
#[derive(Clone)]
pub struct Config {
    // Auth Keys
    pub enable_fake_auth: bool,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub gitlab_client_id: Option<String>,
    pub gitlab_client_secret: Option<String>,
    pub orchid_client_id: Option<String>,
    pub orchid_client_secret: Option<String>,
    
    // Timeouts & TTLs
    pub device_poll_interval: u64,
    pub jwt_ttl_secs: u64,
    pub refresh_ttl_secs: u64,

    // Compute
    pub noenv_flake_path: String,
    pub default_compute_provider: String,
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
                .ok().and_then(|s| s.parse().ok()).unwrap_or(15),
            jwt_ttl_secs: std::env::var("JWT_TTL_SECS")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(900),
            refresh_ttl_secs: std::env::var("REFRESH_TTL_SECS")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(14 * 24 * 3600),
            
            noenv_flake_path: std::env::var("NOENV_FLAKE_PATH")
                .context("NOENV_FLAKE_PATH must be set")?,
            default_compute_provider: std::env::var("DEFAULT_COMPUTE_PROVIDER")
                .unwrap_or_else(|_| "local".to_string()),
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

    // Compute & Session state
    pub sessions: SessionStore,
    // Map is wrapped in Arc to allow cheap cloning of AppState
    pub compute_providers: Arc<HashMap<String, Arc<dyn ComputeProvider>>>,
}

impl AppState {
    pub async fn try_new() -> anyhow::Result<Arc<Self>> {
        // 1. Load Config first to fail fast on missing env vars
        let config = Config::from_env()?;

        let http = Client::builder()
            .user_agent("steadystate-backend/0.1")
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(8)
            .build()
            .context("build reqwest client")?;

        let secret = std::env::var("JWT_SECRET").context("JWT_SECRET not set")?;
        let issuer = std::env::var("JWT_ISSUER").unwrap_or("steadystate".into());
        let jwt = JwtKeys::new(&secret, &issuer, config.jwt_ttl_secs);

        // 2. Setup Compute Providers
        let mut compute_providers = HashMap::<String, Arc<dyn ComputeProvider>>::new();

        // Initialize local provider using config path
        let local_provider = Arc::new(LocalComputeProvider::new(config.noenv_flake_path.clone().into()));
        compute_providers.insert(local_provider.id().to_string(), local_provider);

        // 3. Build State
        let state = Arc::new(Self {
            http,
            jwt,
            config,
            device_pending: Arc::new(DashMap::new()),
            refresh_store: Arc::new(DashMap::new()),
            providers: Arc::new(DashMap::new()),
            provider_factories: Arc::new(DashMap::new()),
            sessions: SessionStore::new(),
            compute_providers: Arc::new(compute_providers),
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

        self.refresh_store.insert(token.clone(), RefreshRecord {
            login,
            provider,
            expires_at,
        });

        token
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
} 
