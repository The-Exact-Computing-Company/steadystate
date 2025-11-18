// backend/src/state.rs

use std::{collections::HashMap, sync::Arc, time::Duration};
use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use once_cell::sync::Lazy;
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
    pub enable_fake_auth: bool,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub gitlab_client_id: Option<String>,
    pub gitlab_client_secret: Option<String>,
    pub orchid_client_id: Option<String>,
    pub orchid_client_secret: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            enable_fake_auth: std::env::var("ENABLE_FAKE_AUTH").is_ok(),
            github_client_id: std::env::var("GITHUB_CLIENT_ID").ok(),
            github_client_secret: std::env::var("GITHUB_CLIENT_SECRET").ok(),
            gitlab_client_id: std::env::var("GITLAB_CLIENT_ID").ok(),
            gitlab_client_secret: std::env::var("GITLAB_CLIENT_SECRET").ok(),
            orchid_client_id: std::env::var("ORCHID_CLIENT_ID").ok(),
            orchid_client_secret: std::env::var("ORCHID_CLIENT_SECRET").ok(),
        }
    }
}

static DEFAULT_DEVICE_POLL_MAX_INTERVAL_SECS: Lazy<u64> = Lazy::new(|| {
    std::env::var("DEVICE_POLL_MAX_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15)
});

// --- AppState Definition ---
// We implement Clone manually to ensure it's cheap (Arc-based).
#[derive(Clone)]
pub struct AppState {
    pub http: Client,
    pub jwt: JwtKeys,
    pub device_max_interval: u64,
    pub config: Config,

    // Auth state (DashMap is internally Arc'd)
    pub device_pending: DashMap<String, PendingDevice>,
    pub refresh_store: DashMap<String, RefreshRecord>,
    pub providers: DashMap<ProviderId, AuthProviderDyn>,
    pub provider_factories: DashMap<String, AuthProviderFactoryDyn>,

    // Compute & Session state
    pub sessions: SessionStore,
    // Wrapped in Arc for cheap cloning of AppState
    pub compute_providers: Arc<HashMap<String, Arc<dyn ComputeProvider>>>,
    pub default_compute_provider: String,
}

impl AppState {
    pub async fn try_new() -> anyhow::Result<Arc<Self>> {
        let http = Client::builder()
            .user_agent("steadystate-backend/0.1")
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(8)
            .build()
            .context("build reqwest client")?;

        let secret = std::env::var("JWT_SECRET").context("JWT_SECRET not set")?;
        let issuer = std::env::var("JWT_ISSUER").unwrap_or("steadystate".into());
        let ttl = std::env::var("JWT_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(900);

        let jwt = JwtKeys::new(&secret, &issuer, ttl);

        // --- COMPUTE PROVIDER SETUP ---
        let mut compute_providers = HashMap::<String, Arc<dyn ComputeProvider>>::new();

        let noenv_flake_path = std::env::var("NOENV_FLAKE_PATH")
            .context("NOENV_FLAKE_PATH must be set to the absolute path of the backend/flakes/noenv directory")?;
        let local_provider = Arc::new(LocalComputeProvider::new(noenv_flake_path.into()));
        compute_providers.insert(local_provider.id().to_string(), local_provider);

        let default_compute_provider = std::env::var("DEFAULT_COMPUTE_PROVIDER")
            .unwrap_or_else(|_| "local".to_string());

        // --- BUILD FINAL APP STATE ---
        let state = Arc::new(Self {
            http,
            jwt,
            device_max_interval: *DEFAULT_DEVICE_POLL_MAX_INTERVAL_SECS,
            config: Config::from_env(),
            device_pending: DashMap::new(),
            refresh_store: DashMap::new(),
            providers: DashMap::new(),
            provider_factories: DashMap::new(),
            sessions: SessionStore::new(),
            compute_providers: Arc::new(compute_providers), // Wrap in Arc
            default_compute_provider,
        });

        auth::register_builtin_providers(&state);

        Ok(state)
    }
    
    pub fn register_provider_factory(&self, factory: AuthProviderFactoryDyn) {
        self.provider_factories.insert(factory.id().to_string(), factory);
    }

    pub async fn get_or_create_provider(self: &Arc<Self>, id: &ProviderId) -> Result<AuthProviderDyn> {
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
        let ttl_secs: u64 = std::env::var("REFRESH_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(14 * 24 * 3600);

        let expires_at = now() + ttl_secs;

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
