// backend/src/state.rs

use std::{sync::Arc, time::Duration};
use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use reqwest::Client;
use tracing::info;
use uuid::Uuid;

use crate::auth;
use crate::auth::provider::{AuthProviderDyn, AuthProviderFactoryDyn};
use crate::jwt::JwtKeys;
use crate::models::{PendingDevice, ProviderId, RefreshRecord};

// --- Centralized Configuration ---
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

pub struct AppState {
    pub http: Client,
    pub jwt: JwtKeys,
    pub device_max_interval: u64,
    pub config: Config,

    // Device flow: device_code -> PendingDevice
    pub device_pending: DashMap<String, PendingDevice>,

    // Refresh tokens: token -> record
    pub refresh_store: DashMap<String, RefreshRecord>,

    // Lazily populated cache of active providers
    pub providers: DashMap<ProviderId, AuthProviderDyn>,

    // Registry of available provider factories
    pub provider_factories: DashMap<String, AuthProviderFactoryDyn>,
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

        let state = Arc::new(Self {
            http,
            jwt,
            device_max_interval: *DEFAULT_DEVICE_POLL_MAX_INTERVAL_SECS,
            config: Config::from_env(),
            device_pending: DashMap::new(),
            refresh_store: DashMap::new(),
            providers: DashMap::new(),
            provider_factories: DashMap::new(),
        });

        // Register all available provider factories at startup.
        auth::register_builtin_providers(&state);

        Ok(state)
    }
    
    /// Registers a factory for creating an authentication provider.
    pub fn register_provider_factory(&self, factory: AuthProviderFactoryDyn) {
        self.provider_factories.insert(factory.id().to_string(), factory);
    }

    /// Lazily gets or creates an authentication provider.
    /// This ensures the server can start even if some providers are misconfigured.
    pub async fn get_or_create_provider(self: &Arc<Self>, id: &ProviderId) -> Result<AuthProviderDyn> {
        // If the provider is already cached, return it immediately.
        if let Some(provider) = self.providers.get(id) {
            return Ok(provider.clone());
        }

        // Otherwise, find the factory, build the provider, cache it, and return it.
        info!("Initializing provider for the first time: {}", id.as_str());
        
        let key = id.as_str();
        let factory = self.provider_factories
            .get(key)
            .ok_or_else(|| anyhow!("Unknown or unsupported provider: '{}'", key))?
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
