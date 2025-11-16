// backend/src/state.rs

use std::{sync::Arc, time::Duration};
use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use reqwest::Client;
use tracing::info;
use uuid::Uuid;

use crate::auth::{fake::FakeAuth, github::GitHubAuth, provider::AuthProviderDyn};
use crate::jwt::JwtKeys;
use crate::models::{PendingDevice, RefreshRecord, ProviderName};

// --- Centralized Configuration ---
pub struct Config {
    pub enable_fake_auth: bool,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            enable_fake_auth: std::env::var("ENABLE_FAKE_AUTH").is_ok(),
            github_client_id: std::env::var("GITHUB_CLIENT_ID").ok(),
            github_client_secret: std::env::var("GITHUB_CLIENT_SECRET").ok(),
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
    pub providers: DashMap<ProviderName, AuthProviderDyn>,
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
            providers: DashMap::new(), // Cache is empty at startup
        });

        Ok(state)
    }

    /// Lazily gets or creates an authentication provider.
    /// This ensures the server can start even if some providers are misconfigured.
    pub fn get_or_create_provider(self: &Arc<Self>, name: ProviderName) -> Result<AuthProviderDyn> {
        // If the provider is already cached, return it immediately.
        if let Some(provider) = self.providers.get(&name) {
            return Ok(provider.clone());
        }

        // Otherwise, try to create it, then cache and return it.
        info!("Initializing provider for the first time: {:?}", name);
        let provider: AuthProviderDyn = match name {
            ProviderName::GitHub => {
                let client_id = self.config.github_client_id.clone()
                    .context("GITHUB_CLIENT_ID is not configured on the server")?;
                let client_secret = self.config.github_client_secret.clone()
                    .context("GITHUB_CLIENT_SECRET is not configured on the server")?;
                
                GitHubAuth::new(self.http.clone(), client_id, client_secret)
            }
            ProviderName::Fake => {
                if !self.config.enable_fake_auth {
                    return Err(anyhow!("The 'fake' provider is not enabled on this server"));
                }
                FakeAuth::new()
            }
            // When you add GitLab, the logic will go here.
            ProviderName::GitLab | ProviderName::Orchid => {
                return Err(anyhow!("Provider '{}' is not implemented yet", name.as_str()));
            }
        };

        self.providers.insert(name, provider.clone());
        Ok(provider)
    }

    pub fn issue_refresh_token(&self, login: String, provider: ProviderName) -> String {
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
