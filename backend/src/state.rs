// backend/src/state.rs

use std::{sync::Arc, time::Duration};
use anyhow::Context;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use reqwest::Client;
use uuid::Uuid;

use crate::auth::{fake::FakeAuth, github::GitHubAuth, provider::AuthProviderDyn};
use crate::jwt::JwtKeys;
use crate::models::{PendingDevice, RefreshRecord, ProviderName};

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

    // Device flow: device_code -> PendingDevice
    pub device_pending: DashMap<String, PendingDevice>,

    // Refresh tokens: token -> record
    pub refresh_store: DashMap<String, RefreshRecord>,

    // Providers registry
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
            device_pending: DashMap::new(),
            refresh_store: DashMap::new(),
            providers: DashMap::new(),
        });

        // Register providers
        let gh = GitHubAuth::from_env(state.clone())?;
        state.providers.insert(ProviderName::GitHub, gh);

        // Register fake provider for testing (enable with env var)
        if std::env::var("ENABLE_FAKE_AUTH").is_ok() {
            state.providers.insert(ProviderName::Fake, FakeAuth::new());
        }

        Ok(state)
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

/// Use the same time base as JwtKeys
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
} 
