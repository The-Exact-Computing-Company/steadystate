// backend/src/auth/provider.rs

use std::sync::Arc;
use async_trait::async_trait;
use serde::Serialize;
use crate::{
    models::{DeviceStartResponse, ProviderId},
    state::AppState,
};

#[derive(Clone, Debug, Serialize)]
pub struct UserIdentity {
    pub id: String,
    pub login: String,
    pub email: Option<String>,
    pub provider: String, // "github" | "gitlab" | ...
}

pub enum DevicePollOutcome {
    Pending,
    SlowDown,
    Complete {
        identity: UserIdentity,
        provider_access_token: Option<String>,
    },
}

// Any type implementing AuthProvider must also implement Debug, Send, and Sync.
#[async_trait]
pub trait AuthProvider: std::fmt::Debug + Send + Sync {
    #[allow(dead_code)]
    fn id(&self) -> ProviderId;
    async fn start_device_flow(&self) -> anyhow::Result<DeviceStartResponse>;
    async fn poll_device_flow(
        &self,
        device_code: &str,
    ) -> anyhow::Result<DevicePollOutcome>;
}

pub type AuthProviderDyn = Arc<dyn AuthProvider>;

#[async_trait]
pub trait AuthProviderFactory: Send + Sync {
    fn id(&self) -> &'static str;
    async fn build(self: Arc<Self>, state: &AppState) -> anyhow::Result<AuthProviderDyn>;
}

pub type AuthProviderFactoryDyn = Arc<dyn AuthProviderFactory>;  
