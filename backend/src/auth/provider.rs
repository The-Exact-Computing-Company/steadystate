use async_trait::async_trait;
use serde::Serialize;

use crate::models::{DeviceStartResponse, ProviderName};

#[derive(Clone, Debug, Serialize)]
pub struct UserIdentity {
    pub id: String,
    pub login: String,
    pub email: Option<String>,
    pub provider: String, // "github" | "gitlab" | ...
}

#[async_trait]
pub trait AuthProvider: Send + Sync {
    fn name(&self) -> ProviderName;

    async fn start_device_flow(&self) -> anyhow::Result<DeviceStartResponse>;

    async fn poll_device_flow(&self, device_code: &str) -> anyhow::Result<UserIdentity>;
}

// type-erased provider
pub type AuthProviderDyn = std::sync::Arc<dyn AuthProvider>;
