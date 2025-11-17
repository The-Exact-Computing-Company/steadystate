// backend/src/auth/gitlab.rs

use std::sync::Arc;
use anyhow::anyhow;
use async_trait::async_trait;

use crate::auth::provider::{
    AuthProvider, AuthProviderDyn, AuthProviderFactory, DevicePollOutcome,
};
use crate::models::{DeviceStartResponse, ProviderId};
use crate::state::AppState;

// --- Provider Stub ---
#[derive(Debug)] // <-- ADDED THIS LINE
pub struct GitLabAuth;

// ... (rest of the file is unchanged) ...
#[async_trait]
impl AuthProvider for GitLabAuth {
    fn id(&self) -> ProviderId {
        ProviderId::from("gitlab")
    }

    async fn start_device_flow(&self) -> anyhow::Result<DeviceStartResponse> {
        Err(anyhow!("GitLab device flow is not implemented yet"))
    }

    async fn poll_device_flow(&self, _device_code: &str) -> anyhow::Result<DevicePollOutcome> {
        Err(anyhow!("GitLab device flow is not implemented yet"))
    }
}

// --- Factory Stub ---
pub struct GitLabFactory;

#[async_trait]
impl AuthProviderFactory for GitLabFactory {
    fn id(&self) -> &'static str {
        "gitlab"
    }

    async fn build(self: Arc<Self>, _state: &AppState) -> anyhow::Result<AuthProviderDyn> {
        Err(anyhow!("The 'gitlab' provider is not configured on the server"))
    }
}  
