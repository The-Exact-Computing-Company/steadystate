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
// This struct will hold state like the http client and secrets once implemented.
pub struct GitLabAuth;

#[async_trait]
impl AuthProvider for GitLabAuth {
    fn id(&self) -> ProviderId {
        ProviderId::from("gitlab")
    }

    async fn start_device_flow(&self) -> anyhow::Result<DeviceStartResponse> {
        // This will be replaced with a real API call to GitLab.
        Err(anyhow!("GitLab device flow is not implemented yet"))
    }

    async fn poll_device_flow(&self, _device_code: &str) -> anyhow::Result<DevicePollOutcome> {
        // This will be replaced with a real API call to GitLab.
        Err(anyhow!("GitLab device flow is not implemented yet"))
    }
}

// --- Factory Stub ---
// This is responsible for constructing the GitLabAuth provider.
pub struct GitLabFactory;

#[async_trait]
impl AuthProviderFactory for GitLabFactory {
    fn id(&self) -> &'static str {
        "gitlab"
    }

    async fn build(self: Arc<Self>, _state: &AppState) -> anyhow::Result<AuthProviderDyn> {
        // A real implementation would read secrets from `state.config`.
        // For now, we return an error to indicate it's not ready.
        Err(anyhow!("The 'gitlab' provider is not configured on the server"))
    }
}
