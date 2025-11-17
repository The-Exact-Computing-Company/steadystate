// backend/src/auth/orchid.rs

use std::sync::Arc;
use anyhow::anyhow;
use async_trait::async_trait;

use crate::auth::provider::{
    AuthProvider, AuthProviderDyn, AuthProviderFactory, DevicePollOutcome,
};
use crate::models::{DeviceStartResponse, ProviderId};
use crate::state::AppState;

// --- Provider Stub ---
pub struct OrchidAuth;

#[async_trait]
impl AuthProvider for OrchidAuth {
    fn id(&self) -> ProviderId {
        ProviderId::from("orchid")
    }

    async fn start_device_flow(&self) -> anyhow::Result<DeviceStartResponse> {
        Err(anyhow!("Orchid device flow is not implemented yet"))
    }

    async fn poll_device_flow(&self, _device_code: &str) -> anyhow::Result<DevicePollOutcome> {
        Err(anyhow!("Orchid device flow is not implemented yet"))
    }
}

// --- Factory Stub ---
pub struct OrchidFactory;

#[async_trait]
impl AuthProviderFactory for OrchidFactory {
    fn id(&self) -> &'static str {
        "orchid"
    }

    async fn build(self: Arc<Self>, _state: &AppState) -> anyhow::Result<AuthProviderDyn> {
        Err(anyhow!("The 'orchid' provider is not configured on the server"))
    }
}
