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

/// Defines the possible outcomes of polling the device flow.
/// This allows the API route to be provider-agnostic.
pub enum DevicePollOutcome {
    /// The user has not yet completed the flow.
    Pending,
    /// The user is polling too frequently.
    SlowDown,
    /// The user has successfully authenticated.
    Complete(UserIdentity),
}

#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Returns the unique string identifier for this provider (e.g., "github").
    fn id(&self) -> ProviderId;

    /// Starts the device authentication flow.
    async fn start_device_flow(&self) -> anyhow::Result<DeviceStartResponse>;

    /// Polls for the result of the device flow.
    async fn poll_device_flow(
        &self,
        device_code: &str,
    ) -> anyhow::Result<DevicePollOutcome>;
}

// Type-erased provider
pub type AuthProviderDyn = Arc<dyn AuthProvider>;

/// A factory responsible for constructing a specific AuthProvider.
/// This allows for lazy, on-demand initialization.
#[async_trait]
pub trait AuthProviderFactory: Send + Sync {
    /// The unique string identifier for the provider this factory creates.
    fn id(&self) -> &'static str;

    /// Builds the provider instance, reading any necessary config from the AppState.
    /// This method is only called once per provider instance.
    async fn build(self: Arc<Self>, state: &AppState) -> anyhow::Result<AuthProviderDyn>;
}

// Type-erased factory
pub type AuthProviderFactoryDyn = Arc<dyn AuthProviderFactory>;
