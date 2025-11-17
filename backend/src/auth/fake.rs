// backend/src/auth/fake.rs

use std::sync::Arc;
use anyhow::anyhow;
use async_trait::async_trait;

use crate::auth::provider::{
    AuthProvider, AuthProviderDyn, AuthProviderFactory, DevicePollOutcome, UserIdentity,
};
use crate::models::{DeviceStartResponse, ProviderId};
use crate::state::AppState;

// --- Provider Implementation ---

pub struct FakeAuth;

impl FakeAuth {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

#[async_trait]
impl AuthProvider for FakeAuth {
    fn id(&self) -> ProviderId {
        ProviderId::from("fake")
    }

    async fn start_device_flow(&self) -> anyhow::Result<DeviceStartResponse> {
        Ok(DeviceStartResponse {
            device_code: "fake-device-code-123".into(),
            user_code: "FAKE-CODE".into(),
            verification_uri: "http://localhost/fake-verify".into(),
            expires_in: 300,
            interval: 1, // Fast polling for CI
        })
    }

    async fn poll_device_flow(&self, device_code: &str) -> anyhow::Result<DevicePollOutcome> {
        if device_code == "fake-device-code-123" {
            Ok(DevicePollOutcome::Complete(UserIdentity {
                id: "fake-user-id-456".into(),
                login: "ci-test-user".into(),
                email: Some("ci@test.local".into()),
                provider: "fake".into(),
            }))
        } else {
            // For testing, just stay pending for any other code.
            Ok(DevicePollOutcome::Pending)
        }
    }
}

// --- Factory Implementation ---

pub struct FakeFactory;

#[async_trait]
impl AuthProviderFactory for FakeFactory {
    fn id(&self) -> &'static str {
        "fake"
    }

    async fn build(self: Arc<Self>, state: &AppState) -> anyhow::Result<AuthProviderDyn> {
        if !state.config.enable_fake_auth {
            return Err(anyhow!("The 'fake' provider is not enabled on this server"));
        }
        Ok(FakeAuth::new())
    }
} 
