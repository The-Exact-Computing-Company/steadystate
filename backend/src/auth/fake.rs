// backend/src/auth/fake.rs

// A deterministic fake provider for CI testing.
// Returns predictable codes and completes authentication immediately.

use std::sync::Arc;
use async_trait::async_trait;

use crate::auth::provider::{AuthProvider, UserIdentity};
use crate::models::{DeviceStartResponse, ProviderName};

pub struct FakeAuth;

impl FakeAuth {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

#[async_trait]
impl AuthProvider for FakeAuth {
    fn name(&self) -> ProviderName {
        ProviderName::Fake
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

    async fn poll_device_flow(&self, device_code: &str) -> anyhow::Result<UserIdentity> {
        // Immediately succeed for the expected device code
        if device_code == "fake-device-code-123" {
            Ok(UserIdentity {
                id: "fake-user-id-456".into(),
                login: "ci-test-user".into(),
                email: Some("ci@test.local".into()),
                provider: "fake".into(),
            })
        } else {
            anyhow::bail!("authorization_pending")
        }
    }
} 
