use std::sync::Arc;
use anyhow::anyhow;
use async_trait::async_trait;

use crate::auth::provider::{AuthProvider, UserIdentity};
use crate::models::{DeviceStartResponse, ProviderName};

pub struct GitLabAuth;

impl GitLabAuth {
    #[allow(dead_code)]
    pub fn new() -> Arc<Self> { Arc::new(Self) }
}

#[async_trait]
impl AuthProvider for GitLabAuth {
    fn name(&self) -> ProviderName { ProviderName::GitLab }

    async fn start_device_flow(&self) -> anyhow::Result<DeviceStartResponse> {
        Err(anyhow!("GitLab provider not implemented yet"))
    }

    async fn poll_device_flow(&self, _device_code: &str) -> anyhow::Result<UserIdentity> {
        Err(anyhow!("GitLab provider not implemented yet"))
    }
}
