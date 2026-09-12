// backend/src/auth/gitlab.rs
//
// GitLab authentication via Personal Access Token (PAT).
//
// GitLab does not implement the OAuth Device Flow (RFC 8628), so the
// device endpoints intentionally stay unimplemented: `steadystate login
// --provider=gitlab` posts the PAT to POST /auth/token instead, which
// validates it here and mints SteadyState JWT + refresh tokens.

use std::sync::Arc;
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use crate::auth::provider::{
    AuthProvider, AuthProviderDyn, AuthProviderFactory, DevicePollOutcome, UserIdentity,
};
use crate::models::{DeviceStartResponse, ProviderId};
use crate::state::AppState;

/// Default public GitLab instance. Override per-server with `GITLAB_URL`.
pub const DEFAULT_GITLAB_URL: &str = "https://gitlab.com";

/// Normalize a configured GitLab base URL: trim whitespace/trailing
/// slashes, require an http(s) scheme.
pub fn normalize_base_url(raw: &str) -> anyhow::Result<String> {
    let base = raw.trim().trim_end_matches('/').to_string();
    if base.starts_with("https://") || base.starts_with("http://") {
        if base.len() > "https://".len() {
            Ok(base)
        } else {
            Err(anyhow!("GITLAB_URL has no host: {:?}", raw))
        }
    } else {
        Err(anyhow!(
            "GITLAB_URL must start with https:// or http://, got {:?}",
            raw
        ))
    }
}

pub fn base_url_from_env() -> anyhow::Result<String> {
    let raw = std::env::var("GITLAB_URL").unwrap_or_else(|_| DEFAULT_GITLAB_URL.to_string());
    normalize_base_url(&raw)
}

// --- Provider Implementation ---

#[derive(Debug)]
pub struct GitLabAuth {
    pub base_url: String,
    pub http: Client,
}

impl GitLabAuth {
    pub fn new(http: Client, base_url: String) -> Arc<Self> {
        Arc::new(Self { base_url, http })
    }

    /// Validate a PAT against `{base}/api/v4/user` and map it to an identity.
    /// Requires at least the `read_user` scope; without it GitLab answers 401.
    pub async fn validate_token(&self, token: &str) -> anyhow::Result<UserIdentity> {
        if token.trim().is_empty() {
            return Err(anyhow!("Empty GitLab token"));
        }
        let user: GlUser = self
            .http
            .get(format!("{}/api/v4/user", self.base_url))
            .header("PRIVATE-TOKEN", token.trim())
            .header("User-Agent", "steadystate-backend/0.1")
            .send()
            .await
            .context("GitLab /api/v4/user request failed")?
            .error_for_status()
            .map_err(|e| {
                anyhow!(
                    "GitLab rejected the token ({}). Check it has read_user scope and is not expired.",
                    e.status().map(|s| s.to_string()).unwrap_or_else(|| "error".into())
                )
            })?
            .json()
            .await
            .context("Failed to decode GitLab /api/v4/user response")?;

        Ok(UserIdentity {
            id: user.id.to_string(),
            login: user.username,
            email: user.email,
            provider: "gitlab".into(),
        })
    }
}

#[async_trait]
impl AuthProvider for GitLabAuth {
    fn id(&self) -> ProviderId {
        ProviderId::from("gitlab")
    }

    async fn start_device_flow(&self) -> anyhow::Result<DeviceStartResponse> {
        Err(anyhow!(
            "GitLab has no OAuth device flow. Use `steadystate login --provider=gitlab` with a Personal Access Token (POST /auth/token) instead."
        ))
    }

    async fn poll_device_flow(&self, _device_code: &str) -> anyhow::Result<DevicePollOutcome> {
        Err(anyhow!(
            "GitLab has no OAuth device flow. Use `steadystate login --provider=gitlab` with a Personal Access Token (POST /auth/token) instead."
        ))
    }
}

// --- Factory Implementation ---

pub struct GitLabFactory;

#[async_trait]
impl AuthProviderFactory for GitLabFactory {
    fn id(&self) -> &'static str {
        "gitlab"
    }

    async fn build(self: Arc<Self>, state: &AppState) -> anyhow::Result<AuthProviderDyn> {
        let base_url = base_url_from_env().context("GITLAB_URL is misconfigured on the server")?;
        Ok(GitLabAuth::new(state.http.clone(), base_url))
    }
}

// --- DTOs for GitLab API ---

#[derive(Deserialize)]
struct GlUser {
    id: u64,
    username: String,
    email: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_base_url() {
        assert_eq!(
            normalize_base_url("https://gitlab.com").unwrap(),
            "https://gitlab.com"
        );
        assert_eq!(
            normalize_base_url("https://gitlab.example.com///").unwrap(),
            "https://gitlab.example.com"
        );
        assert_eq!(
            normalize_base_url("http://10.0.0.5:8080/").unwrap(),
            "http://10.0.0.5:8080"
        );
        assert!(normalize_base_url("gitlab.com").is_err());
        assert!(normalize_base_url("https://").is_err());
        assert!(normalize_base_url("").is_err());
    }
}
