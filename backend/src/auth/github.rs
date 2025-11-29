// backend/src/auth/github.rs

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

// --- Provider Implementation ---

#[derive(Debug)]
pub struct GitHubAuth {
    pub client_id: String,
    pub client_secret: String,
    pub http: Client,
}

impl GitHubAuth {
    pub fn new(http: Client, client_id: String, client_secret: String) -> Arc<Self> {
        Arc::new(Self {
            client_id,
            client_secret,
            http,
        })
    }
}

#[async_trait]
impl AuthProvider for GitHubAuth {
    fn id(&self) -> ProviderId {
        ProviderId::from("github")
    }

    async fn start_device_flow(&self) -> anyhow::Result<DeviceStartResponse> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("scope", "read:user repo read:org"),
        ];

        let resp = self.http
            .post("https://github.com/login/device/code")
            .header("Accept", "application/json")
            .header("User-Agent", "steadystate-backend/0.1")
            .form(&params)
            .send()
            .await?
            .error_for_status()?;

        let out: DeviceStartOut = resp.json().await
            .context("Failed to decode GitHub's device code response")?;

        Ok(DeviceStartResponse {
            device_code: out.device_code,
            user_code: out.user_code,
            verification_uri: out.verification_uri,
            expires_in: out.expires_in,
            interval: out.interval.unwrap_or(5),
        })
    }

    async fn poll_device_flow(&self, device_code: &str) -> anyhow::Result<DevicePollOutcome> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("device_code", device_code),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_secret", self.client_secret.as_str()),
        ];

        let resp = self.http
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .header("User-Agent", "steadystate-backend/0.1")
            .form(&params)
            .send()
            .await?
            .error_for_status()?;

        let token: DeviceTokenOut = resp.json().await
            .context("Failed to decode GitHub's access token response")?;

        match token {
            DeviceTokenOut::Ok { access_token, .. } => {
                let user = self.http
                    .get("https://api.github.com/user")
                    .bearer_auth(&access_token)
                    .header("User-Agent", "steadystate-backend/0.1")
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<GhUser>()
                    .await?;

                Ok(DevicePollOutcome::Complete {
                    identity: UserIdentity {
                        id: user.id.to_string(),
                        login: user.login,
                        email: user.email,
                        provider: "github".into(),
                    },
                    provider_access_token: Some(access_token),
                })
            }
            DeviceTokenOut::Err(err) => match err.error {
                GitHubError::AuthorizationPending => Ok(DevicePollOutcome::Pending),
                GitHubError::SlowDown => Ok(DevicePollOutcome::SlowDown),
                other_error => Err(anyhow!("GitHub device flow error: {:?}", other_error)),
            },
        }
    }
}

// --- Factory Implementation ---

pub struct GitHubFactory;

#[async_trait]
impl AuthProviderFactory for GitHubFactory {
    fn id(&self) -> &'static str { "github" }

    async fn build(self: Arc<Self>, state: &AppState) -> anyhow::Result<AuthProviderDyn> {
        let client_id = state.config.github_client_id.clone()
            .context("GITHUB_CLIENT_ID is not configured on the server")?;
        let client_secret = state.config.github_client_secret.clone()
            .context("GITHUB_CLIENT_SECRET is not configured on the server")?;

        Ok(GitHubAuth::new(
            state.http.clone(),
            client_id,
            client_secret,
        ))
    }
}


// --- DTOs for GitHub API ---

#[derive(Deserialize)]
struct DeviceStartOut {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
enum GitHubError {
    AuthorizationPending,
    SlowDown,
    ExpiredToken,
    UnsupportedGrantType,
    IncorrectClientCredentials,
    IncorrectDeviceCode,
    AccessDenied,
    // Catch-all for any unknown errors GitHub might add in the future.
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize)]
struct DeviceTokenError {
    error: GitHubError,
    #[serde(rename = "error_description")]
    _error_description: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DeviceTokenOut {
    Ok {
        access_token: String,
        #[serde(rename = "token_type")]
        _token_type: String,
        #[serde(rename = "scope")]
        _scope: String,
    },
    Err(DeviceTokenError),
}

#[derive(Deserialize)]
struct GhUser {
    login: String,
    id: u64,
    email: Option<String>,
}
