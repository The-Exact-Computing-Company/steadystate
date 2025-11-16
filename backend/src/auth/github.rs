// backend/src/auth/github.rs

use std::sync::Arc;
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::auth::provider::{AuthProvider, UserIdentity};
use crate::models::{DeviceStartResponse, ProviderName};

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

#[derive(Deserialize)]
struct DeviceStartOut {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DeviceTokenOut {
    Ok {
        access_token: String,
        token_type: String,
        scope: String,
    },
    Err {
        error: String,
        error_description: Option<String>,
    },
}

#[derive(Deserialize)]
struct GhUser {
    login: String,
    id: u64,
    email: Option<String>,
}

#[async_trait]
impl AuthProvider for GitHubAuth {
    fn name(&self) -> ProviderName {
        ProviderName::GitHub
    }

    async fn start_device_flow(&self) -> anyhow::Result<DeviceStartResponse> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("scope", "read:user"),
        ];

        let resp = self.http
            .post("https://github.com/login/device/code")
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await?
            .error_for_status()?;

        let out: DeviceStartOut = resp.json().await?;

        Ok(DeviceStartResponse {
            device_code: out.device_code,
            user_code: out.user_code,
            verification_uri: out.verification_uri,
            expires_in: out.expires_in,
            interval: out.interval.unwrap_or(5),
        })
    }

    async fn poll_device_flow(&self, device_code: &str) -> anyhow::Result<UserIdentity> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("device_code", device_code),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_secret", self.client_secret.as_str()),
        ];

        let resp = self.http
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await?
            .error_for_status()?;

        let token: DeviceTokenOut = resp.json().await?;

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

                Ok(UserIdentity {
                    id: user.id.to_string(),
                    login: user.login,
                    email: user.email,
                    provider: "github".into(),
                })
            }
            DeviceTokenOut::Err {
                error,
                error_description,
            } => Err(anyhow!(error_description.unwrap_or(error))),
        }
    }
} 
