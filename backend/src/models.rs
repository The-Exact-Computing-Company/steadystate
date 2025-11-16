// backend/src/models.rs

use serde::{Deserialize, Serialize};
use crate::auth::provider::UserIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderName {
    GitHub,
    GitLab,
    Orchid,
    Fake,
}

impl ProviderName {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "github" => Some(Self::GitHub),
            "gitlab" => Some(Self::GitLab),
            "orchid" => Some(Self::Orchid),
            "fake" => Some(Self::Fake),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::GitLab => "gitlab",
            Self::Orchid => "orchid",
            Self::Fake => "fake",
        }
    }
}

#[derive(Clone)]
pub struct PendingDevice {
    pub provider: ProviderName,
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub interval: u64,
    pub created_at: u64,
}

#[derive(Clone)]
pub struct RefreshRecord {
    pub login: String,
    pub provider: ProviderName,
    pub expires_at: u64,
}

#[derive(Serialize)]
pub struct DeviceStartResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Serialize)]
pub struct PollOut {
    pub status: Option<String>,
    pub jwt: Option<String>,
    pub refresh_token: Option<String>,
    pub login: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct PollQuery {
    pub device_code: String,
}

#[derive(Deserialize)]
pub struct DeviceQuery {
    pub provider: Option<String>, // default github
}

#[derive(Deserialize)]
pub struct RefreshIn {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct RefreshOut {
    pub jwt: String,
    pub refresh_expires_at: Option<u64>,
}

#[derive(Deserialize)]
pub struct RevokeIn {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct WhoamiOut {
    pub login: String,
    pub provider: String,
}

impl From<UserIdentity> for WhoamiOut {
    fn from(u: UserIdentity) -> Self {
        Self { login: u.login, provider: u.provider }
    }
}

#[derive(Serialize)]
pub struct UserInfo {
    pub login: String,
    pub provider: String,
} 
