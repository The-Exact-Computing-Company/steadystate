// backend/src/models.rs

use serde::{Deserialize, Serialize};
use crate::auth::provider::UserIdentity;

/// A type-safe, string-based identifier for an authentication provider.
/// This replaces the rigid ProviderName enum to allow for new providers
/// to be added without modifying core models.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ProviderId(String);

impl ProviderId {
    pub fn as_str(&self) -> &str { &self.0 }
}

impl From<String> for ProviderId {
    fn from(s: String) -> Self { ProviderId(s) }
}

impl From<&str> for ProviderId {
    fn from(s: &str) -> Self { ProviderId(s.to_owned()) }
}

#[derive(Clone)]
pub struct PendingDevice {
    pub provider: ProviderId,
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub interval: u64,
    pub created_at: u64,
}

#[derive(Clone)]
pub struct RefreshRecord {
    pub login: String,
    pub provider: ProviderId,
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
    pub provider: Option<String>,
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
