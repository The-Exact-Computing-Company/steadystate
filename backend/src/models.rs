// backend/src/models.rs

use serde::{Deserialize, Serialize};
use crate::auth::provider::UserIdentity;
pub use steadystate_common::types::{SessionInfo, SessionState, DeviceFlowResponse};

// ============================================================================
//  Authentication & Identity Models
// ============================================================================

/// A type-safe, string-based identifier for an authentication provider.
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
    #[allow(dead_code)]
    pub device_code: String,
    #[allow(dead_code)]
    pub user_code: String,
    #[allow(dead_code)]
    pub verification_uri: String,
    #[allow(dead_code)]
    pub interval: u64,
    #[allow(dead_code)]
    pub created_at: u64,
}

#[derive(Clone)]
pub struct RefreshRecord {
    pub login: String,
    pub provider: ProviderId,
    pub expires_at: u64,
}

pub type DeviceStartResponse = DeviceFlowResponse;

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

// ============================================================================
//  Compute & Session Models
// ============================================================================

// SessionState is now imported from steadystate_common::types

/// The internal representation of a session, stored in the backend.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub state: SessionState,
    #[allow(dead_code)]
    pub repo_url: String,
    #[allow(dead_code)]
    pub branch: Option<String>,
    #[allow(dead_code)]
    pub environment: Option<String>,
    pub endpoint: Option<String>,
    pub compute_provider: String,
    #[allow(dead_code)]
    pub creator_login: String,
    #[allow(dead_code)]
    pub created_at: std::time::SystemTime,
    pub updated_at: std::time::SystemTime,
    pub error_message: Option<String>,
    pub magic_link: Option<String>,
    pub host_public_key: Option<String>,
}

/// The request from the CLI to create a new session.
#[derive(Debug, Deserialize)]
pub struct SessionRequest {
    pub repo_url: String,
    pub branch: Option<String>,
    pub environment: Option<String>,
    pub provider_config: Option<serde_json::Value>,
    pub allowed_users: Option<Vec<String>>,
    #[serde(default)]
    pub public: bool,
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLink {
    pub mode: String,
    pub session_id: String,
    pub username: String,
    pub hostname: String,
    pub port: Option<u16>,
    pub token: Option<String>,
    pub fingerprint: Option<String>,
    pub upterm_url: Option<String>,
}

impl From<&Session> for SessionInfo {
    fn from(session: &Session) -> Self {
        Self {
            id: session.id.clone(),
            state: session.state.clone(),
            endpoint: session.endpoint.clone(),
            compute_provider: Some(session.compute_provider.clone()),
            message: session.error_message.clone(),
            magic_link: session.magic_link.clone(),
            host_public_key: session.host_public_key.clone(),
        }
    }
}

/// The result of a successful session start operation.
#[derive(Debug)]
pub struct SessionStartResult {
    pub endpoint: Option<String>,
    pub magic_link: Option<String>,
    pub host_public_key: Option<String>,
}
