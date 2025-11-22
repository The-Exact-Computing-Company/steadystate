// backend/src/models.rs

use serde::{Deserialize, Serialize};
use crate::auth::provider::UserIdentity;

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
    pub _device_code: String,
    pub _user_code: String,
    pub _verification_uri: String,
    pub _interval: u64,
    pub _created_at: u64,
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

// ============================================================================
//  Compute & Session Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionState {
    Provisioning,
    Running,
    Failed,
    Terminating,
    Terminated,
}

/// The internal representation of a session, stored in the backend.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub state: SessionState,
    pub _repo_url: String,
    pub _branch: Option<String>,
    pub _environment: Option<String>,
    pub endpoint: Option<String>,
    pub compute_provider: String,
    pub _creator_login: String,
    pub _created_at: std::time::SystemTime,
    pub updated_at: std::time::SystemTime,
    pub error_message: Option<String>,
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

/// The information about a session that is sent back to the CLI.
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub state: SessionState,
    pub endpoint: Option<String>,
    pub compute_provider: String,
    pub message: Option<String>,
}

impl From<&Session> for SessionInfo {
    fn from(session: &Session) -> Self {
        Self {
            id: session.id.clone(),
            state: session.state.clone(),
            endpoint: session.endpoint.clone(),
            compute_provider: session.compute_provider.clone(),
            message: session.error_message.clone(),
        }
    }
} 
