use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionInfo {
    pub id: String,
    pub endpoint: Option<String>,
    pub magic_link: Option<String>,
    pub state: SessionState,
    pub host_public_key: Option<String>,
    pub compute_provider: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionState {
    Provisioning,
    Running,
    Terminating,
    Terminated,
    Failed,
}

impl SessionState {
    pub fn as_str(&self) -> &str {
        match self {
            SessionState::Provisioning => "Provisioning",
            SessionState::Running => "Running",
            SessionState::Terminating => "Terminating",
            SessionState::Terminated => "Terminated",
            SessionState::Failed => "Failed",
        }
    }
}

// Shared between CLI and backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFlowResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}
