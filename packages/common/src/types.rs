use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionInfo {
    pub id: String,
    pub endpoint: Option<String>,
    pub magic_link: Option<String>,
    pub state: SessionState,
    pub host_public_key: Option<String>,
    pub compute_provider: Option<String>,
    pub message: Option<String>,
    /// Expiry as Unix epoch seconds. Absent on records written before
    /// expiry tracking existed (treated as non-expiring legacy).
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Repository the session was created for. Absent on records written
    /// before it was exposed (populated going forward).
    #[serde(default)]
    pub repo_url: Option<String>,
    /// Last observed activity as Unix epoch seconds (SSH connection,
    /// sync, or tmux client). Absent on pre-tracking records.
    #[serde(default)]
    pub last_activity_at: Option<u64>,
}

impl SessionInfo {
    /// Redacted view for non-creators: connection secrets removed, but
    /// lifecycle state stays visible. Joining never needs the API —
    /// collaborators connect with the out-of-band magic link over SSH.
    pub fn redacted(&self) -> Self {
        Self {
            magic_link: None,
            endpoint: None,
            host_public_key: None,
            ..self.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redacted_hides_connection_secrets() {
        let full = SessionInfo {
            id: "abc".to_string(),
            endpoint: Some("ssh://steady@host:2222".to_string()),
            magic_link: Some("steadystate://collab/abc?ssh=x".to_string()),
            state: SessionState::Running,
            host_public_key: Some("ssh-ed25519 AAAA".to_string()),
            compute_provider: Some("local".to_string()),
            message: None,
            expires_at: Some(9_999_999),
            repo_url: Some("https://github.com/user/repo".to_string()),
            last_activity_at: Some(9_999_000),
        };
        let red = full.redacted();
        assert_eq!(red.magic_link, None);
        assert_eq!(red.endpoint, None);
        assert_eq!(red.host_public_key, None);
        // Lifecycle stays visible.
        assert_eq!(red.id, "abc");
        assert_eq!(red.state, SessionState::Running);
        assert_eq!(red.expires_at, Some(9_999_999));
        assert_eq!(red.compute_provider.as_deref(), Some("local"));
        assert_eq!(red.last_activity_at, Some(9_999_000));
    }
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
