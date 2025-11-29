use std::time::Duration;
use serde::{Serialize, Deserialize};

/// Capabilities a provider may or may not support
#[derive(Debug, Clone, Default)]
pub struct ProviderCapabilities {
    pub supports_pair_mode: bool,
    pub supports_collab_mode: bool,
    pub supports_persistent_storage: bool,
    pub supports_snapshots: bool,
    pub max_session_duration: Option<Duration>,
    pub supported_environments: Vec<String>, // "flake", "noenv", "legacy-nix"
}

/// Health status of a running session
#[derive(Debug, Clone)]
pub enum SessionHealth {
    Healthy,
    Degraded { reason: String },
    Unhealthy { reason: String },
    Unknown,
}

/// Resource usage information for cost tracking
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    pub cpu_seconds: Option<f64>,
    pub memory_mb_hours: Option<f64>,
    pub storage_gb_hours: Option<f64>,
    pub network_egress_gb: Option<f64>,
    pub estimated_cost_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStartResult {
    pub endpoint: Option<String>,
    pub magic_link: Option<String>,
    pub host_public_key: Option<String>,
}
