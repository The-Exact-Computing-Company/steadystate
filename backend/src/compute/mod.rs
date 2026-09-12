// backend/src/compute/mod.rs

pub mod common;
pub mod error;
pub mod providers;
pub mod traits;
pub mod types;

pub use providers::hetzner::provider::HetznerComputeProvider;
pub use providers::local::provider::{LocalComputeProvider, LocalProviderConfig};
pub use traits::ComputeProvider;

/// The system user used for SSH sessions across all providers.
/// This user must exist on any machine running the backend.
/// Priority:
/// 1. STEADYSTATE_SSH_USER env var
/// 2. USER env var (current user running the backend)
/// 3. "steadystate" (default fallback)
pub fn ssh_session_user() -> String {
    std::env::var("STEADYSTATE_SSH_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "steadystate".to_string())
}
