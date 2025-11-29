// backend/src/compute/mod.rs

use crate::models::{Session, SessionRequest};

pub mod traits;
pub mod types;
pub mod error;
pub mod common;
pub mod providers;

pub use traits::ComputeProvider;
pub use providers::local::provider::{LocalComputeProvider, LocalProviderConfig};

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
