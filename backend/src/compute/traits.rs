use async_trait::async_trait;
use std::time::Duration;
use std::path::Path;
use std::process::ExitStatus;
use anyhow::{Result, anyhow};
use crate::models::{Session, SessionRequest};
pub use super::types::{SessionStartResult, SessionHealth, ResourceUsage, ProviderCapabilities};

/// Abstraction over local vs remote command execution
#[async_trait]
pub trait RemoteExecutor: Send + Sync + std::fmt::Debug {
    /// Execute a command and wait for completion
    async fn exec(&self, cmd: &str, args: &[&str]) -> Result<CommandOutput>;
    
    /// Execute a command and return immediately with handles to output streams
    async fn exec_streaming(
        &self, 
        cmd: &str, 
        args: &[&str],
    ) -> Result<(u32, BoxedAsyncRead, BoxedAsyncRead)>;
    
    /// Execute a shell script
    async fn exec_shell(&self, script: &str) -> Result<CommandOutput>;
    
    /// Upload a file to the remote (no-op for local)
    async fn upload_file(&self, local_path: &Path, remote_path: &Path) -> Result<()>;
    
    /// Download a file from the remote (no-op for local)
    async fn download_file(&self, remote_path: &Path, local_path: &Path) -> Result<()>;
    
    /// Write content directly to a remote file
    async fn write_file(&self, path: &Path, content: &[u8], mode: u32) -> Result<()>;
    
    /// Read content from a remote file
    async fn read_file(&self, path: &Path) -> Result<Vec<u8>>;
    
    /// Create a directory (with parents)
    async fn mkdir_p(&self, path: &Path, mode: u32) -> Result<()>;
    
    /// Check if a path exists
    async fn exists(&self, path: &Path) -> Result<bool>;
    
    /// Remove a file or directory recursively
    async fn remove_all(&self, path: &Path) -> Result<()>;

    /// Set permissions on a file or directory
    async fn set_permissions(&self, path: &Path, mode: u32) -> Result<()>;
}

pub type BoxedAsyncRead = Box<dyn tokio::io::AsyncRead + Unpin + Send>;

/// Output from a command execution
#[derive(Debug)]
pub struct CommandOutput {
    pub exit_status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

#[async_trait]
pub trait ComputeProvider: Send + Sync + std::fmt::Debug {
    /// Unique identifier for this provider (e.g., "local", "hetzner")
    fn id(&self) -> &'static str;
    
    /// Human-readable name
    fn display_name(&self) -> &'static str;
    
    /// What this provider can do
    fn capabilities(&self) -> ProviderCapabilities;
    
    /// Start a new session
    async fn start_session(
        &self,
        session_id: &str,
        request: &SessionRequest,
    ) -> Result<SessionStartResult>;
    
    /// Terminate a session and clean up resources
    async fn terminate_session(&self, session: &Session) -> Result<()>;
    
    /// Check if a session is still running and healthy
    async fn health_check(&self, _session: &Session) -> Result<SessionHealth> {
        // Default implementation for providers that don't support health checks
        Ok(SessionHealth::Unknown)
    }
    
    /// Get resource usage for billing/monitoring
    async fn get_resource_usage(&self, _session: &Session) -> Result<ResourceUsage> {
        Ok(ResourceUsage::default())
    }
    
    /// Extend session timeout (if supported)
    async fn extend_session(&self, _session: &Session, _duration: Duration) -> Result<()> {
        Err(anyhow!("Session extension not supported by this provider"))
    }
}
