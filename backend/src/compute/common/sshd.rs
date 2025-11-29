use std::path::{Path, PathBuf};
use anyhow::{Result, anyhow};
use crate::compute::traits::RemoteExecutor;

#[derive(Debug, Clone)]
pub struct SshdConfig {
    pub port: u16,
    pub host_key_path: PathBuf,
    pub authorized_keys_path: PathBuf,
    pub pid_file_path: PathBuf,
    pub log_level: SshdLogLevel,
    pub permit_user_environment: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum SshdLogLevel {
    Quiet,
    Fatal,
    Error,
    Info,
    Verbose,
    Debug,
    Debug2,
    Debug3,
}

impl SshdConfig {
    pub fn generate(&self) -> String {
        format!(r#"# SteadyState SSH Configuration
Port {port}
ListenAddress 0.0.0.0
HostKey {host_key}
PidFile {pid_file}

# Authentication
PubkeyAuthentication yes
AuthorizedKeysFile {auth_keys}
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
PermitRootLogin no

# Security
StrictModes no
PermitUserEnvironment {permit_env}

# Logging
SyslogFacility USER
LogLevel {log_level}

# Session
PrintMotd no
PrintLastLog no
AcceptEnv LANG LC_*

# Subsystems
Subsystem sftp internal-sftp
"#,
            port = self.port,
            host_key = self.host_key_path.display(),
            auth_keys = self.authorized_keys_path.display(),
            pid_file = self.pid_file_path.display(),
            permit_env = if self.permit_user_environment { "yes" } else { "no" },
            log_level = self.log_level.as_str(),
        )
    }
}

impl SshdLogLevel {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Quiet => "QUIET",
            Self::Fatal => "FATAL",
            Self::Error => "ERROR",
            Self::Info => "INFO",
            Self::Verbose => "VERBOSE",
            Self::Debug => "DEBUG",
            Self::Debug2 => "DEBUG2",
            Self::Debug3 => "DEBUG3",
        }
    }
}

/// Find the sshd binary on the system
pub async fn find_sshd_binary(executor: &dyn RemoteExecutor) -> Result<String> {
    // Try common locations first
    for path in &["/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"] {
        if executor.exists(Path::new(path)).await.unwrap_or(false) {
            return Ok(path.to_string());
        }
    }
    
    // Fall back to which
    let output = executor.exec("which", &["sshd"]).await?;
    if output.exit_status.success() {
        return Ok(output.stdout.trim().to_string());
    }
    
    Err(anyhow!("sshd binary not found"))
}

/// Generate SSH host keys
pub async fn generate_host_keys(
    executor: &dyn RemoteExecutor,
    key_path: &Path,
) -> Result<()> {
    let key_str = key_path.to_str().ok_or_else(|| anyhow!("Invalid path"))?;
    
    let output = executor
        .exec("ssh-keygen", &["-t", "ed25519", "-f", key_str, "-N", ""])
        .await?;
        
    if !output.exit_status.success() {
        return Err(anyhow!("ssh-keygen failed: {}", output.stderr));
    }
    
    // Set correct permissions
    executor.set_permissions(key_path, 0o600).await?;
    
    Ok(())
}
