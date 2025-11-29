use crate::compute::traits::{RemoteExecutor, CommandOutput, BoxedAsyncRead};
use tokio::process::Command;
use anyhow::{Result, anyhow, Context};
use async_trait::async_trait;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct LocalExecutor;

#[async_trait]
impl RemoteExecutor for LocalExecutor {
    async fn exec(&self, cmd: &str, args: &[&str]) -> Result<CommandOutput> {
        let output = Command::new(cmd)
            .args(args)
            .output()
            .await
            .context(format!("Failed to execute {}", cmd))?;
            
        Ok(CommandOutput {
            exit_status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
    
    async fn exec_streaming(
        &self,
        cmd: &str,
        args: &[&str],
    ) -> Result<(u32, BoxedAsyncRead, BoxedAsyncRead)> {
        let mut child = Command::new(cmd)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context(format!("Failed to spawn {}", cmd))?;
            
        let pid = child.id().ok_or_else(|| anyhow!("No PID"))?;
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("No stdout"))?;
        let stderr = child.stderr.take().ok_or_else(|| anyhow!("No stderr"))?;
        
        Ok((pid, Box::new(stdout), Box::new(stderr)))
    }
    
    async fn exec_shell(&self, script: &str) -> Result<CommandOutput> {
        self.exec("sh", &["-c", script]).await
    }
    
    async fn upload_file(&self, local: &Path, remote: &Path) -> Result<()> {
        // For local, just copy
        tokio::fs::copy(local, remote).await?;
        Ok(())
    }
    
    async fn download_file(&self, remote: &Path, local: &Path) -> Result<()> {
        tokio::fs::copy(remote, local).await?;
        Ok(())
    }
    
    async fn write_file(&self, path: &Path, content: &[u8], mode: u32) -> Result<()> {
        tokio::fs::write(path, content).await?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
        }
        
        Ok(())
    }
    
    async fn read_file(&self, path: &Path) -> Result<Vec<u8>> {
        Ok(tokio::fs::read(path).await?)
    }
    
    async fn mkdir_p(&self, path: &Path, mode: u32) -> Result<()> {
        tokio::fs::create_dir_all(path).await?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
        }
        
        Ok(())
    }
    
    async fn exists(&self, path: &Path) -> Result<bool> {
        Ok(tokio::fs::try_exists(path).await?)
    }
    
    async fn remove_all(&self, path: &Path) -> Result<()> {
        if tokio::fs::try_exists(path).await? {
            tokio::fs::remove_dir_all(path).await?;
        }
        Ok(())
    }

    async fn set_permissions(&self, path: &Path, mode: u32) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
        }
        Ok(())
    }
}
