use crate::compute::traits::{RemoteExecutor, CommandOutput, BoxedAsyncRead};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct HetznerExecutor;

#[async_trait]
impl RemoteExecutor for HetznerExecutor {
    async fn exec(&self, _cmd: &str, _args: &[&str]) -> Result<CommandOutput> {
        Err(anyhow!("Hetzner executor not implemented yet"))
    }
    
    async fn exec_streaming(
        &self,
        _cmd: &str,
        _args: &[&str],
    ) -> Result<(u32, BoxedAsyncRead, BoxedAsyncRead)> {
        Err(anyhow!("Hetzner executor not implemented yet"))
    }
    
    async fn exec_shell(&self, _script: &str) -> Result<CommandOutput> {
        Err(anyhow!("Hetzner executor not implemented yet"))
    }
    
    async fn upload_file(&self, _local: &Path, _remote: &Path) -> Result<()> {
        Err(anyhow!("Hetzner executor not implemented yet"))
    }
    
    async fn download_file(&self, _remote: &Path, _local: &Path) -> Result<()> {
        Err(anyhow!("Hetzner executor not implemented yet"))
    }
    
    async fn write_file(&self, _path: &Path, _content: &[u8], _mode: u32) -> Result<()> {
        Err(anyhow!("Hetzner executor not implemented yet"))
    }
    
    async fn read_file(&self, _path: &Path) -> Result<Vec<u8>> {
        Err(anyhow!("Hetzner executor not implemented yet"))
    }
    
    async fn mkdir_p(&self, _path: &Path, _mode: u32) -> Result<()> {
        Err(anyhow!("Hetzner executor not implemented yet"))
    }
    
    async fn exists(&self, _path: &Path) -> Result<bool> {
        Err(anyhow!("Hetzner executor not implemented yet"))
    }
    
    async fn remove_all(&self, _path: &Path) -> Result<()> {
        Err(anyhow!("Hetzner executor not implemented yet"))
    }

    async fn set_permissions(&self, _path: &Path, _mode: u32) -> Result<()> {
        Err(anyhow!("Hetzner executor not implemented yet"))
    }
}
