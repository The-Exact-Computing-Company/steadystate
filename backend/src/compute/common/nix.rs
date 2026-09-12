use crate::compute::traits::RemoteExecutor;
use anyhow::Result;
use std::path::Path;

pub struct NixEnvironment {
    pub has_flake: bool,
    pub has_default_nix: bool,
    pub has_shell_nix: bool,
}

impl NixEnvironment {
    pub async fn detect(executor: &dyn RemoteExecutor, repo_path: &Path) -> Result<Self> {
        let has_flake = executor.exists(&repo_path.join("flake.nix")).await?;
        let has_default_nix = executor.exists(&repo_path.join("default.nix")).await?;
        let has_shell_nix = executor.exists(&repo_path.join("shell.nix")).await?;

        Ok(Self {
            has_flake,
            has_default_nix,
            has_shell_nix,
        })
    }
}
