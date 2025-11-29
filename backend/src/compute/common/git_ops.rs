use std::path::Path;
use anyhow::{Result, anyhow};
use crate::compute::traits::RemoteExecutor;

pub struct GitOps<'a> {
    executor: &'a dyn RemoteExecutor,
}

impl<'a> GitOps<'a> {
    pub fn new(executor: &'a dyn RemoteExecutor) -> Self {
        Self { executor }
    }
    
    /// Clone a repository
    pub async fn clone(
        &self,
        repo_url: &str,
        dest: &Path,
        depth: Option<u32>,
        branch: Option<&str>,
    ) -> Result<()> {
        let mut args = vec!["clone"];
        
        if let Some(d) = depth {
            args.push("--depth");
            // We need to keep the string alive, so we can't just push &d.to_string()
            // But wait, args is Vec<&str>. We can't push a temporary string reference.
            // We need to construct the command differently or change the signature of exec.
            // The trait exec takes &[&str].
            // Let's format the depth argument separately if needed, but here we are constructing a Vec of &str.
            // We can't store the String in the Vec<&str> if the String is temporary.
        }
        
        // To handle the lifetime issue with args, we'll construct the command string or use a different approach.
        // Actually, let's just use a Vec<String> for building args, then convert to Vec<&str>.
        
        let mut cmd_args = vec!["clone".to_string()];
        
        if let Some(d) = depth {
            cmd_args.push("--depth".to_string());
            cmd_args.push(d.to_string());
        }
        
        if let Some(b) = branch {
            cmd_args.push("--branch".to_string());
            cmd_args.push(b.to_string());
        }
        
        cmd_args.push(repo_url.to_string());
        cmd_args.push(dest.to_str().ok_or_else(|| anyhow!("Invalid path"))?.to_string());
        
        let args_str: Vec<&str> = cmd_args.iter().map(|s| s.as_str()).collect();
        
        let output = self.executor.exec("git", &args_str).await?;
        
        if !output.exit_status.success() {
            return Err(anyhow!("git clone failed: {}", output.stderr));
        }
        
        Ok(())
    }
    
    /// Create and checkout a new branch
    pub async fn checkout_new_branch(&self, repo_path: &Path, branch: &str) -> Result<()> {
        let path_str = repo_path.to_str().ok_or_else(|| anyhow!("Invalid path"))?;
        
        let output = self.executor
            .exec("git", &["-C", path_str, "checkout", "-b", branch])
            .await?;
            
        if !output.exit_status.success() {
            return Err(anyhow!("Failed to create branch {}: {}", branch, output.stderr));
        }
        
        Ok(())
    }
    
    /// Configure git user for a repository
    pub async fn configure_user(
        &self,
        repo_path: &Path,
        name: &str,
        email: &str,
    ) -> Result<()> {
        let path_str = repo_path.to_str().ok_or_else(|| anyhow!("Invalid path"))?;
        
        self.executor
            .exec("git", &["-C", path_str, "config", "user.name", name])
            .await?;
            
        self.executor
            .exec("git", &["-C", path_str, "config", "user.email", email])
            .await?;
            
        Ok(())
    }
    
    /// Add a remote
    pub async fn add_remote(
        &self,
        repo_path: &Path,
        name: &str,
        url: &str,
    ) -> Result<()> {
        let path_str = repo_path.to_str().ok_or_else(|| anyhow!("Invalid path"))?;
        
        let output = self.executor
            .exec("git", &["-C", path_str, "remote", "add", name, url])
            .await?;
            
        // Ignore "already exists" errors
        if !output.exit_status.success() && !output.stderr.contains("already exists") {
            return Err(anyhow!("Failed to remote add: {}", output.stderr));
        }
        
        Ok(())
    }
    
    /// Rename a remote
    pub async fn rename_remote(
        &self,
        repo_path: &Path,
        old_name: &str,
        new_name: &str,
    ) -> Result<()> {
        let path_str = repo_path.to_str().ok_or_else(|| anyhow!("Invalid path"))?;
        
        let output = self.executor
            .exec("git", &["-C", path_str, "remote", "rename", old_name, new_name])
            .await?;
            
        if !output.exit_status.success() {
             // If old remote doesn't exist or new one already exists, this might fail.
             // For now, treat as error unless we want to be more specific.
             return Err(anyhow!("Failed to rename remote: {}", output.stderr));
        }
        
        Ok(())
    }

    /// Set remote URL
    pub async fn set_remote_url(
        &self,
        repo_path: &Path,
        name: &str,
        url: &str,
    ) -> Result<()> {
        let path_str = repo_path.to_str().ok_or_else(|| anyhow!("Invalid path"))?;
        
        let output = self.executor
            .exec("git", &["-C", path_str, "remote", "set-url", name, url])
            .await?;
            
        if !output.exit_status.success() {
            return Err(anyhow!("Failed to set remote url: {}", output.stderr));
        }
        
        Ok(())
    }
}
