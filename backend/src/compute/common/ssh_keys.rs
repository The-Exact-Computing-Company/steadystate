use reqwest::Client;
use std::collections::HashSet;
use anyhow::{Result, anyhow, Context};
use crate::compute::common::github::{self, RepoInfo};

#[derive(Debug, Clone)]
pub struct AuthorizedKey {
    pub user: String,
    pub key: String,
}

#[derive(Debug)]
pub struct SshKeyManager {
    http_client: Client,
}

impl SshKeyManager {
    pub fn new() -> Self {
        Self {
            http_client: Client::new(),
        }
    }
    
    /// Fetch SSH keys for a GitHub user
    pub async fn fetch_github_keys(&self, username: &str) -> Result<Vec<String>> {
        let url = format!("https://github.com/{}.keys", username);
        
        let response = self.http_client
            .get(&url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .context("Failed to fetch GitHub keys")?;
            
        if !response.status().is_success() {
            return Err(anyhow!("GitHub returned {}", response.status()));
        }
        
        let body = response.text().await?;
        let keys: Vec<String> = body
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect();
            
        Ok(keys)
    }
    
    /// Build authorized_keys entries for a repository session
    /// 
    /// This fetches SSH keys for:
    /// 1. The session creator
    /// 2. Explicitly allowed users (if provided)
    /// 3. All repository collaborators (if repo_url and token provided)
    pub async fn build_authorized_keys_for_repo(
        &self,
        creator: Option<&str>,
        allowed_users: Option<&[String]>,
        repo_url: Option<&str>,
        github_token: Option<&str>,
    ) -> Vec<AuthorizedKey> {
        let mut seen_keys = HashSet::new();
        let mut result = Vec::new();
        let mut usernames: Vec<String> = Vec::new();
        
        // 1. Add creator
        if let Some(creator) = creator {
            usernames.push(creator.to_string());
        }
        
        // 2. Add explicitly allowed users
        if let Some(users) = allowed_users {
            usernames.extend(users.iter().cloned());
        }
        
        // 3. Fetch repository collaborators (including upstream if fork)
        if let (Some(url), Some(token)) = (repo_url, github_token) {
            match RepoInfo::from_url(url) {
                Ok(repo_info) => {
                    tracing::info!(
                        "Fetching repo details for {}/{}",
                        repo_info.owner,
                        repo_info.repo
                    );
                    
                    // First fetch repo details to check for fork
                    match github::fetch_repo_details(
                        &self.http_client,
                        &repo_info.owner,
                        &repo_info.repo,
                        Some(token),
                    ).await {
                        Ok(repo_details) => {
                            // Fetch collaborators for this repo
                            self.fetch_and_add_collaborators(
                                &repo_info.owner,
                                &repo_info.repo,
                                token,
                                &mut usernames
                            ).await;
                            
                            // If it's a fork, fetch from parent
                            if let Some(parent) = repo_details.parent {
                                tracing::info!(
                                    "Repository is a fork of {}/{}. Fetching upstream collaborators.",
                                    parent.owner.login,
                                    parent.name
                                );
                                self.fetch_and_add_collaborators(
                                    &parent.owner.login,
                                    &parent.name,
                                    token,
                                    &mut usernames
                                ).await;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to fetch repo details: {}", e);
                            // Fallback to just fetching for this repo
                             self.fetch_and_add_collaborators(
                                &repo_info.owner,
                                &repo_info.repo,
                                token,
                                &mut usernames
                            ).await;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to parse repo URL '{}': {}", url, e);
                }
            }
        }
        
        // 4. Fetch SSH keys for all users
        tracing::info!("Fetching SSH keys for {} users: {:?}", usernames.len(), usernames);
        
        for username in usernames {
            match self.fetch_github_keys(&username).await {
                Ok(keys) => {
                    tracing::debug!("Found {} keys for {}", keys.len(), username);
                    for key in keys {
                        if seen_keys.insert(key.clone()) {
                            result.push(AuthorizedKey {
                                user: username.clone(),
                                key,
                            });
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch keys for {}: {}", username, e);
                }
            }
        }
        
        tracing::info!(
            "Built authorized_keys with {} keys for {} unique users",
            result.len(),
            result.iter().map(|k| &k.user).collect::<HashSet<_>>().len()
        );
        
        result
    }

    /// Build authorized_keys entries for multiple users
    pub async fn build_authorized_keys(
        &self,
        creator: Option<&str>,
        allowed_users: Option<&[String]>,
        github_token: Option<&str>,
    ) -> Vec<AuthorizedKey> {
        self.build_authorized_keys_for_repo(creator, allowed_users, None, github_token).await
    }

    async fn fetch_and_add_collaborators(
        &self,
        owner: &str,
        repo: &str,
        token: &str,
        usernames: &mut Vec<String>,
    ) {
        match github::fetch_collaborators(
            &self.http_client,
            owner,
            repo,
            Some(token),
        ).await {
            Ok(collaborators) => {
                tracing::info!(
                    "Found {} collaborators for {}/{}",
                    collaborators.len(),
                    owner,
                    repo
                );
                for collab in collaborators {
                    if !usernames.contains(&collab.login) {
                        usernames.push(collab.login);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to fetch collaborators for {}/{}: {}",
                    owner,
                    repo,
                    e
                );
            }
        }
    }
    
    /// Generate authorized_keys file content
    pub fn generate_authorized_keys_file(
        &self,
        keys: &[AuthorizedKey],
        command_template: Option<&str>,
    ) -> String {
        let mut content = String::new();
        
        for ak in keys {
            if let Some(template) = command_template {
                let command = template.replace("{user}", &ak.user);
                content.push_str(&format!("command=\"{}\" {}\n", command, ak.key));
            } else {
                content.push_str(&format!("{}\n", ak.key));
            }
        }
        
        content
    }
}
