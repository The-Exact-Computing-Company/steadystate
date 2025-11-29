use anyhow::{Result, anyhow, Context};
use reqwest::Client;
use serde::Deserialize;

/// Parsed GitHub repository information
#[derive(Debug, Clone)]
pub struct RepoInfo {
    pub owner: String,
    pub repo: String,
}

impl RepoInfo {
    /// Parse a GitHub repository URL into owner and repo components
    /// 
    /// Supports:
    /// - https://github.com/owner/repo
    /// - https://github.com/owner/repo.git
    /// - git@github.com:owner/repo.git
    /// - github.com/owner/repo
    pub fn from_url(url: &str) -> Result<Self> {
        let url = url.trim();
        
        // Handle SSH format: git@github.com:owner/repo.git
        if url.starts_with("git@github.com:") {
            let path = url.strip_prefix("git@github.com:").unwrap();
            let path = path.strip_suffix(".git").unwrap_or(path);
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() >= 2 {
                return Ok(Self {
                    owner: parts[0].to_string(),
                    repo: parts[1].to_string(),
                });
            }
        }
        
        // Handle HTTPS format
        let url = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);
        
        let url = url.strip_prefix("github.com/").unwrap_or(url);
        let url = url.strip_prefix("www.github.com/").unwrap_or(url);
        let url = url.strip_suffix(".git").unwrap_or(url);
        
        let parts: Vec<&str> = url.split('/').filter(|s| !s.is_empty()).collect();
        
        if parts.len() >= 2 {
            Ok(Self {
                owner: parts[0].to_string(),
                repo: parts[1].to_string(),
            })
        } else {
            Err(anyhow!("Could not parse GitHub repo from URL: {}", url))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct GitHubCollaborator {
    pub login: String,
    pub id: u64,
    #[serde(default)]
    pub permissions: Option<CollaboratorPermissions>,
}

#[derive(Debug, Deserialize)]
pub struct GitHubRepo {
    pub parent: Option<Box<GitHubRepo>>,
    pub owner: GitHubUser,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct GitHubUser {
    pub login: String,
}

#[derive(Debug, Deserialize)]
pub struct CollaboratorPermissions {
    #[serde(default)]
    pub admin: bool,
    #[serde(default)]
    pub push: bool,
    #[serde(default)]
    pub pull: bool,
}

/// Fetch repository details to check for forks
pub async fn fetch_repo_details(
    client: &Client,
    owner: &str,
    repo: &str,
    token: Option<&str>,
) -> Result<GitHubRepo> {
    let url = format!("https://api.github.com/repos/{}/{}", owner, repo);
    
    let mut request = client
        .get(&url)
        .header("User-Agent", "steadystate")
        .header("Accept", "application/vnd.github.v3+json");
    
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {}", token));
    }
    
    let response = request
        .send()
        .await
        .context("Failed to fetch repo details from GitHub")?;
        
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("GitHub API error {}: {}", status, body));
    }
    
    let repo: GitHubRepo = response
        .json()
        .await
        .context("Failed to parse repo details")?;
        
    Ok(repo)
}

/// Fetch collaborators for a GitHub repository
/// 
/// Requires a GitHub token with `repo` scope for private repos,
/// or works without auth for public repos (with rate limits).
pub async fn fetch_collaborators(
    client: &Client,
    owner: &str,
    repo: &str,
    token: Option<&str>,
) -> Result<Vec<GitHubCollaborator>> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/collaborators",
        owner, repo
    );
    
    let mut request = client
        .get(&url)
        .header("User-Agent", "steadystate")
        .header("Accept", "application/vnd.github.v3+json");
    
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {}", token));
    }
    
    let response = request
        .send()
        .await
        .context("Failed to fetch collaborators from GitHub")?;
    
    if response.status() == 404 {
        // Repository not found or no access
        tracing::warn!("Could not fetch collaborators: repo not found or no access");
        return Ok(vec![]);
    }
    
    if response.status() == 403 {
        // Rate limited or forbidden
        tracing::warn!("Could not fetch collaborators: forbidden (rate limit or permissions)");
        return Ok(vec![]);
    }
    
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::warn!("GitHub API error {}: {}", status, body);
        return Ok(vec![]);
    }
    
    let collaborators: Vec<GitHubCollaborator> = response
        .json()
        .await
        .context("Failed to parse collaborators response")?;
    
    Ok(collaborators)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_https_url() {
        let info = RepoInfo::from_url("https://github.com/b-rodrigues/housing").unwrap();
        assert_eq!(info.owner, "b-rodrigues");
        assert_eq!(info.repo, "housing");
    }
    
    #[test]
    fn test_parse_https_url_with_git_suffix() {
        let info = RepoInfo::from_url("https://github.com/b-rodrigues/housing.git").unwrap();
        assert_eq!(info.owner, "b-rodrigues");
        assert_eq!(info.repo, "housing");
    }
    
    #[test]
    fn test_parse_ssh_url() {
        let info = RepoInfo::from_url("git@github.com:b-rodrigues/housing.git").unwrap();
        assert_eq!(info.owner, "b-rodrigues");
        assert_eq!(info.repo, "housing");
    }
    
    #[test]
    fn test_parse_bare_url() {
        let info = RepoInfo::from_url("github.com/b-rodrigues/housing").unwrap();
        assert_eq!(info.owner, "b-rodrigues");
        assert_eq!(info.repo, "housing");
    }
}
