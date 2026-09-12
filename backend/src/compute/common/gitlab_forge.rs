use anyhow::{Result, anyhow, Context};
use reqwest::Client;
use serde::Deserialize;

use crate::auth::gitlab::{DEFAULT_GITLAB_URL, normalize_base_url};

/// Effective GitLab base URL for forge operations (keys, members).
/// Reads `GITLAB_URL`, falling back to gitlab.com — same source the
/// auth factory uses, so login and session setup always agree.
pub fn base_url() -> String {
    std::env::var("GITLAB_URL")
        .ok()
        .and_then(|raw| normalize_base_url(&raw).ok())
        .unwrap_or_else(|| DEFAULT_GITLAB_URL.to_string())
}

/// Base URL for a specific repository host: gitlab.com always uses the
/// public instance; other hosts prefer `GITLAB_URL` when it matches,
/// else fall back to `https://{host}`.
pub fn base_for_repo(host: &str) -> String {
    if host.eq_ignore_ascii_case("gitlab.com") {
        return DEFAULT_GITLAB_URL.to_string();
    }
    if let Ok(raw) = std::env::var("GITLAB_URL") {
        if let Ok(base) = normalize_base_url(&raw) {
            let base_host = base
                .split("://")
                .nth(1)
                .unwrap_or(&base)
                .split('/')
                .next()
                .unwrap_or(&base);
            if base_host.eq_ignore_ascii_case(host) {
                return base;
            }
        }
    }
    format!("https://{}", host)
}

/// Fetch a GitLab user's public SSH keys without authentication via
/// `{base}/{username}.keys` (same convention as GitHub's `/{user}.keys`).
pub async fn fetch_user_keys(
    http: &Client,
    base_url: &str,
    username: &str,
) -> Result<Vec<String>> {
    let url = format!("{}/{}.keys", base_url.trim_end_matches('/'), username);
    let response = http
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .header("User-Agent", "steadystate-backend/0.1")
        .send()
        .await
        .context("Failed to fetch GitLab keys")?;

    if !response.status().is_success() {
        return Err(anyhow!("GitLab returned {}", response.status()));
    }

    Ok(response
        .text()
        .await?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect())
}

/// Authenticated fallback: `{base}/api/v4/users?username=` then
/// `/users/:id/keys`. Used when the `.keys` page is unavailable
/// (e.g. some self-managed instances disable it).
pub async fn fetch_user_keys_api(
    http: &Client,
    base_url: &str,
    username: &str,
    token: &str,
) -> Result<Vec<String>> {
    #[derive(Deserialize)]
    struct IdOnly {
        id: u64,
    }
    #[derive(Deserialize)]
    struct KeyOnly {
        key: String,
    }

    let users: Vec<IdOnly> = http
        .get(format!("{}/api/v4/users", base_url.trim_end_matches('/')))
        .query(&[("username", username)])
        .header("PRIVATE-TOKEN", token)
        .header("User-Agent", "steadystate-backend/0.1")
        .send()
        .await
        .context("GitLab user lookup failed")?
        .error_for_status()?
        .json()
        .await
        .context("Failed to decode GitLab user lookup")?;
    let id = users
        .first()
        .ok_or_else(|| anyhow!("GitLab user '{}' not found", username))?
        .id;

    let keys: Vec<KeyOnly> = http
        .get(format!("{}/api/v4/users/{}/keys", base_url.trim_end_matches('/'), id))
        .header("PRIVATE-TOKEN", token)
        .header("User-Agent", "steadystate-backend/0.1")
        .send()
        .await
        .context("GitLab keys lookup failed")?
        .error_for_status()?
        .json()
        .await
        .context("Failed to decode GitLab keys")?;
    Ok(keys.into_iter().map(|k| k.key).collect())
}

#[derive(Debug, Deserialize)]
pub struct GitLabMember {
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct GitLabProject {
    pub path_with_namespace: String,
    pub forked_from_project: Option<Box<GitLabProject>>,
}

/// Fetch project details (used for fork/parent traversal).
pub async fn fetch_project(
    http: &Client,
    base_url: &str,
    encoded_path: &str,
    token: Option<&str>,
) -> Result<GitLabProject> {
    let mut req = http
        .get(format!(
            "{}/api/v4/projects/{}",
            base_url.trim_end_matches('/'),
            encoded_path
        ))
        .header("User-Agent", "steadystate-backend/0.1");
    if let Some(t) = token {
        req = req.header("PRIVATE-TOKEN", t);
    }
    req.send()
        .await
        .context("GitLab project lookup failed")?
        .error_for_status()
        .map_err(|e| anyhow!("GitLab project lookup failed: {}", e))?
        .json()
        .await
        .context("Failed to decode GitLab project")
}

/// All members of a project (direct + inherited + invited).
/// Needs `read_api` scope on the token.
pub async fn fetch_project_members(
    http: &Client,
    base_url: &str,
    encoded_path: &str,
    token: &str,
) -> Result<Vec<GitLabMember>> {
    http.get(format!(
            "{}/api/v4/projects/{}/members/all",
            base_url.trim_end_matches('/'),
            encoded_path
        ))
        .query(&[("per_page", "100")])
        .header("PRIVATE-TOKEN", token)
        .header("User-Agent", "steadystate-backend/0.1")
        .send()
        .await
        .context("GitLab members lookup failed")?
        .error_for_status()
        .map_err(|e| anyhow!("GitLab members lookup failed (needs read_api scope): {}", e))?
        .json()
        .await
        .context("Failed to decode GitLab members")
}
