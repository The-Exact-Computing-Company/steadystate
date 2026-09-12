use crate::compute::common::forge::{ForgeAuth, ForgeRepo};
use crate::compute::common::github;
use crate::compute::common::gitlab_forge;
use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct AuthorizedKey {
    pub user: String,
    pub key: String,
}

#[derive(Debug)]
pub struct SshKeyManager {
    http_client: Client,
}

impl Default for SshKeyManager {
    fn default() -> Self {
        Self::new()
    }
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

        let response = self
            .http_client
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

    /// Fetch local SSH public keys from ~/.ssh/*.pub
    pub async fn fetch_local_keys(&self) -> Result<Vec<String>> {
        let mut keys = Vec::new();

        if let Some(home_dir) = dirs::home_dir() {
            let ssh_dir = home_dir.join(".ssh");
            if ssh_dir.exists()
                && let Ok(mut entries) = tokio::fs::read_dir(ssh_dir).await
            {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if let Some(extension) = path.extension()
                        && extension == "pub"
                        && let Ok(content) = tokio::fs::read_to_string(&path).await
                    {
                        for line in content.lines() {
                            let line = line.trim();
                            if !line.is_empty() && !line.starts_with('#') {
                                keys.push(line.to_string());
                            }
                        }
                    }
                }
            }
        }

        Ok(keys)
    }

    /// Build authorized_keys entries for a repository session
    ///
    /// This fetches SSH keys for:
    /// 1. The session creator
    /// 2. Explicitly allowed users (if provided)
    /// 3. All repository collaborators/members (if repo_url and a token are provided)
    /// 4. Local SSH keys of the user running the backend
    ///
    /// GitHub and GitLab forges are dispatched on the repository host
    /// (GitLab paths support nested subgroups). When no repo URL is given,
    /// keys are fetched from the auth provider's forge (`auth`), defaulting
    /// to GitHub for backwards compatibility.
    pub async fn build_authorized_keys_for_repo(
        &self,
        creator: Option<&str>,
        allowed_users: Option<&[String]>,
        repo_url: Option<&str>,
        auth: Option<&ForgeAuth>,
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

        // 3. Fetch repository collaborators/members (including upstream if fork)
        // Dispatch on forge: github.com keeps the GitHub API flow, anything
        // else goes through the GitLab Projects API when the auth provider
        // is gitlab (or the repo host matches the configured GitLab base).
        if let Some(url) = repo_url {
            let token = auth.and_then(|a| a.token.as_deref());
            match ForgeRepo::from_url(url) {
                Ok(repo) if repo.is_github() => {
                    self.fetch_github_collaborators_flow(url, token, &mut usernames)
                        .await;
                }
                Ok(repo) => {
                    self.fetch_gitlab_members_flow(&repo, token, &mut usernames)
                        .await;
                }
                Err(e) => {
                    tracing::warn!("Failed to parse repo URL '{}': {}", url, e);
                }
            }
        }

        let gitlab_mode = auth.map(|a| a.provider == "gitlab").unwrap_or(false)
            || repo_url
                .and_then(|u| ForgeRepo::from_url(u).ok())
                .map(|r| !r.is_github())
                .unwrap_or(false);

        // 4. Fetch SSH keys for all users
        tracing::info!(
            "Fetching SSH keys for {} users: {:?}",
            usernames.len(),
            usernames
        );

        for username in usernames {
            match self.fetch_user_keys(&username, gitlab_mode, auth).await {
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

        // 5. Add local SSH keys
        match self.fetch_local_keys().await {
            Ok(local_keys) => {
                tracing::info!("Found {} local SSH keys", local_keys.len());
                for key in local_keys {
                    if seen_keys.insert(key.clone()) {
                        result.push(AuthorizedKey {
                            user: "local-user".to_string(),
                            key,
                        });
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to fetch local SSH keys: {}", e);
            }
        }

        tracing::info!("Built authorized_keys with {} keys", result.len());

        result
    }

    /// Fetch SSH keys for one user, trying the session forge first and
    /// falling back to the other forge (usernames may exist on both;
    /// a 404 on the first is cheap and harmless).
    async fn fetch_user_keys(
        &self,
        username: &str,
        gitlab_mode: bool,
        auth: Option<&ForgeAuth>,
    ) -> Result<Vec<String>> {
        if gitlab_mode {
            let base = gitlab_forge::base_url();
            match gitlab_forge::fetch_user_keys(&self.http_client, &base, username).await {
                Ok(keys) if !keys.is_empty() => return Ok(keys),
                Ok(_) => {}
                Err(e) => tracing::debug!("GitLab .keys miss for {}: {}", username, e),
            }
            if let Some(token) = auth.and_then(|a| a.token.as_deref())
                && let Ok(keys) =
                    gitlab_forge::fetch_user_keys_api(&self.http_client, &base, username, token)
                        .await
                && !keys.is_empty()
            {
                return Ok(keys);
            }
            self.fetch_github_keys(username).await
        } else {
            match self.fetch_github_keys(username).await {
                Ok(keys) if !keys.is_empty() => Ok(keys),
                _ => {
                    let base = gitlab_forge::base_url();
                    gitlab_forge::fetch_user_keys(&self.http_client, &base, username).await
                }
            }
        }
    }

    /// GitHub collaborator flow (repo + upstream parent on forks).
    async fn fetch_github_collaborators_flow(
        &self,
        url: &str,
        token: Option<&str>,
        usernames: &mut Vec<String>,
    ) {
        let Some(repo) = ForgeRepo::from_url(url).ok().and_then(|r| {
            let (owner, repo) = r.owner_repo()?;
            Some((owner, repo))
        }) else {
            tracing::warn!("Failed to parse GitHub repo URL '{}'", url);
            return;
        };
        let (owner, repo) = repo;
        tracing::info!("Fetching repo details for {}/{}", owner, repo);

        let Some(t) = token else {
            tracing::debug!("No token: skipping GitHub collaborator lookup");
            return;
        };

        // First fetch repo details to check for fork
        match github::fetch_repo_details(&self.http_client, &owner, &repo, Some(t)).await {
            Ok(repo_details) => {
                // Fetch collaborators for this repo
                self.fetch_and_add_collaborators(&owner, &repo, t, usernames)
                    .await;

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
                        t,
                        usernames,
                    )
                    .await;
                }
            }
            Err(e) => {
                tracing::warn!("Failed to fetch repo details: {}", e);
                // Fallback to just fetching for this repo
                self.fetch_and_add_collaborators(&owner, &repo, t, usernames)
                    .await;
            }
        }
    }

    /// GitLab members flow (project + upstream parent on forks).
    /// Needs a token with `read_api` scope; without one, only the
    /// creator/--allow users get keys (same degraded mode as GitHub).
    async fn fetch_gitlab_members_flow(
        &self,
        repo: &ForgeRepo,
        token: Option<&str>,
        usernames: &mut Vec<String>,
    ) {
        let Some(t) = token else {
            tracing::debug!("No token: skipping GitLab members lookup");
            return;
        };
        let base = gitlab_forge::base_for_repo(&repo.host);
        let mut paths = vec![repo.gitlab_encoded_path()];
        // Traverse fork parents best-effort.
        if let Ok(details) =
            gitlab_forge::fetch_project(&self.http_client, &base, &paths[0], Some(t)).await
        {
            let mut parent = details.forked_from_project.as_deref();
            while let Some(p) = parent {
                paths.push(urlencoding::encode(&p.path_with_namespace).into_owned());
                parent = p.forked_from_project.as_deref();
            }
        }
        for path in paths {
            match gitlab_forge::fetch_project_members(&self.http_client, &base, &path, t).await {
                Ok(members) => {
                    tracing::info!(
                        "Found {} members for GitLab project {}",
                        members.len(),
                        path
                    );
                    for m in members {
                        if !usernames.contains(&m.username) {
                            usernames.push(m.username);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch GitLab members for {}: {}", path, e);
                }
            }
        }
    }

    async fn fetch_and_add_collaborators(
        &self,
        owner: &str,
        repo: &str,
        token: &str,
        usernames: &mut Vec<String>,
    ) {
        match github::fetch_collaborators(&self.http_client, owner, repo, Some(token)).await {
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
