use anyhow::{Result, anyhow};

/// Auth material for a forge session: which provider the session creator
/// logged in with, plus the OAuth/PAT token used for API calls and
/// token-injected git operations. Replaces the old GitHub-only
/// `github_token: Option<&str>` parameter threading.
#[derive(Debug, Clone, Default)]
pub struct ForgeAuth {
    /// "github" | "gitlab" | ...
    pub provider: String,
    pub login: Option<String>,
    pub token: Option<String>,
}

impl ForgeAuth {
    pub fn github(login: Option<String>, token: Option<String>) -> Self {
        Self {
            provider: "github".to_string(),
            login,
            token,
        }
    }

    pub fn gitlab(login: Option<String>, token: Option<String>) -> Self {
        Self {
            provider: "gitlab".to_string(),
            login,
            token,
        }
    }

    /// Username to embed in token-injected HTTPS clone URLs.
    pub fn token_username(&self) -> &'static str {
        match self.provider.as_str() {
            "gitlab" => "oauth2",
            _ => "x-access-token",
        }
    }
}

/// A parsed forge repository URL: host + full project path.
/// GitHub paths are always `owner/repo`; GitLab paths may nest
/// (`group/subgroup/repo`), so `path` keeps every segment.
#[derive(Debug, Clone)]
pub struct ForgeRepo {
    /// Lowercased host, e.g. `github.com`, `gitlab.com`.
    pub host: String,
    /// Full project path without leading/trailing slashes or `.git`.
    pub path: String,
}

impl ForgeRepo {
    /// Parse repository URLs in any of these forms:
    /// - `https://github.com/owner/repo[.git]`
    /// - `https://gitlab.com/group/sub/repo[.git]`
    /// - `https://host:port/group/repo.git` (self-managed, port kept out of path)
    /// - `git@github.com:owner/repo.git` / `git@host:group/repo.git`
    /// - `github.com/owner/repo`, `gitlab.com/group/repo` (bare)
    pub fn from_url(url: &str) -> Result<Self> {
        let url = url.trim();
        if url.is_empty() {
            return Err(anyhow!("Empty repository URL"));
        }

        // SCP-like SSH syntax: [user@]host:path (no scheme, path not absolute).
        if !url.contains("://")
            && let Some(colon) = url.find(':')
        {
            let before = &url[..colon];
            let after = &url[colon + 1..];
            if !before.contains('/') && !after.starts_with('/') && !after.is_empty() {
                let host = before.rsplit('@').next().unwrap_or(before);
                return Self::build(host, after);
            }
        }

        // URL syntax (with or without scheme).
        let without_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .or_else(|| url.strip_prefix("ssh://"))
            .unwrap_or(url);
        // Strip userinfo (user@, user:pass@) used by token-injected URLs.
        let without_userinfo = match without_scheme.rsplit_once('@') {
            Some((_, rest)) if without_scheme.contains('@') => rest,
            _ => without_scheme,
        };
        // Split host[:port] from path at the first slash.
        let (hostport, path) = without_userinfo
            .split_once('/')
            .ok_or_else(|| anyhow!("Could not parse repository URL: {}", url))?;
        let host = hostport
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(hostport);
        Self::build(host, path)
    }

    fn build(host: &str, path: &str) -> Result<Self> {
        let host = host.trim().trim_start_matches("www.").to_lowercase();
        let path = path
            .trim()
            .trim_matches('/')
            .strip_suffix(".git")
            .unwrap_or(path.trim().trim_matches('/'));
        if host.is_empty() || path.is_empty() || !path.contains('/') {
            return Err(anyhow!("Could not parse repository from host/path"));
        }
        Ok(Self {
            host,
            path: path.to_string(),
        })
    }

    /// True for github.com (and www alias).
    pub fn is_github(&self) -> bool {
        self.host == "github.com"
    }

    /// Owner + repo for GitHub-style two-segment paths.
    pub fn owner_repo(&self) -> Option<(String, String)> {
        let mut parts = self.path.split('/').filter(|s| !s.is_empty());
        match (parts.next(), parts.next()) {
            (Some(owner), Some(repo)) => Some((owner.to_string(), repo.to_string())),
            _ => None,
        }
    }

    /// URL-encoded project path for the GitLab Projects API.
    pub fn gitlab_encoded_path(&self) -> String {
        urlencoding::encode(&self.path).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_https() {
        let r = ForgeRepo::from_url("https://github.com/owner/repo").unwrap();
        assert_eq!(r.host, "github.com");
        assert_eq!(r.path, "owner/repo");
        assert!(r.is_github());
        assert_eq!(r.owner_repo(), Some(("owner".into(), "repo".into())));
    }

    #[test]
    fn test_github_variants() {
        for url in [
            "https://github.com/owner/repo.git",
            "http://github.com/owner/repo",
            "git@github.com:owner/repo.git",
            "github.com/owner/repo",
            "www.github.com/owner/repo",
        ] {
            let r = ForgeRepo::from_url(url).unwrap();
            assert_eq!(
                (r.host.as_str(), r.path.as_str()),
                ("github.com", "owner/repo"),
                "{}",
                url
            );
        }
    }

    #[test]
    fn test_gitlab_nested_subgroups() {
        let r = ForgeRepo::from_url("https://gitlab.com/group/sub/repo.git").unwrap();
        assert_eq!(r.host, "gitlab.com");
        assert_eq!(r.path, "group/sub/repo");
        assert!(!r.is_github());
        assert_eq!(r.gitlab_encoded_path(), "group%2Fsub%2Frepo");
    }

    #[test]
    fn test_gitlab_ssh_and_self_managed() {
        let r = ForgeRepo::from_url("git@gitlab.com:group/repo.git").unwrap();
        assert_eq!(
            (r.host.as_str(), r.path.as_str()),
            ("gitlab.com", "group/repo")
        );

        let r = ForgeRepo::from_url("https://git.example.com:8443/team/project.git").unwrap();
        assert_eq!(
            (r.host.as_str(), r.path.as_str()),
            ("git.example.com", "team/project")
        );
    }

    #[test]
    fn test_token_injected_url() {
        let r = ForgeRepo::from_url("https://oauth2:glpat-xxx@gitlab.com/group/repo.git").unwrap();
        assert_eq!(
            (r.host.as_str(), r.path.as_str()),
            ("gitlab.com", "group/repo")
        );
    }

    #[test]
    fn test_rejects_garbage() {
        for url in ["", "not a url", "github.com/onlyowner", "https://"] {
            assert!(ForgeRepo::from_url(url).is_err(), "{}", url);
        }
    }

    #[test]
    fn test_token_usernames() {
        assert_eq!(ForgeAuth::gitlab(None, None).token_username(), "oauth2");
        assert_eq!(
            ForgeAuth::github(None, None).token_username(),
            "x-access-token"
        );
    }
}
