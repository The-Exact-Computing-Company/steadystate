use crate::compute::common::forge::ForgeAuth;
use crate::compute::common::git_ops::GitOps;
use crate::compute::traits::RemoteExecutor;
use crate::models::SessionRequest;

/// Extract forge auth material from a session request's `provider_config`.
/// Understands both shapes the CLI sends:
/// `{ "github": { "login", "access_token" } }` and
/// `{ "gitlab": { "login", "access_token" } }`.
/// Returns `None` when no provider block is present (e.g. tests or
/// public sessions without stored credentials).
pub fn extract_forge_config(request: &SessionRequest) -> Option<ForgeAuth> {
    let cfg = request.provider_config.as_ref()?;
    for provider in ["github", "gitlab"] {
        if let Some(block) = cfg.get(provider) {
            #[derive(serde::Deserialize)]
            struct Creds {
                #[serde(default)]
                login: Option<String>,
                #[serde(default)]
                access_token: Option<String>,
            }
            if let Ok(creds) = serde_json::from_value::<Creds>(block.clone())
                && (creds.login.is_some() || creds.access_token.is_some())
            {
                return Some(ForgeAuth {
                    provider: provider.to_string(),
                    login: creds.login,
                    token: creds.access_token,
                });
            }
        }
    }
    None
}

/// Split the auth into (login, token) for call sites that only need those.
pub fn login_and_token(request: &SessionRequest) -> (Option<String>, Option<String>) {
    match extract_forge_config(request) {
        Some(f) => (f.login, f.token),
        None => (None, None),
    }
}

/// Inject the forge token into an HTTPS origin URL for passwordless
/// push/pull (`x-access-token` for GitHub, `oauth2` for GitLab).
/// No-op without a token or for non-HTTPS URLs.
pub async fn inject_token_auth(
    executor: &dyn RemoteExecutor,
    repo_path: &std::path::Path,
    repo_url: &str,
    auth: &ForgeAuth,
) {
    let Some(token) = auth.token.as_deref() else {
        return;
    };
    if !repo_url.starts_with("https://") {
        return;
    }
    if let Ok(mut url) = url::Url::parse(repo_url) {
        let _ = url.set_username(auth.token_username());
        let _ = url.set_password(Some(token));
        let git = GitOps::new(executor);
        if let Err(e) = git.set_remote_url(repo_path, "origin", url.as_str()).await {
            tracing::warn!(
                "Failed to configure git auth for {}: {}",
                repo_path.display(),
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_with(provider: &str, login: &str, token: &str) -> SessionRequest {
        SessionRequest {
            repo_url: "https://github.com/u/r".to_string(),
            branch: None,
            environment: None,
            provider: None,
            provider_config: Some(serde_json::json!({
                provider: { "login": login, "access_token": token }
            })),
            allowed_users: None,
            mode: None,
            ttl_secs: None,
        }
    }

    #[test]
    fn test_extract_github_shape() {
        let f = extract_forge_config(&req_with("github", "octo", "tok")).unwrap();
        assert_eq!(f.provider, "github");
        assert_eq!(f.login.as_deref(), Some("octo"));
        assert_eq!(f.token.as_deref(), Some("tok"));
        assert_eq!(f.token_username(), "x-access-token");
    }

    #[test]
    fn test_extract_gitlab_shape() {
        let f = extract_forge_config(&req_with("gitlab", "gluser", "glpat")).unwrap();
        assert_eq!(f.provider, "gitlab");
        assert_eq!(f.login.as_deref(), Some("gluser"));
        assert_eq!(f.token.as_deref(), Some("glpat"));
        assert_eq!(f.token_username(), "oauth2");
    }

    #[test]
    fn test_extract_absent_is_none() {
        let mut req = req_with("github", "u", "t");
        req.provider_config = None;
        assert!(extract_forge_config(&req).is_none());
        assert_eq!(login_and_token(&req), (None, None));
    }
}
