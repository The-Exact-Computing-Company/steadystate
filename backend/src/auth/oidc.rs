// backend/src/auth/oidc.rs
//
// Enterprise SSO via generic OpenID Connect.
//
// Flow (PKCE lives in the CLI, RFC 8252 native-app style):
// 1. CLI generates a PKCE verifier/challenge pair.
// 2. POST /auth/oidc/start { code_challenge } -> { key, auth_url, expires_in }.
//    The backend mints `state`, stores {state, challenge} under `key`.
// 3. The user completes login in a browser; the IdP redirects to the CLI's
//    localhost listener, which captures `code` + echoed `state`.
// 4. POST /auth/oidc/complete { key, code, verifier } -> JWT + refresh.
//    The backend exchanges the code (proving `verifier` against the stored
//    challenge), reads userinfo, and mints SteadyState credentials.
//
// The backend never serves browser traffic, so this works even when it is
// not browser-reachable. Identity comes from the userinfo endpoint, so no
// ID-token JWT validation (and no new crypto dependencies) is needed.

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

use crate::auth::provider::{
    AuthProvider, AuthProviderDyn, AuthProviderFactory, DevicePollOutcome, UserIdentity,
};
use crate::models::{DeviceStartResponse, ProviderId};
use crate::state::AppState;

/// How long a pending OIDC login (start -> complete) stays valid.
pub const OIDC_PENDING_TTL_SECS: u64 = 600;

/// Pending login created by /auth/oidc/start, completed by /complete.
#[derive(Clone, Debug)]
pub struct OidcPending {
    pub state: String,
    pub code_challenge: String,
    /// The CLI's localhost callback, echoed back at authorize time and
    /// required verbatim at exchange time.
    pub redirect_uri: String,
    pub created_at: u64,
}

/// Resolved OIDC configuration: endpoints from discovery + client credentials.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: String,
    pub login_claim: String,
}

/// Expand `OIDC_ISSUER`: either a full `https://...` URL or a preset:
/// - `google` -> https://accounts.google.com
/// - `entra:{tenant}` -> https://login.microsoftonline.com/{tenant}/v2.0
/// - `okta:{domain}` -> https://{domain}
pub fn expand_issuer_preset(raw: &str) -> anyhow::Result<String> {
    let raw = raw.trim();
    if raw.starts_with("https://") || raw.starts_with("http://") {
        return Ok(raw.trim_end_matches('/').to_string());
    }
    if raw == "google" {
        return Ok("https://accounts.google.com".to_string());
    }
    if let Some(tenant) = raw.strip_prefix("entra:") {
        let tenant = tenant.trim();
        if tenant.is_empty() {
            return Err(anyhow!("entra preset needs a tenant, e.g. entra:common"));
        }
        return Ok(format!(
            "https://login.microsoftonline.com/{}/v2.0",
            tenant.trim_end_matches('/')
        ));
    }
    if let Some(domain) = raw.strip_prefix("okta:") {
        let domain = domain.trim().trim_end_matches('/');
        if domain.is_empty() {
            return Err(anyhow!(
                "okta preset needs a domain, e.g. okta:example.okta.com"
            ));
        }
        return Ok(format!("https://{}", domain));
    }
    Err(anyhow!(
        "OIDC_ISSUER must be an https:// URL or a preset (google, entra:{{tenant}}, okta:{{domain}}), got {:?}",
        raw
    ))
}

#[derive(Deserialize)]
struct DiscoveryDoc {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

impl OidcConfig {
    /// Resolve from env and run OIDC discovery. Fails fast with a clear
    /// error so misconfiguration surfaces at provider build, not at login.
    pub async fn from_env(http: &Client) -> anyhow::Result<Self> {
        let raw_issuer =
            std::env::var("OIDC_ISSUER").context("OIDC_ISSUER is not configured on the server")?;
        let issuer = expand_issuer_preset(&raw_issuer)?;
        // Cleartext issuers leak client_secret + codes. Allow only behind an
        // explicit escape hatch (local mock IdPs, closed test networks).
        if issuer.starts_with("http://") && std::env::var("OIDC_ALLOW_HTTP").is_err() {
            return Err(anyhow!(
                "OIDC_ISSUER uses http:// which would send the client secret in cleartext; use https:// or set OIDC_ALLOW_HTTP=1 only for a trusted test IdP"
            ));
        }
        let client_id = std::env::var("OIDC_CLIENT_ID")
            .context("OIDC_CLIENT_ID is not configured on the server")?;
        let client_secret = std::env::var("OIDC_CLIENT_SECRET")
            .context("OIDC_CLIENT_SECRET is not configured on the server")?;
        let scopes =
            std::env::var("OIDC_SCOPES").unwrap_or_else(|_| "openid profile email".to_string());
        let login_claim =
            std::env::var("OIDC_LOGIN_CLAIM").unwrap_or_else(|_| "preferred_username".to_string());

        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let doc: DiscoveryDoc = http
            .get(&discovery_url)
            .header("User-Agent", "steadystate-backend/0.1")
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .with_context(|| format!("OIDC discovery failed for {}", issuer))?
            .error_for_status()
            .map_err(|e| anyhow!("OIDC discovery rejected for {}: {}", issuer, e))?
            .json()
            .await
            .context("Failed to decode OIDC discovery document")?;

        Ok(Self {
            issuer,
            authorization_endpoint: doc.authorization_endpoint,
            token_endpoint: doc.token_endpoint,
            userinfo_endpoint: doc.userinfo_endpoint,
            client_id,
            client_secret,
            scopes,
            login_claim,
        })
    }

    /// Build the authorization URL the CLI opens in a browser.
    /// `redirect_uri` is the CLI's localhost callback; `state` binds the
    /// round-trip against CSRF.
    pub fn authorization_url(&self, state: &str, challenge: &str, redirect_uri: &str) -> String {
        let enc = urlencoding::encode;
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            self.authorization_endpoint,
            enc(&self.client_id),
            enc(redirect_uri),
            enc(&self.scopes),
            enc(state),
            enc(challenge),
        )
    }

    /// Exchange `code` + `verifier` for an access token.
    pub async fn exchange_code(
        &self,
        http: &Client,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> anyhow::Result<String> {
        if code.trim().is_empty() || verifier.trim().is_empty() {
            return Err(anyhow!("Empty code or verifier"));
        }
        let resp: TokenResponse = http
            .post(&self.token_endpoint)
            .header("User-Agent", "steadystate-backend/0.1")
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.trim()),
                ("redirect_uri", redirect_uri),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code_verifier", verifier.trim()),
            ])
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .context("OIDC token request failed")?
            .error_for_status()
            .map_err(|e| anyhow!("IdP rejected the code exchange: {}", e))?
            .json()
            .await
            .context("Failed to decode OIDC token response")?;
        if resp.access_token.trim().is_empty() {
            return Err(anyhow!("IdP returned an empty access token"));
        }
        Ok(resp.access_token)
    }

    /// Read userinfo and map it to a SteadyState identity.
    pub async fn fetch_identity(
        &self,
        http: &Client,
        access_token: &str,
    ) -> anyhow::Result<UserIdentity> {
        let claims: serde_json::Value = http
            .get(&self.userinfo_endpoint)
            .bearer_auth(access_token)
            .header("User-Agent", "steadystate-backend/0.1")
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .context("OIDC userinfo request failed")?
            .error_for_status()
            .map_err(|e| anyhow!("IdP rejected the userinfo request: {}", e))?
            .json()
            .await
            .context("Failed to decode OIDC userinfo")?;

        let str_claim = |name: &str| {
            claims
                .get(name)
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        let login = str_claim(&self.login_claim)
            .or_else(|| str_claim("preferred_username"))
            .or_else(|| str_claim("email"))
            .or_else(|| str_claim("sub"))
            .ok_or_else(|| anyhow!("IdP userinfo has no usable login claim"))?;
        let sub = str_claim("sub").unwrap_or_else(|| login.clone());
        Ok(UserIdentity {
            id: format!("oidc:{}", sub),
            login,
            email: str_claim("email"),
            provider: "oidc".into(),
        })
    }
}

// --- AuthProvider glue (device flow intentionally unsupported) ---

#[derive(Debug)]
pub struct OidcAuth {
    pub config: OidcConfig,
}

#[async_trait]
impl AuthProvider for OidcAuth {
    fn id(&self) -> ProviderId {
        ProviderId::from("oidc")
    }

    async fn start_device_flow(&self) -> anyhow::Result<DeviceStartResponse> {
        Err(anyhow!(
            "OIDC has no device flow. Use `steadystate login --provider=oidc` (browser + localhost callback) instead."
        ))
    }

    async fn poll_device_flow(&self, _device_code: &str) -> anyhow::Result<DevicePollOutcome> {
        Err(anyhow!(
            "OIDC has no device flow. Use `steadystate login --provider=oidc` (browser + localhost callback) instead."
        ))
    }
}

pub struct OidcFactory;

#[async_trait]
impl AuthProviderFactory for OidcFactory {
    fn id(&self) -> &'static str {
        "oidc"
    }

    async fn build(self: Arc<Self>, state: &AppState) -> anyhow::Result<AuthProviderDyn> {
        let config = OidcConfig::from_env(&state.http).await?;
        Ok(Arc::new(OidcAuth { config }) as AuthProviderDyn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_issuer_preset() {
        assert_eq!(
            expand_issuer_preset("https://sso.example.com/realms/x/").unwrap(),
            "https://sso.example.com/realms/x"
        );
        assert_eq!(
            expand_issuer_preset("google").unwrap(),
            "https://accounts.google.com"
        );
        assert_eq!(
            expand_issuer_preset("entra:common").unwrap(),
            "https://login.microsoftonline.com/common/v2.0"
        );
        assert_eq!(
            expand_issuer_preset("okta:example.okta.com").unwrap(),
            "https://example.okta.com"
        );
        assert!(expand_issuer_preset("entra:").is_err());
        assert!(expand_issuer_preset("okta:").is_err());
        assert!(expand_issuer_preset("keycloak").is_err());
        assert!(expand_issuer_preset("").is_err());
    }

    #[test]
    fn test_authorization_url_params() {
        let cfg = OidcConfig {
            issuer: "https://sso.example.com".to_string(),
            authorization_endpoint: "https://sso.example.com/authorize".to_string(),
            token_endpoint: "https://sso.example.com/token".to_string(),
            userinfo_endpoint: "https://sso.example.com/userinfo".to_string(),
            client_id: "cid".to_string(),
            client_secret: "csecret".to_string(),
            scopes: "openid profile email".to_string(),
            login_claim: "preferred_username".to_string(),
        };
        let url = cfg.authorization_url("st4te", "chall3nge", "http://127.0.0.1:9/callback");
        assert!(url.starts_with("https://sso.example.com/authorize?"));
        for needle in [
            "response_type=code",
            "client_id=cid",
            "state=st4te",
            "code_challenge=chall3nge",
            "code_challenge_method=S256",
            "scope=openid",
        ] {
            assert!(url.contains(needle), "{}", url);
        }
    }
}
