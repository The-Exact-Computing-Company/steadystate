// backend/src/jwt.rs

use std::collections::HashSet;
use std::sync::Arc;
use anyhow::{anyhow, Result};
use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, StatusCode},
};
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
use crate::state::AppState;

#[derive(Clone)]
pub struct JwtKeys {
    key: HS256Key,
    issuer: String,
    ttl_duration: Duration,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct InternalCustomClaims {
    provider: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomClaims {
    pub sub: String,
    pub provider: String,
}

impl JwtKeys {
    pub fn new(secret: &str, issuer: &str, ttl_secs: u64) -> Self {
        Self {
            key: HS256Key::from_bytes(secret.as_bytes()),
            issuer: issuer.into(),
            ttl_duration: Duration::from_secs(ttl_secs),
        }
    }

    pub fn sign(&self, login: &str, provider: &str) -> Result<String> {
        let internal_claims = InternalCustomClaims {
            provider: provider.to_string(),
        };

        let claims = Claims::with_custom_claims(internal_claims, self.ttl_duration)
            .with_issuer(self.issuer.clone())
            .with_subject(login.to_string());

        self.key.authenticate(claims).map_err(|e| anyhow!("Failed to sign JWT: {}", e))
    }

    pub fn verify(&self, token: &str) -> Result<CustomClaims> {
        let mut allowed_issuers = HashSet::new();
        allowed_issuers.insert(self.issuer.clone());

        let options = VerificationOptions {
            allowed_issuers: Some(allowed_issuers),
            ..Default::default()
        };

        let claims = self.key
            .verify_token::<InternalCustomClaims>(token, Some(options))
            .map_err(|e| anyhow!("Invalid or expired JWT: {}", e))?;
        
        let sub = claims.subject.ok_or_else(|| anyhow!("JWT missing subject claim"))?;

        Ok(CustomClaims {
            sub,
            provider: claims.custom.provider,
        })
    }
}

// --- AXUM 0.8 EXTRACTOR FOR CUSTOM CLAIMS ---
// NOTE: Do NOT use #[async_trait] here. Axum 0.8 uses standard async fn traits.

impl FromRequestParts<Arc<AppState>> for CustomClaims {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, "Missing Authorization header".into())
            })?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| {
                (StatusCode::BAD_REQUEST, "Invalid token type; expected Bearer".into())
            })?;

        state
            .jwt
            .verify(token)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))
    }
}
