// backend/src/jwt.rs

use std::collections::HashSet;
// We don't need Arc here anymore for the extractor logic, but it's fine to keep common imports.
use anyhow::{anyhow, Result};
// EXPLICITLY import async_trait from the crate, not via axum
use async_trait::async_trait;
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
        let custom_claims = CustomClaims {
            sub: login.to_string(),
            provider: provider.to_string(),
        };

        let claims = Claims::with_custom_claims(custom_claims, self.ttl_duration)
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
            .verify_token::<CustomClaims>(token, Some(options))
            .map_err(|e| anyhow!("Invalid or expired JWT: {}", e))?;
        
        Ok(claims.custom)
    }
}

// --- AXUM EXTRACTOR FOR CUSTOM CLAIMS ---

// Ensure this attribute is present and coming from the `async_trait` crate
#[async_trait]
impl FromRequestParts<AppState> for CustomClaims {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
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
