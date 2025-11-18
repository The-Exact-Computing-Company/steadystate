// backend/src/jwt.rs

use std::sync::Arc;
use anyhow::{anyhow, Result};
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header, request::Parts, StatusCode},
};
// Import the necessary items from jwt-simple
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
use crate::state::AppState;

// This struct can now be a simple wrapper around the key.
#[derive(Clone)]
pub struct JwtKeys {
    key: HS256Key,
    issuer: String,
    ttl_duration: Duration,
}

// The claims struct remains the same.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub exp: usize,
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
        let claims = Claims {
            sub: login.to_string(),
            iss: self.issuer.clone(),
            // `jwt-simple` handles exp automatically via `with_duration`
            exp: 0, 
            provider: provider.to_string(),
        };

        let jwt_claims = JWTClaims::with_custom_claims(claims, self.ttl_duration);
        self.key.authenticate(jwt_claims).map_err(|e| anyhow!("Failed to sign JWT: {}", e))
    }

    pub fn verify(&self, token: &str) -> Result<Claims> {
        // Verification options ensure we check the issuer.
        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from_strings(&[self.issuer.as_str()])),
            ..Default::default()
        };

        let claims = self.key
            .verify_token::<Claims>(token, Some(options))
            .map_err(|e| anyhow!("Invalid or expired JWT: {}", e))?;
        
        Ok(claims.custom)
    }
}

// --- AXUM EXTRACTOR FOR CLAIMS (no changes needed here) ---

#[async_trait]
impl FromRequestParts<Arc<AppState>> for Claims {
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
