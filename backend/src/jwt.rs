// backend/src/jwt.rs

use std::sync::Arc;
use anyhow::{anyhow, Result};
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header, request::Parts, StatusCode},
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Clone)]
pub struct JwtKeys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
    pub issuer: String,
    pub ttl_secs: u64,
}

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
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
            issuer: issuer.into(),
            ttl_secs,
        }
    }

    pub fn sign(&self, login: &str, provider: &str) -> Result<String> {
        let exp = (now() + self.ttl_secs) as usize;

        let claims = Claims {
            sub: login.into(),
            iss: self.issuer.clone(),
            exp,
            provider: provider.into(),
        };

        encode(&Header::default(), &claims, &self.encoding)
            .map_err(|e| anyhow!("encode jwt: {}", e))
    }

    pub fn verify(&self, token: &str) -> Result<Claims> {
        let data = decode::<Claims>(
            token,
            &self.decoding,
            &Validation::default(),
        )
        .map_err(|e| anyhow!("invalid or expired JWT: {}", e))?;

        Ok(data.claims)
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// --- NEW AXUM EXTRACTOR FOR CLAIMS ---

#[async_trait]
impl FromRequestParts<Arc<AppState>> for Claims {
    type Rejection = (StatusCode, String);

    /// Extracts JWT claims from the Authorization header.
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Get the Authorization header.
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, "Missing Authorization header".into())
            })?;

        // Check for "Bearer " prefix and get the token.
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| {
                (StatusCode::BAD_REQUEST, "Invalid token type; expected Bearer".into())
            })?;

        // Verify the token using the keys in our app state.
        state
            .jwt
            .verify(token)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))
    }
}
