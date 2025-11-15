// src/jwt.rs

use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

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
