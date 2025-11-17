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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "a-very-secret-key-for-testing";
    const TEST_ISSUER: &str = "steadystate-test";

    #[test]
    fn test_sign_verify_cycle_success() {
        let keys = JwtKeys::new(TEST_SECRET, TEST_ISSUER, 60);
        let token = keys.sign("test-user", "github").unwrap();

        let claims = keys.verify(&token).unwrap();
        assert_eq!(claims.sub, "test-user");
        assert_eq!(claims.provider, "github");
        assert_eq!(claims.iss, TEST_ISSUER);
    }

    #[test]
    fn test_verify_fails_on_immediately_expired_token() {
        // Use a zero-second TTL to create an instantly expired token.
        let keys = JwtKeys::new(TEST_SECRET, TEST_ISSUER, 0);
        let token = keys.sign("test-user", "fake").unwrap();

        let result = keys.verify(&token);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        // Assert on the error type, which is more stable than the full message.
        assert!(err_msg.contains("ExpiredSignature"));
    }

    #[test]
    fn test_verify_fails_on_wrong_secret() {
        let signing_keys = JwtKeys::new("secret-one", TEST_ISSUER, 60);
        let verifying_keys = JwtKeys::new("secret-two", TEST_ISSUER, 60);

        let token = signing_keys.sign("test-user", "github").unwrap();
        let result = verifying_keys.verify(&token);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("InvalidSignature"));
    }

    #[test]
    fn test_verify_fails_on_tampered_payload() {
        let keys = JwtKeys::new(TEST_SECRET, TEST_ISSUER, 60);
        let token = keys.sign("admin", "github").unwrap();
        
        // Correctly tamper by replacing the payload with a valid-but-different one.
        // `e30` is the Base64URL encoding of `{}`, an empty JSON object.
        let mut parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have three parts");
        parts[1] = "e30"; // Tamper the payload
        let tampered_token = parts.join(".");

        let result = keys.verify(&tampered_token);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        // The signature will no longer match the header + tampered payload.
        assert!(err_msg.contains("InvalidSignature"));
    }
}
