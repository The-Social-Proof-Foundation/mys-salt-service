//! Session token issuance for MySocial wallet and OAuth auth flows.
//!
//! Access tokens: JWT, 30 min, sub=user_identifier.
//! Refresh tokens: 32 random bytes, hashed with SHA-256 before storage.

use anyhow::{Context, Result};
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ACCESS_TOKEN_EXPIRY_SECS: i64 = 1800; // 30 minutes

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
}

/// Issue an access token (JWT) for the given user identifier.
pub fn issue_access_token(
    user_identifier: &str,
    issuer: &str,
    signing_key: &[u8],
) -> Result<String> {
    let now = Utc::now().timestamp();
    let claims = SessionClaims {
        sub: user_identifier.to_string(),
        iat: now,
        exp: now + ACCESS_TOKEN_EXPIRY_SECS,
        iss: issuer.to_string(),
    };

    let header = Header::default();
    let key = EncodingKey::from_secret(signing_key);
    encode(&header, &claims, &key).context("Failed to encode access token")
}

/// Generate a new refresh token (32 bytes, 256 bits) and its hash for storage.
/// Returns (opaque_token, hash_hex).
pub fn generate_refresh_token() -> Result<(String, String)> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let opaque = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &bytes,
    );
    let hash = hash_refresh_token(&opaque);
    Ok((opaque, hash))
}

/// Hash a refresh token for storage (SHA-256 hex).
pub fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}
