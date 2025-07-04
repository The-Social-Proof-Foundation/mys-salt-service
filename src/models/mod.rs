use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserSalt {
    pub id: Uuid,
    pub user_identifier: String,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub encrypted_salt: Vec<u8>,
    pub encryption_version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub user_identifier: String,
    pub action_type: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub jwt_hash: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub iss: String,  // Issuer
    pub aud: String,  // Audience
    pub sub: String,  // Subject (user ID)
    pub exp: i64,     // Expiration
    pub iat: i64,     // Issued at
    pub nonce: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSaltRequest {
    pub jwt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSaltResponse {
    pub salt: String,  // Base64 encoded
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ActionType {
    Create,
    Read,
    Rotate,
    Error,
}

impl ActionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActionType::Create => "CREATE",
            ActionType::Read => "READ",
            ActionType::Rotate => "ROTATE",
            ActionType::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProviderConfig {
    pub issuer: String,
    pub jwks_uri: String,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
}

impl OAuthProviderConfig {
    pub fn google() -> Self {
        Self {
            issuer: "https://accounts.google.com".to_string(),
            jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".to_string(),
            token_endpoint: Some("https://oauth2.googleapis.com/token".to_string()),
            userinfo_endpoint: Some("https://openidconnect.googleapis.com/v1/userinfo".to_string()),
        }
    }

    pub fn facebook() -> Self {
        Self {
            issuer: "https://www.facebook.com".to_string(),
            jwks_uri: "https://www.facebook.com/.well-known/oauth/openid/jwks/".to_string(),
            token_endpoint: Some("https://graph.facebook.com/v12.0/oauth/access_token".to_string()),
            userinfo_endpoint: Some("https://graph.facebook.com/me".to_string()),
        }
    }
    
    pub fn apple() -> Self {
        Self {
            issuer: "https://appleid.apple.com".to_string(),
            jwks_uri: "https://appleid.apple.com/auth/keys".to_string(),
            token_endpoint: Some("https://appleid.apple.com/auth/token".to_string()),
            userinfo_endpoint: None, // Apple doesn't provide a userinfo endpoint
        }
    }
} 