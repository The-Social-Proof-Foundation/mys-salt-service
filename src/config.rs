use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedClient {
    pub client_id: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub master_seed_base64: String,
    pub port: u16,
    pub allowed_origins: Vec<String>,
    pub rate_limit_per_minute: i32,
    pub log_level: String,
    pub twitch_client_id: Option<String>,
    pub facebook_app_secret: Option<String>,
    pub facebook_app_id: Option<String>,
    /// Canonical aud for Google JWT validation. Web and iOS must use same client ID.
    pub allowed_audience_google: Option<String>,
    /// Canonical aud for Apple JWT validation. Web and iOS must use same client ID.
    pub allowed_audience_apple: Option<String>,
    /// Canonical aud for Facebook access-token flow.
    pub allowed_audience_facebook: Option<String>,
    /// Canonical aud for Twitch access-token flow.
    pub allowed_audience_twitch: Option<String>,
    pub auth_api_base_url: Option<String>,
    pub allowed_clients: Vec<AllowedClient>,
    pub auth_client_secret: Option<String>,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        Ok(Config {
            database_url: env::var("DATABASE_URL")
                .context("DATABASE_URL not set")?,
            master_seed_base64: env::var("MASTER_SEED")
                .context("MASTER_SEED not set")?,
            port: env::var("PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .context("Invalid PORT")?,
            allowed_origins: env::var("ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "https://mysocial.network,http://localhost:3000".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            rate_limit_per_minute: env::var("RATE_LIMIT")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .context("Invalid RATE_LIMIT")?,
            log_level: env::var("LOG_LEVEL")
                .unwrap_or_else(|_| "info".to_string()),
            twitch_client_id: env::var("TWITCH_CLIENT_ID").ok(),
            facebook_app_secret: env::var("FACEBOOK_APP_SECRET").ok(),
            facebook_app_id: env::var("FACEBOOK_APP_ID").ok(),
            allowed_audience_google: env::var("ALLOWED_AUDIENCE_GOOGLE").ok(),
            allowed_audience_apple: env::var("ALLOWED_AUDIENCE_APPLE").ok(),
            allowed_audience_facebook: env::var("ALLOWED_AUDIENCE_FACEBOOK").ok(),
            allowed_audience_twitch: env::var("ALLOWED_AUDIENCE_TWITCH").ok(),
            auth_api_base_url: env::var("AUTH_API_BASE_URL").ok(),
            allowed_clients: parse_allowed_clients().unwrap_or_default(),
            auth_client_secret: env::var("AUTH_CLIENT_SECRET").ok(),
        })
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate master seed
        let seed = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.master_seed_base64
        ).context("Invalid MASTER_SEED base64")?;

        if seed.len() < 32 {
            anyhow::bail!("MASTER_SEED must be at least 32 bytes");
        }

        // Validate database URL
        if !self.database_url.starts_with("postgresql://") && !self.database_url.starts_with("postgres://") {
            anyhow::bail!("DATABASE_URL must be a PostgreSQL connection string");
        }

        // Require allowed audiences for JWT providers (Google, Apple)
        if self.allowed_audience_google.is_none() || self.allowed_audience_google.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
            anyhow::bail!("ALLOWED_AUDIENCE_GOOGLE must be set for JWT validation");
        }
        if self.allowed_audience_apple.is_none() || self.allowed_audience_apple.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
            anyhow::bail!("ALLOWED_AUDIENCE_APPLE must be set for JWT validation");
        }

        // Require allowed audiences for access-token providers when configured
        if self.facebook_app_id.is_some() && (self.allowed_audience_facebook.is_none() || self.allowed_audience_facebook.as_ref().map(|s| s.is_empty()).unwrap_or(true)) {
            anyhow::bail!("ALLOWED_AUDIENCE_FACEBOOK must be set when FACEBOOK_APP_ID is configured");
        }
        if self.twitch_client_id.is_some() && (self.allowed_audience_twitch.is_none() || self.allowed_audience_twitch.as_ref().map(|s| s.is_empty()).unwrap_or(true)) {
            anyhow::bail!("ALLOWED_AUDIENCE_TWITCH must be set when TWITCH_CLIENT_ID is configured");
        }

        if self.auth_api_base_url.is_some() && self.allowed_clients.is_empty() {
            anyhow::bail!("ALLOWED_CLIENTS must be non-empty when AUTH_API_BASE_URL is configured");
        }

        Ok(())
    }
}

fn parse_allowed_clients() -> Result<Vec<AllowedClient>> {
    let s = env::var("ALLOWED_CLIENTS").ok();
    let s = match s {
        Some(s) if !s.trim().is_empty() => s,
        _ => return Ok(Vec::new()),
    };
    serde_json::from_str(&s).context("Invalid ALLOWED_CLIENTS JSON")
}
