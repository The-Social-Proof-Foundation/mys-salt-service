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
    pub twitch_client_secret: Option<String>,
    pub facebook_app_secret: Option<String>,
    pub facebook_app_id: Option<String>,
    /// Canonical aud for Google JWT validation. Web and iOS must use same client ID.
    pub allowed_audience_google: Option<String>,
    /// Google client secret for token exchange.
    pub google_client_secret: Option<String>,
    /// Canonical aud for Apple JWT validation. Web and iOS must use same client ID.
    pub allowed_audience_apple: Option<String>,
    /// Apple Team ID for JWT client assertion.
    pub apple_team_id: Option<String>,
    /// Apple Key Identifier for JWT client assertion.
    pub apple_key_identifier: Option<String>,
    /// Apple private key (PEM) for JWT client assertion.
    pub apple_private_key: Option<String>,
    /// Canonical aud for Facebook access-token flow.
    pub allowed_audience_facebook: Option<String>,
    /// Canonical aud for Twitch access-token flow.
    pub allowed_audience_twitch: Option<String>,
    /// Auth frontend OAuth callback URL (where Google/Apple redirect after login). Used for token exchange.
    pub auth_callback_url: Option<String>,
    pub allowed_clients: Vec<AllowedClient>,
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
            twitch_client_secret: env::var("TWITCH_CLIENT_SECRET").ok(),
            facebook_app_secret: env::var("FACEBOOK_APP_SECRET").ok(),
            facebook_app_id: env::var("FACEBOOK_APP_ID").ok(),
            allowed_audience_google: env::var("ALLOWED_AUDIENCE_GOOGLE").ok(),
            google_client_secret: env::var("GOOGLE_CLIENT_SECRET").ok(),
            allowed_audience_apple: env::var("ALLOWED_AUDIENCE_APPLE").ok(),
            apple_team_id: env::var("APPLE_TEAM_ID").ok(),
            apple_key_identifier: env::var("APPLE_KEY_IDENTIFIER").ok(),
            apple_private_key: env::var("APPLE_PRIVATE_KEY").ok(),
            allowed_audience_facebook: env::var("ALLOWED_AUDIENCE_FACEBOOK").ok(),
            allowed_audience_twitch: env::var("ALLOWED_AUDIENCE_TWITCH").ok(),
            auth_callback_url: env::var("AUTH_CALLBACK_URL").ok(),
            allowed_clients: parse_allowed_clients_for_auth()?,
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

        if !self.allowed_clients.is_empty() && (self.auth_callback_url.is_none() || self.auth_callback_url.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true)) {
            anyhow::bail!("AUTH_CALLBACK_URL must be set when ALLOWED_CLIENTS is non-empty. Set to auth frontend OAuth callback (e.g. https://auth.testnet.mysocial.network/callback)");
        }

        Ok(())
    }
}

fn parse_allowed_clients_for_auth() -> Result<Vec<AllowedClient>> {
    let s = env::var("ALLOWED_CLIENTS").ok();
    let s = match s {
        Some(s) if !s.trim().is_empty() => s,
        _ => return Ok(Vec::new()),
    };
    let clients: Vec<AllowedClient> = serde_json::from_str(&s).context("Invalid ALLOWED_CLIENTS JSON")?;
    Ok(clients)
}
