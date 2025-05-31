use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub master_seed_base64: String,
    pub port: u16,
    pub allowed_origins: Vec<String>,
    pub rate_limit_per_minute: i32,
    pub log_level: String,
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
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .context("Invalid PORT")?,
            allowed_origins: env::var("ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "https://wallet.mysocial.network".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            rate_limit_per_minute: env::var("RATE_LIMIT")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .context("Invalid RATE_LIMIT")?,
            log_level: env::var("LOG_LEVEL")
                .unwrap_or_else(|_| "info".to_string()),
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

        Ok(())
    }
} 