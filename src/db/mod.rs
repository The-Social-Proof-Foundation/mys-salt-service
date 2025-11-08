use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::models::{ActionType, AuditLogEntry, JwtClaims, UserSalt};
use crate::security::jwt::JwtValidator;

#[derive(Clone)]
pub struct SaltStore {
    pool: PgPool,
}

impl SaltStore {
    /// Create a new SaltStore with database connection
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .connect(database_url)
            .await
            .context("Failed to connect to database")?;

        Ok(Self { pool })
    }

    /// Get pool for migrations
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Store encrypted salt for a user
    /// Returns the stored salt, or None if a salt already exists (to handle race conditions)
    /// This function NEVER overwrites existing salts - salts are immutable once created
    pub async fn store_salt(
        &self,
        claims: &JwtClaims,
        encrypted_salt: &[u8],
    ) -> Result<Option<UserSalt>> {
        let user_identifier = JwtValidator::generate_user_identifier(claims);

        // Try to insert, but do nothing if salt already exists (ON CONFLICT DO NOTHING)
        // This prevents race conditions where two requests try to create a salt simultaneously
        let result = sqlx::query_as::<_, UserSalt>(
            r#"
            INSERT INTO user_salts (user_identifier, iss, aud, sub, encrypted_salt, encryption_version)
            VALUES ($1, $2, $3, $4, $5, 1)
            ON CONFLICT (user_identifier) DO NOTHING
            RETURNING 
                id, 
                user_identifier, 
                iss, 
                aud, 
                sub, 
                encrypted_salt, 
                encryption_version, 
                created_at, 
                updated_at
            "#
        )
        .bind(&user_identifier)
        .bind(&claims.iss)
        .bind(&claims.aud)
        .bind(&claims.sub)
        .bind(encrypted_salt)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to store salt")?;

        Ok(result)
    }

    /// Retrieve encrypted salt for a user
    pub async fn get_salt(&self, claims: &JwtClaims) -> Result<Option<UserSalt>> {
        let user_identifier = JwtValidator::generate_user_identifier(claims);

        // Log the database query for debugging
        tracing::debug!(
            "Querying salt for user_identifier: {} (iss: {}, sub: {})",
            user_identifier,
            claims.iss,
            claims.sub
        );

        let salt = sqlx::query_as::<_, UserSalt>(
            r#"
            SELECT 
                id, 
                user_identifier, 
                iss, 
                aud, 
                sub, 
                encrypted_salt, 
                encryption_version, 
                created_at, 
                updated_at
            FROM user_salts
            WHERE user_identifier = $1
            "#
        )
        .bind(&user_identifier)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to retrieve salt")?;

        Ok(salt)
    }

    /// Log an audit entry
    pub async fn log_audit(
        &self,
        user_identifier: &str,
        action_type: ActionType,
        ip_address: Option<String>,
        user_agent: Option<String>,
        jwt_hash: Option<String>,
        success: bool,
        error_message: Option<String>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO salt_audit_log 
            (user_identifier, action_type, ip_address, user_agent, jwt_hash, success, error_message)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#
        )
        .bind(user_identifier)
        .bind(action_type.as_str())
        .bind(&ip_address)
        .bind(&user_agent)
        .bind(&jwt_hash)
        .bind(success)
        .bind(&error_message)
        .execute(&self.pool)
        .await
        .context("Failed to log audit entry")?;

        Ok(())
    }

    /// Get audit logs for a user
    pub async fn get_audit_logs(&self, user_identifier: &str) -> Result<Vec<AuditLogEntry>> {
        let logs = sqlx::query_as::<_, AuditLogEntry>(
            r#"
            SELECT 
                id, 
                user_identifier, 
                action_type, 
                ip_address, 
                user_agent, 
                jwt_hash, 
                success, 
                error_message, 
                created_at
            FROM salt_audit_log
            WHERE user_identifier = $1
            ORDER BY created_at DESC
            LIMIT 100
            "#
        )
        .bind(user_identifier)
        .fetch_all(&self.pool)
        .await
        .context("Failed to retrieve audit logs")?;

        Ok(logs)
    }

    /// Check rate limit for an identifier
    pub async fn check_rate_limit(&self, identifier: &str, window_minutes: i32, max_requests: i32) -> Result<bool> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM rate_limit_entries
            WHERE identifier = $1
              AND window_start > NOW() - INTERVAL '1 minute' * $2::float
            "#
        )
        .bind(identifier)
        .bind(window_minutes as f64)
        .fetch_one(&self.pool)
        .await
        .context("Failed to check rate limit")?;

        if count >= max_requests as i64 {
            return Ok(false);
        }

        // Record the request
        sqlx::query(
            r#"
            INSERT INTO rate_limit_entries (identifier)
            VALUES ($1)
            "#
        )
        .bind(identifier)
        .execute(&self.pool)
        .await
        .context("Failed to record rate limit entry")?;

        Ok(true)
    }

    /// Clean up old rate limit entries
    pub async fn cleanup_rate_limits(&self, older_than_hours: i32) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM rate_limit_entries
            WHERE window_start < NOW() - INTERVAL '1 hour' * $1::float
            "#
        )
        .bind(older_than_hours as f64)
        .execute(&self.pool)
        .await
        .context("Failed to cleanup rate limits")?;

        Ok(result.rows_affected())
    }
}

// Integration tests for DB live under `tests/` and require a live database.
