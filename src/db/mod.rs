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
    pub async fn store_salt(
        &self,
        claims: &JwtClaims,
        encrypted_salt: &[u8],
    ) -> Result<UserSalt> {
        let user_identifier = JwtValidator::generate_user_identifier(claims);

        let salt = sqlx::query_as!(
            UserSalt,
            r#"
            INSERT INTO user_salts (user_identifier, iss, aud, sub, encrypted_salt, encryption_version)
            VALUES ($1, $2, $3, $4, $5, 1)
            ON CONFLICT (user_identifier) DO UPDATE
            SET encrypted_salt = EXCLUDED.encrypted_salt,
                updated_at = CURRENT_TIMESTAMP
            RETURNING 
                id, 
                user_identifier, 
                iss, 
                aud, 
                sub, 
                encrypted_salt, 
                encryption_version, 
                created_at as "created_at!", 
                updated_at as "updated_at!"
            "#,
            user_identifier,
            claims.iss,
            claims.aud,
            claims.sub,
            encrypted_salt
        )
        .fetch_one(&self.pool)
        .await
        .context("Failed to store salt")?;

        Ok(salt)
    }

    /// Retrieve encrypted salt for a user
    pub async fn get_salt(&self, claims: &JwtClaims) -> Result<Option<UserSalt>> {
        let user_identifier = JwtValidator::generate_user_identifier(claims);

        let salt = sqlx::query_as!(
            UserSalt,
            r#"
            SELECT 
                id, 
                user_identifier, 
                iss, 
                aud, 
                sub, 
                encrypted_salt, 
                encryption_version, 
                created_at as "created_at!", 
                updated_at as "updated_at!"
            FROM user_salts
            WHERE user_identifier = $1
            "#,
            user_identifier
        )
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
        sqlx::query!(
            r#"
            INSERT INTO salt_audit_log 
            (user_identifier, action_type, ip_address, user_agent, jwt_hash, success, error_message)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            user_identifier,
            action_type.as_str(),
            ip_address,
            user_agent,
            jwt_hash,
            success,
            error_message
        )
        .execute(&self.pool)
        .await
        .context("Failed to log audit entry")?;

        Ok(())
    }

    /// Get audit logs for a user
    pub async fn get_audit_logs(&self, user_identifier: &str) -> Result<Vec<AuditLogEntry>> {
        let logs = sqlx::query_as!(
            AuditLogEntry,
            r#"
            SELECT 
                id, 
                user_identifier, 
                action_type, 
                ip_address, 
                user_agent, 
                jwt_hash, 
                success as "success!", 
                error_message, 
                created_at as "created_at!"
            FROM salt_audit_log
            WHERE user_identifier = $1
            ORDER BY created_at DESC
            LIMIT 100
            "#,
            user_identifier
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to retrieve audit logs")?;

        Ok(logs)
    }

    /// Check rate limit for an identifier
    pub async fn check_rate_limit(&self, identifier: &str, window_minutes: i32, max_requests: i32) -> Result<bool> {
        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM rate_limit_entries
            WHERE identifier = $1
              AND window_start > NOW() - INTERVAL '1 minute' * $2::float
            "#,
            identifier,
            window_minutes as f64
        )
        .fetch_one(&self.pool)
        .await
        .context("Failed to check rate limit")?;

        if count >= max_requests as i64 {
            return Ok(false);
        }

        // Record the request
        sqlx::query!(
            r#"
            INSERT INTO rate_limit_entries (identifier)
            VALUES ($1)
            "#,
            identifier
        )
        .execute(&self.pool)
        .await
        .context("Failed to record rate limit entry")?;

        Ok(true)
    }

    /// Clean up old rate limit entries
    pub async fn cleanup_rate_limits(&self, older_than_hours: i32) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            DELETE FROM rate_limit_entries
            WHERE window_start < NOW() - INTERVAL '1 hour' * $1::float
            "#,
            older_than_hours as f64
        )
        .execute(&self.pool)
        .await
        .context("Failed to cleanup rate limits")?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiting() {
        // This would require a test database
        // For production, we'd set up proper integration tests
    }
} 