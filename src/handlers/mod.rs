use axum::{
    extract::{State, Json, ConnectInfo},
    http::{StatusCode, HeaderMap}
};
use base64::{Engine as _, engine::general_purpose};
use std::net::SocketAddr;
use tracing::{error, info, warn};

use crate::{
    AppState,
    models::{GetSaltRequest, GetSaltResponse, HealthCheckResponse, ActionType},
    security::{jwt::JwtValidator, hash_jwt_for_audit},
};

/// Handle salt generation/retrieval requests
pub async fn get_salt(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<GetSaltRequest>,
) -> Result<Json<GetSaltResponse>, (StatusCode, String)> {
    state.metrics.increment_requests();
    
    let ip_address = addr.ip().to_string();
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    
    // Rate limiting
    let rate_limit_ok = state
        .store
        .check_rate_limit(&ip_address, 1, state.config.rate_limit_per_minute)
        .await
        .map_err(|e| {
            error!("Rate limit check failed: {}", e);
            state.metrics.increment_failed();
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        })?;

    if !rate_limit_ok {
        warn!("Rate limit exceeded for IP: {}", ip_address);
        state.metrics.increment_rate_limit();
        state.metrics.increment_failed();
        return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string()));
    }

    // Validate JWT
    let claims = match state.jwt_validator.validate(&request.jwt).await {
        Ok(c) => c,
        Err(e) => {
            error!("JWT validation failed: {}", e);
            state.metrics.increment_jwt_failed();
            state.metrics.increment_failed();
            
            // Log failed attempt
            let _ = state.store.log_audit(
                "unknown",
                ActionType::Error,
                Some(ip_address),
                user_agent,
                Some(hash_jwt_for_audit(&request.jwt)),
                false,
                Some(e.to_string()),
            ).await;
            
            return Err((StatusCode::UNAUTHORIZED, "Invalid JWT".to_string()));
        }
    };

    let user_identifier = JwtValidator::generate_user_identifier(&claims);
    let jwt_hash = hash_jwt_for_audit(&request.jwt);

    // Check or generate salt
    let salt = match state.store.get_salt(&claims).await {
        Ok(Some(existing)) => {
            // Decrypt existing salt
            let decrypted = state
                .salt_manager
                .decrypt_salt(&existing.encrypted_salt)
                .map_err(|e| {
                    error!("Failed to decrypt salt: {}", e);
                    state.metrics.increment_failed();
                    (StatusCode::INTERNAL_SERVER_ERROR, "Decryption error".to_string())
                })?;

            // Log read action
            let _ = state.store.log_audit(
                &user_identifier,
                ActionType::Read,
                Some(ip_address),
                user_agent,
                Some(jwt_hash),
                true,
                None,
            ).await;

            info!("Retrieved existing salt for user: {}", user_identifier);
            state.metrics.increment_salt_retrieved();
            decrypted
        }
        Ok(None) => {
            // Generate new salt
            let salt = state
                .salt_manager
                .generate_salt(&claims)
                .map_err(|e| {
                    error!("Failed to generate salt: {}", e);
                    state.metrics.increment_failed();
                    (StatusCode::INTERNAL_SERVER_ERROR, "Generation error".to_string())
                })?;

            // Encrypt and store
            let encrypted = state
                .salt_manager
                .encrypt_salt(&salt)
                .map_err(|e| {
                    error!("Failed to encrypt salt: {}", e);
                    state.metrics.increment_failed();
                    (StatusCode::INTERNAL_SERVER_ERROR, "Encryption error".to_string())
                })?;

            state
                .store
                .store_salt(&claims, &encrypted)
                .await
                .map_err(|e| {
                    error!("Failed to store salt: {}", e);
                    state.metrics.increment_failed();
                    (StatusCode::INTERNAL_SERVER_ERROR, "Storage error".to_string())
                })?;

            // Log creation
            let _ = state.store.log_audit(
                &user_identifier,
                ActionType::Create,
                Some(ip_address),
                user_agent,
                Some(jwt_hash),
                true,
                None,
            ).await;

            info!("Created new salt for user: {}", user_identifier);
            state.metrics.increment_salt_created();
            salt
        }
        Err(e) => {
            error!("Database error: {}", e);
            state.metrics.increment_failed();
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()));
        }
    };

    state.metrics.increment_success();
    Ok(Json(GetSaltResponse {
        salt: general_purpose::STANDARD.encode(salt),
    }))
}

/// Health check endpoint
pub async fn health_check(
    State(state): State<AppState>,
) -> Result<Json<HealthCheckResponse>, StatusCode> {
    // Check database connectivity
    match sqlx::query("SELECT 1 as check")
        .fetch_one(state.store.pool())
        .await
    {
        Ok(_) => Ok(Json(HealthCheckResponse {
            status: "healthy".to_string(),
            timestamp: chrono::Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        })),
        Err(e) => {
            error!("Health check failed: {}", e);
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

/// Get audit logs for a user (admin endpoint)
// pub async fn get_audit_logs(
//     State(state): State<AppState>,
//     user_identifier: String,
// ) -> Result<impl IntoResponse, StatusCode> {
//     match state.store.get_audit_logs(&user_identifier).await {
//         Ok(logs) => Ok(Json(logs)),
//         Err(e) => {
//             error!("Failed to retrieve audit logs: {}", e);
//             Err(StatusCode::INTERNAL_SERVER_ERROR)
//         }
//     }
// }

/// Get service metrics
pub async fn get_metrics(
    State(state): State<AppState>,
) -> Json<crate::monitoring::MetricsSnapshot> {
    Json(state.metrics.get_stats())
}

/// Test endpoint for development - accepts simple JWTs
pub async fn get_salt_test(
    State(state): State<AppState>,
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Json(request): Json<GetSaltRequest>,
) -> Result<Json<GetSaltResponse>, (StatusCode, String)> {
    // Only allow in non-production environments
    if std::env::var("ENVIRONMENT").unwrap_or_default() == "production" {
        return Err((StatusCode::NOT_FOUND, "Not found".to_string()));
    }

    state.metrics.increment_requests();
    
    // let ip_address = addr.ip().to_string();
    // let user_agent = headers
    //     .get("user-agent")
    //     .and_then(|v| v.to_str().ok())
    //     .map(|s| s.to_string());

    // Decode the JWT without validation for testing
    let parts: Vec<&str> = request.jwt.split('.').collect();
    if parts.len() != 3 {
        return Err((StatusCode::BAD_REQUEST, "Invalid JWT format".to_string()));
    }

    // Decode payload
    let payload_bytes = base64::Engine::decode(
        &general_purpose::URL_SAFE_NO_PAD,
        parts[1]
    ).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid base64 in JWT".to_string()))?;
    
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid JSON in JWT payload".to_string()))?;

    // Create fake claims for testing
    let claims = crate::models::JwtClaims {
        iss: payload.get("iss")
            .and_then(|v| v.as_str())
            .unwrap_or("https://test.example.com")
            .to_string(),
        aud: payload.get("aud")
            .and_then(|v| v.as_str())
            .unwrap_or("test-client-id")
            .to_string(),
        sub: payload.get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("test-user-id")
            .to_string(),
        exp: payload.get("exp").and_then(|v| v.as_i64()).unwrap_or(1999999999),
        iat: payload.get("iat").and_then(|v| v.as_i64()).unwrap_or(1516239022),
        nonce: None,
        email: payload.get("email").and_then(|v| v.as_str()).map(|s| s.to_string()),
    };

    let user_identifier = JwtValidator::generate_user_identifier(&claims);
    // let jwt_hash = hash_jwt_for_audit(&request.jwt);

    // Generate salt (same logic as production)
    let salt = state
        .salt_manager
        .generate_salt(&claims)
        .map_err(|e| {
            error!("Failed to generate salt: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Generation error".to_string())
        })?;

    // Log for testing
    info!("Test endpoint: Generated salt for claims: {:?}", claims);
    info!("Test endpoint: User identifier: {}", user_identifier);

    state.metrics.increment_success();
    Ok(Json(GetSaltResponse {
        salt: general_purpose::STANDARD.encode(salt),
    }))
} 