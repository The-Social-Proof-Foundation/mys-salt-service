use axum::{
    extract::{State, Json, ConnectInfo},
    http::{StatusCode, HeaderMap}
};
use base64::engine::general_purpose;
use std::net::SocketAddr;
use tracing::{error, info, warn};
use hex;

use crate::{
    auth::exchange,
    models::{
        GetSaltRequest, GetSaltResponse, HealthCheckResponse, ActionType,
        AuthCallbackRequest, AuthCallbackResponse,
    },
    security::{jwt::JwtValidator, hash_token_for_audit},
    state::AppState,
};

/// Resolve provider from request or infer from client_id.
fn resolve_provider(request: &AuthCallbackRequest, config: &crate::config::Config) -> Result<String, String> {
    if let Some(ref p) = request.provider {
        let s = p.trim().to_lowercase();
        if !s.is_empty() {
            return Ok(s);
        }
    }
    let cid = request.client_id.trim();
    if config.allowed_audience_google.as_deref().map(|a| a == cid).unwrap_or(false) {
        return Ok("google".to_string());
    }
    if config.allowed_audience_apple.as_deref().map(|a| a == cid).unwrap_or(false) {
        return Ok("apple".to_string());
    }
    if config.allowed_audience_facebook.as_deref().map(|a| a == cid).unwrap_or(false) {
        return Ok("facebook".to_string());
    }
    if config.allowed_audience_twitch.as_deref().map(|a| a == cid).unwrap_or(false) {
        return Ok("twitch".to_string());
    }
    Err("Could not determine provider. Set provider in request or use client_id that matches an ALLOWED_AUDIENCE_* value.".to_string())
}

/// Get the OAuth client_id to use for token exchange. The auth frontend uses the provider's
/// client ID (from env) for the OAuth request; we must use the same for the token exchange.
fn get_oauth_client_id_for_provider(
    provider: &str,
    _request_client_id: &str,
    config: &crate::config::Config,
) -> Result<String, String> {
    let provider_lower = provider.to_lowercase();
    match provider_lower.as_str() {
        "google" => config
            .allowed_audience_google
            .clone()
            .ok_or_else(|| "ALLOWED_AUDIENCE_GOOGLE not configured".to_string()),
        "apple" => config
            .allowed_audience_apple
            .clone()
            .ok_or_else(|| "ALLOWED_AUDIENCE_APPLE not configured".to_string()),
        "facebook" => config
            .allowed_audience_facebook
            .clone()
            .or_else(|| config.facebook_app_id.clone())
            .ok_or_else(|| "ALLOWED_AUDIENCE_FACEBOOK or FACEBOOK_APP_ID not configured".to_string()),
        "twitch" => config
            .allowed_audience_twitch
            .clone()
            .or_else(|| config.twitch_client_id.clone())
            .ok_or_else(|| "ALLOWED_AUDIENCE_TWITCH or TWITCH_CLIENT_ID not configured".to_string()),
        _ => Err(format!("Unknown provider: {}", provider)),
    }
}

/// Convert salt bytes to BigInt string for zkLogin compatibility
/// Converts exactly 16 bytes to a BigInt decimal string following zkLogin standards
fn salt_to_bigint_string(salt_bytes: &[u8]) -> String {
    // zkLogin requires exactly 16 bytes (128 bits), but handle legacy 32-byte salts
    let salt_16_bytes = if salt_bytes.len() == 32 {
        // Legacy 32-byte salt - take first 16 bytes for zkLogin compatibility
        &salt_bytes[0..16]
    } else if salt_bytes.len() == 16 {
        // Modern 16-byte salt - use as-is
        salt_bytes
    } else {
        panic!("Salt must be either 16 bytes (new format) or 32 bytes (legacy format), got {} bytes", salt_bytes.len());
    };
    
    // Convert bytes to hex string (32 characters for 16 bytes)
    let hex_salt = hex::encode(salt_16_bytes);
    
    // Parse as hex BigInt and convert to decimal string
    let bigint_value = u128::from_str_radix(&hex_salt, 16)
        .expect("Failed to parse hex salt as BigInt");
    
    // Return as decimal string (BigInt format)
    bigint_value.to_string()
}

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

    // Extract claims based on request type
    let (claims, token_hash) = if request.is_jwt() {
        // JWT-based request (legacy or JWT providers)
        let token = request.token();
        match state.jwt_validator.validate(token).await {
            Ok(c) => {
                let hash = hash_token_for_audit(token);
                (c, hash)
            }
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
                    Some(hash_token_for_audit(token)),
                    false,
                    Some(e.to_string()),
                ).await;
                
                return Err((StatusCode::UNAUTHORIZED, "Invalid JWT".to_string()));
            }
        }
    } else {
        // Provider + token request (Facebook/Twitch only)
        let provider = request.provider().unwrap_or("unknown");
        let provider_lower = provider.to_lowercase();
        
        // Apple only supports JWT format, not provider+token format
        if provider_lower == "apple" {
            return Err((
                StatusCode::BAD_REQUEST,
                "Apple authentication requires JWT format. Use { \"jwt\": \"...\" } instead of { \"provider\": \"apple\", \"token\": \"...\" }".to_string(),
            ));
        }
        
        let token = request.token();
        
        match state.access_token_validator.extract_claims_from_token(provider, token).await {
            Ok(c) => {
                let hash = hash_token_for_audit(token);
                (c, hash)
            }
            Err(e) => {
                error!("Access token validation failed for provider {}: {}", provider, e);
                state.metrics.increment_jwt_failed();
                state.metrics.increment_failed();
                
                // Log failed attempt
                let _ = state.store.log_audit(
                    "unknown",
                    ActionType::Error,
                    Some(ip_address),
                    user_agent,
                    Some(hash_token_for_audit(token)),
                    false,
                    Some(format!("Provider {}: {}", provider, e)),
                ).await;
                
                return Err((
                    StatusCode::UNAUTHORIZED,
                    format!("Invalid token for provider {}", provider),
                ));
            }
        }
    };

    let user_identifier = JwtValidator::generate_user_identifier(&claims);
    let token_hash = token_hash;

    // Log the lookup attempt for debugging
    info!(
        "Salt lookup for user: {} (iss: {}, sub: {})",
        user_identifier, claims.iss, claims.sub
    );

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
                Some(token_hash),
                true,
                None,
            ).await;

            info!("Successfully retrieved existing salt for user: {}", user_identifier);
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

            // Store salt - ON CONFLICT will return existing row if race condition occurred
            let stored_salt = state.store.store_salt(&claims, &encrypted).await
                .map_err(|e| {
                    error!("Failed to store salt: {}", e);
                    state.metrics.increment_failed();
                    (StatusCode::INTERNAL_SERVER_ERROR, "Storage error".to_string())
                })?;

            // Decrypt the stored salt (could be newly inserted or existing from race condition)
            let decrypted = state
                .salt_manager
                .decrypt_salt(&stored_salt.encrypted_salt)
                .map_err(|e| {
                    error!("Failed to decrypt stored salt: {}", e);
                    state.metrics.increment_failed();
                    (StatusCode::INTERNAL_SERVER_ERROR, "Decryption error".to_string())
                })?;

            // Verify the decrypted salt matches what we generated (consistency check)
            if decrypted != salt {
                error!(
                    "CRITICAL: Stored salt mismatch for user {} - generated: {:?}, stored: {:?}",
                    user_identifier,
                    hex::encode(&salt),
                    hex::encode(&decrypted)
                );
                state.metrics.increment_failed();
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Salt consistency check failed".to_string(),
                ));
            }

            // Check if this was a new insert or existing salt by checking created_at vs updated_at
            let is_new = stored_salt.created_at == stored_salt.updated_at;
            
            if is_new {
                // Log creation
                let _ = state.store.log_audit(
                    &user_identifier,
                    ActionType::Create,
                    Some(ip_address),
                    user_agent,
                    Some(token_hash),
                    true,
                    None,
                ).await;
                info!("Successfully created new salt for user: {}", user_identifier);
                state.metrics.increment_salt_created();
            } else {
                // Race condition: another request created it first
                warn!("Race condition detected for user {} - salt was created by another request", user_identifier);
                let _ = state.store.log_audit(
                    &user_identifier,
                    ActionType::Read,
                    Some(ip_address),
                    user_agent,
                    Some(token_hash),
                    true,
                    None,
                ).await;
                state.metrics.increment_salt_retrieved();
            }
            
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
        salt: salt_to_bigint_string(&salt),
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

pub async fn salt_check(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match sqlx::query("SELECT 1 as check")
        .fetch_one(state.store.pool())
        .await
    {
        Ok(_) => Ok(Json(serde_json::json!({
            "status": "ready",
            "salt_endpoint": "/salt",
            "version": env!("CARGO_PKG_VERSION")
        }))),
        Err(e) => {
            error!("Salt check failed: {}", e);
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

pub async fn auth_provider_callback(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<AuthCallbackRequest>,
) -> Result<Json<AuthCallbackResponse>, (StatusCode, String)> {
    let ip_address = addr.ip().to_string();
    let rate_limit_ok = state
        .store
        .check_rate_limit(&ip_address, 1, state.config.rate_limit_per_minute)
        .await
        .map_err(|e| {
            error!("Rate limit check failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        })?;
    if !rate_limit_ok {
        warn!("Rate limit exceeded for IP: {}", ip_address);
        state.metrics.increment_rate_limit();
        return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string()));
    }

    let _client = state
        .config
        .allowed_clients
        .iter()
        .find(|c| c.client_id == request.client_id)
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Unknown client".to_string(),
        ))?;

    let provider = resolve_provider(&request, &state.config)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let oauth_client_id = get_oauth_client_id_for_provider(&provider, &request.client_id, &state.config)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let oauth_redirect_uri = state
        .config
        .auth_callback_url
        .as_deref()
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "AUTH_CALLBACK_URL not configured".to_string(),
        ))?;

    let tokens = exchange::exchange_code_for_tokens(
        &state.http_client,
        &provider,
        &request.code,
        oauth_redirect_uri,
        &oauth_client_id,
        request.code_verifier.as_deref(),
        &state.config,
    )
    .await
    .map_err(|e| {
        error!("Token exchange failed: {}", e);
        (StatusCode::BAD_GATEWAY, format!("Auth exchange failed: {}", e))
    })?;

    let (claims, token_hash) = if let Some(ref id_token) = tokens.id_token {
        match state.jwt_validator.validate(id_token).await {
            Ok(c) => {
                let hash = hash_token_for_audit(id_token);
                (c, hash)
            }
            Err(e) => {
                error!("JWT validation failed after exchange: {}", e);
                return Err((
                    StatusCode::UNAUTHORIZED,
                    format!("Invalid JWT: {}", e),
                ));
            }
        }
    } else if let Some(ref access_token) = tokens.access_token {
        let provider = tokens
            .user
            .as_ref()
            .and_then(|u| {
                u.get("provider")
                    .or_else(|| u.get("iss"))
                    .and_then(|v| v.as_str())
            })
            .map(|s| {
                if s.contains("facebook") {
                    "facebook"
                } else if s.contains("twitch") {
                    "twitch"
                } else {
                    s
                }
            })
            .unwrap_or("unknown");
        let provider_lower = provider.to_lowercase();
        if provider_lower == "apple" || provider_lower == "google" {
            return Err((
                StatusCode::BAD_REQUEST,
                "id_token required for Google/Apple".to_string(),
            ));
        }
        match state
            .access_token_validator
            .extract_claims_from_token(provider, access_token)
            .await
        {
            Ok(c) => {
                let hash = hash_token_for_audit(access_token);
                (c, hash)
            }
            Err(e) => {
                error!("Access token validation failed: {}", e);
                return Err((
                    StatusCode::UNAUTHORIZED,
                    format!("Invalid token for provider {}: {}", provider, e),
                ));
            }
        }
    } else {
        return Err((
            StatusCode::BAD_GATEWAY,
            "Auth response missing id_token and access_token".to_string(),
        ));
    };

    let user_identifier = JwtValidator::generate_user_identifier(&claims);
    info!(
        "Auth callback: salt lookup for user {} (iss: {}, sub: {})",
        user_identifier, claims.iss, claims.sub
    );

    let salt = match state.store.get_salt(&claims).await {
        Ok(Some(existing)) => {
            state
                .salt_manager
                .decrypt_salt(&existing.encrypted_salt)
                .map_err(|e| {
                    error!("Failed to decrypt salt: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Decryption error".to_string())
                })?
        }
        Ok(None) => {
            let salt_bytes = state.salt_manager.generate_salt(&claims).map_err(|e| {
                error!("Failed to generate salt: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Salt generation error".to_string())
            })?;
            let encrypted = state.salt_manager.encrypt_salt(&salt_bytes).map_err(|e| {
                error!("Failed to encrypt salt: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Encryption error".to_string())
            })?;
            let stored = state.store.store_salt(&claims, &encrypted).await.map_err(|e| {
                error!("Failed to store salt: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Storage error".to_string())
            })?;
            state
                .salt_manager
                .decrypt_salt(&stored.encrypted_salt)
                .map_err(|e| {
                    error!("Failed to decrypt stored salt: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Decryption error".to_string())
                })?
        }
        Err(e) => {
            error!("Database error: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            ));
        }
    };

    let _ = state.store.log_audit(
        &user_identifier,
        ActionType::Read,
        Some(addr.ip().to_string()),
        None,
        Some(token_hash),
        true,
        None,
    ).await;

    let code = tokens
        .id_token
        .clone()
        .or(tokens.access_token.clone())
        .unwrap_or_default();

    Ok(Json(AuthCallbackResponse {
        code,
        salt: salt_to_bigint_string(&salt),
        id_token: tokens.id_token.clone(),
        user: tokens.user,
        access_token: tokens.access_token,
    }))
}

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
    let token = match &request {
        GetSaltRequest::Jwt { jwt } => jwt,
        GetSaltRequest::Provider { .. } => {
            return Err((StatusCode::BAD_REQUEST, "Test endpoint only accepts JWT format".to_string()));
        }
    };
    let parts: Vec<&str> = token.split('.').collect();
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
        email_verified: payload.get("email_verified").and_then(|v| v.as_bool()),
        name: payload.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()),
        picture: payload.get("picture").and_then(|v| v.as_str()).map(|s| s.to_string()),
        given_name: payload.get("given_name").and_then(|v| v.as_str()).map(|s| s.to_string()),
        family_name: payload.get("family_name").and_then(|v| v.as_str()).map(|s| s.to_string()),
    };

    let user_identifier = JwtValidator::generate_user_identifier(&claims);

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
        salt: salt_to_bigint_string(&salt),
    }))
}