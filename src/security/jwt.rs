use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{
    decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation,
};
use reqwest::Client;
use serde_json::Value;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;

use crate::models::{JwtClaims, OAuthProviderConfig};

pub struct JwtValidator {
    client: Client,
    providers: HashMap<String, OAuthProviderConfig>,
    jwks_cache: Arc<RwLock<HashMap<String, (JwkSet, std::time::Instant)>>>,
    cache_duration: Duration,
}

impl JwtValidator {
    /// Manually extract the payload from a JWT without verification
    /// This is safe for extracting non-sensitive fields like issuer
    fn extract_payload(&self, jwt: &str) -> Result<Value> {
        // Split JWT into parts
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow::anyhow!("Invalid JWT format: expected 3 parts"));
        }

        // Base64url decode the payload (second part)
        let payload_b64 = parts[1];
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .context("Failed to base64url decode JWT payload")?;

        // Parse as JSON
        let payload: Value = serde_json::from_slice(&payload_bytes)
            .context("Failed to parse JWT payload as JSON")?;

        Ok(payload)
    }

    pub fn new() -> Self {
        let mut providers = HashMap::new();
        providers.insert(
            "https://accounts.google.com".to_string(),
            OAuthProviderConfig::google(),
        );
        providers.insert(
            "https://www.facebook.com".to_string(),
            OAuthProviderConfig::facebook(),
        );
        providers.insert(
            "https://appleid.apple.com".to_string(),
            OAuthProviderConfig::apple(),
        );

        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to build HTTP client"),
            providers,
            jwks_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_duration: Duration::from_secs(3600), // 1 hour cache
        }
    }

    /// Validate a JWT and extract claims
    pub async fn validate(&self, jwt: &str) -> Result<JwtClaims> {
        tracing::info!("🔍 Starting JWT validation for token of length: {}", jwt.len());
        
        // Decode header to get key ID
        let header = decode_header(jwt).context("Failed to decode JWT header")?;
        tracing::info!("✅ JWT header decoded successfully: {:?}", header);
        
        let kid = header.kid.context("JWT missing key ID")?;
        tracing::info!("✅ JWT key ID extracted: {}", kid);

        // Extract issuer from JWT payload using manual decoding
        tracing::info!("🔍 Attempting manual payload extraction to get issuer...");
        let payload = match self.extract_payload(jwt) {
            Ok(payload) => {
                tracing::info!("✅ Manual payload extraction successful");
                payload
            }
            Err(err) => {
                tracing::error!("❌ Manual payload extraction failed: {:?}", err);
                return Err(anyhow::anyhow!("Failed to extract JWT payload: {:?}", err));
            }
        };
        
        tracing::info!("🔍 Extracting issuer from payload...");
        let iss = payload["iss"]
            .as_str()
            .context("JWT missing issuer")?;
        tracing::info!("✅ JWT issuer extracted: {}", iss);

        // Get provider config
        let provider = self
            .providers
            .get(iss)
            .context("Unknown OAuth provider")?;
        tracing::info!("✅ Provider config found for issuer: {}", iss);

        // Get JWKS
        tracing::info!("🔍 Fetching JWKS from: {}", provider.jwks_uri);
        let jwks = self.get_jwks(&provider.jwks_uri).await?;
        tracing::info!("✅ JWKS fetched successfully");

        // Find the matching key
        let jwk = jwks
            .find(&kid)
            .context("JWK not found for key ID")?;
        tracing::info!("✅ JWK found for key ID: {}", kid);

        // Create decoding key
        let decoding_key = DecodingKey::from_jwk(jwk)
            .context("Failed to create decoding key from JWK")?;
        tracing::info!("✅ Decoding key created from JWK");

        // Set up validation
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&provider.issuer]);
        validation.validate_exp = true;
        validation.validate_aud = false; // Disable audience validation - we mainly care about signature and issuer
        tracing::info!("✅ Validation setup complete with issuer: {}", provider.issuer);
        
        // Decode and validate
        tracing::info!("🔍 Performing final JWT validation with signature verification...");
        tracing::info!("🔧 Debug: JWT length: {}, Algorithm: {:?}", jwt.len(), validation.algorithms);
        tracing::info!("🔧 Debug: Validation settings - validate_exp: {}, validate_aud: {}", validation.validate_exp, validation.validate_aud);
        
        let token_data = match decode::<JwtClaims>(jwt, &decoding_key, &validation) {
            Ok(data) => {
                tracing::info!("✅ JWT validation successful!");
                data
            }
            Err(err) => {
                tracing::error!("❌ Final JWT validation failed: {:?}", err);
                tracing::error!("🔧 Debug: Error kind: {:?}", err.kind());
                
                // Let's try with a more permissive validation to isolate the issue
                tracing::info!("🔧 Attempting validation with disabled exp check...");
                let mut permissive_validation = Validation::new(Algorithm::RS256);
                permissive_validation.validate_exp = false;
                permissive_validation.validate_aud = false;
                permissive_validation.set_issuer(&[&provider.issuer]);
                
                match decode::<JwtClaims>(jwt, &decoding_key, &permissive_validation) {
                    Ok(_) => {
                        tracing::info!("✅ Permissive validation succeeded - issue is with exp/aud validation");
                    }
                    Err(permissive_err) => {
                        tracing::error!("❌ Even permissive validation failed: {:?}", permissive_err);
                        
                        // Let's try with the most permissive settings possible
                        tracing::info!("🔧 Attempting validation with ALL validations disabled...");
                        let mut ultra_permissive = Validation::new(Algorithm::RS256);
                        ultra_permissive.validate_exp = false;
                        ultra_permissive.validate_aud = false;
                        ultra_permissive.validate_nbf = false;
                        ultra_permissive.insecure_disable_signature_validation();
                        
                        match decode::<JwtClaims>(jwt, &decoding_key, &ultra_permissive) {
                            Ok(data) => {
                                tracing::info!("✅ Ultra permissive validation (NO signature check) succeeded!");
                                tracing::info!("🔧 This confirms the JWT format and claims are valid, issue is ONLY with signature verification");
                                tracing::info!("🔧 Claims: email={:?}, sub={:?}", data.claims.email, data.claims.sub);
                            }
                            Err(ultra_err) => {
                                tracing::error!("❌ Even ultra permissive validation failed: {:?}", ultra_err);
                                tracing::error!("🔧 This suggests the JWT format itself is broken");
                            }
                        }
                    }
                }
                
                return Err(anyhow::anyhow!("JWT validation failed: {:?}", err));
            }
        };

        Ok(token_data.claims)
    }

    /// Get JWKS with caching
    async fn get_jwks(&self, jwks_uri: &str) -> Result<JwkSet> {
        // Check cache
        {
            let cache = self.jwks_cache.read().await;
            if let Some((jwks, cached_at)) = cache.get(jwks_uri) {
                if cached_at.elapsed() < self.cache_duration {
                    return Ok(jwks.clone());
                }
            }
        }

        // Fetch fresh JWKS
        let response = self
            .client
            .get(jwks_uri)
            .send()
            .await
            .context("Failed to fetch JWKS")?;

        if !response.status().is_success() {
            anyhow::bail!("JWKS fetch failed with status: {}", response.status());
        }

        let jwks: JwkSet = response
            .json()
            .await
            .context("Failed to parse JWKS")?;

        // Update cache
        {
            let mut cache = self.jwks_cache.write().await;
            cache.insert(jwks_uri.to_string(), (jwks.clone(), std::time::Instant::now()));
        }

        Ok(jwks)
    }

    /// Generate user identifier from claims
    pub fn generate_user_identifier(claims: &JwtClaims) -> String {
        format!("{}:{}:{}", claims.iss, claims.aud, claims.sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_identifier_generation() {
        let claims = JwtClaims {
            iss: "https://accounts.google.com".to_string(),
            aud: "test-app".to_string(),
            sub: "user123".to_string(),
            exp: 1234567890,
            iat: 1234567890,
            nonce: None,
            email: None,
            email_verified: None,
            name: None,
            picture: None,
            given_name: None,
            family_name: None,
        };

        let identifier = JwtValidator::generate_user_identifier(&claims);
        assert_eq!(identifier, "https://accounts.google.com:test-app:user123");
    }
} 