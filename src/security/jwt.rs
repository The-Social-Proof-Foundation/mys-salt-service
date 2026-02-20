use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{
    decode, decode_header, jwk::JwkSet, DecodingKey, Validation,
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
    allowed_audience_google: Option<String>,
    allowed_audience_apple: Option<String>,
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

    pub fn new(
        allowed_audience_google: Option<String>,
        allowed_audience_apple: Option<String>,
    ) -> Self {
        let mut providers = HashMap::new();
        providers.insert(
            "https://accounts.google.com".to_string(),
            OAuthProviderConfig::google(),
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
            allowed_audience_google,
            allowed_audience_apple,
        }
    }

    /// Validate that claims.aud matches the configured allowed audience for the issuer.
    fn validate_audience(&self, claims: &JwtClaims) -> Result<()> {
        let allowed = match claims.iss.as_str() {
            "https://accounts.google.com" => self.allowed_audience_google.as_ref(),
            "https://appleid.apple.com" => self.allowed_audience_apple.as_ref(),
            _ => None,
        };
        let allowed = allowed
            .context("No allowed audience configured for this provider")?;
        if claims.aud != *allowed {
            anyhow::bail!(
                "Audience mismatch: expected {} for this provider, got {}",
                allowed,
                claims.aud
            );
        }
        Ok(())
    }

    /// Validate a JWT and extract claims
    pub async fn validate(&self, jwt: &str) -> Result<JwtClaims> {
        // Decode header to get key ID and algorithm
        let header = decode_header(jwt).context("Failed to decode JWT header")?;
        let kid = header.kid.context("JWT missing key ID")?;
        
        // Extract algorithm from header (RS256 for Google, ES256 for Apple)
        let algorithm = header.alg;

        // Extract issuer from JWT payload using manual decoding
        let payload = self.extract_payload(jwt)
            .context("Failed to extract JWT payload")?;
        
        let iss = payload["iss"]
            .as_str()
            .context("JWT missing issuer")?;

        // Get provider config
        let provider = self
            .providers
            .get(iss)
            .context("Unknown OAuth provider")?;

        // Get JWKS
        let jwks = self.get_jwks(&provider.jwks_uri).await?;

        // Find the matching key
        let jwk = jwks
            .find(&kid)
            .context("JWK not found for key ID")?;

        // Create decoding key
        let decoding_key = DecodingKey::from_jwk(jwk)
            .context("Failed to create decoding key from JWK")?;

        // Set up validation with algorithm from JWT header
        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[&provider.issuer]);
        validation.validate_exp = true;
        validation.validate_aud = false; // Disable audience validation - we mainly care about signature and issuer
        
        // Decode and validate
        let token_data = decode::<JwtClaims>(jwt, &decoding_key, &validation)
            .context("JWT validation failed")?;

        // Validate audience matches configured allowed value for this provider
        self.validate_audience(&token_data.claims)?;

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
        // Unify across platforms/clients: key by issuer + subject only
        format!("{}:{}", claims.iss, claims.sub)
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
            sub: "111631294628286022835".to_string(),
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
        assert_eq!(identifier, "https://accounts.google.com:111631294628286022835");
    }

    #[test]
    fn test_validate_audience_rejects_wrong_aud() {
        let validator = JwtValidator::new(
            Some("expected-google-aud".to_string()),
            Some("expected-apple-aud".to_string()),
        );

        let claims_wrong_aud = JwtClaims {
            iss: "https://accounts.google.com".to_string(),
            aud: "wrong-aud".to_string(),
            sub: "123".to_string(),
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

        let result = validator.validate_audience(&claims_wrong_aud);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Audience mismatch"));
    }

    #[test]
    fn test_validate_audience_accepts_correct_aud() {
        let validator = JwtValidator::new(
            Some("expected-google-aud".to_string()),
            Some("expected-apple-aud".to_string()),
        );

        let claims = JwtClaims {
            iss: "https://accounts.google.com".to_string(),
            aud: "expected-google-aud".to_string(),
            sub: "123".to_string(),
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

        assert!(validator.validate_audience(&claims).is_ok());
    }
} 
