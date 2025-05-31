use anyhow::{Context, Result};
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
        // Decode header to get key ID
        let header = decode_header(jwt).context("Failed to decode JWT header")?;
        let kid = header.kid.context("JWT missing key ID")?;

        // Extract issuer from unverified claims to determine provider
        let unverified_validation = {
            let mut v = Validation::default();
            v.insecure_disable_signature_validation();
            v.validate_exp = false;
            v
        };
        
        let unverified = decode::<Value>(jwt, &DecodingKey::from_secret(b"dummy"), &unverified_validation)
            .context("Failed to decode JWT")?;
        
        let iss = unverified.claims["iss"]
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

        // Set up validation
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&provider.issuer]);
        validation.validate_exp = true;
        
        // Decode and validate
        let token_data = decode::<JwtClaims>(jwt, &decoding_key, &validation)
            .context("JWT validation failed")?;

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
        };

        let identifier = JwtValidator::generate_user_identifier(&claims);
        assert_eq!(identifier, "https://accounts.google.com:test-app:user123");
    }
} 