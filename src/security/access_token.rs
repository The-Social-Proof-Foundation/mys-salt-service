use anyhow::{Context, Result};
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::models::{JwtClaims, OAuthProviderConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacebookUserInfo {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FacebookDebugTokenResponse {
    data: FacebookTokenData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FacebookTokenData {
    app_id: Option<String>,
    #[serde(rename = "is_valid")]
    is_valid: bool,
    user_id: Option<String>,
    error: Option<FacebookTokenError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FacebookTokenError {
    message: String,
    code: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwitchUserInfo {
    pub id: String,
    pub login: String,
    pub display_name: String,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TwitchUsersResponse {
    data: Vec<TwitchUserInfo>,
}

pub struct AccessTokenValidator {
    client: Client,
    twitch_client_id: Option<String>,
    facebook_app_secret: Option<String>,
    facebook_app_id: Option<String>,
}

impl AccessTokenValidator {
    pub fn new(
        twitch_client_id: Option<String>,
        facebook_app_secret: Option<String>,
        facebook_app_id: Option<String>,
    ) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to build HTTP client"),
            twitch_client_id,
            facebook_app_secret,
            facebook_app_id,
        }
    }

    /// Validate Facebook access token using app secret and fetch user info
    pub async fn validate_facebook_token(&self, token: &str) -> Result<FacebookUserInfo> {
        // If we have both app_id and app_secret, use debug_token endpoint for proper validation
        if let (Some(app_id), Some(app_secret)) = (&self.facebook_app_id, &self.facebook_app_secret) {
            // Validate token using debug_token endpoint
            let app_access_token = format!("{}|{}", app_id, app_secret);
            let debug_url = format!(
                "https://graph.facebook.com/debug_token?input_token={}&access_token={}",
                token, app_access_token
            );

            let debug_response = self
                .client
                .get(&debug_url)
                .send()
                .await
                .context("Failed to validate Facebook token")?;

            if !debug_response.status().is_success() {
                let status = debug_response.status();
                let error_text = debug_response.text().await.unwrap_or_default();
                anyhow::bail!(
                    "Facebook token validation failed: status {}, response: {}",
                    status,
                    error_text
                );
            }

            let debug_result: FacebookDebugTokenResponse = debug_response
                .json()
                .await
                .context("Failed to parse Facebook debug token response")?;

            // Check if token is valid
            if !debug_result.data.is_valid {
                let error_msg = debug_result.data.error
                    .map(|e| format!("Code {}: {}", e.code, e.message))
                    .unwrap_or_else(|| "Token is invalid".to_string());
                anyhow::bail!("Facebook token validation failed: {}", error_msg);
            }

            // Verify the token belongs to our app
            if let Some(token_app_id) = &debug_result.data.app_id {
                if token_app_id != app_id {
                    anyhow::bail!(
                        "Token belongs to different app (app_id: {}, expected: {})",
                        token_app_id,
                        app_id
                    );
                }
            }

            // Get user info
            let user_id = debug_result.data.user_id
                .context("Token validation succeeded but user_id is missing")?;

            let user_info_url = format!(
                "https://graph.facebook.com/{}?access_token={}&fields=id,name,email",
                user_id, token
            );

            let user_response = self
                .client
                .get(&user_info_url)
                .send()
                .await
                .context("Failed to fetch Facebook user info")?;

            if !user_response.status().is_success() {
                let status = user_response.status();
                let error_text = user_response.text().await.unwrap_or_default();
                anyhow::bail!(
                    "Facebook API error fetching user info: status {}, response: {}",
                    status,
                    error_text
                );
            }

            let user_info: FacebookUserInfo = user_response
                .json()
                .await
                .context("Failed to parse Facebook user info")?;

            Ok(user_info)
        } else if self.facebook_app_secret.is_some() {
            // If only app_secret is configured (without app_id), use /me endpoint
            // but log a warning that full validation requires app_id
            tracing::warn!("FACEBOOK_APP_ID not configured. Using basic token validation. For enhanced security, configure FACEBOOK_APP_ID to enable full token validation.");
            
            let url = format!(
                "https://graph.facebook.com/me?access_token={}&fields=id,name,email",
                token
            );

            let response = self
                .client
                .get(&url)
                .send()
                .await
                .context("Failed to fetch Facebook user info")?;

            if !response.status().is_success() {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_default();
                anyhow::bail!(
                    "Facebook API error: status {}, response: {}",
                    status,
                    error_text
                );
            }

            let user_info: FacebookUserInfo = response
                .json()
                .await
                .context("Failed to parse Facebook user info")?;

            Ok(user_info)
        } else {
            // If app secret not configured, still validate via /me endpoint
            // but log a warning
            tracing::warn!("FACEBOOK_APP_SECRET not configured. Using basic token validation only. Configure FACEBOOK_APP_SECRET for enhanced security.");
            
            let url = format!(
                "https://graph.facebook.com/me?access_token={}&fields=id,name,email",
                token
            );

            let response = self
                .client
                .get(&url)
                .send()
                .await
                .context("Failed to fetch Facebook user info")?;

            if !response.status().is_success() {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_default();
                anyhow::bail!(
                    "Facebook API error: status {}, response: {}",
                    status,
                    error_text
                );
            }

            let user_info: FacebookUserInfo = response
                .json()
                .await
                .context("Failed to parse Facebook user info")?;

            Ok(user_info)
        }
    }

    /// Validate Twitch access token and fetch user info
    /// Note: Requires Client-ID header for Twitch API
    pub async fn validate_twitch_token(&self, token: &str) -> Result<TwitchUserInfo> {
        let client_id = self.twitch_client_id.as_ref()
            .context("TWITCH_CLIENT_ID not configured. Twitch API requires Client-ID header.")?;

        let response = self
            .client
            .get("https://api.twitch.tv/helix/users")
            .header("Authorization", format!("Bearer {}", token))
            .header("Client-Id", client_id)
            .send()
            .await
            .context("Failed to fetch Twitch user info")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Twitch API error: status {}, response: {}",
                status,
                error_text
            );
        }

        let users_response: TwitchUsersResponse = response
            .json()
            .await
            .context("Failed to parse Twitch user info")?;

        users_response
            .data
            .into_iter()
            .next()
            .context("Twitch API returned empty user list")
    }

    /// Extract claims from access token based on provider
    pub async fn extract_claims_from_token(
        &self,
        provider: &str,
        token: &str,
    ) -> Result<JwtClaims> {
        let now = Utc::now().timestamp();
        let provider_lower = provider.to_lowercase();

        match provider_lower.as_str() {
            "facebook" => {
                let user_info = self.validate_facebook_token(token).await?;
                let config = OAuthProviderConfig::facebook();

                Ok(JwtClaims {
                    iss: config.issuer,
                    aud: "facebook-client".to_string(), // Could be made configurable
                    sub: user_info.id,
                    exp: now + 3600, // 1 hour expiry
                    iat: now,
                    nonce: None,
                    email: user_info.email,
                    email_verified: None,
                    name: user_info.name,
                    picture: None,
                    given_name: None,
                    family_name: None,
                })
            }
            "twitch" => {
                let user_info = self.validate_twitch_token(token).await?;
                let config = OAuthProviderConfig::twitch();

                Ok(JwtClaims {
                    iss: config.issuer,
                    aud: "twitch-client".to_string(), // Could be made configurable
                    sub: user_info.id,
                    exp: now + 3600, // 1 hour expiry
                    iat: now,
                    nonce: None,
                    email: user_info.email,
                    email_verified: None,
                    name: Some(user_info.display_name),
                    picture: None,
                    given_name: None,
                    family_name: None,
                })
            }
            _ => anyhow::bail!("Unsupported provider for access token validation: {}", provider),
        }
    }
}

impl Default for AccessTokenValidator {
    fn default() -> Self {
        Self::new(None, None, None)
    }
}

