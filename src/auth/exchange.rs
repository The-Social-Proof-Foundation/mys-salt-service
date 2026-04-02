use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use tracing::warn;

use crate::config::Config;
use crate::models::AuthExchangeResponse;

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: Option<String>,
    id_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct AppleTokenResponse {
    access_token: Option<String>,
    id_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct FacebookTokenResponse {
    access_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TwitchTokenResponse {
    access_token: Option<String>,
    id_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

/// Exchange an OAuth authorization code for tokens by calling the provider's token endpoint.
pub async fn exchange_code_for_tokens(
    client: &Client,
    provider: &str,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    code_verifier: Option<&str>,
    config: &Config,
) -> Result<AuthExchangeResponse> {
    let provider_lower = provider.to_lowercase();
    match provider_lower.as_str() {
        "google" => exchange_google(client, code, redirect_uri, client_id, code_verifier, config).await,
        "apple" => exchange_apple(client, code, redirect_uri, client_id, code_verifier, config).await,
        "facebook" => exchange_facebook(client, code, redirect_uri, client_id, config).await,
        "twitch" => exchange_twitch(client, code, redirect_uri, client_id, config).await,
        _ => anyhow::bail!("Unknown provider: {}", provider),
    }
}

async fn exchange_google(
    client: &Client,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    code_verifier: Option<&str>,
    config: &Config,
) -> Result<AuthExchangeResponse> {
    let client_secret = config
        .google_client_secret
        .as_deref()
        .context("GOOGLE_CLIENT_SECRET not configured")?;

    let mut params = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];
    if let Some(cv) = code_verifier {
        params.push(("code_verifier", cv));
    }

    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await
        .context("Google token request failed")?;

    let status = resp.status();
    let text = resp.text().await.context("Failed to read Google token response")?;
    if !status.is_success() {
        warn!(
            redirect_uri = %redirect_uri,
            google_oauth_client_id = %client_id,
            http_status = %status,
            response_body = %text,
            "Google token exchange rejected; redirect_uri must exactly match an entry under Authorized redirect URIs for this Google OAuth client"
        );
        anyhow::bail!("Google token exchange failed ({}): {}", status, text);
    }

    let token: GoogleTokenResponse = serde_json::from_str(&text)
        .context("Failed to parse Google token response")?;

    Ok(AuthExchangeResponse {
        access_token: token.access_token,
        id_token: token.id_token,
        refresh_token: token.refresh_token,
        expires_in: token.expires_in,
        user: None,
    })
}

fn generate_apple_client_secret(
    team_id: &str,
    key_id: &str,
    client_id: &str,
    private_key_pem: &str,
) -> Result<String> {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let exp = now + 15777000; // 6 months max per Apple docs

    let header = json!({
        "alg": "ES256",
        "kid": key_id
    });
    let header: Header = serde_json::from_value(header).context("Invalid Apple JWT header")?;

    let payload = json!({
        "iss": team_id,
        "iat": now,
        "exp": exp,
        "aud": "https://appleid.apple.com",
        "sub": client_id
    });

    let key = EncodingKey::from_ec_pem(private_key_pem.as_bytes())
        .context("Invalid Apple private key PEM")?;

    let token = encode(&header, &payload, &key).context("Failed to sign Apple client secret JWT")?;
    Ok(token)
}

async fn exchange_apple(
    client: &Client,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    code_verifier: Option<&str>,
    config: &Config,
) -> Result<AuthExchangeResponse> {
    let team_id = config
        .apple_team_id
        .as_deref()
        .context("APPLE_TEAM_ID not configured")?;
    let key_id = config
        .apple_key_identifier
        .as_deref()
        .context("APPLE_KEY_IDENTIFIER not configured")?;
    let private_key = config
        .apple_private_key
        .as_deref()
        .context("APPLE_PRIVATE_KEY not configured")?;

    let client_secret = generate_apple_client_secret(team_id, key_id, client_id, private_key)?;

    let mut params: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("client_secret", &client_secret),
    ];
    if let Some(cv) = code_verifier {
        params.push(("code_verifier", cv));
    }

    let resp = client
        .post("https://appleid.apple.com/auth/token")
        .form(&params)
        .send()
        .await
        .context("Apple token request failed")?;

    let status = resp.status();
    let text = resp.text().await.context("Failed to read Apple token response")?;
    if !status.is_success() {
        anyhow::bail!("Apple token exchange failed ({}): {}", status, text);
    }

    let token: AppleTokenResponse = serde_json::from_str(&text)
        .context("Failed to parse Apple token response")?;

    Ok(AuthExchangeResponse {
        access_token: token.access_token,
        id_token: token.id_token,
        refresh_token: token.refresh_token,
        expires_in: token.expires_in,
        user: None,
    })
}

async fn exchange_facebook(
    client: &Client,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    config: &Config,
) -> Result<AuthExchangeResponse> {
    let client_secret = config
        .facebook_app_secret
        .as_deref()
        .context("FACEBOOK_APP_SECRET not configured")?;

    let params = [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("redirect_uri", redirect_uri),
        ("code", code),
    ];

    let resp = client
        .get("https://graph.facebook.com/v18.0/oauth/access_token")
        .query(&params)
        .send()
        .await
        .context("Facebook token request failed")?;

    let status = resp.status();
    let text = resp.text().await.context("Failed to read Facebook token response")?;
    if !status.is_success() {
        anyhow::bail!("Facebook token exchange failed ({}): {}", status, text);
    }

    let token: FacebookTokenResponse = serde_json::from_str(&text)
        .context("Failed to parse Facebook token response")?;

    let access_token = token.access_token.context("Facebook response missing access_token")?;

    let user = fetch_facebook_user(client, &access_token, config).await.ok();

    Ok(AuthExchangeResponse {
        access_token: Some(access_token),
        id_token: None,
        refresh_token: None,
        expires_in: None,
        user: user.map(|u| serde_json::json!({ "provider": "facebook", "id": u.id, "name": u.name, "email": u.email })),
    })
}

#[derive(Debug, Deserialize)]
struct FacebookUser {
    id: String,
    name: Option<String>,
    email: Option<String>,
}

async fn fetch_facebook_user(client: &Client, access_token: &str, _config: &Config) -> Result<FacebookUser> {
    let resp = client
        .get("https://graph.facebook.com/me")
        .query(&[
            ("fields", "id,name,email"),
            ("access_token", access_token),
        ])
        .send()
        .await
        .context("Facebook userinfo request failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("Facebook userinfo failed: {}", resp.status());
    }
    let user: FacebookUser = resp.json().await.context("Failed to parse Facebook user")?;
    Ok(user)
}

async fn exchange_twitch(
    client: &Client,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    config: &Config,
) -> Result<AuthExchangeResponse> {
    let client_secret = config
        .twitch_client_secret
        .as_deref()
        .context("TWITCH_CLIENT_SECRET not configured")?;

    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];

    let resp = client
        .post("https://id.twitch.tv/oauth2/token")
        .form(&params)
        .send()
        .await
        .context("Twitch token request failed")?;

    let status = resp.status();
    let text = resp.text().await.context("Failed to read Twitch token response")?;
    if !status.is_success() {
        anyhow::bail!("Twitch token exchange failed ({}): {}", status, text);
    }

    let token: TwitchTokenResponse = serde_json::from_str(&text)
        .context("Failed to parse Twitch token response")?;

    let access_token = token.access_token.context("Twitch response missing access_token")?;

    let user = fetch_twitch_user(client, &access_token, config).await.ok();

    Ok(AuthExchangeResponse {
        access_token: Some(access_token),
        id_token: token.id_token,
        refresh_token: token.refresh_token,
        expires_in: token.expires_in,
        user: user.map(|u| serde_json::json!({ "provider": "twitch", "id": u.id, "login": u.login, "display_name": u.display_name, "email": u.email })),
    })
}

#[derive(Debug, Deserialize)]
struct TwitchUser {
    id: String,
    login: String,
    #[serde(rename = "display_name")]
    display_name: String,
    email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TwitchUsersResponse {
    data: Vec<TwitchUser>,
}

async fn fetch_twitch_user(client: &Client, access_token: &str, config: &Config) -> Result<TwitchUser> {
    let client_id = config.twitch_client_id.as_deref().context("TWITCH_CLIENT_ID not configured")?;

    let resp = client
        .get("https://api.twitch.tv/helix/users")
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Client-Id", client_id)
        .send()
        .await
        .context("Twitch userinfo request failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("Twitch userinfo failed: {}", resp.status());
    }
    let data: TwitchUsersResponse = resp.json().await.context("Failed to parse Twitch users")?;
    data.data
        .into_iter()
        .next()
        .context("Twitch users response empty")
}
