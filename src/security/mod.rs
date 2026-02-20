pub mod jwt;
pub mod access_token;

use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose};

use crate::models::JwtClaims;

const NONCE_SIZE: usize = 12;

#[derive(Clone)]
pub struct SaltManager {
    master_seed: Vec<u8>,
    encryption_key: Key,
}

impl SaltManager {
    /// Create a new SaltManager with the provided master seed
    pub fn new(master_seed: Vec<u8>) -> Result<Self> {
        if master_seed.len() < 32 {
            anyhow::bail!("Master seed must be at least 32 bytes");
        }

        // Derive encryption key from master seed
        let mut hasher = <Sha256 as Digest>::new();
        hasher.update(b"MYSOCIAL_ENCRYPTION_KEY_V1");
        hasher.update(&master_seed);
        let key_bytes = hasher.finalize();
        let encryption_key = Key::from_slice(&key_bytes);

        Ok(Self {
            master_seed,
            encryption_key: *encryption_key,
        })
    }

    /// Generate a deterministic salt from JWT claims
    /// Returns exactly 16 bytes (128 bits) for zkLogin compatibility
    ///
    /// Uses iss + sub (stable per provider) to align with DB key and avoid
    /// cross-provider sub collisions. aud is not included since we enforce
    /// a single aud per provider; differing aud is rejected earlier in the flow.
    pub fn generate_salt(&self, claims: &JwtClaims) -> Result<Vec<u8>> {
        let mut hasher = <Sha256 as Digest>::new();

        // Domain separation for versioning and server binding
        hasher.update(b"MYSOCIAL_SALT_V1");
        hasher.update(&self.master_seed);
        hasher.update(claims.iss.as_bytes());
        hasher.update(claims.sub.as_bytes());

        let hash = hasher.finalize();

        // Take exactly first 16 bytes for zkLogin compatibility (128 bits)
        let salt = hash[..16].to_vec();
        Ok(salt)
    }

    /// Encrypt salt for storage
    pub fn encrypt_salt(&self, salt: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.encryption_key);
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the salt
        let ciphertext = cipher
            .encrypt(nonce, salt)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
        
        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    /// Decrypt salt from storage
    pub fn decrypt_salt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() < NONCE_SIZE {
            anyhow::bail!("Encrypted data too short");
        }

        let cipher = ChaCha20Poly1305::new(&self.encryption_key);
        
        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        // Decrypt
        let salt = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
        
        Ok(salt)
    }
}

/// Generate a secure random master seed
#[allow(dead_code)]
pub fn generate_master_seed() -> Vec<u8> {
    let mut seed = vec![0u8; 64]; // 512 bits
    OsRng.fill_bytes(&mut seed);
    seed
}

/// Hash a token (JWT or access token) for audit logging
pub fn hash_token_for_audit(token: &str) -> String {
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(token.as_bytes());
    general_purpose::STANDARD.encode(hasher.finalize())
}

/// Hash a JWT for audit logging (backward compatibility)
#[deprecated(note = "Use hash_token_for_audit instead")]
pub fn hash_jwt_for_audit(jwt: &str) -> String {
    hash_token_for_audit(jwt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salt_generation_deterministic() {
        let seed = generate_master_seed();
        let manager = SaltManager::new(seed).unwrap();
        
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
        
        let salt1 = manager.generate_salt(&claims).unwrap();
        let salt2 = manager.generate_salt(&claims).unwrap();
        
        assert_eq!(salt1, salt2, "Salt generation should be deterministic");
    }

    #[test]
    fn test_salt_encryption_decryption() {
        let seed = generate_master_seed();
        let manager = SaltManager::new(seed).unwrap();
        
        let salt = b"test-salt-value";
        let encrypted = manager.encrypt_salt(salt).unwrap();
        let decrypted = manager.decrypt_salt(&encrypted).unwrap();
        
        assert_eq!(salt.to_vec(), decrypted, "Encryption/decryption roundtrip should work");
    }

    #[test]
    fn test_salt_same_across_platforms() {
        let seed = generate_master_seed();
        let manager = SaltManager::new(seed).unwrap();

        // Same user sub, different audiences/issuers/timestamps
        let claims_web = JwtClaims {
            iss: "https://accounts.google.com".to_string(),
            aud: "web-client-id".to_string(),
            sub: "111631294628286022835".to_string(),
            exp: 2000000000,
            iat: 1500000000,
            nonce: None,
            email: None,
            email_verified: None,
            name: None,
            picture: None,
            given_name: None,
            family_name: None,
        };

        let claims_ios = JwtClaims {
            iss: "https://accounts.google.com".to_string(),
            aud: "ios-client-id".to_string(),
            sub: "111631294628286022835".to_string(),
            exp: 2100000000,
            iat: 1600000000,
            nonce: Some("random".to_string()),
            email: None,
            email_verified: None,
            name: None,
            picture: None,
            given_name: None,
            family_name: None,
        };

        let salt_web = manager.generate_salt(&claims_web).unwrap();
        let salt_ios = manager.generate_salt(&claims_ios).unwrap();

        assert_eq!(salt_web, salt_ios, "Salts must match across platforms for same iss+sub (aud must match configured one in production)");
    }

    #[test]
    fn test_salt_differs_across_issuers() {
        let seed = generate_master_seed();
        let manager = SaltManager::new(seed).unwrap();

        // Same sub, different issuers - must produce different salts
        let claims_google = JwtClaims {
            iss: "https://accounts.google.com".to_string(),
            aud: "test-app".to_string(),
            sub: "12345".to_string(),
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

        let claims_facebook = JwtClaims {
            iss: "https://www.facebook.com".to_string(),
            aud: "test-app".to_string(),
            sub: "12345".to_string(),
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

        let salt_google = manager.generate_salt(&claims_google).unwrap();
        let salt_facebook = manager.generate_salt(&claims_facebook).unwrap();

        assert_ne!(salt_google, salt_facebook, "Salts must differ when iss differs (same sub)");
    }
}
