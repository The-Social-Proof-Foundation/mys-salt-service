pub mod jwt;

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
    pub fn generate_salt(&self, claims: &JwtClaims) -> Result<Vec<u8>> {
        let mut hasher = <Sha256 as Digest>::new();
        
        // Domain separation for versioning
        hasher.update(b"MYSOCIAL_SALT_V1");
        hasher.update(&self.master_seed);
        hasher.update(claims.iss.as_bytes());
        hasher.update(claims.aud.as_bytes());
        hasher.update(claims.sub.as_bytes());
        
        let salt = hasher.finalize().to_vec();
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

/// Hash a JWT for audit logging
pub fn hash_jwt_for_audit(jwt: &str) -> String {
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(jwt.as_bytes());
    general_purpose::STANDARD.encode(hasher.finalize())
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
            sub: "user123".to_string(),
            exp: 1234567890,
            iat: 1234567890,
            nonce: None,
            email: None,
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
} 