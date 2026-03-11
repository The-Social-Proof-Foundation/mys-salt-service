//! Ed25519 address derivation from sub + salt.
//!
//! Formula: combinedSeed = sub + "_" + salt → SHA256 → seed[0:32] → Ed25519 keypair → address
//! Address format: 0x + 64 hex characters (32 bytes), Sui-style.

use anyhow::Result;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

/// Derive an Ed25519 address from sub and salt.
///
/// Uses the same formula as the client:
/// - combinedSeed = sub + "_" + salt
/// - hash = SHA256(combinedSeed)
/// - seed = hash[0:32]
/// - keypair = Ed25519Keypair.fromSecretKey(seed)
/// - address = keypair.getPublicKey().toMySoAddress()
///
/// Returns address as hex: `0x` + 64 hex characters (32 bytes).
pub fn derive_ed25519_address(sub: &str, salt: &str) -> Result<String> {
    let combined_seed = format!("{}_{}", sub, salt);
    let mut hasher = Sha256::new();
    hasher.update(combined_seed.as_bytes());
    let hash = hasher.finalize();

    let seed: [u8; 32] = hash
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("SHA256 hash must be 32 bytes"))?;

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let address = format!("0x{}", hex::encode(verifying_key.as_bytes()));
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_address_deterministic() {
        let addr1 = derive_ed25519_address("12345", "14286852330947081862955449959256637702976107966405724670306989168212871471264").unwrap();
        let addr2 = derive_ed25519_address("12345", "14286852330947081862955449959256637702976107966405724670306989168212871471264").unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_derive_address_format() {
        let addr = derive_ed25519_address("sub", "salt").unwrap();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 66); // 0x + 64 hex chars
        assert!(addr[2..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_derive_address_differs_for_different_inputs() {
        let addr1 = derive_ed25519_address("sub1", "salt").unwrap();
        let addr2 = derive_ed25519_address("sub2", "salt").unwrap();
        let addr3 = derive_ed25519_address("sub", "salt1").unwrap();
        assert_ne!(addr1, addr2);
        assert_ne!(addr1, addr3);
    }
}
