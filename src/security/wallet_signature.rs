//! Ed25519 signature verification for wallet authentication.
//!
//! Expects base64-encoded Ed25519 SimpleSignature format:
//! - Byte 0: 0x00 (Ed25519 scheme flag)
//! - Bytes 1-64: Ed25519 signature (64 bytes)
//! - Bytes 65-96: Ed25519 public key (32 bytes)

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use myso_sdk_types::Ed25519PublicKey;

const ED25519_FLAG: u8 = 0x00;
const ED25519_SIG_LEN: usize = 64;
const ED25519_PUBKEY_LEN: usize = 32;
const SIMPLE_SIG_LEN: usize = 1 + ED25519_SIG_LEN + ED25519_PUBKEY_LEN;

/// Normalize a MySo address for comparison (lowercase, ensure 0x prefix).
fn normalize_address(addr: &str) -> String {
    let s = addr.trim().to_lowercase();
    if s.starts_with("0x") {
        s
    } else {
        format!("0x{}", s)
    }
}

/// Verify that the signature was produced by the private key corresponding to the given address.
///
/// - `address`: MySo-style address (0x + 64 hex chars)
/// - `message`: The message that was signed (e.g. challenge text)
/// - `signature_b64`: Base64-encoded Ed25519 SimpleSignature (97 bytes)
pub fn verify_wallet_signature(address: &str, message: &str, signature_b64: &str) -> Result<()> {
    let bytes = BASE64
        .decode(signature_b64.trim())
        .context("Invalid base64 in signature")?;

    if bytes.len() != SIMPLE_SIG_LEN {
        anyhow::bail!(
            "Invalid signature length: expected {} bytes, got {}",
            SIMPLE_SIG_LEN,
            bytes.len()
        );
    }

    if bytes[0] != ED25519_FLAG {
        anyhow::bail!("Unsupported signature scheme: expected Ed25519 (0x00), got 0x{:02x}", bytes[0]);
    }

    let sig_bytes: [u8; ED25519_SIG_LEN] = bytes[1..(1 + ED25519_SIG_LEN)]
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid signature slice"))?;
    let pubkey_bytes: [u8; ED25519_PUBKEY_LEN] = bytes[(1 + ED25519_SIG_LEN)..]
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid public key slice"))?;

    let public_key = Ed25519PublicKey::new(pubkey_bytes);
    let derived_address = public_key.derive_address().to_string();

    let normalized_request = normalize_address(address);
    let normalized_derived = normalize_address(&derived_address);

    if normalized_request != normalized_derived {
        anyhow::bail!(
            "Address mismatch: request address does not match signer (derived: {})",
            derived_address
        );
    }

    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .context("Invalid Ed25519 public key")?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(message.as_bytes(), &signature)
        .context("Signature verification failed")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_simple_signature(signing_key: &SigningKey, message: &[u8]) -> Vec<u8> {
        let sig = signing_key.sign(message);
        let mut buf = vec![ED25519_FLAG];
        buf.extend_from_slice(sig.to_bytes().as_ref());
        buf.extend_from_slice(signing_key.verifying_key().as_bytes());
        buf
    }

    #[test]
    fn test_verify_wallet_signature_success() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pubkey = Ed25519PublicKey::new(signing_key.verifying_key().to_bytes());
        let address = pubkey.derive_address().to_string();

        let message = "Sign in to MySocial at 2025-03-11";
        let sig_bytes = make_simple_signature(&signing_key, message.as_bytes());
        let sig_b64 = BASE64.encode(&sig_bytes);

        let result = verify_wallet_signature(&address, message, &sig_b64);
        assert!(result.is_ok(), "Verification should succeed: {:?}", result.err());
    }

    #[test]
    fn test_verify_wallet_signature_wrong_address() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let message = "test message";
        let sig_bytes = make_simple_signature(&signing_key, message.as_bytes());
        let sig_b64 = BASE64.encode(&sig_bytes);

        let wrong_address = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let result = verify_wallet_signature(wrong_address, message, &sig_b64);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wallet_signature_wrong_message() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pubkey = Ed25519PublicKey::new(signing_key.verifying_key().to_bytes());
        let address = pubkey.derive_address().to_string();

        let sig_bytes = make_simple_signature(&signing_key, b"original message");
        let sig_b64 = BASE64.encode(&sig_bytes);

        let result = verify_wallet_signature(&address, "tampered message", &sig_b64);
        assert!(result.is_err());
    }
}
