//! Sealed-record crypto — encrypt-before-gossip for the
//! private DNA v2. Every gossiping record is an opaque `{cipher, nonce}`
//! blob; entry type, timestamps, app ids, relationships all live INSIDE the
//! ciphertext.
//!
//! Method (deliberately NOT crypto_box-by-agent-key — per-device agent
//! keys differ, which would make records unreadable across devices):
//! XSalsa20-Poly1305 secretbox with the per-user symmetric data key
//!   data_key = HMAC-SHA256("flowsta-data-encryption-v1", bip39_seed)
//! (see key_derivation::derive_data_encryption_key, golden-vector-verified).
//! Every device derives the same key from the phrase — multi-device gossip
//! decrypts with zero key exchange, and recovery needs only the phrase.
//!
//! The zome never sees plaintext: seal before create_sealed, unseal after
//! get_all_sealed.

use lair_keystore_api::dependencies::sodoken;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Version tag inside every sealed payload — bump on layout change so old
/// records stay decodable forever (records are immutable once gossiped).
pub const SEALED_PAYLOAD_V1: u16 = 1;

pub const NONCE_BYTES: usize = sodoken::secretbox::XSALSA_NONCEBYTES; // 24
pub const MAC_BYTES: usize = sodoken::secretbox::XSALSA_MACBYTES; // 16

#[derive(Error, Debug)]
pub enum SealedError {
    #[error("Encryption failed: {0}")]
    Encrypt(String),

    #[error("Decryption failed (wrong key or tampered record): {0}")]
    Decrypt(String),

    #[error("Payload encoding failed: {0}")]
    Encode(String),

    #[error("Payload decoding failed: {0}")]
    Decode(String),
}

/// The plaintext-before-encryption layout. `body` carries the original
/// v1.11 entry struct unmodified (so migration is a mechanical wrap),
/// serialized as embedded MessagePack alongside the metadata that
/// v1.11 leaked in the clear.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedPayload {
    pub v: u16,
    /// Which v1.11 entry type this wraps: "user_profile", "login_activity",
    /// "email_permission", "dashboard_activity", "oauth_activity",
    /// "privacy_settings", "app_analytics_id", "profile_picture".
    /// (RecoveryPhrase + TotpConfig never become Sealed — root secrets are
    /// never gossiped.)
    pub entry_type: String,
    /// Creation time in ms — inside the cipher; the DHT action timestamp is
    /// the only timing a peer sees.
    pub created_at: u64,
    /// The original entry struct, MessagePack-encoded by the caller.
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    /// Related record references (action hashes, base64) — inside the
    /// cipher so relationships don't leak as link structure.
    pub refs: Vec<String>,
}

/// Encrypt a payload with the per-user data key. Returns (cipher, nonce);
/// the nonce is random per record (never reused — 24 random bytes).
pub fn seal(payload: &SealedPayload, data_key: &[u8; 32]) -> Result<(Vec<u8>, [u8; NONCE_BYTES]), SealedError> {
    let plain = rmp_serde::to_vec_named(payload).map_err(|e| SealedError::Encode(e.to_string()))?;

    let mut nonce = [0u8; NONCE_BYTES];
    sodoken::random::randombytes_buf(&mut nonce).map_err(|e| SealedError::Encrypt(e.to_string()))?;

    let mut cipher = vec![0u8; plain.len() + MAC_BYTES];
    sodoken::secretbox::xsalsa_easy(&mut cipher, &nonce, &plain, data_key)
        .map_err(|e| SealedError::Encrypt(e.to_string()))?;

    Ok((cipher, nonce))
}

/// Decrypt and decode a sealed record. Fails on a wrong key or any
/// tampering (Poly1305 authenticates the whole cipher).
pub fn unseal(cipher: &[u8], nonce: &[u8; NONCE_BYTES], data_key: &[u8; 32]) -> Result<SealedPayload, SealedError> {
    if cipher.len() < MAC_BYTES {
        return Err(SealedError::Decrypt("cipher shorter than MAC".into()));
    }
    let mut plain = vec![0u8; cipher.len() - MAC_BYTES];
    sodoken::secretbox::xsalsa_open_easy(&mut plain, cipher, nonce, data_key)
        .map_err(|e| SealedError::Decrypt(e.to_string()))?;

    rmp_serde::from_slice(&plain).map_err(|e| SealedError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_derivation::derive_data_encryption_key;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn test_payload() -> SealedPayload {
        SealedPayload {
            v: SEALED_PAYLOAD_V1,
            entry_type: "oauth_activity".into(),
            created_at: 1_751_500_000_000,
            body: rmp_serde::to_vec_named(&serde_json::json!({
                "app_id": "flowsta_app_2f0660",
                "app_name": "Website",
                "event_type": "login",
            }))
            .unwrap(),
            refs: vec!["uhCkkExampleActionHash".into()],
        }
    }

    #[test]
    fn test_seal_unseal_roundtrip() {
        let key = derive_data_encryption_key(TEST_MNEMONIC).unwrap();
        let payload = test_payload();

        let (cipher, nonce) = seal(&payload, &key).unwrap();
        assert!(cipher.len() > MAC_BYTES);

        let out = unseal(&cipher, &nonce, &key).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn test_multi_device_same_phrase_decrypts() {
        // Device A and device B derive the key independently from the same
        // phrase — B must decrypt what A sealed (the multi-device property).
        let key_a = derive_data_encryption_key(TEST_MNEMONIC).unwrap();
        let key_b = derive_data_encryption_key(TEST_MNEMONIC).unwrap();
        let (cipher, nonce) = seal(&test_payload(), &key_a).unwrap();
        assert!(unseal(&cipher, &nonce, &key_b).is_ok());
    }

    #[test]
    fn test_tamper_detection() {
        let key = derive_data_encryption_key(TEST_MNEMONIC).unwrap();
        let (mut cipher, nonce) = seal(&test_payload(), &key).unwrap();
        cipher[0] ^= 0x01;
        assert!(matches!(unseal(&cipher, &nonce, &key), Err(SealedError::Decrypt(_))));
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = derive_data_encryption_key(TEST_MNEMONIC).unwrap();
        let (cipher, nonce) = seal(&test_payload(), &key).unwrap();
        let wrong = [0x42u8; 32];
        assert!(unseal(&cipher, &nonce, &wrong).is_err());
    }

    #[test]
    fn test_nonce_uniqueness() {
        let key = derive_data_encryption_key(TEST_MNEMONIC).unwrap();
        let (c1, n1) = seal(&test_payload(), &key).unwrap();
        let (c2, n2) = seal(&test_payload(), &key).unwrap();
        assert_ne!(n1, n2, "nonces must be random per record");
        assert_ne!(c1, c2, "same plaintext must not produce the same cipher");
    }

    #[test]
    fn test_unknown_future_version_still_decodes() {
        // Forward-compat: a v2 payload with the same fields decodes (the
        // version tag is data, not a gate) — callers branch on `v`.
        let key = derive_data_encryption_key(TEST_MNEMONIC).unwrap();
        let mut payload = test_payload();
        payload.v = 2;
        let (cipher, nonce) = seal(&payload, &key).unwrap();
        assert_eq!(unseal(&cipher, &nonce, &key).unwrap().v, 2);
    }
}
