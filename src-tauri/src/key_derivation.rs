//! Key derivation from BIP39 recovery phrase via HMAC-SHA256.
//!
//! Port of `api/src/services/recoveryPhrase.js` to Rust.
//! Same mnemonic + same constant = same agent key (cross-language deterministic).
//!
//! Derivation constants:
//! - `flowsta-holochain-identity` — web agent key (existing, used by API)
//! - `flowsta-device-1` — desktop agent key
//! - `flowsta-sync-encryption` — cross-device sync encryption key (future)
//! - `flowsta-sync-anchor` — DHT sync anchor lookup key (future)
//! - `flowsta-recovery-lookup` — recovery phrase lookup hash (existing, used by API)
//! - `flowsta-data-encryption-v1` — DNA v2 Sealed-record symmetric key (R2)
//! - `flowsta-private-network-v2` — per-user private-DHT network seed (R2)

use bip39::Mnemonic;
use blake2::digest::{consts::U32, Digest};
use blake2::Blake2b;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

/// Desktop agent key derivation constant.
/// Matches the plan in DESKTOP_APP_AND_SDK_VISION.md Q1.
pub const DEVICE_1_CONSTANT: &str = "flowsta-device-1";

/// Web agent key derivation constant (for cross-language verification only).
/// The API uses this in `recoveryPhrase.js` line 65.
pub const WEB_IDENTITY_CONSTANT: &str = "flowsta-holochain-identity";

/// Recovery lookup hash constant (for agent key discovery during linking).
/// The API uses this in `recoveryPhrase.js` line 252.
pub const RECOVERY_LOOKUP_CONSTANT: &str = "flowsta-recovery-lookup";

/// Symmetric data-encryption key for the encrypted private DNA v2
/// ("Sealed" records, R2 encrypt-before-gossip). Phrase-derived so every
/// device computes the same key — multi-device gossip decrypts without key
/// exchange (per-device AGENT keys differ by design; this key does not).
/// JS reference: `recoveryPhrase.js` deriveDataEncryptionKey.
pub const DATA_ENCRYPTION_CONSTANT: &str = "flowsta-data-encryption-v1";

/// Per-user private-DHT network seed for DNA v2 installs (hex of the derived
/// 32 bytes). All the user's devices derive the same seed → same private
/// network with zero coordination; different users → disjoint networks.
/// JS reference: `recoveryPhrase.js` derivePrivateNetworkSeed.
pub const PRIVATE_NETWORK_SEED_CONSTANT: &str = "flowsta-private-network-v2";

#[derive(Error, Debug)]
pub enum KeyDerivationError {
    #[error("Invalid recovery phrase: {0}")]
    InvalidMnemonic(String),

    #[error("HMAC error: {0}")]
    HmacError(String),
}

/// Derive a 32-byte seed from a BIP39 mnemonic using HMAC-SHA256.
///
/// This mirrors the JavaScript implementation:
/// ```js
/// const seed = await bip39.mnemonicToSeed(normalized);
/// const hmac = crypto.createHmac('sha256', derivationKey);
/// hmac.update(seed);
/// const derivedSeed = hmac.digest();
/// ```
///
/// IMPORTANT: In the JS code, the HMAC key is the derivation constant and
/// the message is the BIP39 seed. This is the correct order.
pub fn derive_seed(mnemonic_str: &str, derivation_constant: &str) -> Result<[u8; 32], KeyDerivationError> {
    // Validate and normalize mnemonic
    let mnemonic = Mnemonic::parse_normalized(mnemonic_str)
        .map_err(|e| KeyDerivationError::InvalidMnemonic(e.to_string()))?;

    // BIP39 mnemonic -> 512-bit seed (with empty passphrase, matching JS bip39.mnemonicToSeed)
    let bip39_seed = mnemonic.to_seed("");

    // HMAC-SHA256(derivation_constant, bip39_seed) -> 32-byte derived seed
    // Note: In JS, crypto.createHmac('sha256', derivationKey).update(seed)
    // means the HMAC key = derivationKey, message = seed
    let mut mac = Hmac::<Sha256>::new_from_slice(derivation_constant.as_bytes())
        .map_err(|e| KeyDerivationError::HmacError(e.to_string()))?;
    mac.update(&bip39_seed);
    let result = mac.finalize().into_bytes();

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&result);
    Ok(seed)
}

/// Derive an Ed25519 signing key from a BIP39 mnemonic.
///
/// Same as `derive_seed` but returns an `ed25519_dalek::SigningKey`.
pub fn derive_signing_key(mnemonic_str: &str, derivation_constant: &str) -> Result<SigningKey, KeyDerivationError> {
    let seed = derive_seed(mnemonic_str, derivation_constant)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Derive the desktop device agent key from a recovery phrase.
pub fn derive_device_keypair(mnemonic_str: &str) -> Result<SigningKey, KeyDerivationError> {
    derive_signing_key(mnemonic_str, DEVICE_1_CONSTANT)
}

/// Derive the recovery lookup hash (hex string) for agent key discovery.
///
/// Used during agent linking: the desktop sends this hash to the API to
/// discover the web agent's pub key without revealing the mnemonic.
pub fn derive_recovery_lookup_hash(mnemonic_str: &str) -> Result<String, KeyDerivationError> {
    let seed = derive_seed(mnemonic_str, RECOVERY_LOOKUP_CONSTANT)?;
    Ok(hex::encode(seed))
}

/// Derive the 32-byte symmetric data-encryption key for DNA v2 Sealed records.
pub fn derive_data_encryption_key(mnemonic_str: &str) -> Result<[u8; 32], KeyDerivationError> {
    derive_seed(mnemonic_str, DATA_ENCRYPTION_CONSTANT)
}

/// Derive the per-user private-DHT network seed (hex string) for DNA v2 installs.
pub fn derive_private_network_seed(mnemonic_str: &str) -> Result<String, KeyDerivationError> {
    let seed = derive_seed(mnemonic_str, PRIVATE_NETWORK_SEED_CONSTANT)?;
    Ok(hex::encode(seed))
}

/// Validate a BIP39 mnemonic string.
pub fn validate_mnemonic(mnemonic_str: &str) -> bool {
    Mnemonic::parse_normalized(mnemonic_str).is_ok()
}

// ── Holochain AgentPubKey Construction ──────────────────────────────
//
// Holochain's AgentPubKey is 39 bytes:
//   [0x84, 0x20, 0x24]  — 3-byte HoloHash type prefix (AgentPubKey)
//   [... 32 bytes ...]   — Ed25519 public key
//   [... 4 bytes ...]    — DHT location (blake2b-256 XOR-folded to 4 bytes)
//
// The DHT location is computed the same way as in the `holo_hash` crate:
//   1. blake2b-256(32-byte ed25519 key) → 32 bytes
//   2. XOR-fold 32 bytes → 4 bytes

/// Holochain AgentPubKey type prefix bytes.
const AGENT_PUB_KEY_PREFIX: [u8; 3] = [0x84, 0x20, 0x24];

/// Compute the Holochain DHT location from a 32-byte ed25519 public key.
///
/// Algorithm (from holo_hash crate):
/// 1. blake2b-256 hash of the 32-byte key → 32 bytes
/// 2. XOR-fold the 32 bytes into 4 bytes (byte[i] ^= hash[i] for i % 4)
pub fn compute_dht_location(ed25519_pub_key: &[u8; 32]) -> [u8; 4] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(ed25519_pub_key);
    let hash = hasher.finalize();

    let mut loc = [0u8; 4];
    for (i, &byte) in hash.iter().enumerate() {
        loc[i % 4] ^= byte;
    }
    loc
}

/// Construct a full 39-byte Holochain AgentPubKey from a 32-byte ed25519 public key.
pub fn construct_agent_pub_key_bytes(ed25519_pub_key: &[u8; 32]) -> [u8; 39] {
    let loc = compute_dht_location(ed25519_pub_key);

    let mut key = [0u8; 39];
    key[..3].copy_from_slice(&AGENT_PUB_KEY_PREFIX);
    key[3..35].copy_from_slice(ed25519_pub_key);
    key[35..39].copy_from_slice(&loc);
    key
}

/// Construct the Holochain uhCAk... string from a 32-byte ed25519 public key.
///
/// Format: "u" (multibase prefix) + base64url_no_pad(39 bytes)
pub fn construct_agent_pub_key_string(ed25519_pub_key: &[u8; 32]) -> String {
    let raw = construct_agent_pub_key_bytes(ed25519_pub_key);
    format!("u{}", base64url_encode_no_pad(&raw))
}

/// Build the sorted agent pair payload (78 bytes) that both agents sign
/// for an IsSamePersonEntry. Matches the integrity zome's `sorted_agent_pair_bytes`.
///
/// Each key is 39 bytes, sorted lexicographically, then concatenated.
pub fn build_sorted_agent_pair_payload(
    agent_a_39: &[u8; 39],
    agent_b_39: &[u8; 39],
) -> [u8; 78] {
    let (first, second) = if agent_a_39[..] <= agent_b_39[..] {
        (agent_a_39, agent_b_39)
    } else {
        (agent_b_39, agent_a_39)
    };

    let mut payload = [0u8; 78];
    payload[..39].copy_from_slice(first);
    payload[39..].copy_from_slice(second);
    payload
}

/// Sign a payload with an ed25519 signing key derived from a device seed.
///
/// IMPORTANT: The payload must already be MessagePack-encoded if it will be
/// verified by Holochain's `verify_signature` (which serializes via MessagePack
/// before verifying). Use `msgpack_encode_bytes` to encode first.
pub fn sign_with_device_seed(device_seed: &[u8; 32], payload: &[u8]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(device_seed);
    let signature = signing_key.sign(payload);
    signature.to_bytes()
}

/// MessagePack-encode a byte slice to match Holochain's `verify_signature` encoding.
///
/// Holochain's `verify_signature(key, sig, data: Vec<u8>)` internally calls
/// `holochain_serialized_bytes::encode(&data)` which serializes the `Vec<u8>` as a
/// MessagePack array of integers (NOT bin format). The signature is verified against
/// this serialized form.
///
/// External signers must sign the same MessagePack-encoded bytes for verification
/// to succeed. This function produces the identical encoding.
pub fn msgpack_encode_bytes(data: &[u8]) -> Vec<u8> {
    // rmp_serde::to_vec serializes Vec<u8> as a MessagePack array of integers,
    // matching holochain_serialized_bytes::encode (which uses default BytesMode::Normal)
    rmp_serde::to_vec(&data.to_vec()).expect("MessagePack encoding of Vec<u8> cannot fail")
}

/// Base64url encoding without padding (Holochain multibase format).
fn base64url_encode_no_pad(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::with_capacity((data.len() * 4 + 2) / 3);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((n >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            result.push(CHARS[(n & 0x3F) as usize] as char);
        }
    }
    result
}

/// Decode a Holochain uhCAk... agent pubkey string to raw 39-byte representation.
///
/// Format: "u" (multibase prefix) + base64url_no_pad(39 bytes)
/// Returns None if the string is malformed.
pub fn decode_agent_pub_key_string(key_string: &str) -> Option<[u8; 39]> {
    // Strip "u" multibase prefix
    let encoded = key_string.strip_prefix('u')?;
    let decoded = base64url_decode_no_pad(encoded)?;
    if decoded.len() != 39 {
        return None;
    }
    // Verify prefix bytes
    if decoded[0] != 0x84 || decoded[1] != 0x20 || decoded[2] != 0x24 {
        return None;
    }
    let mut result = [0u8; 39];
    result.copy_from_slice(&decoded);
    Some(result)
}

/// Base64url decoding without padding (Holochain multibase format).
fn base64url_decode_no_pad(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i < bytes.len() {
        let a = val(*bytes.get(i)?)?;
        let b = val(*bytes.get(i + 1)?)?;
        out.push(((a << 2) | (b >> 4)) as u8);
        i += 2;
        if i < bytes.len() {
            let c = val(*bytes.get(i)?)?;
            out.push((((b & 0xF) << 4) | (c >> 2)) as u8);
            i += 1;
            if i < bytes.len() {
                let d = val(*bytes.get(i)?)?;
                out.push((((c & 0x3) << 6) | d) as u8);
                i += 1;
            }
        }
    }
    Some(out)
}

/// Standard base64 encoding (with + / and padding). Used for API payloads.
pub fn base64_standard_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((data.len() * 4 + 2) / 3 + 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((n >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(n & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test mnemonic (DO NOT use in production)
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn test_validate_mnemonic() {
        assert!(validate_mnemonic(TEST_MNEMONIC));
        assert!(!validate_mnemonic("not a valid mnemonic"));
        assert!(!validate_mnemonic(""));
    }

    #[test]
    fn test_derive_seed_deterministic() {
        let seed1 = derive_seed(TEST_MNEMONIC, DEVICE_1_CONSTANT).unwrap();
        let seed2 = derive_seed(TEST_MNEMONIC, DEVICE_1_CONSTANT).unwrap();
        assert_eq!(seed1, seed2, "Same mnemonic + same constant must produce same seed");
    }

    #[test]
    fn test_different_constants_different_seeds() {
        let device_seed = derive_seed(TEST_MNEMONIC, DEVICE_1_CONSTANT).unwrap();
        let web_seed = derive_seed(TEST_MNEMONIC, WEB_IDENTITY_CONSTANT).unwrap();
        assert_ne!(device_seed, web_seed, "Different constants must produce different seeds");
    }

    #[test]
    fn test_derive_signing_key() {
        let key = derive_device_keypair(TEST_MNEMONIC).unwrap();
        let pub_key = key.verifying_key();
        // Verify the public key is 32 bytes
        assert_eq!(pub_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_recovery_lookup_hash() {
        let hash = derive_recovery_lookup_hash(TEST_MNEMONIC).unwrap();
        // Should be 64 hex characters (32 bytes)
        assert_eq!(hash.len(), 64);
        // Should be deterministic
        let hash2 = derive_recovery_lookup_hash(TEST_MNEMONIC).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_construct_agent_pub_key_bytes() {
        let key = derive_device_keypair(TEST_MNEMONIC).unwrap();
        let pub_key = key.verifying_key();
        let full_key = construct_agent_pub_key_bytes(pub_key.as_bytes());

        // First 3 bytes = AgentPubKey prefix
        assert_eq!(&full_key[..3], &[0x84, 0x20, 0x24]);
        // Next 32 bytes = ed25519 public key
        assert_eq!(&full_key[3..35], pub_key.as_bytes());
        // Last 4 bytes = DHT location (non-zero for any real key)
        assert_eq!(full_key.len(), 39);
    }

    #[test]
    fn test_agent_pub_key_string_format() {
        let key = derive_device_keypair(TEST_MNEMONIC).unwrap();
        let pub_key = key.verifying_key();
        let key_string = construct_agent_pub_key_string(pub_key.as_bytes());

        // Must start with "uhCAk" (u multibase prefix + hCAk base64url of prefix bytes)
        assert!(key_string.starts_with("uhCAk"), "Key should start with uhCAk, got: {}", key_string);
        // Must be 53 chars: "u" + base64url_no_pad(39 bytes) = 1 + 52 = 53
        assert_eq!(key_string.len(), 53, "Key should be 53 chars, got: {}", key_string.len());
    }

    #[test]
    fn test_sorted_agent_pair_payload() {
        let device_key = derive_device_keypair(TEST_MNEMONIC).unwrap();
        let web_key = derive_signing_key(TEST_MNEMONIC, WEB_IDENTITY_CONSTANT).unwrap();

        let device_39 = construct_agent_pub_key_bytes(device_key.verifying_key().as_bytes());
        let web_39 = construct_agent_pub_key_bytes(web_key.verifying_key().as_bytes());

        let payload = build_sorted_agent_pair_payload(&device_39, &web_39);
        assert_eq!(payload.len(), 78);

        // Verify it's sorted: first 39 bytes <= last 39 bytes
        assert!(payload[..39] <= payload[39..]);

        // Same result regardless of argument order
        let payload2 = build_sorted_agent_pair_payload(&web_39, &device_39);
        assert_eq!(payload, payload2);
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let device_seed = derive_seed(TEST_MNEMONIC, DEVICE_1_CONSTANT).unwrap();
        let payload = b"test payload for signing";
        let sig_bytes = sign_with_device_seed(&device_seed, payload);

        // Verify with ed25519_dalek
        let signing_key = SigningKey::from_bytes(&device_seed);
        let verifying_key = signing_key.verifying_key();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(verifying_key.verify_strict(payload, &signature).is_ok());
    }

    /// Cross-language verification: Rust must produce identical output to
    /// `api/src/services/recoveryPhrase.js` for the same mnemonic + constant.
    /// These hex values were verified by running both implementations on 2026-02-23.
    #[test]
    fn test_cross_language_matches_javascript() {
        // flowsta-holochain-identity (web agent key — used by API)
        let web_seed = derive_seed(TEST_MNEMONIC, WEB_IDENTITY_CONSTANT).unwrap();
        let web_pub = derive_signing_key(TEST_MNEMONIC, WEB_IDENTITY_CONSTANT).unwrap().verifying_key();
        assert_eq!(
            hex::encode(web_seed),
            "bc9730785c42869e0cb178d7af6be8f47d3004a33ab1c7922097bac1b2999d23"
        );
        assert_eq!(
            hex::encode(web_pub.as_bytes()),
            "c5036f7e3ec0a16a06d89d1d2150e7b47db68fbb041c267893f18109e151c965"
        );

        // flowsta-device-1 (desktop agent key)
        let device_seed = derive_seed(TEST_MNEMONIC, DEVICE_1_CONSTANT).unwrap();
        let device_pub = derive_signing_key(TEST_MNEMONIC, DEVICE_1_CONSTANT).unwrap().verifying_key();
        assert_eq!(
            hex::encode(device_seed),
            "f1ba995113fa5d15e4967627e5c53ac3d459a68620064822a4431afc7dcc255a"
        );
        assert_eq!(
            hex::encode(device_pub.as_bytes()),
            "efc0b35169dd2750c4f83712e4655b822e40b141dc08bb9200c9b005268cc2e8"
        );

        // flowsta-recovery-lookup (agent key discovery hash)
        let lookup_hash = derive_recovery_lookup_hash(TEST_MNEMONIC).unwrap();
        assert_eq!(
            lookup_hash,
            "48cd5576e3f9693029baa0d6d4169638177cbfb9419ab4de98a8f1d5373cd519"
        );
    }

    /// Cross-language verification for the R2 (DNA v2) derivations.
    /// Hex values produced by `api/src/services/recoveryPhrase.js`
    /// deriveDataEncryptionKey / derivePrivateNetworkSeed on 2026-07-03.
    #[test]
    fn test_cross_language_r2_derivations_match_javascript() {
        // flowsta-data-encryption-v1 (Sealed-record symmetric key)
        let data_key = derive_data_encryption_key(TEST_MNEMONIC).unwrap();
        assert_eq!(
            hex::encode(data_key),
            "401c869a469f2ce675ec080f5bddd514233512816afa9c93b658260ca4f72ab4"
        );

        // flowsta-private-network-v2 (per-user network seed)
        let net_seed = derive_private_network_seed(TEST_MNEMONIC).unwrap();
        assert_eq!(
            net_seed,
            "968d4bb05b710dfcb30cf9c5fbafcacec67591305135cfd93ebaf4a11f110497"
        );

        // Domain separation: the new constants must not collide with each
        // other or any existing derivation.
        let device_seed = derive_seed(TEST_MNEMONIC, DEVICE_1_CONSTANT).unwrap();
        let web_seed = derive_seed(TEST_MNEMONIC, WEB_IDENTITY_CONSTANT).unwrap();
        let lookup_seed = derive_seed(TEST_MNEMONIC, RECOVERY_LOOKUP_CONSTANT).unwrap();
        let all = [data_key, device_seed, web_seed, lookup_seed];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "derivation constants must yield distinct keys");
            }
        }
        assert_ne!(hex::encode(data_key), net_seed);
    }

    #[test]
    fn test_msgpack_encode_bytes() {
        // Small payload: values 0-3 (all positive fixint, 1 byte each)
        let small = vec![0u8, 1, 2, 3];
        let encoded = msgpack_encode_bytes(&small);
        // fixarray(4) = 0x94, then each byte as positive fixint
        assert_eq!(encoded, vec![0x94, 0x00, 0x01, 0x02, 0x03]);

        // Byte value >= 128: uint8 format = 0xcc + value
        let high = vec![0xff_u8];
        let encoded = msgpack_encode_bytes(&high);
        // fixarray(1) = 0x91, then 0xcc 0xff
        assert_eq!(encoded, vec![0x91, 0xcc, 0xff]);

        // 78-byte payload: array 16 header (0xdc, 0x00, 0x4e)
        let payload = vec![0x42u8; 78];
        let encoded = msgpack_encode_bytes(&payload);
        assert_eq!(encoded[0], 0xdc); // array 16 marker
        assert_eq!(encoded[1], 0x00); // length high byte
        assert_eq!(encoded[2], 0x4e); // length low byte (78)
        // 0x42 < 128 so each element is 1 byte (positive fixint)
        assert_eq!(encoded.len(), 3 + 78); // header + elements
    }
}
