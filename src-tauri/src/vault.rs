//! Master password vault encryption.
//!
//! Encrypts the vault config file (`vault.enc`) with the user's master password.
//! Uses Argon2id for key derivation and AES-256-GCM for encryption.
//!
//! The vault config stores:
//! - Agent pub key (derived from seed phrase)
//! - DID
//! - Installed hApp IDs
//! - Created timestamp
//!
//! The seed phrase itself is NEVER stored — only the lair-encrypted derived key persists.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Params};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Vault configuration stored encrypted on disk.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultConfig {
    /// Agent public key in Holochain format (uhCAk...)
    pub agent_pub_key: String,
    /// W3C DID (did:flowsta:uhCAk...)
    pub did: String,
    /// Installed hApp IDs on the local conductor
    pub installed_app_ids: Vec<String>,
    /// Unix timestamp of vault creation
    pub created_at: i64,

    /// 32-byte HMAC-derived device seed (encrypted at rest).
    /// Used for Ed25519 signing during agent linking.
    /// The mnemonic is never stored — only this derived seed persists.
    #[serde(default)]
    pub device_seed: Option<Vec<u8>>,

    /// Recovery lookup hash (hex string) for agent key discovery via API.
    /// Derived from HMAC-SHA256(mnemonic, "flowsta-recovery-lookup").
    #[serde(default)]
    pub recovery_lookup_hash: Option<String>,

    /// Full 39-byte Holochain AgentPubKey (base64, standard encoding).
    /// Includes prefix + ed25519 key + DHT location bytes.
    /// Used for zome call serialization during agent linking.
    #[serde(default)]
    pub agent_pub_key_raw_b64: Option<String>,

    /// Web account agent pub key (uhCAk... format).
    /// Stored to show linked web identity on dashboard.
    #[serde(default)]
    pub web_agent_pub_key: Option<String>,

    /// Web account email address.
    #[serde(default)]
    pub web_email: Option<String>,

    /// Web account username.
    #[serde(default)]
    pub web_username: Option<String>,

    /// User's display name from Flowsta profile.
    #[serde(default)]
    pub display_name: Option<String>,

    /// Profile picture URL or base64 data URI.
    #[serde(default)]
    pub profile_picture: Option<String>,

    /// Currently installed private DNA version (e.g. "1.10").
    /// Used by the DNA updater to detect when the server has a newer version.
    /// Defaults to None for vaults created before the update system existed —
    /// the updater treats None as the version bundled with this app build.
    #[serde(default)]
    pub private_dna_version: Option<String>,

    /// Currently installed identity DNA version (e.g. "1.3").
    #[serde(default)]
    pub identity_dna_version: Option<String>,

    /// Holochain conductor version this vault was last run with (e.g. "0.6.0").
    /// Stored for future conductor upgrade detection.
    #[serde(default)]
    pub conductor_version: Option<String>,

    /// Hosting model: `Some("device-hosted")` for identities created in Vault
    /// (R1 Track B — no web password, no API cells; auth via Vault-grant).
    /// `None` = legacy restore-from-web vault (custodial web account).
    #[serde(default)]
    pub hosting_model: Option<String>,
}

/// Encrypted vault on disk (serialized as JSON).
#[derive(Serialize, Deserialize)]
pub struct EncryptedVault {
    /// Argon2id salt (base64)
    pub salt: String,
    /// AES-256-GCM nonce (base64, 12 bytes)
    pub nonce: String,
    /// Encrypted VaultConfig (base64)
    pub ciphertext: String,
    /// Format version for future migration
    pub version: u32,
    /// Unencrypted display email (shown on unlock screen without decrypting).
    #[serde(default)]
    pub display_email: Option<String>,
}

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: wrong password or corrupted vault")]
    Decryption,

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Derive a 32-byte AES key from a master password using Argon2id.
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], VaultError> {
    let params = Params::new(
        65536,  // 64 MB memory
        3,      // 3 iterations
        1,      // 1 degree of parallelism
        Some(32),
    )
    .map_err(|e| VaultError::Encryption(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;

    Ok(key)
}

/// Encrypt a VaultConfig with the user's master password.
pub fn encrypt_vault(config: &VaultConfig, password: &str) -> Result<EncryptedVault, VaultError> {
    // Serialize config to JSON
    let plaintext = serde_json::to_vec(config)
        .map_err(|e| VaultError::Serialization(e.to_string()))?;

    // Generate random salt (16 bytes)
    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);

    // Derive AES key from password
    let key = derive_key(password, &salt_bytes)?;

    // Generate random nonce (12 bytes for AES-256-GCM)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| VaultError::Encryption("AES-GCM encryption failed".into()))?;

    Ok(EncryptedVault {
        salt: base64_encode(&salt_bytes),
        nonce: base64_encode(&nonce_bytes),
        ciphertext: base64_encode(&ciphertext),
        version: 1,
        display_email: None,
    })
}

/// Decrypt a VaultConfig with the user's master password.
pub fn decrypt_vault(encrypted: &EncryptedVault, password: &str) -> Result<VaultConfig, VaultError> {
    let salt_bytes = base64_decode(&encrypted.salt).map_err(|_| VaultError::Decryption)?;
    let nonce_bytes = base64_decode(&encrypted.nonce).map_err(|_| VaultError::Decryption)?;
    let ciphertext = base64_decode(&encrypted.ciphertext).map_err(|_| VaultError::Decryption)?;

    // Derive AES key from password
    let key = derive_key(password, &salt_bytes)?;

    // Decrypt
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| VaultError::Decryption)?;

    // Deserialize
    let config: VaultConfig = serde_json::from_slice(&plaintext)
        .map_err(|e| VaultError::Serialization(e.to_string()))?;

    Ok(config)
}

/// Save encrypted vault to disk.
pub fn save_vault(path: &std::path::Path, encrypted: &EncryptedVault) -> Result<(), VaultError> {
    let json = serde_json::to_string_pretty(encrypted)
        .map_err(|e| VaultError::Serialization(e.to_string()))?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Load encrypted vault from disk.
pub fn load_vault(path: &std::path::Path) -> Result<EncryptedVault, VaultError> {
    let json = std::fs::read_to_string(path)?;
    let encrypted: EncryptedVault = serde_json::from_str(&json)
        .map_err(|e| VaultError::Serialization(e.to_string()))?;
    Ok(encrypted)
}

/// Check if a vault file exists at the given path.
pub fn vault_exists(path: &std::path::Path) -> bool {
    path.exists()
}

fn base64_encode(data: &[u8]) -> String {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut encoder = base64_writer(&mut buf);
        encoder.write_all(data).unwrap();
    }
    String::from_utf8(buf).unwrap()
}

// Simple base64 encode/decode without pulling in another crate.
// We already have serde_json — using a manual implementation.
fn base64_writer(writer: &mut Vec<u8>) -> impl std::io::Write + '_ {
    struct B64Writer<'a>(&'a mut Vec<u8>);
    impl<'a> std::io::Write for B64Writer<'a> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            for chunk in buf.chunks(3) {
                let b0 = chunk[0] as u32;
                let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
                let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
                let n = (b0 << 16) | (b1 << 8) | b2;
                self.0.push(CHARS[((n >> 18) & 0x3F) as usize]);
                self.0.push(CHARS[((n >> 12) & 0x3F) as usize]);
                if chunk.len() > 1 {
                    self.0.push(CHARS[((n >> 6) & 0x3F) as usize]);
                } else {
                    self.0.push(b'=');
                }
                if chunk.len() > 2 {
                    self.0.push(CHARS[(n & 0x3F) as usize]);
                } else {
                    self.0.push(b'=');
                }
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    B64Writer(writer)
}

fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    fn val(c: u8) -> Result<u32, ()> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(()),
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 { break; }
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        out.push(((a << 2) | (b >> 4)) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' {
            let c = val(chunk[2])?;
            out.push((((b & 0xF) << 4) | (c >> 2)) as u8);
            if chunk.len() > 3 && chunk[3] != b'=' {
                let d = val(chunk[3])?;
                out.push((((c & 0x3) << 6) | d) as u8);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let config = VaultConfig {
            agent_pub_key: "uhCAkTestKey123".to_string(),
            did: "did:flowsta:uhCAkTestKey123".to_string(),
            installed_app_ids: vec!["flowsta_identity_v1_3".to_string()],
            created_at: 1708905600,
            device_seed: Some(vec![1u8; 32]),
            recovery_lookup_hash: Some("abcd1234".repeat(8)),
            agent_pub_key_raw_b64: Some("dGVzdA==".to_string()),
            web_agent_pub_key: Some("uhCAkWebKey456".to_string()),
            web_email: Some("test@example.com".to_string()),
            web_username: Some("testuser".to_string()),
            display_name: Some("Test User".to_string()),
            profile_picture: Some("https://example.com/pic.jpg".to_string()),
            private_dna_version: Some("1.10".to_string()),
            identity_dna_version: Some("1.3".to_string()),
            conductor_version: Some("0.6.0".to_string()),
            hosting_model: None,
        };

        let encrypted = encrypt_vault(&config, "test-password-123").unwrap();
        let decrypted = decrypt_vault(&encrypted, "test-password-123").unwrap();

        assert_eq!(config.agent_pub_key, decrypted.agent_pub_key);
        assert_eq!(config.did, decrypted.did);
        assert_eq!(config.installed_app_ids, decrypted.installed_app_ids);
        assert_eq!(config.created_at, decrypted.created_at);
        assert_eq!(config.device_seed, decrypted.device_seed);
        assert_eq!(config.recovery_lookup_hash, decrypted.recovery_lookup_hash);
        assert_eq!(config.agent_pub_key_raw_b64, decrypted.agent_pub_key_raw_b64);
        assert_eq!(config.web_agent_pub_key, decrypted.web_agent_pub_key);
        assert_eq!(config.web_email, decrypted.web_email);
        assert_eq!(config.web_username, decrypted.web_username);
        assert_eq!(config.display_name, decrypted.display_name);
        assert_eq!(config.profile_picture, decrypted.profile_picture);
        assert_eq!(config.private_dna_version, decrypted.private_dna_version);
        assert_eq!(config.identity_dna_version, decrypted.identity_dna_version);
        assert_eq!(config.conductor_version, decrypted.conductor_version);
    }

    #[test]
    fn test_wrong_password_fails() {
        let config = VaultConfig {
            agent_pub_key: "uhCAkTestKey123".to_string(),
            did: "did:flowsta:uhCAkTestKey123".to_string(),
            installed_app_ids: vec![],
            created_at: 1708905600,
            device_seed: None,
            recovery_lookup_hash: None,
            agent_pub_key_raw_b64: None,
            web_agent_pub_key: None,
            web_email: None,
            web_username: None,
            display_name: None,
            profile_picture: None,
            private_dna_version: None,
            identity_dna_version: None,
            conductor_version: None,
            hosting_model: None,
        };

        let encrypted = encrypt_vault(&config, "correct-password").unwrap();
        let result = decrypt_vault(&encrypted, "wrong-password");

        assert!(result.is_err());
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, Flowsta Vault!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }
}
