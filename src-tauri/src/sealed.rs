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


// ── Zome-call layer: store/list sealed records on the v2 device cell ───────
//
// Same conductor-access recipe as the Sign It commit path: admin WS →
// authorize credentials for the cell → app auth token → app WS → call_zome.
// The zome only ever sees ciphertext; seal/unseal happen here.

use crate::commands::AppState;
use std::sync::Arc;
use tauri::State;

/// A decrypted sealed record as returned to the frontend.
#[derive(Debug, Serialize)]
pub struct SealedListItem {
    /// Hex of the raw 39-byte ActionHash (same convention as Sign It).
    pub action_hash: String,
    pub entry_type: String,
    pub created_at: u64,
    /// The wrapped body decoded back to JSON for the frontend.
    pub body: serde_json::Value,
    pub refs: Vec<String>,
}

async fn connect_sealed_app_ws(
    admin_port: u16,
    app_port: u16,
) -> Result<(holochain_client::AppWebsocket, String), String> {
    use holochain_client::{
        AdminWebsocket, AppWebsocket, AuthorizeSigningCredentialsPayload, CellInfo,
        ClientAgentSigner, IssueAppAuthenticationTokenPayload,
    };

    let app_id = crate::dna::make_app_id("private", crate::dna::BUNDLED_PRIVATE_V2_VERSION);

    let admin_ws = AdminWebsocket::connect(
        format!("localhost:{}", admin_port),
        Some("flowsta-vault-sealed".to_string()),
    )
    .await
    .map_err(|e| format!("Admin WS connect failed: {}", e))?;

    let apps = admin_ws
        .list_apps(None)
        .await
        .map_err(|e| format!("list_apps failed: {}", e))?;
    let app = apps
        .iter()
        .find(|a| a.installed_app_id == app_id)
        .ok_or_else(|| format!("Encrypted private DNA not installed ({})", app_id))?;

    let role_name = app
        .cell_info
        .keys()
        .find(|k| k.starts_with("flowsta_private_v2"))
        .ok_or("No flowsta_private_v2 role found")?
        .clone();
    let cell_id = app.cell_info[&role_name]
        .iter()
        .find_map(|c| match c {
            CellInfo::Provisioned(p) => Some(p.cell_id.clone()),
            _ => None,
        })
        .ok_or("No provisioned sealed cell")?;

    let credentials = admin_ws
        .authorize_signing_credentials(AuthorizeSigningCredentialsPayload {
            cell_id: cell_id.clone(),
            functions: None,
        })
        .await
        .map_err(|e| format!("authorize_signing_credentials failed: {}", e))?;

    let issued = admin_ws
        .issue_app_auth_token(IssueAppAuthenticationTokenPayload::for_installed_app_id(
            app_id,
        ))
        .await
        .map_err(|e| format!("issue_app_auth_token failed: {}", e))?;

    let signer = ClientAgentSigner::default();
    signer.add_credentials(cell_id, credentials);
    let app_ws = AppWebsocket::connect_with_config(
        format!("localhost:{}", app_port),
        crate::commands::long_request_ws_config(),
        issued.token,
        signer.into(),
        Some("flowsta-vault-sealed".into()),
    )
    .await
    .map_err(|e| format!("App WS connect failed: {}", e))?;

    Ok((app_ws, role_name))
}

fn conductor_ports(state: &AppState) -> Result<(u16, u16), String> {
    let handle = state.conductor_handle.lock().unwrap();
    let h = handle.as_ref().ok_or("Conductor not running")?;
    Ok((h.admin_port, h.app_port))
}

fn vault_data_key(state: &AppState) -> Result<[u8; 32], String> {
    let config = state.vault_config.lock().unwrap();
    let cfg = config.as_ref().ok_or("vault_locked")?;
    let key_vec = cfg.data_key.clone().ok_or(
        "No data key in this vault — restore from your recovery phrase to enable encrypted records",
    )?;
    if key_vec.len() != 32 {
        return Err("Invalid data key length".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_vec);
    Ok(key)
}

/// Wire format for the zome's SealedInput (mirrors the v2 coordinator).
#[derive(Serialize)]
struct SealedInputWire {
    #[serde(with = "serde_bytes")]
    cipher: Vec<u8>,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
}

/// Seal and store a record on the encrypted private cell.
/// `body` is arbitrary JSON — wrapped, encrypted, and linked from the agent.
#[tauri::command]
pub async fn sealed_store(
    entry_type: String,
    body: serde_json::Value,
    refs: Option<Vec<String>>,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    use holochain_client::ZomeCallTarget;
    use holochain_types::prelude::{ExternIO, Record};

    let (admin_port, app_port) = conductor_ports(&state)?;
    let data_key = vault_data_key(&state)?;

    let payload = SealedPayload {
        v: SEALED_PAYLOAD_V1,
        entry_type,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis() as u64,
        body: rmp_serde::to_vec_named(&body).map_err(|e| e.to_string())?,
        refs: refs.unwrap_or_default(),
    };
    let (cipher, nonce) = seal(&payload, &data_key).map_err(|e| e.to_string())?;

    let input = rmp_serde::to_vec_named(&SealedInputWire {
        cipher,
        nonce: nonce.to_vec(),
    })
    .map_err(|e| e.to_string())?;

    let (app_ws, role_name) = connect_sealed_app_ws(admin_port, app_port).await?;
    let result = app_ws
        .call_zome(
            ZomeCallTarget::RoleName(role_name),
            "private_data".into(),
            "create_sealed".into(),
            ExternIO::from(input),
        )
        .await
        .map_err(|e| format!("create_sealed failed: {:?}", e))?;

    let record: Record = rmp_serde::from_slice(result.as_bytes())
        .map_err(|e| format!("Record decode failed: {}", e))?;
    Ok(hex::encode(record.action_address().get_raw_39()))
}

/// Fetch and decrypt every live sealed record. Records that fail to
/// decrypt (foreign/corrupt) are skipped with a warning, never fatal.
#[tauri::command]
pub async fn sealed_list(state: State<'_, Arc<AppState>>) -> Result<Vec<SealedListItem>, String> {
    use holochain_client::ZomeCallTarget;
    use holochain_types::prelude::{Entry, ExternIO, Record};

    let (admin_port, app_port) = conductor_ports(&state)?;
    let data_key = vault_data_key(&state)?;

    let (app_ws, role_name) = connect_sealed_app_ws(admin_port, app_port).await?;
    let result = app_ws
        .call_zome(
            ZomeCallTarget::RoleName(role_name),
            "private_data".into(),
            "get_all_sealed".into(),
            ExternIO::from(rmp_serde::to_vec_named(&()).map_err(|e| e.to_string())?),
        )
        .await
        .map_err(|e| format!("get_all_sealed failed: {:?}", e))?;

    let records: Vec<Record> = rmp_serde::from_slice(result.as_bytes())
        .map_err(|e| format!("Records decode failed: {}", e))?;

    let mut items = Vec::with_capacity(records.len());
    for record in &records {
        let Some(Entry::App(entry_bytes)) = record.entry().as_option() else {
            continue;
        };
        #[derive(Deserialize)]
        struct SealedEntryWire {
            #[serde(with = "serde_bytes")]
            cipher: Vec<u8>,
            #[serde(with = "serde_bytes")]
            nonce: Vec<u8>,
        }
        let sealed: SealedEntryWire = match rmp_serde::from_slice(entry_bytes.bytes()) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("Skipping undecodable sealed entry: {}", e);
                continue;
            }
        };
        if sealed.nonce.len() != NONCE_BYTES {
            log::warn!("Skipping sealed entry with bad nonce length");
            continue;
        }
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.copy_from_slice(&sealed.nonce);
        let payload = match unseal(&sealed.cipher, &nonce, &data_key) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Skipping undecryptable sealed record: {}", e);
                continue;
            }
        };
        let body: serde_json::Value =
            rmp_serde::from_slice(&payload.body).unwrap_or(serde_json::Value::Null);
        items.push(SealedListItem {
            action_hash: hex::encode(record.action_address().get_raw_39()),
            entry_type: payload.entry_type,
            created_at: payload.created_at,
            body,
            refs: payload.refs,
        });
    }
    // Newest first — the natural reading order for activity-style data.
    items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(items)
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
