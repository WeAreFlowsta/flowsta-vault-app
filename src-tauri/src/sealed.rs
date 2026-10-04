//! Sealed-record crypto - encrypt-before-gossip for the
//! private DNA v2. Every gossiping record is an opaque `{cipher, nonce}`
//! blob; entry type, timestamps, app ids, relationships all live INSIDE the
//! ciphertext.
//!
//! Method (deliberately NOT crypto_box-by-agent-key - per-device agent
//! keys differ, which would make records unreadable across devices):
//! XSalsa20-Poly1305 secretbox with the per-user symmetric data key
//!   data_key = HMAC-SHA256("flowsta-data-encryption-v1", bip39_seed)
//! (see key_derivation::derive_data_encryption_key, golden-vector-verified).
//! Every device derives the same key from the phrase - multi-device gossip
//! decrypts with zero key exchange, and recovery needs only the phrase.
//!
//! The zome never sees plaintext: seal before create_sealed, unseal after
//! get_all_sealed.

use lair_keystore_api::dependencies::sodoken;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Version tag inside every sealed payload - bump on layout change so old
/// records stay decodable forever (records are immutable once gossiped).
pub const SEALED_PAYLOAD_V1: u16 = 1;
/// v2 adds the fields a person's several devices need to agree on one view:
/// a logical id, an update time, the writing device and a deletion flag.
/// A v1 reader ignores them and still decodes the record.
pub const SEALED_PAYLOAD_V2: u16 = 2;

/// Record types that exist once per identity: their logical id is the type.
const SINGLETON_TYPES: [&str; 3] = ["user_profile", "profile_picture", "privacy_settings"];

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
    /// (RecoveryPhrase + TotpConfig never become Sealed - root secrets are
    /// never gossiped.)
    pub entry_type: String,
    /// Creation time in ms - inside the cipher; the DHT action timestamp is
    /// the only timing a peer sees.
    pub created_at: u64,
    /// The original entry struct, MessagePack-encoded by the caller.
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    /// Related record references (action hashes, base64) - inside the
    /// cipher so relationships don't leak as link structure.
    pub refs: Vec<String>,
    /// Logical id: the same on every version of one record, on every
    /// device. Absent on v1 records (see `logical_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// When this version was written, in ms. The newest version of a
    /// logical id is the record. Absent on v1 records (`created_at` counts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
    /// The install that wrote this version (its install id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// This version says the record was deleted. A deletion is a record so
    /// that it survives an export, an import and a merge between devices.
    #[serde(default, skip_serializing_if = "is_false")]
    pub deleted: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// The logical id of a record that carries none: the type for a
/// once-per-identity type, else the type and its creation time (the pair
/// import has always deduplicated on).
pub fn derived_logical_id(entry_type: &str, created_at: u64) -> String {
    if SINGLETON_TYPES.contains(&entry_type) {
        entry_type.to_string()
    } else {
        format!("{}:{}", entry_type, created_at)
    }
}

impl SealedPayload {
    pub fn logical_id(&self) -> String {
        self.id
            .clone()
            .unwrap_or_else(|| derived_logical_id(&self.entry_type, self.created_at))
    }

    pub fn version_time(&self) -> u64 {
        self.updated_at.unwrap_or(self.created_at)
    }
}

/// One stored version of a record, as read from the cell.
#[derive(Debug, Clone)]
pub struct StoredVersion {
    /// Raw 39-byte action hash.
    pub action_hash: Vec<u8>,
    pub payload: SealedPayload,
}

/// Reduce every stored version to the newest per logical id. Returns the
/// winners (deletions included) and the versions they supersede. The order
/// between two versions is the same on every device: newer time first, then
/// a deletion over a live version, then the larger action hash.
pub fn latest_versions(versions: Vec<StoredVersion>) -> (Vec<StoredVersion>, Vec<StoredVersion>) {
    use std::collections::HashMap;
    let mut winners: HashMap<String, StoredVersion> = HashMap::new();
    let mut superseded = Vec::new();
    for version in versions {
        let id = version.payload.logical_id();
        match winners.get(&id) {
            None => {
                winners.insert(id, version);
            }
            Some(current) => {
                let rank = |v: &StoredVersion| (v.payload.version_time(), v.payload.deleted, v.action_hash.clone());
                if rank(&version) > rank(current) {
                    let old = winners.insert(id, version).expect("present");
                    superseded.push(old);
                } else if version.action_hash != current.action_hash {
                    superseded.push(version);
                }
            }
        }
    }
    (winners.into_values().collect(), superseded)
}

/// Encrypt a payload with the per-user data key. Returns (cipher, nonce);
/// the nonce is random per record (never reused - 24 random bytes).
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
    /// Logical id: the same for every version of this record on every device.
    pub id: String,
    /// When this version was written (ms).
    pub updated_at: u64,
    /// The install that wrote this version, when it recorded one.
    pub device: Option<String>,
}

async fn connect_sealed_app_ws(
    state: &Arc<AppState>,
    admin_port: u16,
    app_port: u16,
) -> Result<(holochain_client::AppWebsocket, String), String> {
    use holochain_client::{
        AdminWebsocket, AppWebsocket, CellInfo, ClientAgentSigner,
        IssueAppAuthenticationTokenPayload,
    };

    let app_id = crate::dna::private_v2_app_id();

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

    let credentials =
        crate::commands::cell_credentials_cached(state, &admin_ws, &cell_id).await?;

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

/// Connect and call a `private_data` zome function, retrying transient
/// failures: right after an unlock the enable/readiness race can fail the
/// credential authorize, and the FIRST call to a freshly-installed cell
/// compiles the WASM module, which can outrun a response timeout. A
/// ModuleBuild failure (bad wasm) is permanent - no retry.
async fn sealed_zome_call(
    state: &Arc<AppState>,
    admin_port: u16,
    app_port: u16,
    zome_fn: &str,
    input: Vec<u8>,
) -> Result<holochain_types::prelude::ExternIO, String> {
    use holochain_client::ZomeCallTarget;
    use holochain_types::prelude::ExternIO;

    let mut last_err = String::new();
    for attempt in 1..=3u32 {
        let result = async {
            let (app_ws, role_name) = connect_sealed_app_ws(state, admin_port, app_port).await?;
            app_ws
                .call_zome(
                    ZomeCallTarget::RoleName(role_name),
                    "private_data".into(),
                    zome_fn.into(),
                    ExternIO::from(input.clone()),
                )
                .await
                .map_err(|e| format!("{} failed: {:?}", zome_fn, e))
        }
        .await;
        match result {
            Ok(r) => return Ok(r),
            Err(e) => {
                last_err = e;
                // Cached credentials can go stale if the chain was reset -
                // drop them so the retry re-authorizes.
                if last_err.contains("nauthorized") {
                    crate::commands::invalidate_cell_credentials(state);
                }
                let permanent = last_err.contains("ModuleBuild");
                let transient = !permanent
                    && ["auth creds", "CellDisabled", "response timeout",
                        "channel dropped", "chain head has moved", "InternalError",
                        "nauthorized"]
                        .iter()
                        .any(|m| last_err.contains(m));
                log::warn!("{} attempt {}/3 failed: {}", zome_fn, attempt, last_err);
                if !transient || attempt == 3 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    }
    Err(last_err)
}

fn conductor_ports(state: &AppState) -> Result<(u16, u16), String> {
    #[cfg(test)]
    if let Some(ports) = *state.test_conductor_ports.lock().unwrap() {
        return Ok(ports);
    }
    let handle = state.conductor_handle.lock().unwrap();
    let h = handle.as_ref().ok_or("Conductor not running")?;
    Ok((h.admin_port, h.app_port))
}

fn vault_data_key(state: &AppState) -> Result<[u8; 32], String> {
    let config = state.vault_config.lock().unwrap();
    let cfg = config.as_ref().ok_or("vault_locked")?;
    let key_vec = cfg.data_key.clone().ok_or(
        "No data key in this vault - restore from your recovery phrase to enable encrypted records",
    )?;
    if key_vec.len() != 32 {
        return Err("Invalid data key length".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_vec);
    Ok(key)
}

/// Wire format for the zome's SealedInput (the original coordinator).
#[derive(Serialize)]
struct SealedInputWire {
    #[serde(with = "serde_bytes")]
    cipher: Vec<u8>,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
}

// Wire formats of the shared-base functions (coordinator rev 2).
#[derive(Serialize)]
struct SealedAtWire {
    base: holochain_types::prelude::AgentPubKey,
    #[serde(with = "serde_bytes")]
    cipher: Vec<u8>,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    tag: Vec<u8>,
}

#[derive(Serialize)]
struct ListAtWire {
    base: holochain_types::prelude::AgentPubKey,
    #[serde(with = "serde_bytes")]
    tag_prefix: Vec<u8>,
    network: bool,
}

#[derive(Deserialize)]
struct ListedWire {
    record: holochain_types::prelude::Record,
}

/// The cell still runs the original coordinator (the hot-swap at start did
/// not go through): the caller falls back to the functions it has.
fn is_missing_function(err: &str) -> bool {
    err.contains("zome function that doesn't exist")
}

/// The base every device of this identity links records from: the
/// identity's agent key in the form the network uses. On an install whose
/// conductor runs the identity seed this is its own agent key, where its
/// records have always hung.
fn sealed_base(state: &AppState) -> Result<holochain_types::prelude::AgentPubKey, String> {
    crate::commands::identity_agent_key(state).ok_or_else(|| "vault_locked".to_string())
}

fn now_ms() -> Result<u64, String> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as u64)
}

/// What to store. `id` / `updated_at` default to a fresh record's; an
/// import passes the values the record already had.
pub(crate) struct StoreSpec {
    pub entry_type: String,
    pub body: serde_json::Value,
    pub refs: Vec<String>,
    pub created_at: u64,
    pub id: Option<String>,
    pub updated_at: Option<u64>,
    pub deleted: bool,
}

/// Seal and store a record on the encrypted private cell.
/// `body` is arbitrary JSON - wrapped, encrypted, and linked from the agent.
#[tauri::command]
pub async fn sealed_store(
    entry_type: String,
    body: serde_json::Value,
    refs: Option<Vec<String>>,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    sealed_store_inner(&state, entry_type, body, refs.unwrap_or_default(), now_ms()?).await
}

/// Store with an explicit creation timestamp - account migration and import
/// preserve the original record times inside the cipher rather than
/// stamping "now". The logical id is derived from the type and that time,
/// so the same record imported on two devices is one record.
pub(crate) async fn sealed_store_inner(
    state: &Arc<AppState>,
    entry_type: String,
    body: serde_json::Value,
    refs: Vec<String>,
    created_at: u64,
) -> Result<String, String> {
    sealed_store_spec(
        state,
        StoreSpec { entry_type, body, refs, created_at, id: None, updated_at: None, deleted: false },
        None,
    )
    .await
}

/// Seal one version and write it at the shared base; `supersedes` retires
/// that earlier version in the same call.
pub(crate) async fn sealed_store_spec(
    state: &Arc<AppState>,
    spec: StoreSpec,
    supersedes: Option<holochain_types::prelude::ActionHash>,
) -> Result<String, String> {
    use holochain_types::prelude::{ActionHash, Record};

    let (admin_port, app_port) = conductor_ports(state)?;
    let data_key = vault_data_key(state)?;
    let base = sealed_base(state)?;

    let id = spec
        .id
        .unwrap_or_else(|| derived_logical_id(&spec.entry_type, spec.created_at));
    let payload = SealedPayload {
        v: SEALED_PAYLOAD_V2,
        entry_type: spec.entry_type,
        created_at: spec.created_at,
        body: rmp_serde::to_vec_named(&spec.body).map_err(|e| e.to_string())?,
        refs: spec.refs,
        id: Some(id),
        updated_at: Some(spec.updated_at.unwrap_or(spec.created_at)),
        device: crate::paths::install_id(&state.data_dir),
        deleted: spec.deleted,
    };
    let (cipher, nonce) = seal(&payload, &data_key).map_err(|e| e.to_string())?;

    #[derive(Serialize)]
    struct ReplaceAtWire {
        original: ActionHash,
        replacement: SealedAtWire,
    }
    let at = SealedAtWire { base, cipher: cipher.clone(), nonce: nonce.to_vec(), tag: Vec::new() };
    let (fn_name, input) = match &supersedes {
        Some(original) => (
            "replace_sealed_at",
            rmp_serde::to_vec_named(&ReplaceAtWire { original: original.clone(), replacement: at }),
        ),
        None => ("create_sealed_at", rmp_serde::to_vec_named(&at)),
    };
    let input = input.map_err(|e| e.to_string())?;

    let result = match sealed_zome_call(state, admin_port, app_port, fn_name, input).await {
        Ok(r) => r,
        Err(e) if is_missing_function(&e) => {
            // Original coordinator: its own-agent functions are equivalent
            // on the one device that can be in this state.
            #[derive(Serialize)]
            struct ReplaceSealedWire {
                original_hash: ActionHash,
                replacement: SealedInputWire,
            }
            let wire = SealedInputWire { cipher, nonce: nonce.to_vec() };
            let (fn_name, input) = match supersedes {
                Some(original_hash) => (
                    "replace_sealed",
                    rmp_serde::to_vec_named(&ReplaceSealedWire { original_hash, replacement: wire }),
                ),
                None => ("create_sealed", rmp_serde::to_vec_named(&wire)),
            };
            sealed_zome_call(state, admin_port, app_port, fn_name, input.map_err(|e| e.to_string())?).await?
        }
        Err(e) => return Err(e),
    };

    let record: Record = rmp_serde::from_slice(result.as_bytes())
        .map_err(|e| format!("Record decode failed: {}", e))?;
    Ok(hex::encode(record.action_address().get_raw_39()))
}

/// Fetch and decrypt every live sealed record. Records that fail to
/// decrypt (foreign/corrupt) are skipped with a warning, never fatal.
#[tauri::command]
pub async fn sealed_list(state: State<'_, Arc<AppState>>) -> Result<Vec<SealedListItem>, String> {
    sealed_list_inner(&state).await
}

/// Supersede an existing sealed record with new content. The new version
/// keeps the original's logical id and creation time and carries "now" as
/// its update time, so it wins on every device whichever device wrote the
/// original. `original_hash_hex` is the hex 39-byte action hash from
/// sealed_list.
pub(crate) async fn sealed_replace_inner(
    state: &Arc<AppState>,
    original_hash_hex: &str,
    entry_type: String,
    body: serde_json::Value,
    refs: Vec<String>,
    created_at: u64,
) -> Result<String, String> {
    use holochain_types::prelude::ActionHash;

    let original_bytes =
        hex::decode(original_hash_hex).map_err(|_| "Bad action hash encoding".to_string())?;
    if original_bytes.len() != 39 {
        return Err(format!(
            "Action hash is {} bytes, expected 39",
            original_bytes.len()
        ));
    }
    // The original's logical id, when it is still among the stored versions.
    let id = sealed_versions(state)
        .await?
        .into_iter()
        .find(|v| v.action_hash == original_bytes)
        .map(|v| v.payload.logical_id());

    sealed_store_spec(
        state,
        StoreSpec { entry_type, body, refs, created_at, id, updated_at: Some(now_ms()?), deleted: false },
        Some(ActionHash::from_raw_39(original_bytes)),
    )
    .await
}

/// Delete a record for every device: write a deletion version of its
/// logical id and retire the version it supersedes.
#[allow(dead_code)] // first caller arrives with connections as records
pub(crate) async fn sealed_delete_inner(state: &Arc<AppState>, action_hash_hex: &str) -> Result<(), String> {
    use holochain_types::prelude::ActionHash;

    let bytes = hex::decode(action_hash_hex).map_err(|_| "Bad action hash encoding".to_string())?;
    let Some(version) = sealed_versions(state).await?.into_iter().find(|v| v.action_hash == bytes) else {
        return Ok(());
    };
    sealed_store_spec(
        state,
        StoreSpec {
            entry_type: version.payload.entry_type.clone(),
            body: serde_json::Value::Null,
            refs: Vec::new(),
            created_at: version.payload.created_at,
            id: Some(version.payload.logical_id()),
            updated_at: Some(now_ms()?),
            deleted: true,
        },
        Some(ActionHash::from_raw_39(bytes)),
    )
    .await
    .map(|_| ())
}

/// Every stored version this device holds for the identity, decrypted.
/// Versions that fail to decrypt (foreign, corrupt, or a plaintext marker)
/// are skipped with a warning, never fatal.
pub(crate) async fn sealed_versions(state: &Arc<AppState>) -> Result<Vec<StoredVersion>, String> {
    use holochain_types::prelude::{Entry, Record};

    let (admin_port, app_port) = conductor_ports(state)?;
    let data_key = vault_data_key(state)?;
    let base = sealed_base(state)?;

    let input = rmp_serde::to_vec_named(&ListAtWire { base, tag_prefix: Vec::new(), network: false })
        .map_err(|e| e.to_string())?;
    let records: Vec<Record> = match sealed_zome_call(state, admin_port, app_port, "get_all_sealed_at", input).await {
        Ok(result) => rmp_serde::from_slice::<Vec<ListedWire>>(result.as_bytes())
            .map_err(|e| format!("Records decode failed: {}", e))?
            .into_iter()
            .map(|l| l.record)
            .collect(),
        Err(e) if is_missing_function(&e) => {
            let result = sealed_zome_call(
                state,
                admin_port,
                app_port,
                "get_all_sealed",
                rmp_serde::to_vec_named(&()).map_err(|e| e.to_string())?,
            )
            .await?;
            rmp_serde::from_slice(result.as_bytes()).map_err(|e| format!("Records decode failed: {}", e))?
        }
        Err(e) => return Err(e),
    };

    let mut versions = Vec::with_capacity(records.len());
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
        versions.push(StoredVersion {
            action_hash: record.action_address().get_raw_39().to_vec(),
            payload,
        });
    }
    Ok(versions)
}

/// The identity's records as every device sees them: the newest version of
/// each logical id, deletions left out. Newest first.
pub(crate) async fn sealed_list_inner(
    state: &Arc<AppState>,
) -> Result<Vec<SealedListItem>, String> {
    let (winners, _superseded) = latest_versions(sealed_versions(state).await?);
    let mut items: Vec<SealedListItem> = winners
        .into_iter()
        .filter(|v| !v.payload.deleted)
        .map(|v| {
            let body: serde_json::Value =
                rmp_serde::from_slice(&v.payload.body).unwrap_or(serde_json::Value::Null);
            SealedListItem {
                action_hash: hex::encode(&v.action_hash),
                id: v.payload.logical_id(),
                updated_at: v.payload.version_time(),
                device: v.payload.device.clone(),
                entry_type: v.payload.entry_type,
                created_at: v.payload.created_at,
                body,
                refs: v.payload.refs,
            }
        })
        .collect();
    // Newest first - the natural reading order for activity-style data.
    items.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| b.action_hash.cmp(&a.action_hash)));
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
            id: None,
            updated_at: None,
            device: None,
            deleted: false,
        }
    }

    fn version(hash: u8, entry_type: &str, created_at: u64, id: Option<&str>, updated_at: Option<u64>, deleted: bool) -> StoredVersion {
        StoredVersion {
            action_hash: vec![hash; 39],
            payload: SealedPayload {
                v: if id.is_some() { SEALED_PAYLOAD_V2 } else { SEALED_PAYLOAD_V1 },
                entry_type: entry_type.into(),
                created_at,
                body: rmp_serde::to_vec_named(&serde_json::json!({ "n": hash })).unwrap(),
                refs: vec![],
                id: id.map(String::from),
                updated_at,
                device: None,
                deleted,
            },
        }
    }

    fn live(versions: Vec<StoredVersion>) -> Vec<u8> {
        let (winners, _) = latest_versions(versions);
        let mut hashes: Vec<u8> = winners.into_iter().filter(|v| !v.payload.deleted).map(|v| v.action_hash[0]).collect();
        hashes.sort();
        hashes
    }

    #[test]
    fn a_record_written_before_ids_existed_still_decodes_and_has_a_stable_id() {
        // What a 1.5.0 Vault wrote: no id, no update time.
        #[derive(Serialize)]
        struct V1 { v: u16, entry_type: String, created_at: u64, #[serde(with = "serde_bytes")] body: Vec<u8>, refs: Vec<String> }
        let bytes = rmp_serde::to_vec_named(&V1 { v: 1, entry_type: "oauth_activity".into(), created_at: 42, body: vec![0xc0], refs: vec![] }).unwrap();
        let payload: SealedPayload = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(payload.logical_id(), "oauth_activity:42");
        assert_eq!(payload.version_time(), 42);
        assert!(!payload.deleted);
        // A once-per-identity type is one record whatever its creation time.
        assert_eq!(derived_logical_id("user_profile", 1), derived_logical_id("user_profile", 999));
    }

    #[test]
    fn a_reader_from_before_ids_existed_still_decodes_a_new_record() {
        #[derive(Deserialize)]
        struct V1 { entry_type: String, created_at: u64 }
        let mut payload = test_payload();
        payload.v = SEALED_PAYLOAD_V2;
        payload.id = Some("x".into());
        payload.updated_at = Some(7);
        payload.deleted = true;
        let old: V1 = rmp_serde::from_slice(&rmp_serde::to_vec_named(&payload).unwrap()).unwrap();
        assert_eq!(old.entry_type, "oauth_activity");
        assert_eq!(old.created_at, 1_751_500_000_000);
    }

    #[test]
    fn the_newest_version_of_a_record_wins_whichever_device_wrote_it() {
        // The profile written on one device, then edited on another.
        let first = version(1, "user_profile", 100, None, None, false);
        let edited = version(2, "user_profile", 100, Some("user_profile"), Some(500), false);
        assert_eq!(live(vec![first.clone(), edited.clone()]), vec![2]);
        assert_eq!(live(vec![edited, first]), vec![2], "the order they arrive in does not matter");
    }

    #[test]
    fn two_devices_that_each_made_a_profile_agree_on_one() {
        let a = version(1, "user_profile", 100, Some("user_profile"), Some(100), false);
        let b = version(2, "user_profile", 300, Some("user_profile"), Some(300), false);
        let (winners, superseded) = latest_versions(vec![a, b]);
        assert_eq!(winners.len(), 1);
        assert_eq!(winners[0].action_hash[0], 2);
        assert_eq!(superseded.len(), 1);
    }

    #[test]
    fn a_deleted_record_stays_deleted_when_an_older_copy_arrives_later() {
        let original = version(1, "email_permission", 100, None, None, false);
        let deletion = version(2, "email_permission", 100, Some("email_permission:100"), Some(900), true);
        // The device that deleted it, then a device that only had the original.
        assert_eq!(live(vec![deletion.clone(), original.clone()]), Vec::<u8>::new());
        assert_eq!(live(vec![original, deletion]), Vec::<u8>::new());
    }

    #[test]
    fn a_record_edited_after_it_was_deleted_elsewhere_is_live_again() {
        let deletion = version(2, "privacy_settings", 100, Some("privacy_settings"), Some(900), true);
        let later = version(3, "privacy_settings", 100, Some("privacy_settings"), Some(1200), false);
        assert_eq!(live(vec![deletion, later]), vec![3]);
    }

    #[test]
    fn the_same_record_imported_on_two_devices_is_one_record() {
        // Two imports of one export: different actions, the same type and time.
        let on_a = version(1, "login_activity", 5000, Some("login_activity:5000"), Some(5000), false);
        let on_b = version(2, "login_activity", 5000, Some("login_activity:5000"), Some(5000), false);
        let other = version(3, "login_activity", 6000, Some("login_activity:6000"), Some(6000), false);
        let result = live(vec![on_a.clone(), on_b.clone(), other.clone()]);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&3));
        // Every device picks the same one of the two.
        assert_eq!(live(vec![on_b, other, on_a]), result);
    }

    #[test]
    fn at_the_same_instant_a_deletion_wins() {
        let edit = version(9, "email_permission", 100, Some("e"), Some(700), false);
        let deletion = version(1, "email_permission", 100, Some("e"), Some(700), true);
        assert_eq!(live(vec![edit.clone(), deletion.clone()]), Vec::<u8>::new());
        assert_eq!(live(vec![deletion, edit]), Vec::<u8>::new());
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
        // phrase - B must decrypt what A sealed (the multi-device property).
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
        // version tag is data, not a gate) - callers branch on `v`.
        let key = derive_data_encryption_key(TEST_MNEMONIC).unwrap();
        let mut payload = test_payload();
        payload.v = 2;
        let (cipher, nonce) = seal(&payload, &key).unwrap();
        assert_eq!(unseal(&cipher, &nonce, &key).unwrap().v, 2);
    }

    // ── Live: real conductors, the bundled binary, the staging rendezvous ──
    //
    // cargo test --lib live_devices_share_one_set_of_records -- --ignored --nocapture

    struct LiveDevice {
        state: Arc<AppState>,
        child: std::process::Child,
        dir: std::path::PathBuf,
    }
    impl Drop for LiveDevice {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn manifest_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// Start a conductor the way the app does, install the private cell on
    /// `seed` under a fresh agent, and return a state the record layer can use.
    async fn live_device(name: &str, admin_port: u16, seed: &str, config: &crate::vault::VaultConfig, hot_swap: bool) -> LiveDevice {
        use holochain_client::{AdminWebsocket, InstallAppPayload};
        use std::io::Write;

        let binary = manifest_dir().join("binaries").join("vault-holochain-x86_64-unknown-linux-gnu");
        assert!(binary.exists(), "the bundled conductor binary is needed for this test");
        let auth = std::fs::read_to_string(manifest_dir().join("../scripts/run-test-instance.sh"))
            .ok()
            .and_then(|t| t.split("FLOWSTA_AUTH_MATERIAL=").nth(1).map(|r| r.split_whitespace().next().unwrap_or("").to_string()))
            .unwrap_or_default();
        // A short path: the key store's socket path has a length limit.
        let dir = std::path::PathBuf::from(format!("/tmp/fvlt-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("data")).unwrap();
        std::fs::create_dir_all(dir.join("ks")).unwrap();
        let config_path = dir.join("conductor-config.yaml");
        std::fs::write(
            &config_path,
            format!(
                "data_root_path: '{d}/data'\nkeystore:\n  type: lair_server_in_proc\n  lair_root: '{d}/ks'\nadmin_interfaces:\n- driver:\n    type: websocket\n    port: {p}\n    allowed_origins: '{o}'\nnetwork:\n  bootstrap_url: https://bootstrap-staging.flowsta.com\n  signal_url: wss://bootstrap-staging.flowsta.com\n  relay_url: https://bootstrap-staging.flowsta.com./\n  base64_auth_material_bootstrap: \"{a}\"\n  base64_auth_material_relay: \"{a}\"\n  request_timeout_s: 240\n",
                d = dir.display(),
                p = admin_port,
                o = crate::conductor::NODE_ORIGINS.join(","),
                a = auth,
            ),
        )
        .unwrap();
        let mut child = std::process::Command::new(&binary)
            .arg("--piped")
            .arg("-c")
            .arg(&config_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::fs::File::create(dir.join("holochain.log")).unwrap())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("start the conductor");
        child.stdin.take().unwrap().write_all(b"live-test\n").unwrap();

        let mut admin = None;
        for _ in 0..60 {
            if let Ok(ws) = AdminWebsocket::connect(format!("localhost:{}", admin_port), Some("flowsta-vault".to_string())).await {
                admin = Some(ws);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        let admin = admin.expect("admin interface");
        let agent_key = admin.generate_agent_pub_key().await.unwrap();
        admin
            .install_app(InstallAppPayload {
                source: holochain_types::prelude::AppBundleSource::Path(manifest_dir().join("resources").join("flowsta_private_v2_0_happ.happ")),
                agent_key: Some(agent_key),
                installed_app_id: Some(crate::dna::private_v2_app_id()),
                network_seed: Some(seed.to_string()),
                roles_settings: None,
                ignore_genesis_failure: false,
            })
            .await
            .expect("install the private cell");
        admin.enable_app(crate::dna::private_v2_app_id()).await.expect("enable");
        if hot_swap {
            crate::dna::ensure_private_v2_coordinators(admin_port, &manifest_dir().join("resources"))
                .await
                .expect("hot-swap the coordinator");
        }
        let app_port = crate::dna::setup_app_interface(admin_port).await.expect("app interface");

        let state = Arc::new(AppState::new(dir.join("vault")));
        *state.vault_config.lock().unwrap() = Some(config.clone());
        *state.test_conductor_ports.lock().unwrap() = Some((admin_port, app_port));
        LiveDevice { state, child, dir }
    }

    async fn eventually<F, Fut>(what: &str, seconds: u64, mut check: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let started = std::time::Instant::now();
        loop {
            if check().await {
                println!("  {} after {}s", what, started.elapsed().as_secs());
                return;
            }
            assert!(started.elapsed().as_secs() < seconds, "not within {}s: {}", seconds, what);
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "starts real conductors and uses the staging rendezvous"]
    async fn live_devices_share_one_set_of_records() {
        let seed = format!("live-{}", hex::encode(crate::key_derivation::new_conductor_seed())[..16].to_string());
        // One identity on both devices: the same identity key and data key.
        let identity_public = crate::key_derivation::public_key_of_seed(&[21u8; 32]);
        let mut config: crate::vault::VaultConfig = serde_json::from_str(
            r#"{"agent_pub_key":"uhCAkTest","did":"did:flowsta:uhCAkTest","installed_app_ids":[],"created_at":1}"#,
        )
        .unwrap();
        config.data_key = Some(vec![33u8; 32]);
        config.agent_pub_key_raw_b64 = Some(crate::key_derivation::base64_standard_encode(
            &crate::key_derivation::construct_agent_pub_key_bytes(&identity_public),
        ));

        let a = live_device("a", 46051, &seed, &config, true).await;
        let b = live_device("b", 46052, &seed, &config, true).await;

        // A writes the profile and a log entry.
        let profile = sealed_store_inner(&a.state, "user_profile".into(), serde_json::json!({ "name": "first" }), vec![], 1000).await.unwrap();
        sealed_store_inner(&a.state, "login_activity".into(), serde_json::json!({ "n": 1 }), vec![], 2000).await.unwrap();
        assert_eq!(sealed_list_inner(&a.state).await.unwrap().len(), 2);

        // B, a different agent, holds and lists them.
        eventually("the second device lists both records", 300, || async { sealed_list_inner(&b.state).await.map(|l| l.len() == 2).unwrap_or(false) }).await;

        // B edits the profile A wrote.
        let on_b = sealed_list_inner(&b.state).await.unwrap();
        let seen = on_b.iter().find(|r| r.entry_type == "user_profile").unwrap();
        assert_eq!(seen.action_hash, profile);
        sealed_replace_inner(&b.state, &seen.action_hash, "user_profile".into(), serde_json::json!({ "name": "edited on the second device" }), vec![], seen.created_at)
            .await
            .expect("a device supersedes a record another device wrote");
        eventually("the first device sees the edit, as one profile", 300, || async {
            sealed_list_inner(&a.state).await.map(|l| {
                let profiles: Vec<_> = l.iter().filter(|r| r.entry_type == "user_profile").collect();
                profiles.len() == 1 && profiles[0].body["name"] == "edited on the second device"
            }).unwrap_or(false)
        })
        .await;

        // A deletes the log entry; it goes on B too and stays gone.
        let log = sealed_list_inner(&a.state).await.unwrap().into_iter().find(|r| r.entry_type == "login_activity").unwrap();
        sealed_delete_inner(&a.state, &log.action_hash).await.unwrap();
        eventually("the deletion reaches the second device", 300, || async { sealed_list_inner(&b.state).await.map(|l| l.iter().all(|r| r.entry_type != "login_activity")).unwrap_or(false) }).await;
        // The same record brought back by an import of an older copy loses to the deletion.
        sealed_store_inner(&b.state, "login_activity".into(), serde_json::json!({ "n": 1 }), vec![], 2000).await.unwrap();
        assert!(sealed_list_inner(&b.state).await.unwrap().iter().all(|r| r.entry_type != "login_activity"), "a deleted record stays deleted");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "starts a real conductor and uses the staging rendezvous"]
    async fn live_the_original_coordinator_still_serves_one_device() {
        let seed = format!("live-{}", hex::encode(crate::key_derivation::new_conductor_seed())[..16].to_string());
        let mut config: crate::vault::VaultConfig = serde_json::from_str(
            r#"{"agent_pub_key":"uhCAkTest","did":"did:flowsta:uhCAkTest","installed_app_ids":[],"created_at":1}"#,
        )
        .unwrap();
        config.data_key = Some(vec![33u8; 32]);
        config.agent_pub_key_raw_b64 = Some(crate::key_derivation::base64_standard_encode(
            &crate::key_derivation::construct_agent_pub_key_bytes(&crate::key_derivation::public_key_of_seed(&[22u8; 32])),
        ));
        // No hot-swap: the cell runs the coordinator the bundle carries.
        let c = live_device("c", 46053, &seed, &config, false).await;
        let first = sealed_store_inner(&c.state, "user_profile".into(), serde_json::json!({ "name": "one" }), vec![], 1000).await.unwrap();
        sealed_replace_inner(&c.state, &first, "user_profile".into(), serde_json::json!({ "name": "two" }), vec![], 1000).await.unwrap();
        let list = sealed_list_inner(&c.state).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].body["name"], "two");
    }
}
