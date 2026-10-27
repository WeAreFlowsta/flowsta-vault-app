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

use crate::hc::{AppClient, Line, RecordView};
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
#[derive(Debug, Clone, Serialize)]
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

pub(crate) async fn connect_sealed_app_ws(
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
        Some(crate::conductor::node_origin()),
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
        Some(crate::conductor::node_origin()),
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
    line: Line,
    zome_fn: &str,
    input: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let mut last_err = String::new();
    for attempt in 1..=3u32 {
        let result = async {
            let (client, role_name) = connect_sealed_client(state, line).await?;
            client.call_zome(&role_name, "private_data", zome_fn, input.clone()).await
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

/// The private cell's app client on one line: the 0.6 one through
/// `connect_sealed_app_ws`, the 0.7 one (private v2.1) through `hc`.
pub(crate) async fn connect_sealed_client(state: &Arc<AppState>, line: Line) -> Result<(AppClient, String), String> {
    let (admin_port, app_port) = crate::hc::line_ports(state, line)?;
    match line {
        Line::V06 => {
            let (ws, role) = connect_sealed_app_ws(state, admin_port, app_port).await?;
            Ok((AppClient::V06(ws), role))
        }
        Line::V07 => {
            let (ws, role) =
                crate::hc::connect_app_07(state, admin_port, app_port, &crate::dna::private_v2_app_id_07(), "flowsta_private_v2").await?;
            Ok((AppClient::V07(ws), role))
        }
    }
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
    /// Coordinator rev 3: more links to the same record, one per tag. An
    /// older coordinator ignores the field and writes the main link only.
    extra_tags: Vec<serde_bytes::ByteBuf>,
}

/// The tag on the second link of every device and removal record, so a
/// device that just joined can ask the other devices for those records
/// alone instead of waiting for everything to arrive. Keyed with the data
/// key: to anyone else it is 16 random-looking bytes, and it says nothing
/// about what the record is.
pub(crate) fn device_records_tag(data_key: &[u8; 32]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(data_key).expect("HMAC accepts any key length");
    mac.update(b"flowsta-device-records-v1");
    mac.finalize().into_bytes()[..16].to_vec()
}

fn tags_for(entry_type: &str, data_key: &[u8; 32]) -> Vec<serde_bytes::ByteBuf> {
    if entry_type == crate::devices::DEVICE_ENTRY_TYPE || entry_type == crate::devices::REMOVAL_ENTRY_TYPE {
        vec![serde_bytes::ByteBuf::from(device_records_tag(data_key))]
    } else {
        Vec::new()
    }
}

#[derive(Serialize)]
struct ListAtWire {
    base: holochain_types::prelude::AgentPubKey,
    #[serde(with = "serde_bytes")]
    tag_prefix: Vec<u8>,
    network: bool,
}

/// `get_all_sealed_at` output, decoded with the line's record type.
fn decode_listed(line: Line, bytes: &[u8]) -> Result<Vec<RecordView>, String> {
    #[derive(Deserialize)]
    struct Listed06 {
        record: holochain_types::prelude::Record,
    }
    #[derive(Deserialize)]
    struct Listed07 {
        record: holochain_types_07::prelude::Record,
    }
    match line {
        Line::V06 => rmp_serde::from_slice::<Vec<Listed06>>(bytes)
            .map(|l| l.iter().map(|x| crate::hc::view_06(&x.record)).collect())
            .map_err(|e| format!("Records decode failed: {}", e)),
        Line::V07 => rmp_serde::from_slice::<Vec<Listed07>>(bytes)
            .map(|l| l.iter().map(|x| crate::hc::view_07(&x.record)).collect())
            .map_err(|e| format!("Records decode failed: {}", e)),
    }
}

/// `list_sealed_at` output, decoded with the line's record type: the
/// targets, each with its record when the cell sent one and whether the
/// link was retired (`left`), and whether more follow.
#[allow(clippy::type_complexity)]
fn decode_listed_refs(
    line: Line,
    bytes: &[u8],
) -> Result<(Vec<(holochain_types::prelude::ActionHash, Option<RecordView>, bool)>, bool), String> {
    #[derive(Deserialize)]
    struct Ref06 {
        target: holochain_types::prelude::ActionHash,
        record: Option<holochain_types::prelude::Record>,
        #[serde(default)]
        left: bool,
    }
    #[derive(Deserialize)]
    struct Refs06 {
        refs: Vec<Ref06>,
        more: bool,
    }
    #[derive(Deserialize)]
    struct Ref07 {
        target: holochain_types::prelude::ActionHash,
        record: Option<holochain_types_07::prelude::Record>,
        #[serde(default)]
        left: bool,
    }
    #[derive(Deserialize)]
    struct Refs07 {
        refs: Vec<Ref07>,
        more: bool,
    }
    match line {
        Line::V06 => {
            let l: Refs06 = rmp_serde::from_slice(bytes).map_err(|e| format!("Records decode failed: {}", e))?;
            Ok((l.refs.into_iter().map(|r| (r.target, r.record.as_ref().map(crate::hc::view_06), r.left)).collect(), l.more))
        }
        Line::V07 => {
            let l: Refs07 = rmp_serde::from_slice(bytes).map_err(|e| format!("Records decode failed: {}", e))?;
            Ok((l.refs.into_iter().map(|r| (r.target, r.record.as_ref().map(crate::hc::view_07), r.left)).collect(), l.more))
        }
    }
}

/// `list_sealed_at` (coordinator revision 4): the links, with records only
/// for targets not in `known`.
#[derive(Serialize)]
struct ListRefsWire<'a> {
    base: holochain_types::prelude::AgentPubKey,
    #[serde(with = "serde_bytes")]
    tag_prefix: Vec<u8>,
    known: &'a [holochain_types::prelude::ActionHash],
    limit: u32,
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
#[derive(Debug, Clone)]
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

/// Write a once-per-identity record AUTOMATICALLY, when a device is added to
/// an existing identity and holds none yet (never for an edit the person
/// makes - that is written with its real time). The real record may simply
/// not have arrived, so this version carries the lowest update time: it
/// stands in until then, and any version another device wrote wins.
#[allow(dead_code)] // used by the add-a-device flows
pub(crate) async fn sealed_store_first(
    state: &Arc<AppState>,
    entry_type: String,
    body: serde_json::Value,
    refs: Vec<String>,
    created_at: u64,
) -> Result<String, String> {
    let joined = state
        .vault_config
        .lock()
        .unwrap()
        .as_ref()
        .map(|c| c.joined_existing)
        .unwrap_or(false);
    sealed_store_spec(
        state,
        StoreSpec { entry_type, body, refs, created_at, id: None, updated_at: if joined { Some(0) } else { None }, deleted: false },
        None,
    )
    .await
}

/// Dev harness only: write the next record with no device, as versions
/// before devices were named did.
pub(crate) static WRITE_WITHOUT_DEVICE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Seal one version and write it at the shared base of the identity's
/// active line; `supersedes` retires that earlier version in the same call.
///
/// While a moved identity's 0.6 line runs beside its 0.7 primary (a sibling
/// still on 1.6.1), the same version is written to the 0.6 cell too, so
/// that sibling holds it: a record written only on 0.7 had no second holder
/// until the household updated, and a reset of this device lost it (the
/// beta9 mixed leg). The mirror is best effort and idempotent - the carry
/// (0.6 → 0.7, by logical id and version time) sees it as present.
pub(crate) async fn sealed_store_spec(
    state: &Arc<AppState>,
    spec: StoreSpec,
    supersedes: Option<holochain_types::prelude::ActionHash>,
) -> Result<String, String> {
    let active = crate::hc::active_line(state);
    let mirror = (active == Line::V07 && crate::hc::line_ports(state, Line::V06).is_ok()).then(|| spec.clone());
    let stored = sealed_store_spec_on(state, active, spec, supersedes).await?;
    if let Some(spec) = mirror {
        if let Err(e) = mirror_to_06(state, spec).await {
            log::info!("[records] a version was not mirrored to the 0.6 line (carried later or by the other device's update): {}", e.chars().take(140).collect::<String>());
        }
    }
    Ok(stored)
}

/// Write one version to the 0.6 cell as the device that wrote it on 0.7,
/// superseding the version of that logical id the 0.6 cell holds when that
/// one is older; nothing when the 0.6 cell already holds this version or a
/// newer one (a sibling on 1.6.1 edited it since).
async fn mirror_to_06(state: &Arc<AppState>, spec: StoreSpec) -> Result<(), String> {
    use holochain_types::prelude::ActionHash;
    let id = spec.id.clone().unwrap_or_else(|| derived_logical_id(&spec.entry_type, spec.created_at));
    let version_time = spec.updated_at.unwrap_or(spec.created_at);
    let held_06 = sealed_held_on(state, Line::V06).await?;
    let supersedes = match held_06.get(&id) {
        Some(held) if held.payload.version_time() >= version_time => return Ok(()),
        Some(held) if held.action_hash.len() == 39 => Some(ActionHash::from_raw_39(held.action_hash.clone())),
        _ => None,
    };
    let entry_type = spec.entry_type.clone();
    let device = if WRITE_WITHOUT_DEVICE.load(std::sync::atomic::Ordering::SeqCst) { None } else { crate::paths::install_id(&state.data_dir) };
    sealed_store_spec_as(state, Line::V06, spec, supersedes, device).await?;
    log::info!("[records] {} mirrored to the 0.6 line for a device still on it", entry_type);
    Ok(())
}

/// `sealed_store_spec` on a named line (the move writes to 0.7 while the
/// identity's writes still go to 0.6).
pub(crate) async fn sealed_store_spec_on(
    state: &Arc<AppState>,
    line: Line,
    spec: StoreSpec,
    supersedes: Option<holochain_types::prelude::ActionHash>,
) -> Result<String, String> {
    let device = if WRITE_WITHOUT_DEVICE.load(std::sync::atomic::Ordering::SeqCst) { None } else { crate::paths::install_id(&state.data_dir) };
    sealed_store_spec_as(state, line, spec, supersedes, device).await
}

/// `sealed_store_spec_on` with the writing device named by the caller: the
/// move copies a record to the other line as the device that wrote it.
pub(crate) async fn sealed_store_spec_as(
    state: &Arc<AppState>,
    line: Line,
    spec: StoreSpec,
    supersedes: Option<holochain_types::prelude::ActionHash>,
    device: Option<String>,
) -> Result<String, String> {
    use holochain_types::prelude::ActionHash;

    let data_key = vault_data_key(state)?;
    let base = sealed_base(state)?;

    let id = spec
        .id
        .unwrap_or_else(|| derived_logical_id(&spec.entry_type, spec.created_at));
    let extra_tags = tags_for(&spec.entry_type, &data_key);
    let payload = SealedPayload {
        v: SEALED_PAYLOAD_V2,
        entry_type: spec.entry_type,
        created_at: spec.created_at,
        body: rmp_serde::to_vec_named(&spec.body).map_err(|e| e.to_string())?,
        refs: spec.refs,
        id: Some(id),
        updated_at: Some(spec.updated_at.unwrap_or(spec.created_at)),
        device,
        deleted: spec.deleted,
    };
    let (cipher, nonce) = seal(&payload, &data_key).map_err(|e| e.to_string())?;

    #[derive(Serialize)]
    struct ReplaceAtWire {
        original: ActionHash,
        replacement: SealedAtWire,
    }
    let at = SealedAtWire { base, cipher: cipher.clone(), nonce: nonce.to_vec(), tag: Vec::new(), extra_tags };
    let (fn_name, input) = match &supersedes {
        Some(original) => (
            "replace_sealed_at",
            rmp_serde::to_vec_named(&ReplaceAtWire { original: original.clone(), replacement: at }),
        ),
        None => ("create_sealed_at", rmp_serde::to_vec_named(&at)),
    };
    let input = input.map_err(|e| e.to_string())?;

    let result = match sealed_zome_call(state, line, fn_name, input).await {
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
            sealed_zome_call(state, line, fn_name, input.map_err(|e| e.to_string())?).await?
        }
        Err(e) => return Err(e),
    };

    forget_recent_versions();
    let record = crate::hc::record(line, &result).map_err(|e| format!("Record decode failed: {}", e))?;
    Ok(hex::encode(record.action_hash))
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

/// The versions read a moment ago, kept so that one operation which lists
/// and then writes does not read the whole cell twice. Dropped after any
/// write here, after a few seconds (another device may have written), and
/// on lock: it holds decrypted records.
struct RecentVersions {
    root: std::path::PathBuf,
    line: Line,
    read_at: std::time::Instant,
    versions: Vec<StoredVersion>,
}
static RECENT_VERSIONS: std::sync::Mutex<Option<RecentVersions>> = std::sync::Mutex::new(None);
const RECENT_FOR: std::time::Duration = std::time::Duration::from_secs(3);

/// Forget the versions kept in memory (lock, identity change, any write).
pub(crate) fn forget_recent_versions() {
    *RECENT_VERSIONS.lock().unwrap() = None;
}

/// Every stored version this device holds for the identity, decrypted.
/// Versions that fail to decrypt (foreign, corrupt, or a plaintext marker)
/// are skipped with a warning, never fatal.
pub(crate) async fn sealed_versions(state: &Arc<AppState>) -> Result<Vec<StoredVersion>, String> {
    sealed_versions_on(state, crate::hc::active_line(state)).await
}

/// `sealed_versions` from a named line's cell (the move reads 0.6 and 0.7
/// side by side).
pub(crate) async fn sealed_versions_on(state: &Arc<AppState>, line: Line) -> Result<Vec<StoredVersion>, String> {
    crate::hc::line_ports(state, line)?;
    let data_key = vault_data_key(state)?;
    let base = sealed_base(state)?;
    let root = state.identity_root();
    if let Some(versions) = recent_versions(&root, line) {
        return Ok(versions);
    }
    // One read at a time; a caller that waited takes the answer of the read
    // it waited for.
    let _one = FULL_READ.lock().await;
    if let Some(versions) = recent_versions(&root, line) {
        return Ok(versions);
    }

    let records: Vec<RecordView> = read_records(state, line, base, &data_key, &root).await?;

    let mut versions = decode_versions(&records, &data_key);
    // Device and removal records the other devices answered with that have
    // not arrived here yet (fetch_device_records).
    if let Some(net) = NETWORK_DEVICE_VERSIONS.lock().unwrap().as_ref() {
        if net.0 == root {
            for v in &net.1 {
                if !versions.iter().any(|h| h.action_hash == v.action_hash) {
                    versions.push(v.clone());
                }
            }
        }
    }
    // A lock while the read ran: decrypted versions do not stay behind it.
    if vault_data_key(state).is_ok() && state.identity_root() == root {
        *RECENT_VERSIONS.lock().unwrap() = Some(RecentVersions {
            root,
            line,
            read_at: std::time::Instant::now(),
            versions: versions.clone(),
        });
    }
    Ok(versions)
}

fn recent_versions(root: &std::path::Path, line: Line) -> Option<Vec<StoredVersion>> {
    RECENT_VERSIONS
        .lock()
        .unwrap()
        .as_ref()
        .filter(|recent| recent.root == root && recent.line == line && recent.read_at.elapsed() < RECENT_FOR)
        .map(|recent| recent.versions.clone())
}

/// One read of every record at a time. 2026-10-17: the Vault asked for
/// them every 30 s and on every Devices page refresh, each read took
/// minutes on a cell of thousands, and ten ran inside the conductor at once
/// (it does not stop a call the Vault stopped waiting for) until gossip
/// with a new device starved.
static FULL_READ: std::sync::LazyLock<tokio::sync::Mutex<()>> = std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Records this device has read, as stored (ciphertext), by action hash.
/// A record never changes (an edit is a new record), so a list asks the
/// cell for its links and only for records not held yet. Per identity;
/// kept across a lock (nothing in it opens without the data key) and in a
/// file sealed with the data key, so a restart does not read every record
/// again.
struct HeldRecords {
    root: std::path::PathBuf,
    records: std::collections::HashMap<holochain_types::prelude::ActionHash, RecordView>,
}
/// One slot per line: the 0.6 cell's records and the 0.7 cell's are
/// different records (different action hashes) of the same identity.
static HELD_RECORDS_06: std::sync::Mutex<Option<HeldRecords>> = std::sync::Mutex::new(None);
static HELD_RECORDS_07: std::sync::Mutex<Option<HeldRecords>> = std::sync::Mutex::new(None);
fn held_slot(line: Line) -> &'static std::sync::Mutex<Option<HeldRecords>> {
    match line {
        Line::V06 => &HELD_RECORDS_06,
        Line::V07 => &HELD_RECORDS_07,
    }
}
/// Forget the held records of both lines (tests; an identity change reads
/// the right file again by itself).
#[cfg(test)]
fn forget_held_records() {
    *HELD_RECORDS_06.lock().unwrap() = None;
    *HELD_RECORDS_07.lock().unwrap() = None;
}

#[cfg(test)]
static LIST_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static RECORDS_FROM_CELL: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// At most this many records read one by one per call: about 0.3 s each on
/// a large cell, so a call stays well inside the 5-minute wait and a long
/// first read keeps what each call brought.
const GETS_PER_CALL: u32 = 100;

pub(crate) fn held_records_path(root: &std::path::Path, line: Line) -> std::path::PathBuf {
    root.join(format!("sealed-records{}.bin", line.file_suffix()))
}

/// The held records for this identity on this line, from its file the
/// first time.
fn ensure_held(root: &std::path::Path, line: Line, data_key: &[u8; 32]) {
    let mut held = held_slot(line).lock().unwrap();
    if held.as_ref().map(|h| h.root == root).unwrap_or(false) {
        return;
    }
    let records = load_held_file(&held_records_path(root, line), data_key)
        .into_iter()
        .map(|r| (holochain_types::prelude::ActionHash::from_raw_39(r.action_hash.clone()), r))
        .collect();
    *held = Some(HeldRecords { root: root.to_path_buf(), records });
}

/// The kept records: the line-free view (1.7.0 on), or the 0.6 `Record`
/// list a Vault before 1.7.0 wrote (read once more and kept in the new
/// shape by the next save, so an update never re-reads a whole cell).
fn load_held_file(path: &std::path::Path, data_key: &[u8; 32]) -> Vec<RecordView> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    if bytes.len() < NONCE_BYTES + MAC_BYTES {
        return Vec::new();
    }
    let (nonce, cipher) = bytes.split_at(NONCE_BYTES);
    let mut nonce_arr = [0u8; NONCE_BYTES];
    nonce_arr.copy_from_slice(nonce);
    let mut plain = vec![0u8; cipher.len() - MAC_BYTES];
    if sodoken::secretbox::xsalsa_open_easy(&mut plain, cipher, &nonce_arr, data_key).is_err() {
        log::info!("[records] the kept records did not open; reading them again");
        return Vec::new();
    }
    if let Ok(views) = rmp_serde::from_slice::<Vec<RecordView>>(&plain) {
        return views;
    }
    match rmp_serde::from_slice::<Vec<holochain_types::prelude::Record>>(&plain) {
        Ok(records) => {
            log::info!("[records] kept records in the pre-1.7.0 shape: {} read", records.len());
            records.iter().map(crate::hc::view_06).collect()
        }
        Err(_) => Vec::new(),
    }
}

fn save_held_file(path: &std::path::Path, records: &[RecordView], data_key: &[u8; 32]) -> Result<(), String> {
    let plain = rmp_serde::to_vec_named(records).map_err(|e| e.to_string())?;
    let mut nonce = [0u8; NONCE_BYTES];
    sodoken::random::randombytes_buf(&mut nonce).map_err(|e| e.to_string())?;
    let mut cipher = vec![0u8; plain.len() + MAC_BYTES];
    sodoken::secretbox::xsalsa_easy(&mut cipher, &nonce, &plain, data_key).map_err(|e| e.to_string())?;
    let mut bytes = nonce.to_vec();
    bytes.extend_from_slice(&cipher);
    crate::vault::write_atomic(path, &bytes).map_err(|e| e.to_string())
}

/// Every record linked from the base with an empty tag that this device
/// holds: the links each time, a record only the first time.
async fn read_records(
    state: &Arc<AppState>,
    line: Line,
    base: holochain_types::prelude::AgentPubKey,
    data_key: &[u8; 32],
    root: &std::path::Path,
) -> Result<Vec<RecordView>, String> {
    use holochain_types::prelude::ActionHash;

    ensure_held(root, line, data_key);
    // Targets this device does not hold yet: not asked for again in this read.
    let mut absent: std::collections::HashSet<ActionHash> = std::collections::HashSet::new();
    let mut added = 0usize;
    let targets: Vec<ActionHash> = loop {
        let known: Vec<ActionHash> = {
            let held = held_slot(line).lock().unwrap();
            let held = held.as_ref().filter(|h| h.root == root).ok_or("identity changed during the read")?;
            held.records.keys().chain(absent.iter()).cloned().collect()
        };
        let input = rmp_serde::to_vec_named(&ListRefsWire { base: base.clone(), tag_prefix: Vec::new(), known: &known, limit: GETS_PER_CALL })
            .map_err(|e| e.to_string())?;
        #[cfg(test)]
        LIST_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (refs, more) = match sealed_zome_call(state, line, "list_sealed_at", input).await {
            Ok(result) => decode_listed_refs(line, &result)?,
            Err(e) if is_missing_function(&e) => return read_records_one_by_one(state, line, base).await,
            Err(e) => return Err(e),
        };
        let mut held = held_slot(line).lock().unwrap();
        let held = held.as_mut().filter(|h| h.root == root).ok_or("identity changed during the read")?;
        let mut targets = Vec::with_capacity(refs.len());
        for (target, record, left) in refs {
            match record {
                Some(record) if record.action_hash == target.get_raw_39() => {
                    held.records.insert(target.clone(), record);
                    added += 1;
                    #[cfg(test)]
                    RECORDS_FROM_CELL.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                Some(_) => {}
                None if !left && !held.records.contains_key(&target) => {
                    absent.insert(target.clone());
                }
                None => {}
            }
            targets.push(target);
        }
        if !more {
            break targets;
        }
    };

    let (records, kept, pruned) = {
        let mut held = held_slot(line).lock().unwrap();
        let held = held.as_mut().filter(|h| h.root == root).ok_or("identity changed during the read")?;
        let live: std::collections::HashSet<&ActionHash> = targets.iter().collect();
        let before = held.records.len();
        held.records.retain(|hash, _| live.contains(hash));
        let pruned = before - held.records.len();
        let records: Vec<_> = targets.iter().filter_map(|t| held.records.get(t).cloned()).collect();
        (records, held.records.len(), pruned)
    };
    // Never recreates an identity's folder (an erase may have just removed it).
    if (added > 0 || pruned > 0) && root.is_dir() {
        let list: Option<Vec<RecordView>> = held_slot(line)
            .lock()
            .unwrap()
            .as_ref()
            .filter(|h| h.root == root)
            .map(|h| h.records.values().cloned().collect());
        if let Some(list) = list {
            if let Err(e) = save_held_file(&held_records_path(root, line), &list, data_key) {
                log::info!("[records] not kept on disk: {}", e);
            }
        }
        if added > 0 {
            log::info!("[records] {} read from the cell, {} held", added, kept);
        }
    }
    Ok(records)
}

/// How many more ops a sibling may report than this device holds and this
/// device still count as caught up (every device writes all the time).
const OPS_AHEAD_MARGIN: u64 = 50;

/// Whether a sibling in the private network reports clearly more ops than
/// this device holds - kitsune2's own measure of how far a sync has got.
/// None when the conductor does not say (no sibling seen yet, or busy).
pub(crate) async fn private_ops_behind(state: &Arc<AppState>) -> Option<bool> {
    let line = crate::hc::active_line(state);
    let (admin_port, _) = crate::hc::line_ports(state, line).ok()?;
    match line {
        Line::V06 => {
            use holochain_client::{AdminWebsocket, CellInfo};
            let admin_ws = AdminWebsocket::connect(format!("localhost:{}", admin_port), Some(crate::conductor::node_origin()))
                .await
                .ok()?;
            let apps = admin_ws.list_apps(None).await.ok()?;
            let app = apps.iter().find(|a| a.installed_app_id == crate::dna::private_v2_app_id())?;
            let dna_hash = app.cell_info.values().flatten().find_map(|c| match c {
                CellInfo::Provisioned(p) => Some(p.cell_id.dna_hash().clone()),
                _ => None,
            })?;
            let metrics = admin_ws.dump_network_metrics(Some(dna_hash), false).await.ok()?;
            let gossip = metrics.into_values().next()?.gossip_state_summary;
            ops_behind(gossip.local_op_count, gossip.peer_meta.values().filter_map(|p| p.dht_op_count))
        }
        Line::V07 => {
            use holochain_client_07::{AdminWebsocket, CellInfo};
            let admin_ws = AdminWebsocket::connect(format!("localhost:{}", admin_port), Some(crate::conductor::node_origin()))
                .await
                .ok()?;
            let apps = admin_ws.list_apps(None).await.ok()?;
            let app = apps.iter().find(|a| a.installed_app_id == crate::dna::private_v2_app_id_07())?;
            let dna_hash = app.cell_info.values().flatten().find_map(|c| match c {
                CellInfo::Provisioned(p) => Some(p.cell_id.dna_hash().clone()),
                _ => None,
            })?;
            let metrics = admin_ws.dump_network_metrics(Some(dna_hash), false).await.ok()?;
            let gossip = metrics.into_values().next()?.gossip_state_summary;
            ops_behind(gossip.local_op_count, gossip.peer_meta.values().filter_map(|p| p.dht_op_count))
        }
    }
}

fn ops_behind(local: u64, sibling_counts: impl Iterator<Item = u64>) -> Option<bool> {
    let mut seen = false;
    let mut behind = false;
    for count in sibling_counts {
        seen = true;
        behind |= count > local.saturating_add(OPS_AHEAD_MARGIN);
    }
    seen.then_some(behind)
}

/// A cell still on an older coordinator: every record, one `get` each.
async fn read_records_one_by_one(
    state: &Arc<AppState>,
    line: Line,
    base: holochain_types::prelude::AgentPubKey,
) -> Result<Vec<RecordView>, String> {
    let input = rmp_serde::to_vec_named(&ListAtWire { base, tag_prefix: Vec::new(), network: false })
        .map_err(|e| e.to_string())?;
    match sealed_zome_call(state, line, "get_all_sealed_at", input).await {
        Ok(result) => decode_listed(line, &result),
        Err(e) if is_missing_function(&e) => {
            let result = sealed_zome_call(
                state,
                line,
                "get_all_sealed",
                rmp_serde::to_vec_named(&()).map_err(|e| e.to_string())?,
            )
            .await?;
            crate::hc::records(line, &result).map_err(|e| format!("Records decode failed: {}", e))
        }
        Err(e) => Err(e),
    }
}

/// Device and removal records as the other devices hold them, kept for the
/// identity they were read for.
static NETWORK_DEVICE_VERSIONS: std::sync::Mutex<Option<(std::path::PathBuf, Vec<StoredVersion>)>> =
    std::sync::Mutex::new(None);

/// Ask the other devices for the identity's device and removal records (the
/// ones on the tagged second link). A device that just joined holds only
/// what has been sent to it since; an older record - a sibling that has not
/// written its own since - would otherwise arrive only with the background
/// sync. Returns how many versions were read.
/// How long one ask of the network for the device records may take.
const ASK_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

pub(crate) async fn fetch_device_records(state: &Arc<AppState>) -> Result<usize, String> {
    let line = crate::hc::active_line(state);
    let data_key = vault_data_key(state)?;
    let base = sealed_base(state)?;
    let root = state.identity_root();
    let input = rmp_serde::to_vec_named(&ListAtWire { base, tag_prefix: device_records_tag(&data_key), network: true })
        .map_err(|e| e.to_string())?;
    // A network read on a cold cell can hang for the client's whole
    // request timeout (304 s on a phrase re-add, 10-27), and this ask is
    // the first step of the round: everything after it, the rendezvous
    // hand-off included, waited behind it. A short budget; the round runs
    // again in a minute and the cell is warmer then.
    let call = sealed_zome_call(state, line, "get_all_sealed_at", input);
    let result = match tokio::time::timeout(ASK_WAIT, call).await {
        Ok(r) => r?,
        Err(_) => return Err(format!("get_all_sealed_at timed out after {} s", ASK_WAIT.as_secs())),
    };
    let records = decode_listed(line, &result)?;
    let versions: Vec<StoredVersion> = decode_versions(&records, &data_key)
        .into_iter()
        .filter(|v| v.payload.entry_type == crate::devices::DEVICE_ENTRY_TYPE || v.payload.entry_type == crate::devices::REMOVAL_ENTRY_TYPE)
        .collect();
    let n = versions.len();
    hold_network_device_versions(&root, versions);
    Ok(n)
}

/// Add device and removal versions to the ones held for this identity
/// (versions never change, so holding a union is safe: the newest per
/// device still wins). A version a sibling sent directly stays held when
/// the network has not answered with it yet.
fn hold_network_device_versions(root: &std::path::Path, versions: Vec<StoredVersion>) -> usize {
    let mut added = 0;
    {
        let mut held = NETWORK_DEVICE_VERSIONS.lock().unwrap();
        if held.as_ref().map(|h| h.0.as_path() != root).unwrap_or(true) {
            *held = Some((root.to_path_buf(), Vec::new()));
        }
        let list = &mut held.as_mut().unwrap().1;
        for v in versions {
            if !list.iter().any(|h| h.action_hash == v.action_hash) {
                list.push(v);
                added += 1;
            }
        }
    }
    if added > 0 {
        forget_recent_versions();
    }
    added
}

/// One device or removal record as a sibling device sends it directly (the
/// lane's "device" piece): sealed again with the identity's data key, so
/// only the identity's own devices can open it - a piece nobody else could
/// have made.
#[derive(Serialize, Deserialize)]
struct DevicePieceWire {
    #[serde(with = "serde_bytes")]
    action_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    cipher: Vec<u8>,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    /// What the sender holds now (sealed too: counts are the identity's
    /// business). Absent from a sender that does not say.
    #[serde(default, with = "serde_bytes")]
    holds_cipher: Vec<u8>,
    #[serde(default, with = "serde_bytes")]
    holds_nonce: Vec<u8>,
}

/// The payload type a device's counts travel in (never stored).
const HOLDS_TYPE: &str = "device_holds";

fn holds_payload(holds: &crate::devices::Holds) -> Result<SealedPayload, String> {
    Ok(SealedPayload {
        v: SEALED_PAYLOAD_V2,
        entry_type: HOLDS_TYPE.to_string(),
        created_at: crate::devices::now_ms(),
        body: rmp_serde::to_vec_named(holds).map_err(|e| e.to_string())?,
        refs: Vec::new(),
        id: None,
        updated_at: None,
        device: None,
        deleted: false,
    })
}

/// What a device piece brought: whose record, whether it is new here, and
/// what that device holds.
pub(crate) struct AcceptedPiece {
    pub device: Option<String>,
    pub new_here: bool,
    pub holds: Option<crate::devices::Holds>,
}

/// This device's own latest device record, sealed for a sibling. None until
/// it has written one.
pub(crate) async fn own_device_piece(state: &Arc<AppState>, holds: &crate::devices::Holds) -> Result<Option<Vec<u8>>, String> {
    let install_id = crate::paths::install_id(&state.data_dir).ok_or("no install id")?;
    let id = crate::devices::device_logical_id(&install_id);
    let data_key = vault_data_key(state)?;
    let latest = sealed_versions(state)
        .await?
        .into_iter()
        .filter(|v| v.payload.entry_type == crate::devices::DEVICE_ENTRY_TYPE && v.payload.logical_id() == id)
        .max_by_key(|v| v.payload.version_time());
    let Some(v) = latest else { return Ok(None) };
    let (cipher, nonce) = seal(&v.payload, &data_key).map_err(|e| format!("{:?}", e))?;
    let (holds_cipher, holds_nonce) = seal(&holds_payload(holds)?, &data_key).map_err(|e| format!("{:?}", e))?;
    rmp_serde::to_vec_named(&DevicePieceWire { action_hash: v.action_hash, cipher, nonce: nonce.to_vec(), holds_cipher, holds_nonce: holds_nonce.to_vec() })
        .map(Some)
        .map_err(|e| e.to_string())
}

/// A sibling device sent its record directly: open it with the data key and
/// hold it with the records the network answered, so the device list shows
/// it at once. Returns the sender's install id when this record is new here.
pub(crate) fn accept_device_piece(state: &Arc<AppState>, data: &[u8]) -> Result<AcceptedPiece, String> {
    let wire: DevicePieceWire = rmp_serde::from_slice(data).map_err(|e| format!("device piece: {}", e))?;
    if wire.nonce.len() != NONCE_BYTES || wire.action_hash.len() != 39 {
        return Err("device piece: bad shape".into());
    }
    let data_key = vault_data_key(state)?;
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&wire.nonce);
    let payload = unseal(&wire.cipher, &nonce, &data_key).map_err(|_| "device piece: not sealed with this identity's key".to_string())?;
    if payload.entry_type != crate::devices::DEVICE_ENTRY_TYPE && payload.entry_type != crate::devices::REMOVAL_ENTRY_TYPE {
        return Err("device piece: not a device record".into());
    }
    let device = payload.device.clone();
    let holds = (wire.holds_nonce.len() == NONCE_BYTES)
        .then(|| {
            let mut n = [0u8; NONCE_BYTES];
            n.copy_from_slice(&wire.holds_nonce);
            n
        })
        .and_then(|n| unseal(&wire.holds_cipher, &n, &data_key).ok())
        .filter(|p| p.entry_type == HOLDS_TYPE)
        .and_then(|p| rmp_serde::from_slice::<crate::devices::Holds>(&p.body).ok());
    let added = hold_network_device_versions(&state.identity_root(), vec![StoredVersion { action_hash: wire.action_hash, payload }]);
    Ok(AcceptedPiece { device, new_here: added > 0, holds })
}

/// Lock and identity change: the device records read from the network
/// (decrypted) leave memory with everything else.
pub(crate) fn forget_network_device_versions() {
    *NETWORK_DEVICE_VERSIONS.lock().unwrap() = None;
    crate::devices::forget_network_asked();
}

fn decode_versions(records: &[RecordView], data_key: &[u8; 32]) -> Vec<StoredVersion> {
    let mut versions = Vec::with_capacity(records.len());
    for record in records {
        let Some(entry_bytes) = record.entry.as_ref() else {
            continue;
        };
        #[derive(Deserialize)]
        struct SealedEntryWire {
            #[serde(with = "serde_bytes")]
            cipher: Vec<u8>,
            #[serde(with = "serde_bytes")]
            nonce: Vec<u8>,
        }
        let sealed: SealedEntryWire = match rmp_serde::from_slice(entry_bytes) {
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
        let payload = match unseal(&sealed.cipher, &nonce, data_key) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Skipping undecryptable sealed record: {}", e);
                continue;
            }
        };
        versions.push(StoredVersion {
            action_hash: record.action_hash.clone(),
            payload,
        });
    }
    versions
}

/// The identity's records for an export: the newest version of each logical
/// id, deletions included (as `deleted: true` with no body), so an import
/// elsewhere keeps a deleted record deleted.
pub(crate) async fn sealed_export_records(state: &Arc<AppState>) -> Result<Vec<serde_json::Value>, String> {
    let (mut winners, _superseded) = latest_versions(sealed_versions(state).await?);
    winners.sort_by(|a, b| b.payload.created_at.cmp(&a.payload.created_at).then_with(|| b.action_hash.cmp(&a.action_hash)));
    Ok(winners.into_iter().map(|v| export_record(&v)).collect())
}

fn export_record(version: &StoredVersion) -> serde_json::Value {
    let p = &version.payload;
    let mut record = serde_json::json!({
        "entry_type": p.entry_type,
        "action_hash": hex::encode(&version.action_hash),
        "created_at": p.created_at,
        "id": p.logical_id(),
        "updated_at": p.version_time(),
        "refs": p.refs,
    });
    if let Some(device) = &p.device {
        record["device"] = serde_json::json!(device);
    }
    if p.deleted {
        record["deleted"] = serde_json::json!(true);
    } else {
        record["body"] = rmp_serde::from_slice(&p.body).unwrap_or(serde_json::Value::Null);
    }
    record
}

/// What an import does with one exported record, given what this device
/// already holds.
#[derive(Debug)]
pub(crate) enum ImportDecision {
    /// Nothing to do: malformed, or this device holds the same or a newer
    /// version of that record.
    Skip,
    /// Store it; `supersedes` is the older version it replaces here.
    Store { spec: StoreSpec, supersedes: Option<Vec<u8>> },
}

/// `held` = this device's newest version per logical id.
pub(crate) fn import_decision(
    held: &std::collections::HashMap<String, StoredVersion>,
    record: &serde_json::Value,
) -> ImportDecision {
    let entry_type = record.get("entry_type").and_then(|v| v.as_str()).unwrap_or("");
    let created_at = record.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
    let deleted = record.get("deleted").and_then(|v| v.as_bool()).unwrap_or(false);
    let body = record.get("body").cloned().unwrap_or(serde_json::Value::Null);
    if entry_type.is_empty() || (body.is_null() && !deleted) {
        return ImportDecision::Skip;
    }
    let id = record
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| derived_logical_id(entry_type, created_at));
    let updated_at = record.get("updated_at").and_then(|v| v.as_u64()).unwrap_or(created_at);
    let current = held.get(&id);
    if current.map(|c| c.payload.version_time() >= updated_at).unwrap_or(false) {
        return ImportDecision::Skip;
    }
    let refs = record
        .get("refs")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    ImportDecision::Store {
        spec: StoreSpec {
            entry_type: entry_type.to_string(),
            body: if deleted { serde_json::Value::Null } else { body },
            refs,
            created_at,
            id: Some(id),
            updated_at: Some(updated_at),
            deleted,
        },
        supersedes: current.map(|c| c.action_hash.clone()),
    }
}

/// This device's newest version per logical id, for `import_decision`.
pub(crate) async fn sealed_held(state: &Arc<AppState>) -> Result<std::collections::HashMap<String, StoredVersion>, String> {
    sealed_held_on(state, crate::hc::active_line(state)).await
}

/// `sealed_held` from a named line's cell.
pub(crate) async fn sealed_held_on(state: &Arc<AppState>, line: Line) -> Result<std::collections::HashMap<String, StoredVersion>, String> {
    let (winners, _superseded) = latest_versions(sealed_versions_on(state, line).await?);
    Ok(winners.into_iter().map(|v| (v.payload.logical_id(), v)).collect())
}

/// The identity's records as every device sees them: the newest version of
/// each logical id, deletions left out. Newest first.
pub(crate) async fn sealed_list_inner(
    state: &Arc<AppState>,
) -> Result<Vec<SealedListItem>, String> {
    sealed_list_on(state, crate::hc::active_line(state)).await
}

/// `sealed_list_inner` from a named line's cell.
pub(crate) async fn sealed_list_on(state: &Arc<AppState>, line: Line) -> Result<Vec<SealedListItem>, String> {
    let (winners, _superseded) = latest_versions(sealed_versions_on(state, line).await?);
    Ok(list_items(winners))
}

/// The device records this identity holds on its 0.7 line, from the kept
/// file alone (no conductor needed): what a start reads to decide whether
/// the 0.6 line is still wanted.
pub(crate) fn held_devices_on_07(root: &std::path::Path, data_key: &[u8; 32]) -> Vec<crate::devices::DeviceRecord> {
    let held = load_held_file(&held_records_path(root, Line::V07), data_key);
    let (winners, _) = latest_versions(decode_versions(&held, data_key));
    crate::devices::devices_in(&list_items(winners))
}

/// The newest version of each logical id as items, deletions left out,
/// newest first.
pub(crate) fn list_items(winners: Vec<StoredVersion>) -> Vec<SealedListItem> {
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
    items
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

    fn held(versions: Vec<StoredVersion>) -> std::collections::HashMap<String, StoredVersion> {
        latest_versions(versions).0.into_iter().map(|v| (v.payload.logical_id(), v)).collect()
    }

    #[test]
    fn an_export_made_before_ids_existed_imports_once_however_often_it_is_run() {
        // A 2.0 export record: no id, no update time.
        let record = serde_json::json!({ "entry_type": "login_activity", "created_at": 5000, "body": { "n": 1 }, "refs": [] });
        let ImportDecision::Store { spec, supersedes } = import_decision(&held(vec![]), &record) else { panic!("stored on an empty device") };
        assert_eq!(spec.id.as_deref(), Some("login_activity:5000"));
        assert_eq!(spec.updated_at, Some(5000));
        assert!(supersedes.is_none());
        // The same file again, here or after it reached this device from another.
        let here = held(vec![version(1, "login_activity", 5000, Some("login_activity:5000"), Some(5000), false)]);
        assert!(matches!(import_decision(&here, &record), ImportDecision::Skip));
        // A device still holding the record as 1.5.0 wrote it.
        let legacy = held(vec![version(1, "login_activity", 5000, None, None, false)]);
        assert!(matches!(import_decision(&legacy, &record), ImportDecision::Skip));
    }

    #[test]
    fn an_older_export_never_replaces_what_a_device_holds() {
        let here = held(vec![version(7, "user_profile", 100, Some("user_profile"), Some(9000), false)]);
        let old = serde_json::json!({ "entry_type": "user_profile", "created_at": 100, "body": { "display_name": "old" }, "refs": [] });
        assert!(matches!(import_decision(&here, &old), ImportDecision::Skip));
        // A newer one does, and retires the version held.
        let newer = serde_json::json!({ "entry_type": "user_profile", "created_at": 100, "id": "user_profile", "updated_at": 9500, "body": { "display_name": "new" }, "refs": [] });
        let ImportDecision::Store { spec, supersedes } = import_decision(&here, &newer) else { panic!("the newer version is stored") };
        assert_eq!(spec.updated_at, Some(9500));
        assert_eq!(supersedes, Some(vec![7u8; 39]));
    }

    #[test]
    fn a_deletion_travels_in_an_export_and_an_import_keeps_it() {
        let deletion = version(2, "email_permission", 100, Some("email_permission:100"), Some(900), true);
        let exported = export_record(&deletion);
        assert_eq!(exported["deleted"], true);
        assert!(exported.get("body").is_none());
        // On a device that still shows the record: the deletion is stored.
        let here = held(vec![version(1, "email_permission", 100, None, None, false)]);
        let ImportDecision::Store { spec, .. } = import_decision(&here, &exported) else { panic!("the deletion is stored") };
        assert!(spec.deleted);
        assert_eq!(spec.id.as_deref(), Some("email_permission:100"));
        // The other way round: an old export of the live record on a device that deleted it.
        let deleted_here = held(vec![deletion]);
        let old = serde_json::json!({ "entry_type": "email_permission", "created_at": 100, "body": { "app": "x" }, "refs": [] });
        assert!(matches!(import_decision(&deleted_here, &old), ImportDecision::Skip));
    }

    #[test]
    fn a_record_with_no_body_that_is_not_a_deletion_is_ignored() {
        assert!(matches!(import_decision(&held(vec![]), &serde_json::json!({ "entry_type": "x", "created_at": 1 })), ImportDecision::Skip));
        assert!(matches!(import_decision(&held(vec![]), &serde_json::json!({ "created_at": 1, "body": {} })), ImportDecision::Skip));
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
    // cargo test --lib sealed::tests::live -- --ignored --nocapture --test-threads=1
    // (name the module: a bare `live_` filter also runs the sidecar sweep test,
    // which stops real leftover sidecars on this machine)

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
                o = crate::conductor::node_origin_for_tests(),
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
            if let Ok(ws) = AdminWebsocket::connect(format!("localhost:{}", admin_port), Some(crate::conductor::node_origin())).await {
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

    async fn c_joins_and_fills_in(seed: &str, config: &crate::vault::VaultConfig, a: &LiveDevice) {
        let mut joined = config.clone();
        joined.joined_existing = true;
        let c = live_device("j", 46054, seed, &joined, true).await;
        // Straight away, before anything has arrived.
        sealed_store_first(&c.state, "privacy_settings".into(), serde_json::json!({ "from": "the new device" }), vec![], 9_000_000_000_000).await.unwrap();
        // A, which holds the real settings, wrote them long before.
        sealed_store_inner(&a.state, "privacy_settings".into(), serde_json::json!({ "from": "the first device" }), vec![], 5000).await.unwrap();
        eventually("both keep the settings the first device wrote", 300, || async {
            let on = |l: Vec<SealedListItem>| l.iter().filter(|r| r.entry_type == "privacy_settings").map(|r| r.body["from"].clone()).collect::<Vec<_>>();
            let on_a = sealed_list_inner(&a.state).await.map(on).unwrap_or_default();
            let on_c = sealed_list_inner(&c.state).await.map(on).unwrap_or_default();
            on_a == vec![serde_json::json!("the first device")] && on_c == on_a
        })
        .await;
    }

    /// A device tells its sibling about itself directly: the sibling lists it
    /// as soon as the two can reach each other, without waiting for the
    /// network to answer its next ask, and answers with its own record.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "starts real conductors and uses the staging rendezvous"]
    async fn live_a_device_tells_its_sibling_at_once() {
        let seed = format!("live-{}", hex::encode(crate::key_derivation::new_conductor_seed())[..16].to_string());
        let mut config: crate::vault::VaultConfig = serde_json::from_str(
            r#"{"agent_pub_key":"uhCAkTest","did":"did:flowsta:uhCAkTest","installed_app_ids":[],"created_at":1}"#,
        )
        .unwrap();
        config.data_key = Some(vec![33u8; 32]);
        config.device_seed = Some(vec![21u8; 32]);
        config.agent_pub_key_raw_b64 = Some(crate::key_derivation::base64_standard_encode(
            &crate::key_derivation::construct_agent_pub_key_bytes(&crate::key_derivation::public_key_of_seed(&[21u8; 32])),
        ));
        let a = live_device("da", 46071, &seed, &config, true).await;
        let b = live_device("db", 46072, &seed, &config, true).await;
        let install_a = crate::paths::install_id(&a.state.data_dir).expect("A's install id");
        assert!(crate::devices::publish_own(&a.state).await.expect("A writes its record"));
        assert!(crate::devices::publish_own(&b.state).await.expect("B writes its record"));
        let lane_a = crate::backup_lane::Lane::open(&a.state).await.expect("A's lane");
        let lane_b = crate::backup_lane::Lane::open(&b.state).await.expect("B's lane");
        assert!(lane_a.alive().await && lane_b.alive().await);
        let b_lists_a = || async {
            crate::devices::list(&b.state).await.map(|l| l.iter().any(|d| d.install_id == install_a)).unwrap_or(false)
        };
        println!("  before: B lists A {}", b_lists_a().await);

        // A tells B, every few seconds, until B has heard it directly.
        let started = std::time::Instant::now();
        while !crate::devices::was_heard(&lane_a.me) {
            assert!(started.elapsed().as_secs() < 240, "B never heard from A directly within 240 s");
            crate::devices::announce_to(&a.state, &lane_a, &lane_b.me, Line::V06).await;
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
        println!("  B heard A directly after {} s", started.elapsed().as_secs());
        assert!(b_lists_a().await, "B heard A but does not list it");
        // B answered with its own record: A heard B too.
        eventually("A heard B's answer", 60, || async { crate::devices::was_heard(&lane_b.me) }).await;
    }

    /// A backup made on one device is fetched by the other in pieces
    /// through their conductors, checked against its index and opened.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "starts real conductors and uses the staging rendezvous"]
    async fn live_a_backup_travels_between_devices() {
        use crate::backup_sync::{local_index, newest_across_devices, store_copy};
        let seed = format!("live-{}", hex::encode(crate::key_derivation::new_conductor_seed())[..16].to_string());
        let mut config: crate::vault::VaultConfig = serde_json::from_str(
            r#"{"agent_pub_key":"uhCAkTest","did":"did:flowsta:uhCAkTest","installed_app_ids":[],"created_at":1}"#,
        )
        .unwrap();
        config.data_key = Some(vec![33u8; 32]);
        config.device_seed = Some(vec![21u8; 32]);
        config.backup_key = Some(vec![44u8; 32]);
        config.agent_pub_key_raw_b64 = Some(crate::key_derivation::base64_standard_encode(
            &crate::key_derivation::construct_agent_pub_key_bytes(&crate::key_derivation::public_key_of_seed(&[21u8; 32])),
        ));
        let a = live_device("a", 46061, &seed, &config, true).await;
        let b = live_device("b", 46062, &seed, &config, true).await;
        let (root_a, root_b) = (a.state.identity_root(), b.state.identity_root());

        // About 1.5 MB of data: several pieces, more than one window.
        let data: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
        crate::backup::save_backup(&a.state, "harness_app", "Harness App", Some("recovery"), &data, Some("application/octet-stream")).unwrap();
        let index = local_index(&root_a, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let slot = index[0].slots[0].clone();
        println!("  the encrypted file is {} bytes = {} pieces", slot.size, crate::backup_lane::pieces_of(slot.size));

        let lane_a = crate::backup_lane::Lane::open(&a.state).await.expect("A's lane");
        let lane_b = crate::backup_lane::Lane::open(&b.state).await.expect("B's lane");
        assert!(lane_a.alive().await && lane_b.alive().await);

        let started = std::time::Instant::now();
        let mut fetched = None;
        while fetched.is_none() {
            assert!(started.elapsed().as_secs() < 300, "the file did not arrive within 300 s");
            match lane_b.fetch(&root_b, &lane_a.me, Line::V06, "harness_app", "recovery", slot.size, &slot.sha256, true, |done, total| println!("  {} of {} pieces", done, total)).await {
                Ok(bytes) => fetched = Some(bytes),
                Err(e) => {
                    println!("  not yet ({}); the devices may not have found each other", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
        println!("  fetched after {} s", started.elapsed().as_secs());
        store_copy(&root_b, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "harness_app", &slot, &fetched.unwrap()).expect("the copy matches A's index");

        // B opens A's backup with the identity's backup key.
        let held = newest_across_devices(&root_b, "harness_app", "recovery").expect("B holds a copy");
        assert_eq!(held.from_install.as_deref(), Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        let keys = crate::backup::backup_keys(&b.state).unwrap();
        let (opened, meta) = crate::backup::open_backup_file(&held.path, &keys).unwrap();
        assert_eq!(opened, data);
        assert_eq!(meta.label.as_deref(), Some("recovery"));

        // A file the other device does not hold: told at once, nothing kept.
        let missing = lane_b.fetch(&root_b, &lane_a.me, Line::V06, "harness_app", "nothing", 10, &"0".repeat(64), true, |_, _| {}).await;
        assert_eq!(missing.err().as_deref(), Some("the other device no longer holds it"));
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

        // Each device writes its own entry and learns of the other.
        for (device, seed) in [(&a, [41u8; 32]), (&b, [42u8; 32])] {
            device.state.vault_config.lock().unwrap().as_mut().unwrap().conductor_seed = Some(seed.to_vec());
            assert!(crate::devices::publish_own(&device.state).await.unwrap());
            assert!(!crate::devices::publish_own(&device.state).await.unwrap(), "nothing changed: not written again");
        }
        eventually("each device lists both devices", 300, || async {
            let on_a = crate::devices::list(&a.state).await.map(|d| d.len()).unwrap_or(0);
            let on_b = crate::devices::list(&b.state).await.map(|d| d.len()).unwrap_or(0);
            on_a == 2 && on_b == 2
        })
        .await;

        // The edit B made is copied into A's own config; B does not copy its own.
        assert!(crate::commands::apply_profile_from_other_devices(&a.state).await.unwrap());
        assert_eq!(a.state.vault_config.lock().unwrap().as_ref().unwrap().display_name, None, "the test profile carries `name`, not `display_name`");
        assert!(!crate::commands::apply_profile_from_other_devices(&a.state).await.unwrap(), "applied once");
        assert!(!crate::commands::apply_profile_from_other_devices(&b.state).await.unwrap(), "its own edit");

        // A device added to an existing identity writes a profile before the
        // real one has reached it: the real one still wins everywhere.
        c_joins_and_fills_in(&seed, &config, &a).await;

        // A deletes the log entry; it goes on B too and stays gone.
        let log = sealed_list_inner(&a.state).await.unwrap().into_iter().find(|r| r.entry_type == "login_activity").unwrap();
        sealed_delete_inner(&a.state, &log.action_hash).await.unwrap();
        eventually("the deletion reaches the second device", 300, || async { sealed_list_inner(&b.state).await.map(|l| l.iter().all(|r| r.entry_type != "login_activity")).unwrap_or(false) }).await;
        // The same record brought back by an import of an older copy loses to the deletion.
        sealed_store_inner(&b.state, "login_activity".into(), serde_json::json!({ "n": 1 }), vec![], 2000).await.unwrap();
        assert!(sealed_list_inner(&b.state).await.unwrap().iter().all(|r| r.entry_type != "login_activity"), "a deleted record stays deleted");
    }

    /// A device that joins later asks the network for the device records and
    /// has the first device's at once - before its own copy has arrived by
    /// the background sync, when that is slower.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "starts real conductors and uses the staging rendezvous"]
    async fn live_a_joining_device_asks_for_the_device_records() {
        let seed = format!("live-{}", hex::encode(crate::key_derivation::new_conductor_seed())[..16].to_string());
        let identity_public = crate::key_derivation::public_key_of_seed(&[21u8; 32]);
        let mut config: crate::vault::VaultConfig = serde_json::from_str(
            r#"{"agent_pub_key":"uhCAkTest","did":"did:flowsta:uhCAkTest","installed_app_ids":[],"created_at":1}"#,
        )
        .unwrap();
        config.data_key = Some(vec![33u8; 32]);
        config.agent_pub_key_raw_b64 = Some(crate::key_derivation::base64_standard_encode(
            &crate::key_derivation::construct_agent_pub_key_bytes(&identity_public),
        ));
        let a = live_device("a", 46071, &seed, &config, true).await;
        a.state.vault_config.lock().unwrap().as_mut().unwrap().conductor_seed = Some([41u8; 32].to_vec());
        assert!(crate::devices::publish_own(&a.state).await.unwrap());
        let a_id = crate::paths::install_id(&a.state.data_dir).unwrap();

        let b = live_device("b", 46072, &seed, &config, true).await;
        let started = std::time::Instant::now();
        loop {
            let held = crate::devices::list(&b.state).await.map(|d| d.iter().any(|x| x.install_id == a_id)).unwrap_or(false);
            if let Ok(n) = fetch_device_records(&b.state).await {
                if n > 0 {
                    println!("  asked after {}s ({} version(s)); held by the background sync already: {}", started.elapsed().as_secs(), n, held);
                    break;
                }
            }
            assert!(started.elapsed().as_secs() < 300, "the network never answered with the device records");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        let listed = crate::devices::list(&b.state).await.unwrap();
        assert!(listed.iter().any(|d| d.install_id == a_id), "the first device is listed from what the network answered");
        // Only device records come in this way, and the lock forgets them.
        forget_network_device_versions();
        assert!(NETWORK_DEVICE_VERSIONS.lock().unwrap().is_none());
    }

    /// Records are read from the cell once: the links each time after that,
    /// one read at a time however many ask, and a restart opens the kept file
    /// instead of reading them again. A device reads its own records from its
    /// chain in one call; another device's a hundred per call.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "starts real conductors and uses the staging rendezvous"]
    async fn live_records_are_read_once_and_kept() {
        use std::sync::atomic::Ordering::SeqCst;
        let seed = format!("live-{}", hex::encode(crate::key_derivation::new_conductor_seed())[..16].to_string());
        let identity_public = crate::key_derivation::public_key_of_seed(&[21u8; 32]);
        let mut config: crate::vault::VaultConfig = serde_json::from_str(
            r#"{"agent_pub_key":"uhCAkTest","did":"did:flowsta:uhCAkTest","installed_app_ids":[],"created_at":1}"#,
        )
        .unwrap();
        config.data_key = Some(vec![33u8; 32]);
        config.agent_pub_key_raw_b64 = Some(crate::key_derivation::base64_standard_encode(
            &crate::key_derivation::construct_agent_pub_key_bytes(&identity_public),
        ));
        let a = live_device("ra", 46081, &seed, &config, true).await;
        std::fs::create_dir_all(a.state.identity_root()).unwrap();
        const N: usize = 150;
        let started = std::time::Instant::now();
        for i in 0..N {
            sealed_store_inner(&a.state, "login_activity".into(), serde_json::json!({ "n": i }), vec![], 1000 + i as u64).await.unwrap();
        }
        println!("  A wrote {} records in {}s", N, started.elapsed().as_secs());

        // A's own records come from its chain, all in one call.
        forget_recent_versions();
        let (calls, from_cell) = (LIST_CALLS.load(SeqCst), RECORDS_FROM_CELL.load(SeqCst));
        assert_eq!(sealed_list_inner(&a.state).await.unwrap().len(), N);
        println!("  A listed its own in {} call(s), {} from the cell", LIST_CALLS.load(SeqCst) - calls, RECORDS_FROM_CELL.load(SeqCst) - from_cell);
        assert_eq!(LIST_CALLS.load(SeqCst) - calls, 1, "a device's own records come in one call");

        // B, another device, reads A's records a hundred per call.
        let b = live_device("rb", 46082, &seed, &config, true).await;
        std::fs::create_dir_all(b.state.identity_root()).unwrap();
        eventually("B holds all of A's records", 600, || async {
            forget_recent_versions();
            sealed_list_inner(&b.state).await.map(|l| l.len() == N).unwrap_or(false)
        })
        .await;

        // Asked again: the links only, no record read again.
        forget_recent_versions();
        let from_cell = RECORDS_FROM_CELL.load(SeqCst);
        assert_eq!(sealed_list_inner(&b.state).await.unwrap().len(), N);
        assert_eq!(RECORDS_FROM_CELL.load(SeqCst), from_cell, "nothing read twice");

        // Six readers at once: one call between them.
        forget_recent_versions();
        let calls = LIST_CALLS.load(SeqCst);
        let readers: Vec<_> = (0..6).map(|_| { let s = b.state.clone(); tokio::spawn(async move { sealed_versions(&s).await.map(|v| v.len()) }) }).collect();
        for r in readers {
            assert_eq!(r.await.unwrap().unwrap(), N);
        }
        assert_eq!(LIST_CALLS.load(SeqCst) - calls, 1, "one read at a time, the others take its answer");

        // A restart: memory gone, the kept file opens instead of the cell.
        forget_held_records();
        forget_recent_versions();
        assert!(held_records_path(&b.state.identity_root(), Line::V06).exists());
        let from_cell = RECORDS_FROM_CELL.load(SeqCst);
        assert_eq!(sealed_list_inner(&b.state).await.unwrap().len(), N);
        assert_eq!(RECORDS_FROM_CELL.load(SeqCst), from_cell, "the kept records were used after the restart");
        // The file opens only with the identity's key.
        assert!(load_held_file(&held_records_path(&b.state.identity_root(), Line::V06), &[34u8; 32]).is_empty());

        // Nothing kept at all: another device's records, a hundred per call.
        forget_held_records();
        std::fs::remove_file(held_records_path(&b.state.identity_root(), Line::V06)).unwrap();
        forget_recent_versions();
        let (calls, from_cell) = (LIST_CALLS.load(SeqCst), RECORDS_FROM_CELL.load(SeqCst));
        assert_eq!(sealed_list_inner(&b.state).await.unwrap().len(), N);
        assert_eq!(RECORDS_FROM_CELL.load(SeqCst) - from_cell, N);
        assert_eq!(LIST_CALLS.load(SeqCst) - calls, 2, "150 of another device's records: 100, then 50");

        // A record retired on A leaves B's list (and B's kept records).
        let first = sealed_list_inner(&a.state).await.unwrap().into_iter().last().unwrap();
        sealed_delete_inner(&a.state, &first.action_hash).await.unwrap();
        eventually("the deletion reaches B", 300, || async {
            forget_recent_versions();
            sealed_list_inner(&b.state).await.map(|l| l.len() == N - 1).unwrap_or(false)
        })
        .await;
    }

    #[test]
    fn a_device_is_behind_only_when_a_sibling_holds_clearly_more() {
        assert_eq!(ops_behind(1000, std::iter::empty()), None, "no sibling has said");
        assert_eq!(ops_behind(1000, [1000u64, 1040].into_iter()), Some(false), "within the margin");
        assert_eq!(ops_behind(1000, [900u64].into_iter()), Some(false), "the sibling is the one behind");
        assert_eq!(ops_behind(10_056, [13_953u64].into_iter()), Some(true), "the Mac on 10-17");
    }

    #[test]
    fn the_device_tag_is_keyed_and_only_on_device_records() {
        let (k1, k2) = ([1u8; 32], [2u8; 32]);
        assert_eq!(device_records_tag(&k1), device_records_tag(&k1));
        assert_ne!(device_records_tag(&k1), device_records_tag(&k2), "another identity's tag differs");
        assert_eq!(device_records_tag(&k1).len(), 16);
        assert!(!device_records_tag(&k1).windows(6).any(|w| w == b"device"), "nothing readable in it");
        assert_eq!(tags_for(crate::devices::DEVICE_ENTRY_TYPE, &k1).len(), 1);
        assert_eq!(tags_for(crate::devices::REMOVAL_ENTRY_TYPE, &k1).len(), 1);
        assert!(tags_for("user_profile", &k1).is_empty());
        assert!(tags_for("login_activity", &k1).is_empty());
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
