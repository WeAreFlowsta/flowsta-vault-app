//! Two installs of one identity that both run as the identity's own key.
//!
//! Every device added since 1.6.0 runs a conductor key of its own. An
//! install set up from the phrase before that runs as the identity's key,
//! and so does the identity's first device: two of those each keep their
//! own chain under the one key, and neither's private records reach the
//! other. The rendezvous keeper sees it (`Round::same_key_elsewhere`: our
//! agent announced from another address in notes signed after ours); the
//! Vault says so and offers this: the install makes a key of its own,
//! registers it with the account, starts empty conductors under it as a
//! device added today does, and writes the records it held back in. The
//! other install stays as it is, and the two sync from then on.
//!
//! The conductor folders this install ran as the identity's key are set
//! aside beside the new ones, and removed 30 days after every record they
//! held is written under the new key (Eric, 2026-11-13).

use crate::commands::AppState;
use lair_keystore_api::dependencies::sodoken;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// The records this install held under the identity's key, sealed with the
/// data key, from before its conductors stop until every one is written
/// under its own key. A Vault closed in between finishes at its next unlock.
const CARRY_FILE: &str = "own-key-carry.bin";
/// When the last carried record was written (unix secs, as text): the
/// folders set aside go `SET_ASIDE_KEPT_FOR` after it.
const CARRIED_AT_FILE: &str = "own-key-carried-at";
const SET_ASIDE_KEPT_FOR: u64 = 30 * 24 * 60 * 60;
/// Conductor folders set aside: `<name>-as-identity-key-<unix secs>`.
pub(crate) const SET_ASIDE_MARK: &str = "-as-identity-key-";

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Carry {
    v: u8,
    at_ms: u64,
    /// The old conductor folders are out of the way.
    set_aside: bool,
    /// `sealed::export_record` shapes: what Export writes and Import reads.
    records: Vec<serde_json::Value>,
    /// The signing cells' own records (v1.5 and v1.6 on the 0.7 line): a
    /// signature this install made under the shared key may be held by no
    /// other peer (seen 11-13: neither install's reached the other).
    #[serde(default)]
    signing: Vec<crate::signing_v16::ChainRecord>,
}

pub(crate) fn carry_path(root: &Path) -> PathBuf {
    root.join(CARRY_FILE)
}

fn save_carry(root: &Path, carry: &Carry, data_key: &[u8; 32]) -> Result<(), String> {
    let plain = rmp_serde::to_vec_named(carry).map_err(|e| e.to_string())?;
    let mut nonce = [0u8; crate::sealed::NONCE_BYTES];
    sodoken::random::randombytes_buf(&mut nonce).map_err(|e| e.to_string())?;
    let mut cipher = vec![0u8; plain.len() + crate::sealed::MAC_BYTES];
    sodoken::secretbox::xsalsa_easy(&mut cipher, &nonce, &plain, data_key).map_err(|e| e.to_string())?;
    let mut bytes = nonce.to_vec();
    bytes.extend_from_slice(&cipher);
    crate::vault::write_atomic(&carry_path(root), &bytes).map_err(|e| e.to_string())
}

/// None: no file. Some(Err): a file that does not open (kept, never
/// removed: it may be the only copy of a record).
fn load_carry(root: &Path, data_key: &[u8; 32]) -> Option<Result<Carry, String>> {
    let bytes = std::fs::read(carry_path(root)).ok()?;
    let open = || -> Result<Carry, String> {
        if bytes.len() < crate::sealed::NONCE_BYTES + crate::sealed::MAC_BYTES {
            return Err("too short".into());
        }
        let (nonce, cipher) = bytes.split_at(crate::sealed::NONCE_BYTES);
        let mut nonce_arr = [0u8; crate::sealed::NONCE_BYTES];
        nonce_arr.copy_from_slice(nonce);
        let mut plain = vec![0u8; cipher.len() - crate::sealed::MAC_BYTES];
        sodoken::secretbox::xsalsa_open_easy(&mut plain, cipher, &nonce_arr, data_key).map_err(|_| "does not open with this identity's data key".to_string())?;
        rmp_serde::from_slice(&plain).map_err(|e| e.to_string())
    };
    Some(open())
}

/// Move a conductor folder out of the way, keeping it. Ok(None): there was
/// none.
fn set_aside(dir: &Path, unix_secs: u64) -> Result<Option<PathBuf>, String> {
    if !dir.exists() {
        return Ok(None);
    }
    let name = dir.file_name().and_then(|n| n.to_str()).ok_or("a conductor folder with no name")?;
    let mut to = dir.with_file_name(format!("{}{}{}", name, SET_ASIDE_MARK, unix_secs));
    let mut n = 1;
    while to.exists() {
        to = dir.with_file_name(format!("{}{}{}-{}", name, SET_ASIDE_MARK, unix_secs, n));
        n += 1;
    }
    std::fs::rename(dir, &to).map_err(|e| format!("{} not set aside: {}", dir.display(), e))?;
    Ok(Some(to))
}

/// Both lines' conductor folders set aside, and the records kept from them
/// forgotten (they are in the carry file; the new conductors hold none yet).
fn set_conductors_aside(root: &Path) -> Result<(), String> {
    let now = crate::ipc_server::unix_now() as u64;
    for dir in [crate::paths::conductor_dir(root), crate::paths::conductor_dir_07(root)] {
        if let Some(to) = set_aside(&dir, now)? {
            log::info!("[own key] {} set aside as {}", dir.display(), to.file_name().and_then(|n| n.to_str()).unwrap_or_default());
        }
    }
    for line in [crate::hc::Line::V06, crate::hc::Line::V07] {
        let _ = std::fs::remove_file(crate::sealed::held_records_path(root, line));
    }
    Ok(())
}

/// What this install runs as, and whether another install is running as the
/// same key right now.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct SameKey {
    /// Another install of this identity runs as the identity's key, as this
    /// one does: the two do not sync until one has a key of its own.
    pub elsewhere: bool,
    /// Records this install held are still being written under its new key.
    pub carrying: bool,
}

pub(crate) fn same_key_now(state: &Arc<AppState>) -> SameKey {
    let (runs_as_identity, data_key) = {
        let config = state.vault_config.lock().unwrap();
        (
            config.as_ref().map(|c| !c.has_own_conductor_key() && c.hosting_model.as_deref() == Some("device-hosted")).unwrap_or(false),
            config.as_ref().and_then(|c| c.data_key.as_deref().and_then(|k| <[u8; 32]>::try_from(k).ok())),
        )
    };
    let seen = FORCED.load(Ordering::SeqCst)
        || [crate::hc::Line::V06, crate::hc::Line::V07]
            .into_iter()
            .any(|line| crate::conductor::supervisor().last_round(line).is_some_and(|s| s.round.same_key_elsewhere > 0));
    SameKey {
        elsewhere: runs_as_identity && seen,
        carrying: data_key.is_some_and(|k| load_carry(&state.identity_root(), &k).is_some()),
    }
}

/// The UI tests show the notice without waiting for two rendezvous notes.
static FORCED: AtomicBool = AtomicBool::new(false);
pub(crate) fn force_seen_for_test(seen: bool) {
    FORCED.store(seen, Ordering::SeqCst);
}

#[tauri::command]
pub fn same_key_status(state: tauri::State<'_, Arc<AppState>>) -> SameKey {
    same_key_now(state.inner())
}

static BUSY: AtomicBool = AtomicBool::new(false);
struct Busy;
impl Drop for Busy {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::SeqCst);
    }
}

/// Give this install a key of its own. `mnemonic`: only for an account
/// that asks for the phrase to add a device (`needs_phrase`).
///
/// Errors the page words: `needs_phrase`, `phrase_mismatch`,
/// `api_unreachable`, `still_moving`, `not_ready`, `already_own_key`.
#[tauri::command]
pub async fn give_this_computer_its_own_key(
    api_url: String,
    mnemonic: Option<String>,
    app_handle: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<usize, String> {
    give_own_key_inner(&api_url, mnemonic, &app_handle, state.inner()).await
}

pub(crate) async fn give_own_key_inner(api_url: &str, mnemonic: Option<String>, app_handle: &tauri::AppHandle, state: &Arc<AppState>) -> Result<usize, String> {
    if BUSY.swap(true, Ordering::SeqCst) {
        return Err("already_running".into());
    }
    let _busy = Busy;
    let root = state.identity_root();
    let (identity_seed, identity_agent_b64, data_key, agent_pub_key) = {
        let config = state.vault_config.lock().unwrap();
        let cfg = config.as_ref().ok_or("vault_locked")?;
        if cfg.has_own_conductor_key() {
            return Err("already_own_key".into());
        }
        if cfg.hosting_model.as_deref() != Some("device-hosted") {
            return Err("not_device_hosted".into());
        }
        let seed: [u8; 32] = cfg.device_seed.as_deref().and_then(|s| s.try_into().ok()).ok_or("vault_locked")?;
        let key: [u8; 32] = cfg.data_key.as_deref().and_then(|k| k.try_into().ok()).ok_or("not_device_hosted")?;
        (seed, cfg.agent_pub_key_raw_b64.clone().ok_or("vault_locked")?, key, cfg.agent_pub_key.clone())
    };
    // The move to 0.7 and the carry of an earlier web account's signatures
    // read this install's 0.6 chain: they finish first.
    if !crate::move_07::settled(&root) {
        return Err("still_moving".into());
    }
    let install_id = crate::paths::install_id(&state.data_dir).ok_or("no install id")?;
    let enrollment_seed = match mnemonic.as_deref().map(crate::migration::normalize_mnemonic) {
        Some(phrase) => {
            let of_phrase = crate::key_derivation::derive_device_keypair(&phrase).map(|k| crate::key_derivation::construct_agent_pub_key_string(k.verifying_key().as_bytes()));
            if of_phrase.ok().as_deref() != Some(agent_pub_key.as_str()) {
                return Err("phrase_mismatch".into());
            }
            Some(crate::key_derivation::derive_seed(&phrase, crate::key_derivation::ENROLLMENT_CONSTANT).map_err(|e| e.to_string())?)
        }
        None => None,
    };

    // 1. What this install holds, read while its conductor still runs.
    let not_ready = |e: String| format!("not_ready: {}", e.chars().take(160).collect::<String>());
    let records = crate::sealed::sealed_export_records(state).await.map_err(not_ready)?;
    let mut signing = crate::signing_v16::chain_of(state, &crate::signing_07::signing_app_id(crate::hc::Line::V07), "1.5").await.map_err(not_ready)?;
    signing.extend(crate::signing_v16::chain_of(state, &crate::signing_v16::app_id(), "1.6").await.map_err(not_ready)?);

    // 2. The account learns the new key first: refused or unreachable,
    //    nothing here has changed.
    let new_seed = crate::key_derivation::new_conductor_seed();
    crate::device_registry::register_own_new_key(api_url, &identity_agent_b64, &identity_seed, &new_seed, &install_id, enrollment_seed.as_ref())
        .await
        .map_err(|e| if e.contains("approval_required") { "needs_phrase".to_string() } else { e })?;
    log::info!("[own key] the account knows this install's new key; {} private record(s) and {} signing record(s) to carry", records.len(), signing.len());

    // 3. The records, where a Vault closed from here on finds them.
    let carried = records.len() + signing.len();
    save_carry(&root, &Carry { v: 1, at_ms: crate::ipc_server::unix_now() as u64 * 1000, set_aside: false, records, signing }, &data_key)?;

    // 4. Stop both lines (the watchdog waits behind the same lock), keep
    //    the new key, set the old conductors aside.
    let changed: Result<(), String> = async {
        let _restart = state.conductor_restart_lock.lock().await;
        let status = crate::conductor::ConductorStatus::Starting { message: "Setting this device up to sync...".into() };
        *state.conductor_status.lock().unwrap() = status.clone();
        let _ = tauri::Emitter::emit(app_handle, "conductor-status", status);
        tokio::task::spawn_blocking(crate::conductor::stop_lines_and_starts).await.map_err(|e| e.to_string())?;
        {
            let mut config = state.vault_config.lock().unwrap();
            let cfg = config.as_mut().ok_or("vault_locked")?;
            cfg.conductor_seed = Some(new_seed.to_vec());
            cfg.joined_existing = true;
        }
        if let Err(e) = crate::commands::persist_config_now(state) {
            // Not saved: this install is what it was.
            if let Some(cfg) = state.vault_config.lock().unwrap().as_mut() {
                cfg.conductor_seed = None;
                cfg.joined_existing = false;
            }
            let _ = std::fs::remove_file(carry_path(&root));
            return Err(format!("the new key was not saved: {}", e));
        }
        finish_set_aside(&root, &data_key)?;
        crate::move_07::mark_own_key(&root)?;
        forget_what_the_old_conductors_gave(state);
        Ok(())
    }
    .await;

    // 5. Start again, whatever happened: under the new key, or as before.
    crate::commands::this_device_comes_online(state.vault_config.lock().unwrap().as_ref().and_then(|c| c.conductor_seed_bytes()), state);
    let started = crate::commands::start_after_own_stop(state, app_handle).await;
    changed?;
    started?;
    log::info!("[own key] this install runs as a key of its own now");
    state.activity.record("device_own_key", "This device was set up to sync with your other devices", None, None, None);
    // The round after a start writes the records back (`carry_in_if_owed`).
    Ok(carried)
}

fn forget_what_the_old_conductors_gave(state: &Arc<AppState>) {
    crate::sealed::forget_recent_versions();
    crate::sealed::forget_network_device_versions();
    crate::sealed::forget_held();
    crate::devices::forget_network_asked();
    state.cell_credentials.lock().unwrap().clear();
    state.cell_credentials_07.lock().unwrap().clear();
}

/// Set the old conductor folders aside when a carry says it is still owed.
fn finish_set_aside(root: &Path, data_key: &[u8; 32]) -> Result<(), String> {
    let Some(carry) = load_carry(root, data_key) else { return Ok(()) };
    let mut carry = carry?;
    if carry.set_aside {
        return Ok(());
    }
    set_conductors_aside(root)?;
    carry.set_aside = true;
    save_carry(root, &carry, data_key)
}

/// Before a conductor start: a Vault that closed between saving its new key
/// and setting the old conductors aside does that now (an install's new key
/// never starts on the chains of the identity's). A carry file whose key
/// was never saved changed nothing: it goes.
pub(crate) fn before_start(root: &Path, config: &crate::vault::VaultConfig) {
    let Some(data_key) = config.data_key.as_deref().and_then(|k| <[u8; 32]>::try_from(k).ok()) else { return };
    if load_carry(root, &data_key).is_none() {
        let gone = drop_set_aside_when_due(root, crate::ipc_server::unix_now() as u64);
        if gone > 0 {
            log::info!("[own key] {} conductor folder(s) set aside 30 days ago removed: their records have been under this install's own key since", gone);
        }
        return;
    }
    if !config.has_own_conductor_key() {
        log::info!("[own key] a carry was begun and the new key never saved: nothing changed, the carry file goes");
        let _ = std::fs::remove_file(carry_path(root));
        return;
    }
    match finish_set_aside(root, &data_key).and_then(|_| crate::move_07::mark_own_key(root)) {
        Ok(()) => {}
        Err(e) => log::warn!("[own key] the old conductor folders were not set aside: {}", e),
    }
}

/// Remove the conductor folders set aside, once every record they held has
/// been under the new key for `SET_ASIDE_KEPT_FOR`. Never while a carry is
/// still owed. Returns how many folders went.
fn drop_set_aside_when_due(root: &Path, now: u64) -> usize {
    if carry_path(root).exists() {
        return 0;
    }
    let Some(carried_at) = std::fs::read_to_string(root.join(CARRIED_AT_FILE)).ok().and_then(|t| t.trim().parse::<u64>().ok()) else { return 0 };
    if now < carried_at.saturating_add(SET_ASIDE_KEPT_FOR) {
        return 0;
    }
    let mut gone = 0;
    let mut left = false;
    for entry in std::fs::read_dir(root).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.contains(SET_ASIDE_MARK) && entry.path().is_dir() {
            match std::fs::remove_dir_all(entry.path()) {
                Ok(()) => gone += 1,
                Err(e) => {
                    left = true;
                    log::warn!("[own key] {} not removed: {}", name, e);
                }
            }
        }
    }
    if !left {
        let _ = std::fs::remove_file(root.join(CARRIED_AT_FILE));
    }
    gone
}

/// After a conductor is ready: write the records this install held, each
/// only where the new cell holds no version as new (what Import does).
/// The file goes once every record is in.
pub(crate) async fn carry_in_if_owed(state: &Arc<AppState>) {
    let root = state.identity_root();
    let Some(data_key) = state.vault_config.lock().unwrap().as_ref().and_then(|c| c.data_key.as_deref().and_then(|k| <[u8; 32]>::try_from(k).ok())) else { return };
    let carry = match load_carry(&root, &data_key) {
        None => return,
        Some(Err(e)) => {
            log::warn!("[own key] the carry file did not read ({}); kept as it is", e);
            return;
        }
        Some(Ok(carry)) => carry,
    };
    if !carry.set_aside {
        return;
    }
    static RUNNING: AtomicBool = AtomicBool::new(false);
    if RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    let done = async {
        let private = carry_in(state, &carry.records).await?;
        let signing = if carry.signing.is_empty() { Default::default() } else { crate::signing_v16::carry_kept(state, &carry.signing).await? };
        Ok::<_, String>((private, signing))
    }
    .await;
    RUNNING.store(false, Ordering::SeqCst);
    match done {
        Ok(((stored, skipped), signing)) => {
            log::info!(
                "[own key] private records: {} carried in, {} already here as new or newer; signing records: {} carried, {} already here, {} for the next round, {} failed, {} signed on 1.6 under the old key",
                stored, skipped, signing.carried, signing.already, signing.waiting, signing.failed, signing.native_v16
            );
            // The file stays while a signing record is still owed.
            if !signing.settled() || signing.native_v16 > 0 {
                return;
            }
            // Only for the identity it was read for.
            if state.identity_root() == root {
                // The clock for the folders set aside starts before the
                // carry file goes: a Vault closed between the two carries
                // again (nothing to write) and starts it then.
                let _ = std::fs::write(root.join(CARRIED_AT_FILE), (crate::ipc_server::unix_now() as u64).to_string());
                let _ = std::fs::remove_file(carry_path(&root));
            }
        }
        Err(e) => log::info!("[own key] records not all carried in yet ({}); tried again next round", e.chars().take(160).collect::<String>()),
    }
}

async fn carry_in(state: &Arc<AppState>, records: &[serde_json::Value]) -> Result<(usize, usize), String> {
    let mut held = crate::sealed::sealed_held(state).await?;
    let _guard = state.commit_serial.lock().await;
    let (mut stored, mut skipped) = (0usize, 0usize);
    for record in records {
        match crate::sealed::import_decision(&held, record) {
            crate::sealed::ImportDecision::Skip => skipped += 1,
            crate::sealed::ImportDecision::Store { spec, supersedes } => {
                let (id, entry_type, created_at, deleted) = (spec.id.clone().unwrap_or_default(), spec.entry_type.clone(), spec.created_at, spec.deleted);
                let version_time = spec.updated_at.unwrap_or(spec.created_at);
                let hash = crate::sealed::sealed_store_spec(state, spec, supersedes.filter(|h| h.len() == 39).map(holochain_types::prelude::ActionHash::from_raw_39)).await?;
                held.insert(
                    id.clone(),
                    crate::sealed::StoredVersion {
                        action_hash: hex::decode(&hash).unwrap_or_default(),
                        payload: crate::sealed::SealedPayload {
                            v: crate::sealed::SEALED_PAYLOAD_V2,
                            entry_type,
                            created_at,
                            body: Vec::new(),
                            refs: Vec::new(),
                            id: Some(id),
                            updated_at: Some(version_time),
                            device: None,
                            deleted,
                        },
                    },
                );
                stored += 1;
            }
        }
    }
    Ok((stored, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fv-own-key-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_carry_opens_only_with_the_identitys_data_key() {
        let root = temp("carry");
        assert!(load_carry(&root, &[1u8; 32]).is_none(), "no file, no carry");
        let carry = Carry { v: 1, at_ms: 7, set_aside: false, records: vec![serde_json::json!({ "entry_type": "user_profile", "created_at": 1, "body": { "name": "A" } })], signing: vec![crate::signing_v16::ChainRecord { cell: "1.6".into(), hash: vec![1; 39], kind: 0, timestamp: 5, author: vec![2; 39], action: vec![3; 80], signature: vec![4; 64], entry: vec![0x80] }] };
        save_carry(&root, &carry, &[1u8; 32]).unwrap();
        assert_eq!(load_carry(&root, &[1u8; 32]).unwrap().unwrap(), carry);
        assert!(load_carry(&root, &[2u8; 32]).unwrap().is_err(), "another key: unread, and the file stays");
        assert!(carry_path(&root).exists());
        let raw = std::fs::read(carry_path(&root)).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("user_profile"), "sealed on disk");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_old_conductors_are_set_aside_once_and_kept() {
        let root = temp("aside");
        for dir in [crate::paths::conductor_dir(&root), crate::paths::conductor_dir_07(&root)] {
            std::fs::create_dir_all(dir.join("databases")).unwrap();
            std::fs::write(dir.join("databases").join("chain"), b"records").unwrap();
        }
        std::fs::write(crate::sealed::held_records_path(&root, crate::hc::Line::V07), b"kept").unwrap();
        save_carry(&root, &Carry { v: 1, at_ms: 7, set_aside: false, records: Vec::new(), signing: Vec::new() }, &[1u8; 32]).unwrap();

        finish_set_aside(&root, &[1u8; 32]).unwrap();
        assert!(!crate::paths::conductor_dir(&root).exists() && !crate::paths::conductor_dir_07(&root).exists(), "the new key starts on empty conductors");
        assert!(!crate::sealed::held_records_path(&root, crate::hc::Line::V07).exists());
        let aside: Vec<String> = std::fs::read_dir(&root).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| n.contains(SET_ASIDE_MARK)).collect();
        assert_eq!(aside.len(), 2, "both kept: {:?}", aside);
        for name in &aside {
            assert_eq!(std::fs::read(root.join(name).join("databases").join("chain")).unwrap(), b"records");
        }
        assert!(load_carry(&root, &[1u8; 32]).unwrap().unwrap().set_aside);

        // Conductors the new key has started since are never set aside by a second call.
        std::fs::create_dir_all(crate::paths::conductor_dir_07(&root)).unwrap();
        finish_set_aside(&root, &[1u8; 32]).unwrap();
        assert!(crate::paths::conductor_dir_07(&root).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn folders_set_aside_go_thirty_days_after_the_carry_and_never_before() {
        let root = temp("due");
        let aside = root.join(format!("conductor-07{}5", SET_ASIDE_MARK));
        std::fs::create_dir_all(aside.join("databases")).unwrap();
        std::fs::create_dir_all(crate::paths::conductor_dir_07(&root)).unwrap();
        // No carry finished: kept, however old.
        assert_eq!(drop_set_aside_when_due(&root, u64::MAX), 0);
        std::fs::write(root.join(CARRIED_AT_FILE), "1000").unwrap();
        assert_eq!(drop_set_aside_when_due(&root, 1000 + SET_ASIDE_KEPT_FOR - 1), 0, "a second short of 30 days");
        // A carry still owed holds them, whatever the clock says.
        save_carry(&root, &Carry { v: 1, at_ms: 7, set_aside: true, records: Vec::new(), signing: Vec::new() }, &[1u8; 32]).unwrap();
        assert_eq!(drop_set_aside_when_due(&root, u64::MAX), 0);
        std::fs::remove_file(carry_path(&root)).unwrap();
        assert!(aside.exists());
        assert_eq!(drop_set_aside_when_due(&root, 1000 + SET_ASIDE_KEPT_FOR), 1);
        assert!(!aside.exists() && crate::paths::conductor_dir_07(&root).exists(), "only the folder set aside goes");
        assert!(!root.join(CARRIED_AT_FILE).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_folder_set_aside_twice_in_one_second_keeps_both() {
        let root = temp("twice");
        let dir = root.join("conductor");
        std::fs::create_dir_all(&dir).unwrap();
        let first = set_aside(&dir, 5).unwrap().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let second = set_aside(&dir, 5).unwrap().unwrap();
        assert!(first.exists() && second.exists() && first != second);
        assert_eq!(set_aside(&dir, 5).unwrap(), None, "none there, none moved");
        let _ = std::fs::remove_dir_all(&root);
    }
}
