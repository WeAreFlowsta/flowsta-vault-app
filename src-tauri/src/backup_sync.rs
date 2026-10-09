//! App backups across the identity's devices.
//!
//! This device's own backups stay where they have always been and every
//! backup request answers from them as before. Beside them, each device
//! keeps a copy of the backups its sibling devices hold:
//!
//!   backups/<app>/<label>.enc                     this device's (unchanged)
//!   backups-from/<install id>/<app>/<label>.enc   copies of another device's
//!
//! Each device says what it holds in small sealed records, one per backup
//! (its time, its size and the SHA-256 of the encrypted file), rewritten
//! only when that backup changes or goes. Together they are the device's
//! index. A device makes its copies match the other devices' indexes: what
//! an index lists and is missing or different here is fetched, what an
//! index no longer lists is dropped. An index is the truth for its own
//! device's backups, and a device that is gone keeps its last index, so
//! its copies stay.
//!
//! The copies are the encrypted files as the other device wrote them. Both
//! backup keys are on every device of the identity, so they open here.

use crate::backup::BackupMeta;
use crate::sealed::SealedListItem;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const SLOT_ENTRY_TYPE: &str = "backup_slot";

/// One backup on one device, as its record says.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SlotRecord {
    pub install_id: String,
    pub client_id: String,
    pub app_name: String,
    #[serde(flatten)]
    pub slot: SlotInfo,
    /// The device no longer holds it.
    #[serde(default)]
    pub gone: bool,
}

pub fn slot_record_id(install_id: &str, client_id: &str, label: &str) -> String {
    format!("{}:{}:{}:{}", SLOT_ENTRY_TYPE, install_id, client_id, label)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SlotInfo {
    pub label: String,
    pub created_at: i64,
    /// Bytes of the encrypted file.
    pub size: u64,
    /// SHA-256 of the encrypted file, hex.
    pub sha256: String,
}

/// What one device holds for one app.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AppIndex {
    pub install_id: String,
    pub client_id: String,
    pub app_name: String,
    /// Sorted by label.
    pub slots: Vec<SlotInfo>,
}

fn is_install_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The SHA-256 of a file, remembered while the file's size and modified
/// time stay the same (backups can be tens of megabytes).
fn file_sha256(path: &Path) -> Option<(u64, String)> {
    use std::sync::Mutex;
    static SEEN: Mutex<BTreeMap<PathBuf, (u64, std::time::SystemTime, String)>> = Mutex::new(BTreeMap::new());
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    if let Some((len, at, sha)) = SEEN.lock().unwrap().get(path) {
        if *len == meta.len() && *at == modified {
            return Some((*len, sha.clone()));
        }
    }
    let sha = sha256_hex(&std::fs::read(path).ok()?);
    SEEN.lock().unwrap().insert(path.to_path_buf(), (meta.len(), modified, sha.clone()));
    Some((meta.len(), sha))
}

/// The `.enc` files of one app folder with what is stored beside each.
fn slots_in(app_dir: &Path) -> Vec<(PathBuf, BackupMeta)> {
    let Ok(entries) = std::fs::read_dir(app_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("enc"))
        .filter_map(|p| crate::backup::read_backup_meta(&p).map(|m| (p, m)))
        .collect()
}

/// What this device holds, one index per app.
pub fn local_index(identity_root: &Path, install_id: &str) -> Vec<AppIndex> {
    let Ok(apps) = std::fs::read_dir(crate::paths::backups_dir(identity_root)) else {
        return Vec::new();
    };
    let mut indexes = Vec::new();
    for app_dir in apps.flatten().map(|e| e.path()).filter(|p| p.is_dir()) {
        let mut slots = Vec::new();
        let mut client_id = None;
        let mut app_name = String::new();
        for (path, meta) in slots_in(&app_dir) {
            let Some((size, sha256)) = file_sha256(&path) else { continue };
            let Some(label) = meta.label.clone() else { continue };
            client_id.get_or_insert(meta.client_id.clone());
            app_name = meta.app_name.clone();
            slots.push(SlotInfo { label, created_at: meta.created_at, size, sha256 });
        }
        if let Some(client_id) = client_id {
            slots.sort_by(|a, b| a.label.cmp(&b.label));
            indexes.push(AppIndex { install_id: install_id.to_string(), client_id, app_name, slots });
        }
    }
    indexes.sort_by(|a, b| a.client_id.cmp(&b.client_id));
    indexes
}

/// Every backup record in a listing of the identity's records.
pub fn slot_records_in(records: &[SealedListItem]) -> Vec<SlotRecord> {
    records
        .iter()
        .filter(|r| r.entry_type == SLOT_ENTRY_TYPE)
        .filter_map(|r| serde_json::from_value::<SlotRecord>(r.body.clone()).ok())
        .filter(|r| is_install_id(&r.install_id))
        .collect()
}

/// The records as one index per device and app (backups that are gone left out).
pub fn indexes_of(records: &[SlotRecord]) -> Vec<AppIndex> {
    let mut by_app: BTreeMap<(String, String), AppIndex> = BTreeMap::new();
    for record in records {
        let index = by_app
            .entry((record.install_id.clone(), record.client_id.clone()))
            .or_insert_with(|| AppIndex {
                install_id: record.install_id.clone(),
                client_id: record.client_id.clone(),
                app_name: record.app_name.clone(),
                slots: Vec::new(),
            });
        if !record.gone {
            index.slots.push(record.slot.clone());
        }
    }
    let mut indexes: Vec<AppIndex> = by_app.into_values().collect();
    for index in &mut indexes {
        index.slots.sort_by(|a, b| a.label.cmp(&b.label));
    }
    indexes
}

/// The records this device should write: one for each of its backups that
/// is new or changed, and one saying "gone" for each it no longer holds.
pub fn records_to_write(mine: &[AppIndex], recorded: &[SlotRecord], install_id: &str) -> Vec<SlotRecord> {
    let mut out = Vec::new();
    let said = |client_id: &str, label: &str| {
        recorded
            .iter()
            .find(|r| r.install_id == install_id && r.client_id == client_id && r.slot.label == label)
    };
    for index in mine {
        for slot in &index.slots {
            let current = SlotRecord {
                install_id: install_id.to_string(),
                client_id: index.client_id.clone(),
                app_name: index.app_name.clone(),
                slot: slot.clone(),
                gone: false,
            };
            if said(&index.client_id, &slot.label) != Some(&current) {
                out.push(current);
            }
        }
    }
    for old in recorded.iter().filter(|r| r.install_id == install_id && !r.gone) {
        let held = mine
            .iter()
            .any(|i| i.client_id == old.client_id && i.slots.iter().any(|s| s.label == old.slot.label));
        if !held {
            out.push(SlotRecord { gone: true, ..old.clone() });
        }
    }
    out
}

// ── Copies of other devices' backups ────────────────────────────────────────

fn copies_app_dir(identity_root: &Path, install_id: &str, client_id: &str) -> PathBuf {
    crate::paths::backup_copies_dir(identity_root)
        .join(install_id)
        .join(crate::backup::sanitize_id(client_id))
}

pub fn copy_path(identity_root: &Path, install_id: &str, client_id: &str, label: &str) -> PathBuf {
    copies_app_dir(identity_root, install_id, client_id).join(format!("{}.enc", crate::backup::sanitize_id(label)))
}

#[derive(Clone, Debug, PartialEq)]
pub enum CopyStep {
    Fetch { install_id: String, client_id: String, slot: SlotInfo },
    Drop { path: PathBuf },
}

/// What brings this device's copies in line with the other devices' indexes.
pub fn plan(identity_root: &Path, my_install_id: &str, indexes: &[AppIndex]) -> Vec<CopyStep> {
    let mut steps = Vec::new();
    for index in indexes.iter().filter(|i| i.install_id != my_install_id && is_install_id(&i.install_id)) {
        let mut wanted: BTreeMap<PathBuf, &SlotInfo> = BTreeMap::new();
        for slot in &index.slots {
            wanted.insert(copy_path(identity_root, &index.install_id, &index.client_id, &slot.label), slot);
        }
        for (path, slot) in &wanted {
            let held = file_sha256(path).map(|(_, sha)| sha);
            if held.as_deref() != Some(slot.sha256.as_str()) {
                steps.push(CopyStep::Fetch { install_id: index.install_id.clone(), client_id: index.client_id.clone(), slot: (*slot).clone() });
            }
        }
        for (path, _) in slots_in(&copies_app_dir(identity_root, &index.install_id, &index.client_id)) {
            if !wanted.contains_key(&path) {
                steps.push(CopyStep::Drop { path });
            }
        }
    }
    steps
}

/// Keep a fetched copy, once its bytes are the ones the index named.
pub fn store_copy(identity_root: &Path, install_id: &str, client_id: &str, slot: &SlotInfo, bytes: &[u8]) -> Result<PathBuf, String> {
    if !is_install_id(install_id) {
        return Err("bad install id".into());
    }
    if sha256_hex(bytes) != slot.sha256 {
        return Err("the copy does not match its index".into());
    }
    let path = copy_path(identity_root, install_id, client_id, &slot.label);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    crate::vault::write_atomic(&path, bytes).map_err(|e| e.to_string())?;
    Ok(path)
}

/// The encrypted file of one of this device's own backups, for a sibling
/// device that asked for it by what the index says.
pub fn own_file_for(identity_root: &Path, client_id: &str, slot: &SlotInfo) -> Option<Vec<u8>> {
    own_file_matching(identity_root, client_id, &slot.label, &slot.sha256)
}

pub fn own_file_matching(identity_root: &Path, client_id: &str, label: &str, sha256: &str) -> Option<Vec<u8>> {
    let dir = crate::paths::backups_dir(identity_root).join(crate::backup::sanitize_id(client_id));
    let path = dir.join(format!("{}.enc", crate::backup::sanitize_id(label)));
    let bytes = std::fs::read(path).ok()?;
    (sha256_hex(&bytes) == sha256).then_some(bytes)
}

/// One backup an app can be given: where it is and which device wrote it.
#[derive(Clone, Debug)]
pub struct Held {
    pub path: PathBuf,
    /// `None` for this device's own.
    pub from_install: Option<String>,
    pub meta: BackupMeta,
}

/// Every backup of an app this device holds, its own and the copies.
pub fn held_across_devices(identity_root: &Path, client_id: &str) -> Vec<Held> {
    let app = crate::backup::sanitize_id(client_id);
    let mut held: Vec<Held> = slots_in(&crate::paths::backups_dir(identity_root).join(&app))
        .into_iter()
        .map(|(path, meta)| Held { path, from_install: None, meta })
        .collect();
    if let Ok(devices) = std::fs::read_dir(crate::paths::backup_copies_dir(identity_root)) {
        for device in devices.flatten() {
            let install = device.file_name().to_string_lossy().to_string();
            if !is_install_id(&install) {
                continue;
            }
            for (path, meta) in slots_in(&device.path().join(&app)) {
                held.push(Held { path, from_install: Some(install.clone()), meta });
            }
        }
    }
    held.retain(|h| h.meta.client_id == client_id);
    held
}

/// The newest backup with this label on any of the person's devices. This
/// device's own wins a tie.
/// The copy with this label held from one named device (the `device` ids
/// `/backup/list` prints under `other_devices`), so an app can read EVERY
/// sibling's copy of a per-device label (a manifest), not only the newest.
pub fn held_from_device(identity_root: &Path, client_id: &str, label: &str, device: &str) -> Option<Held> {
    pick_from_device(held_across_devices(identity_root, client_id), label, device)
}

fn pick_from_device(held: Vec<Held>, label: &str, device: &str) -> Option<Held> {
    held.into_iter()
        .find(|h| h.meta.label.as_deref() == Some(label) && h.from_install.as_deref() == Some(device))
}

pub fn newest_across_devices(identity_root: &Path, client_id: &str, label: &str) -> Option<Held> {
    held_across_devices(identity_root, client_id)
        .into_iter()
        .filter(|h| h.meta.label.as_deref() == Some(label))
        .max_by_key(|h| (h.meta.created_at, h.from_install.is_none()))
}

/// What an import of another device's backups from an export file did.
#[derive(Debug, Default, PartialEq)]
pub struct CopiesImported {
    pub restored: usize,
    pub skipped: usize,
    pub failed: usize,
}

/// Restore the copies of other devices' backups an export file carries
/// (`app_data.other_devices`). A copy already held is left alone unless
/// `overwrite`. The exporting device's entries for THIS device are not
/// copies: this device's own backups are the truth for it.
pub fn import_copies(
    state: &crate::commands::AppState,
    other_devices: &[serde_json::Value],
    my_install_id: &str,
    overwrite: bool,
) -> CopiesImported {
    let root = state.identity_root();
    let mut outcome = CopiesImported::default();
    for device in other_devices {
        let Some(install_id) = device.get("device").and_then(|v| v.as_str()).filter(|id| is_install_id(id)) else {
            continue;
        };
        if install_id == my_install_id {
            continue;
        }
        for snap in device.get("snapshots").and_then(|s| s.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
            let text = |key: &str| snap.get(key).and_then(|v| v.as_str());
            let (Some(client_id), Some(label), Some(raw)) = (text("client_id"), text("label"), text("restore_base64")) else {
                outcome.failed += 1;
                continue;
            };
            let path = copy_path(&root, install_id, client_id, label);
            if path.exists() && !overwrite {
                outcome.skipped += 1;
                continue;
            }
            let written = crate::commands::base64_standard_decode(raw)
                .map_err(|_| "bad base64".to_string())
                .and_then(|bytes| {
                    crate::backup::write_backup_file(
                        state,
                        &path,
                        client_id,
                        text("app_name").unwrap_or(client_id),
                        label,
                        &bytes,
                        text("content_type"),
                        snap.get("saved_at").and_then(|v| v.as_i64()),
                    )
                });
            match written {
                Ok(()) => outcome.restored += 1,
                Err(e) => {
                    log::warn!("[import] a copy of another device's backup was not restored: {}", e);
                    outcome.failed += 1;
                }
            }
        }
    }
    outcome
}

/// What this device keeps from one of the identity's other devices.
#[derive(Serialize, Debug, PartialEq)]
pub struct KeptFromDevice {
    pub install_id: String,
    pub backups: usize,
    /// Bytes of data, as the apps stored it.
    pub bytes: u64,
}

/// The copies this device keeps, counted per device.
pub fn kept_from_devices(identity_root: &Path) -> Vec<KeptFromDevice> {
    let Ok(devices) = std::fs::read_dir(crate::paths::backup_copies_dir(identity_root)) else {
        return Vec::new();
    };
    let mut kept = Vec::new();
    for device in devices.flatten() {
        let install_id = device.file_name().to_string_lossy().to_string();
        if !is_install_id(&install_id) {
            continue;
        }
        let Ok(apps) = std::fs::read_dir(device.path()) else { continue };
        let metas: Vec<BackupMeta> = apps.flatten().flat_map(|app| slots_in(&app.path())).map(|(_, meta)| meta).collect();
        if !metas.is_empty() {
            kept.push(KeptFromDevice { install_id, backups: metas.len(), bytes: metas.iter().map(|m| m.data_size as u64).sum() });
        }
    }
    kept.sort_by(|a, b| a.install_id.cmp(&b.install_id));
    kept
}

/// For Your Data: what this device keeps from the identity's other devices.
#[tauri::command]
pub fn backups_kept_from_devices(state: tauri::State<'_, Arc<crate::commands::AppState>>) -> Vec<KeptFromDevice> {
    kept_from_devices(&state.identity_root())
}

// ── The round ───────────────────────────────────────────────────────────────

#[derive(Debug, Default, PartialEq)]
pub struct RoundOutcome {
    /// Records written about this device's own backups.
    pub recorded: usize,
    pub fetched: usize,
    pub dropped: usize,
    /// Copies still missing (the device that holds them was not reachable).
    pub waiting: usize,
}

impl RoundOutcome {
    pub fn changed(&self) -> bool {
        self.recorded + self.fetched + self.dropped > 0
    }
}

/// At most this much is fetched in one round; the rest waits for the next.
const FETCH_BYTES_PER_ROUND: u64 = 200 * 1024 * 1024;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// This device's end of the lane, opened when needed and again when the
/// conductor it was opened on has gone.
pub(crate) async fn lane(state: &Arc<crate::commands::AppState>) -> Result<Arc<crate::backup_lane::Lane>, String> {
    let mut slot = state.backup_lane.lock().await;
    if let Some(lane) = slot.as_ref() {
        if lane.alive().await {
            return Ok(lane.clone());
        }
    }
    let lane = crate::backup_lane::Lane::open(state).await?;
    *slot = Some(lane.clone());
    Ok(lane)
}

/// One pass: write the records for this device's backups that changed,
/// drop copies their device no longer holds, fetch copies that are missing.
pub async fn round(state: &Arc<crate::commands::AppState>) -> Result<RoundOutcome, String> {
    let records = crate::sealed::sealed_list_inner(state).await?;
    let me = crate::paths::install_id(&state.data_dir).ok_or("no install id")?;
    let root = state.identity_root();
    let mut outcome = RoundOutcome::default();

    // The lane is open on every device that takes part, so it can be asked.
    let lane = lane(state).await;

    let recorded = slot_records_in(&records);
    for record in records_to_write(&local_index(&root, &me), &recorded, &me) {
        let now = now_ms();
        crate::sealed::sealed_store_spec(
            state,
            crate::sealed::StoreSpec {
                entry_type: SLOT_ENTRY_TYPE.to_string(),
                body: serde_json::to_value(&record).map_err(|e| e.to_string())?,
                refs: Vec::new(),
                created_at: now,
                id: Some(slot_record_id(&record.install_id, &record.client_id, &record.slot.label)),
                updated_at: Some(now),
                deleted: false,
            },
            None,
        )
        .await?;
        outcome.recorded += 1;
    }

    // Where each sibling device can be reached: the key its conductor runs.
    let devices = crate::devices::devices_in(&records);
    let agent_of = |install_id: &str| {
        devices
            .iter()
            .find(|d| d.install_id == install_id && d.removed_at.is_none())
            .and_then(|d| crate::commands::base64_standard_decode(&d.conductor_key).ok())
            .filter(|raw| raw.len() == 39)
            .map(holochain_types::prelude::AgentPubKey::from_raw_39)
    };

    let mut budget = FETCH_BYTES_PER_ROUND;
    for step in plan(&root, &me, &indexes_of(&recorded)) {
        match step {
            CopyStep::Drop { path } => {
                if std::fs::remove_file(&path).is_ok() {
                    outcome.dropped += 1;
                }
            }
            CopyStep::Fetch { install_id, client_id, slot } => {
                let (Ok(lane), Some(from)) = (lane.as_ref(), agent_of(&install_id)) else {
                    outcome.waiting += 1;
                    continue;
                };
                if slot.size > budget {
                    outcome.waiting += 1;
                    continue;
                }
                let lane: &Arc<crate::backup_lane::Lane> = lane;
                match lane.fetch(&root, &from, &client_id, &slot.label, slot.size, &slot.sha256, |_, _| {}).await {
                    Ok(bytes) => match store_copy(&root, &install_id, &client_id, &slot, &bytes) {
                        Ok(_) => {
                            budget -= slot.size;
                            outcome.fetched += 1;
                        }
                        Err(e) => {
                            log::warn!("[backups] a fetched copy was not kept: {}", e);
                            outcome.waiting += 1;
                        }
                    },
                    Err(e) => {
                        log::info!("[backups] {}/{} not fetched this time: {}", client_id, slot.label, e);
                        outcome.waiting += 1;
                    }
                }
            }
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// A backup file as the Vault writes it (the contents are not opened here).
    fn file(client_id: &str, label: &str, created_at: i64, body: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "nonce": "00", "ciphertext": hex::encode(body),
            "meta": { "client_id": client_id, "app_name": "Poll App", "label": label, "created_at": created_at, "data_size": body.len(), "content_type": "application/json" },
        }))
        .unwrap()
    }

    fn write_own(root: &Path, client_id: &str, label: &str, created_at: i64, body: &str) -> SlotInfo {
        let dir = crate::paths::backups_dir(root).join(client_id);
        std::fs::create_dir_all(&dir).unwrap();
        let bytes = file(client_id, label, created_at, body);
        std::fs::write(dir.join(format!("{}.enc", label)), &bytes).unwrap();
        SlotInfo { label: label.into(), created_at, size: bytes.len() as u64, sha256: sha256_hex(&bytes) }
    }

    #[test]
    fn a_device_lists_what_it_holds_per_app() {
        let tmp = tempfile::tempdir().unwrap();
        let latest = write_own(tmp.path(), "app", "latest", 10, "one");
        let manifest = write_own(tmp.path(), "app", "manifest", 20, "two");
        write_own(tmp.path(), "other_app", "latest", 5, "x");
        let index = local_index(tmp.path(), ME);
        assert_eq!(index.len(), 2);
        assert_eq!(index[0], AppIndex { install_id: ME.into(), client_id: "app".into(), app_name: "Poll App".into(), slots: vec![latest, manifest] });
        assert!(local_index(&tmp.path().join("nothing"), ME).is_empty());
    }

    #[test]
    fn a_backup_is_recorded_when_it_is_new_changed_or_gone_and_not_otherwise() {
        let tmp = tempfile::tempdir().unwrap();
        write_own(tmp.path(), "app", "latest", 10, "one");
        write_own(tmp.path(), "app", "manifest", 10, "m");
        let mine = local_index(tmp.path(), ME);
        let first = records_to_write(&mine, &[], ME);
        assert_eq!(first.len(), 2);
        assert!(records_to_write(&mine, &first, ME).is_empty());
        assert_eq!(indexes_of(&first), mine);

        // One backup rewritten: one record, not the whole index.
        std::thread::sleep(std::time::Duration::from_millis(20));
        write_own(tmp.path(), "app", "latest", 11, "one-b");
        let changed = local_index(tmp.path(), ME);
        let second = records_to_write(&changed, &first, ME);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].slot.label, "latest");
        assert!(!second[0].gone);

        // Everything deleted here: each is said to be gone, once.
        let gone = records_to_write(&[], &first, ME);
        assert_eq!(gone.len(), 2);
        assert!(gone.iter().all(|r| r.gone));
        assert!(records_to_write(&[], &gone, ME).is_empty());
        assert!(indexes_of(&gone)[0].slots.is_empty());

        // Another device's records are never rewritten from here.
        let theirs: Vec<SlotRecord> = first.iter().map(|r| SlotRecord { install_id: OTHER.into(), ..r.clone() }).collect();
        assert!(records_to_write(&[], &theirs, ME).is_empty());
    }

    #[test]
    fn an_export_brings_back_the_copies_of_a_device_that_is_gone() {
        let tmp = tempfile::tempdir().unwrap();
        let state = crate::commands::AppState::new(tmp.path().to_path_buf());
        *state.backup_key.lock().unwrap() = Some([7u8; 32]);
        let snap = |label: &str, text: &str| serde_json::json!({
            "app_name": "Poll App", "client_id": "app", "label": label, "saved_at": 5,
            "content_type": "text/plain", "restore_base64": crate::key_derivation::base64_standard_encode(text.as_bytes()),
        });
        let export = vec![
            serde_json::json!({ "device": OTHER, "snapshots": [snap("recovery", "theirs"), snap("latest", "theirs too"), { "label": "broken" }] }),
            serde_json::json!({ "device": ME, "snapshots": [snap("recovery", "mine, as the other device saw it")] }),
            serde_json::json!({ "device": "../escape", "snapshots": [snap("recovery", "x")] }),
        ];
        assert_eq!(import_copies(&state, &export, ME, false), CopiesImported { restored: 2, skipped: 0, failed: 1 });
        // Again: nothing is written twice.
        assert_eq!(import_copies(&state, &export, ME, false), CopiesImported { restored: 0, skipped: 2, failed: 1 });
        assert_eq!(import_copies(&state, &export, ME, true).restored, 2);

        // The copies open and are offered across devices; nothing was written as this device's own.
        let held = newest_across_devices(tmp.path(), "app", "recovery").unwrap();
        assert_eq!(held.from_install.as_deref(), Some(OTHER));
        let keys = crate::backup::backup_keys(&state).unwrap();
        assert_eq!(crate::backup::open_backup_file(&held.path, &keys).unwrap().0, b"theirs");
        assert_eq!(kept_from_devices(tmp.path()).len(), 1);
        assert!(local_index(tmp.path(), ME).is_empty());
    }

    #[test]
    fn copies_follow_the_other_devices_indexes() {
        let source = tempfile::tempdir().unwrap();
        let here = tempfile::tempdir().unwrap();
        let latest = write_own(source.path(), "app", "latest", 10, "one");
        let conv = write_own(source.path(), "app", "conv-1", 12, "two");
        let theirs = local_index(source.path(), OTHER);

        // Nothing held: both are fetched. This device's own index asks for nothing.
        let steps = plan(here.path(), ME, &theirs);
        assert_eq!(steps.len(), 2);
        assert!(plan(here.path(), OTHER, &theirs).is_empty());

        // The source hands over exactly the file its index named.
        let bytes = own_file_for(source.path(), "app", &latest).unwrap();
        let mut wrong = latest.clone();
        wrong.sha256 = "00".into();
        assert!(own_file_for(source.path(), "app", &wrong).is_none());

        // Bytes that do not match the index are not kept.
        assert!(store_copy(here.path(), OTHER, "app", &conv, &bytes).is_err());
        assert!(store_copy(here.path(), "../x", "app", &latest, &bytes).is_err());
        store_copy(here.path(), OTHER, "app", &latest, &bytes).unwrap();
        assert_eq!(plan(here.path(), ME, &theirs), vec![CopyStep::Fetch { install_id: OTHER.into(), client_id: "app".into(), slot: conv.clone() }]);

        // The other device deleted "latest": its copy is dropped here.
        let mut after = theirs.clone();
        after[0].slots.retain(|s| s.label != "latest");
        let steps = plan(here.path(), ME, &after);
        assert!(steps.contains(&CopyStep::Drop { path: copy_path(here.path(), OTHER, "app", "latest") }));
    }

    #[test]
    fn an_app_can_be_given_the_newest_backup_on_any_device() {
        let source = tempfile::tempdir().unwrap();
        let here = tempfile::tempdir().unwrap();
        write_own(here.path(), "app", "recovery", 10, "mine");
        let newer = write_own(source.path(), "app", "recovery", 30, "theirs");
        store_copy(here.path(), OTHER, "app", &newer, &own_file_for(source.path(), "app", &newer).unwrap()).unwrap();

        let newest = newest_across_devices(here.path(), "app", "recovery").unwrap();
        assert_eq!(newest.from_install.as_deref(), Some(OTHER));
        assert_eq!(newest.meta.created_at, 30);
        assert_eq!(held_across_devices(here.path(), "app").len(), 2);
        assert_eq!(kept_from_devices(here.path()), vec![KeptFromDevice { install_id: OTHER.into(), backups: 1, bytes: 6 }]);
        assert!(newest_across_devices(here.path(), "app", "missing").is_none());
        assert!(held_across_devices(here.path(), "another_app").is_empty());

        // This device's own wins a tie.
        write_own(here.path(), "app", "recovery", 30, "mine again");
        assert_eq!(newest_across_devices(here.path(), "app", "recovery").unwrap().from_install, None);
    }

    #[test]
    fn a_named_devices_copy_is_picked_by_label_and_device() {
        let held = |label: &str, from: Option<&str>, at: i64| Held {
            path: PathBuf::from(format!("/x/{}-{}", label, from.unwrap_or("own"))),
            from_install: from.map(String::from),
            meta: crate::backup::BackupMeta {
                client_id: "app".into(),
                app_name: "App".into(),
                label: Some(label.into()),
                created_at: at,
                data_size: 1,
                content_type: "application/json".into(),
                identity: None,
                summary: None,
            },
        };
        let all = vec![held("manifest", None, 30), held("manifest", Some("inst-a"), 10), held("manifest", Some("inst-b"), 20), held("recovery", Some("inst-b"), 5)];
        let pick = |label: &str, dev: &str| pick_from_device(all.iter().map(|h| Held { path: h.path.clone(), from_install: h.from_install.clone(), meta: h.meta.clone() }).collect(), label, dev);
        assert_eq!(pick("manifest", "inst-a").map(|h| h.path), Some(PathBuf::from("/x/manifest-inst-a")));
        assert_eq!(pick("manifest", "inst-b").map(|h| h.path), Some(PathBuf::from("/x/manifest-inst-b")));
        assert!(pick("manifest", "inst-c").is_none(), "an unknown device has no copy");
        assert!(pick("recovery", "inst-a").is_none(), "the label must match too");
    }

}
