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

// ── The list a locked Vault can read and write ──────────────────────────────
//
// The same records again, sealed with a key made from the backup key (which
// a locked Vault keeps) instead of the data key (which it does not), and
// linked under a tag of their own, so the identity's ordinary listing never
// returns them. A Vault that is locked and still syncing passes app backups
// between the person's devices from these alone; it reads and writes no
// private record to do it.

/// Where a device can be asked for a backup file: the key its conductor
/// runs and the Holochain line it listens on. In the open list because the
/// device records themselves are sealed with the data key.
pub const REACH_ENTRY_TYPE: &str = "backup_reach";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ReachRecord {
    pub install_id: String,
    /// Standard base64 of the 39-byte agent key, as in the device record.
    pub conductor_key: String,
    pub generation: String,
}

pub fn reach_record_id(install_id: &str) -> String {
    format!("{}:{}", REACH_ENTRY_TYPE, install_id)
}

/// The key the open list is sealed with and the tag it is linked under,
/// both made from the backup key every device of the identity derives from
/// its seed (never the backup key itself, which encrypts the files).
#[derive(Clone)]
pub struct OpenList {
    pub key: [u8; 32],
    pub tag: Vec<u8>,
}

impl OpenList {
    pub fn from_backup_key(legacy_backup_key: &[u8; 32]) -> Self {
        use hmac::{Hmac, Mac};
        let derive = |label: &str| -> [u8; 32] {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(legacy_backup_key).expect("HMAC takes a key of any size");
            mac.update(label.as_bytes());
            mac.finalize().into_bytes().into()
        };
        let mut tag = b"bl1:".to_vec();
        tag.extend_from_slice(&derive("flowsta-backup-list-tag-v1")[..12]);
        OpenList { key: derive("flowsta-backup-list-key-v1"), tag }
    }

    pub fn of(state: &crate::commands::AppState) -> Result<Self, String> {
        Ok(Self::from_backup_key(&crate::backup::backup_keys(state)?.legacy))
    }
}

/// Every backup record in a listing, each with when it was written.
fn slot_records_with_time(records: &[SealedListItem]) -> Vec<(SlotRecord, u64)> {
    records
        .iter()
        .filter(|r| r.entry_type == SLOT_ENTRY_TYPE)
        .filter_map(|r| serde_json::from_value::<SlotRecord>(r.body.clone()).ok().map(|s| (s, r.updated_at)))
        .filter(|(r, _)| is_install_id(&r.install_id))
        .collect()
}

/// The two lists as one: a backup counts once (by device, app and label),
/// and where both lists name it the record written last is the one that
/// counts. A device that is locked writes the open list only, and a device
/// on a Vault from before the open list writes the other only.
pub fn merged_slot_records(sealed: &[SealedListItem], open: &[SealedListItem]) -> Vec<SlotRecord> {
    let mut newest: BTreeMap<(String, String, String), (SlotRecord, u64)> = BTreeMap::new();
    for (record, at) in slot_records_with_time(sealed).into_iter().chain(slot_records_with_time(open)) {
        let key = (record.install_id.clone(), record.client_id.clone(), record.slot.label.clone());
        match newest.get(&key) {
            Some((_, held_at)) if *held_at >= at => {}
            _ => {
                newest.insert(key, (record, at));
            }
        }
    }
    newest.into_values().map(|(r, _)| r).collect()
}

/// Each device's reach, from the open list.
pub fn reach_records_in(open: &[SealedListItem]) -> Vec<ReachRecord> {
    open.iter()
        .filter(|r| r.entry_type == REACH_ENTRY_TYPE)
        .filter_map(|r| serde_json::from_value::<ReachRecord>(r.body.clone()).ok())
        .filter(|r| is_install_id(&r.install_id))
        .collect()
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

/// This device's end of the lane, opened when needed, again when the
/// conductor it was opened on has gone, and again when the set of running
/// lines changed: a 0.6 line attached a minute after the start (a sibling
/// on 1.6.1) must be listened on too, or that sibling's pieces and
/// announcements never arrive here (the beta9 mixed leg).
pub(crate) async fn lane(state: &Arc<crate::commands::AppState>) -> Result<Arc<crate::backup_lane::Lane>, String> {
    let mut slot = state.backup_lane.lock().await;
    let running: Vec<crate::hc::Line> = [crate::hc::Line::V06, crate::hc::Line::V07]
        .into_iter()
        .filter(|l| crate::hc::line_ports(state, *l).is_ok())
        .collect();
    if let Some(lane) = slot.as_ref() {
        if lane.lines() == running && lane.alive().await {
            return Ok(lane.clone());
        }
        if lane.lines() != running {
            log::info!("[backups] the lane reopens: the lines changed ({:?} -> {:?})", lane.lines(), running);
        }
    }
    let lane = crate::backup_lane::Lane::open(state).await?;
    *slot = Some(lane.clone());
    Ok(lane)
}

/// One pass: write the records for this device's backups that changed,
/// drop copies their device no longer holds, fetch copies that are missing.
/// An app saved or deleted a backup: the devices loop wakes, waits for the
/// burst to end, and says so to the other devices (10-20: a picture change
/// took up to ten minutes to reach the other device, on the five-minute
/// rounds; 10-29: a removal waited for the next pass the same way).
pub static SAVED: std::sync::LazyLock<tokio::sync::Notify> = std::sync::LazyLock::new(tokio::sync::Notify::new);

pub fn note_saved() {
    SAVED.notify_one();
}

/// The other devices' backups seen announced in an earlier round, so a NEW
/// announcement is copied at once while a copy that keeps failing (the
/// other device out of reach) waits for the slower schedule.
static SEEN: std::sync::Mutex<Option<std::collections::HashSet<String>>> = std::sync::Mutex::new(None);

fn step_key(install_id: &str, client_id: &str, slot: &SlotInfo) -> String {
    format!("{install_id}/{client_id}/{}/{}", slot.label, slot.sha256)
}

/// Which of `now` were not in `before` (all of them on a first round), and
/// the set to remember.
pub(crate) fn fresh_announcements(before: Option<&std::collections::HashSet<String>>, now: &[String]) -> (std::collections::HashSet<String>, std::collections::HashSet<String>) {
    let fresh = now.iter().filter(|k| before.map(|b| !b.contains(*k)).unwrap_or(true)).cloned().collect();
    (fresh, now.iter().cloned().collect())
}

/// The unlocked round's part in the open list: write this device's records
/// there that are missing or changed, and its reach, and return the list as
/// it stands (every device's records).
async fn open_list_round(
    state: &Arc<crate::commands::AppState>,
    root: &Path,
    me: &str,
    devices: &[crate::devices::DeviceRecord],
) -> Result<Vec<SealedListItem>, String> {
    let open = OpenList::of(state)?;
    let base = crate::commands::identity_agent_key(state).ok_or("vault_locked")?;
    let line = crate::hc::active_line(state);
    let mut items = crate::sealed::list_tagged(state, line, base.clone(), &open.key, open.tag.clone()).await?;
    let said = slot_records_with_time(&items).into_iter().map(|(r, _)| r).collect::<Vec<_>>();
    let mut wrote = 0usize;
    for record in records_to_write(&local_index(root, me), &said, me) {
        let now = now_ms();
        crate::sealed::store_tagged(
            state,
            line,
            base.clone(),
            &open.key,
            open.tag.clone(),
            crate::sealed::StoreSpec {
                entry_type: SLOT_ENTRY_TYPE.to_string(),
                body: serde_json::to_value(&record).map_err(|e| e.to_string())?,
                refs: Vec::new(),
                created_at: now,
                id: Some(slot_record_id(&record.install_id, &record.client_id, &record.slot.label)),
                updated_at: Some(now),
                deleted: false,
            },
        )
        .await?;
        wrote += 1;
    }
    // This device's reach, as its own device record has it.
    if let Some(own) = devices.iter().find(|d| d.install_id == me && d.removed_at.is_none()) {
        let reach = ReachRecord { install_id: me.to_string(), conductor_key: own.conductor_key.clone(), generation: own.generation.clone() };
        if !reach_records_in(&items).contains(&reach) {
            let now = now_ms();
            crate::sealed::store_tagged(
                state,
                line,
                base.clone(),
                &open.key,
                open.tag.clone(),
                crate::sealed::StoreSpec {
                    entry_type: REACH_ENTRY_TYPE.to_string(),
                    body: serde_json::to_value(&reach).map_err(|e| e.to_string())?,
                    refs: Vec::new(),
                    created_at: now,
                    id: Some(reach_record_id(me)),
                    updated_at: Some(now),
                    deleted: false,
                },
            )
            .await?;
            wrote += 1;
        }
    }
    if wrote > 0 {
        log::info!("[backups] the open list: {} record(s) written", wrote);
        items = crate::sealed::list_tagged(state, line, base, &open.key, open.tag).await?;
    }
    Ok(items)
}

/// This device read itself as removed while locked (the identity's public
/// record): which identity, so nothing more is fetched or answered for it.
static LOCKED_REMOVED: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// Whether a locked round found this device removed from this identity.
pub fn removed_while_locked(identity_root: &Path) -> bool {
    LOCKED_REMOVED.lock().unwrap().as_deref() == Some(identity_root)
}

/// The round of a Vault that is locked and still syncing: its own list out
/// and the other devices' in, from the open list alone, then the same
/// fetching and dropping as an unlocked round. It reads and writes no
/// private record. First it asks the identity's public record whether this
/// device was removed: a removed device fetches nothing more.
pub async fn locked_round(state: &Arc<crate::commands::AppState>, fetch_all: bool) -> Result<RoundOutcome, String> {
    let (base, own_key) = {
        let kept = state.kept_conductor.lock().unwrap();
        let kept = kept.as_ref().ok_or("not syncing")?;
        (kept.base.clone().ok_or("no identity key kept")?, crate::key_derivation::public_key_of_seed(&kept.seed))
    };
    let root = state.identity_root();
    if removed_while_locked(&root) {
        return Err("this device was removed from the identity".into());
    }
    let line = crate::hc::active_line(state);
    if line != crate::hc::Line::V07 {
        return Err("the identity's records are not on the 0.7 line yet".into());
    }
    if crate::identity_07::removed_on_07(state, &own_key).await == Some(true) {
        *LOCKED_REMOVED.lock().unwrap() = Some(root.clone());
        log::info!("[locked] this device is removed, by the identity's own record: no more backups are fetched");
        return Err("this device was removed from the identity".into());
    }
    let me = crate::paths::install_id(&state.data_dir).ok_or("no install id")?;
    let open = OpenList::of(state)?;
    let mut outcome = RoundOutcome::default();
    let mut items = crate::sealed::list_tagged(state, line, base.clone(), &open.key, open.tag.clone()).await?;
    let said: Vec<SlotRecord> = slot_records_with_time(&items).into_iter().map(|(r, _)| r).collect();
    for record in records_to_write(&local_index(&root, &me), &said, &me) {
        let now = now_ms();
        crate::sealed::store_tagged(
            state,
            line,
            base.clone(),
            &open.key,
            open.tag.clone(),
            crate::sealed::StoreSpec {
                entry_type: SLOT_ENTRY_TYPE.to_string(),
                body: serde_json::to_value(&record).map_err(|e| e.to_string())?,
                refs: Vec::new(),
                created_at: now,
                id: Some(slot_record_id(&record.install_id, &record.client_id, &record.slot.label)),
                updated_at: Some(now),
                deleted: false,
            },
        )
        .await?;
        outcome.recorded += 1;
    }
    if outcome.recorded > 0 {
        items = crate::sealed::list_tagged(state, line, base, &open.key, open.tag).await?;
    }
    // A lock or an identity change while this ran: stop here.
    if !crate::commands::syncing_while_locked(state) || state.identity_root() != root {
        return Ok(outcome);
    }
    let recorded = merged_slot_records(&[], &items);
    // Where each device is reached, from the open list; only a device this
    // one knows as current is asked.
    let reach = reach_records_in(&items);
    let agent_of = |install_id: &str| {
        reach.iter().find(|r| r.install_id == install_id).and_then(|r| {
            crate::commands::base64_standard_decode(&r.conductor_key)
                .ok()
                .filter(|raw| raw.len() == 39 && crate::devices::is_current_device(&root, raw))
                .map(|raw| (holochain_types::prelude::AgentPubKey::from_raw_39(raw), r.generation.clone()))
        })
    };
    let lane = lane(state).await;
    copy_from_others(state, &root, &me, &recorded, &agent_of, lane, fetch_all, outcome).await
}

/// One round: say what this device holds (always), and copy what the other
/// devices hold - every missing copy when `fetch_all`, else only the ones
/// announced since the last round.
/// Devices said once this session to be unheard-from (short backup tries).
static QUIET_SAID: std::sync::Mutex<Option<std::collections::HashSet<String>>> = std::sync::Mutex::new(None);

pub async fn round(state: &Arc<crate::commands::AppState>, fetch_all: bool) -> Result<RoundOutcome, String> {
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

    // The same again in the list a locked Vault can read and write, and
    // what the other devices wrote there (a locked one writes nowhere else).
    // A failure here never fails the round: the sealed list above stands.
    let open_items = match open_list_round(state, &root, &me, &devices).await {
        Ok(items) => items,
        Err(e) => {
            log::info!("[backups] the open list was not read or written this round: {}", e.chars().take(140).collect::<String>());
            Vec::new()
        }
    };
    let recorded = merged_slot_records(&records, &open_items);
    // ...and the line it listens on (its record's generation).
    let agent_of = |install_id: &str| {
        devices
            .iter()
            .find(|d| d.install_id == install_id && d.removed_at.is_none())
            .and_then(|d| {
                crate::commands::base64_standard_decode(&d.conductor_key)
                    .ok()
                    .filter(|raw| raw.len() == 39)
                    .map(|raw| (holochain_types::prelude::AgentPubKey::from_raw_39(raw), d.generation.clone()))
            })
    };

    copy_from_others(state, &root, &me, &recorded, &agent_of, lane, fetch_all, outcome).await
}

/// Bring this device's copies in line with what the other devices hold:
/// fetch what their lists name and this device lacks, drop what they no
/// longer name. `agent_of` says where a device is reached.
#[allow(clippy::too_many_arguments)]
async fn copy_from_others(
    state: &Arc<crate::commands::AppState>,
    root: &Path,
    me: &str,
    recorded: &[SlotRecord],
    agent_of: &(dyn Fn(&str) -> Option<(holochain_types::prelude::AgentPubKey, String)> + Sync),
    lane: Result<Arc<crate::backup_lane::Lane>, String>,
    fetch_all: bool,
    mut outcome: RoundOutcome,
) -> Result<RoundOutcome, String> {
    let root = root.to_path_buf();
    let me = me.to_string();
    let indexes = indexes_of(recorded);
    let steps = plan(&root, &me, &indexes);
    let wanted_keys: Vec<String> = steps
        .iter()
        .filter_map(|s| match s {
            CopyStep::Fetch { install_id, client_id, slot } => Some(step_key(install_id, client_id, slot)),
            _ => None,
        })
        .collect();
    let fresh = {
        let mut seen = SEEN.lock().unwrap();
        let (fresh, remember) = fresh_announcements(seen.as_ref(), &wanted_keys);
        *seen = Some(remember);
        fresh
    };
    // How much of the other devices' backups this device should hold, and
    // how much of it is still to come (Overview and Devices show it while a
    // device is being set up).
    let wanted: u64 = indexes.iter().filter(|i| i.install_id != me && is_install_id(&i.install_id)).flat_map(|i| i.slots.iter()).map(|s| s.size).sum();
    let mut pending: u64 = steps.iter().map(|s| if let CopyStep::Fetch { slot, .. } = s { slot.size } else { 0 }).sum();
    let mut budget = FETCH_BYTES_PER_ROUND;
    // What is still to come from each device after this round.
    let mut still: std::collections::BTreeMap<String, (u64, u64)> = std::collections::BTreeMap::new();
    let mut note_still = |install_id: &str, size: u64| {
        let e = still.entry(install_id.to_string()).or_insert((0, 0));
        e.0 += 1;
        e.1 += size;
    };
    for step in steps {
        match step {
            CopyStep::Drop { path } => {
                if std::fs::remove_file(&path).is_ok() {
                    outcome.dropped += 1;
                }
            }
            CopyStep::Fetch { install_id, client_id, slot } => {
                if !fetch_all && !fresh.contains(&step_key(&install_id, &client_id, &slot)) {
                    outcome.waiting += 1;
                    note_still(&install_id, slot.size);
                    continue;
                }
                let (Ok(lane), Some((from, generation))) = (lane.as_ref(), agent_of(&install_id)) else {
                    outcome.waiting += 1;
                    note_still(&install_id, slot.size);
                    continue;
                };
                if slot.size > budget {
                    outcome.waiting += 1;
                    note_still(&install_id, slot.size);
                    continue;
                }
                let lane: &Arc<crate::backup_lane::Lane> = lane;
                let heard = crate::devices::was_heard(&from);
                if !heard && QUIET_SAID.lock().unwrap().get_or_insert_with(Default::default).insert(install_id.clone()) {
                    let short: String = install_id.chars().take(8).collect();
                    log::info!("[backups] {}… has not been heard from this session - one short try for its copies each round until it is", short);
                }
                match lane.fetch(&root, &from, lane.line_for(&generation), &client_id, &slot.label, slot.size, &slot.sha256, heard, |_, _| {}).await {
                    Ok(bytes) => match store_copy(&root, &install_id, &client_id, &slot, &bytes) {
                        Ok(_) => {
                            budget -= slot.size;
                            pending = pending.saturating_sub(slot.size);
                            outcome.fetched += 1;
                        }
                        Err(e) => {
                            log::warn!("[backups] a fetched copy was not kept: {}", e);
                            outcome.waiting += 1;
                            note_still(&install_id, slot.size);
                        }
                    },
                    Err(e) => {
                        log::info!("[backups] {}/{} not fetched this time: {}", client_id, slot.label, e);
                        outcome.waiting += 1;
                        note_still(&install_id, slot.size);
                    }
                }
            }
        }
    }
    *COPIES_PROGRESS.lock().unwrap() = Some((state.identity_root(), wanted, pending));
    let still = still.into_iter().map(|(install_id, (backups, bytes))| FetchingFrom { install_id, backups, bytes }).collect();
    *STILL_TO_FETCH.lock().unwrap() = Some((state.identity_root(), still));
    Ok(outcome)
}

/// Backups still to come from one device, as of the last round.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FetchingFrom {
    pub install_id: String,
    pub backups: u64,
    pub bytes: u64,
}

static STILL_TO_FETCH: std::sync::Mutex<Option<(PathBuf, Vec<FetchingFrom>)>> = std::sync::Mutex::new(None);

/// What this device is still getting from each of the others (the Devices
/// page says so under this device: a fetch that missed used to show
/// nowhere while it waited for the next round).
pub fn still_to_fetch(identity_root: &Path) -> Vec<FetchingFrom> {
    STILL_TO_FETCH
        .lock()
        .unwrap()
        .as_ref()
        .filter(|(root, _)| root.as_path() == identity_root)
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

/// The other devices' backups this device should hold, and how much of that
/// is still to come, as of the last round: (wanted, pending) bytes.
static COPIES_PROGRESS: std::sync::Mutex<Option<(PathBuf, u64, u64)>> = std::sync::Mutex::new(None);

pub fn copies_progress(identity_root: &Path) -> (u64, u64) {
    COPIES_PROGRESS
        .lock()
        .unwrap()
        .as_ref()
        .filter(|(root, _, _)| root.as_path() == identity_root)
        .map(|(_, w, p)| (*w, *p))
        .unwrap_or((0, 0))
}

#[cfg(test)]
mod tests {
    fn listed(entry_type: &str, body: serde_json::Value, updated_at: u64) -> crate::sealed::SealedListItem {
        crate::sealed::SealedListItem { action_hash: String::new(), entry_type: entry_type.into(), created_at: updated_at, body, refs: Vec::new(), id: String::new(), updated_at, device: None }
    }

    fn slot_item(install: &str, label: &str, sha: &str, gone: bool, at: u64) -> crate::sealed::SealedListItem {
        let record = super::SlotRecord {
            install_id: install.into(),
            client_id: "app".into(),
            app_name: "App".into(),
            slot: super::SlotInfo { label: label.into(), created_at: 1, size: 10, sha256: sha.into() },
            gone,
        };
        listed(super::SLOT_ENTRY_TYPE, serde_json::to_value(record).unwrap(), at)
    }

    #[test]
    fn the_open_list_has_its_own_key_and_tag_made_from_the_backup_key() {
        let backup_key = [7u8; 32];
        let a = super::OpenList::from_backup_key(&backup_key);
        let again = super::OpenList::from_backup_key(&backup_key);
        assert_eq!((a.key, a.tag.clone()), (again.key, again.tag.clone()), "every device of the identity makes the same");
        assert_ne!(a.key, backup_key, "never the key the backup files are encrypted with");
        assert!(a.tag.starts_with(b"bl1:") && a.tag.len() == 16, "a tag of its own: the ordinary listing asks for links with none");
        assert!(!a.tag.windows(12).any(|w| w == &a.key[..12]), "the tag says nothing of the key");
        let other = super::OpenList::from_backup_key(&[8u8; 32]);
        assert_ne!((a.key, a.tag), (other.key, other.tag), "another identity, another list");
    }

    #[test]
    fn a_backup_counts_once_across_the_two_lists_and_the_record_written_last_counts() {
        let a = "a".repeat(32);
        let b = "b".repeat(32);
        // Device a wrote both lists; then, locked, changed one backup and
        // dropped another in the open list only.
        let sealed = vec![slot_item(&a, "manifest", "old", false, 10), slot_item(&a, "conv-1", "c1", false, 10), slot_item(&b, "manifest", "b-old", false, 10)];
        let open = vec![
            slot_item(&a, "manifest", "new", false, 20),
            slot_item(&a, "conv-1", "c1", true, 20),
            slot_item(&a, "conv-2", "c2", false, 20),
            // An older open record does not undo a newer sealed one (a
            // device back on a Vault from before the open list).
            slot_item(&b, "manifest", "b-older", false, 5),
            super::tests::listed(super::REACH_ENTRY_TYPE, serde_json::json!({"install_id": a, "conductor_key": "k", "generation": "holochain-0.7"}), 20),
        ];
        let merged = super::merged_slot_records(&sealed, &open);
        assert_eq!(merged.len(), 4, "one per device, app and label: {merged:?}");
        let of = |install: &str, label: &str| merged.iter().find(|r| r.install_id == install && r.slot.label == label).unwrap();
        assert_eq!(of(&a, "manifest").slot.sha256, "new");
        assert!(of(&a, "conv-1").gone);
        assert_eq!(of(&a, "conv-2").slot.sha256, "c2");
        assert_eq!(of(&b, "manifest").slot.sha256, "b-old");
        let indexes = super::indexes_of(&merged);
        let a_index = indexes.iter().find(|i| i.install_id == a).unwrap();
        assert_eq!(a_index.slots.iter().map(|s| s.label.as_str()).collect::<Vec<_>>(), vec!["conv-2", "manifest"], "a backup that is gone is in no index");
        assert_eq!(super::reach_records_in(&open), vec![super::ReachRecord { install_id: a.clone(), conductor_key: "k".into(), generation: "holochain-0.7".into() }]);
        assert!(super::merged_slot_records(&sealed, &[]).len() == 3 && super::merged_slot_records(&[], &open).len() == 4, "either list alone stands");
    }

    #[test]
    fn a_new_announcement_is_fresh_once_and_a_first_round_takes_all() {
        use super::fresh_announcements;
        let a = "dev/app/manifest/aaa".to_string();
        let b = "dev/app/ais/bbb".to_string();
        let (fresh, seen) = fresh_announcements(None, &[a.clone()]);
        assert!(fresh.contains(&a), "first round: everything is fresh");
        let (fresh, seen) = fresh_announcements(Some(&seen), &[a.clone(), b.clone()]);
        assert!(!fresh.contains(&a), "still missing from before: waits for the slower schedule");
        assert!(fresh.contains(&b), "announced since the last round: copied now");
        let b2 = "dev/app/ais/ccc".to_string();
        let (fresh, _) = fresh_announcements(Some(&seen), &[a, b2.clone()]);
        assert!(fresh.contains(&b2), "a new version of the same backup is a new announcement");
    }

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

    /// The totals count the copies kept of another device's backups in the
    /// apps and bytes held here, not in the backups made here (a Mac holding
    /// only copies read "3 apps · 0 B").
    #[test]
    fn copies_count_in_what_is_held_not_in_what_was_made_here() {
        let tmp = tempfile::tempdir().unwrap();
        write_own(tmp.path(), "app", "latest", 10, "made here");
        let slot = SlotInfo { label: "latest".into(), created_at: 20, size: 0, sha256: String::new() };
        let bytes = file("other_app", "latest", 20, "kept from the other device");
        let path = copy_path(tmp.path(), OTHER, "other_app", &slot.label);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        let stats = crate::backup::get_backup_stats(tmp.path());
        assert_eq!(stats.app_count, 2);
        assert_eq!(stats.total_backups, 1, "only the backup made here");
        assert_eq!(stats.total_size as usize, "made here".len() + "kept from the other device".len());
        assert_eq!(stats.apps.iter().filter(|a| a.from_device.as_deref() == Some(OTHER)).count(), 1);
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
