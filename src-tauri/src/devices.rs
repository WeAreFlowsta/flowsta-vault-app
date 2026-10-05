//! The devices of one identity, as each of them knows them.
//!
//! Every device keeps one record about itself in the identity's private
//! network: what it is called, which conductor key it runs, which version
//! it is on and how recent the records it holds are. The records are
//! ordinary sealed records (type `device`, one logical id per install), so
//! they reach every other device with everything else and the newest
//! version of each wins.
//!
//! This is what a device knows about its siblings without any server. It
//! decides nothing about who may sign in.

use crate::commands::AppState;
use crate::sealed::{SealedListItem, StoreSpec};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Devices on different network generations cannot sync with each other.
/// Bumped with a breaking conductor upgrade.
pub const NETWORK_GENERATION: &str = "holochain-0.6";

pub const DEVICE_ENTRY_TYPE: &str = "device";
/// A removal is its own record, so that a removed device's routine refresh
/// of its record (written before it heard) can never overwrite it.
pub const REMOVAL_ENTRY_TYPE: &str = "device_removed";

/// A device refreshes its own record at most this often when nothing about
/// it changed: each refresh is a new entry every device keeps.
const REFRESH_AFTER_MS: u64 = 24 * 60 * 60 * 1000;

/// A device whose records changed says so again no sooner than this (the
/// other devices read "up to date" from it).
const REFRESH_AFTER_CHANGE_MS: u64 = 4 * 60 * 1000;

/// A device that has not refreshed its record for this long is "not seen".
const NOT_SEEN_AFTER_MS: u64 = 3 * REFRESH_AFTER_MS;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DeviceRecord {
    pub install_id: String,
    /// The conductor agent key this device runs (standard base64 of the 39
    /// bytes, network form).
    pub conductor_key: String,
    pub name: String,
    /// "linux", "macos" or "windows".
    pub platform: String,
    pub vault_version: String,
    pub generation: String,
    pub added_at: u64,
    /// When this device last wrote this record (ms).
    pub seen_at: u64,
    /// The newest version time among the records this device held then
    /// (device records left out).
    pub latest_change: u64,
    #[serde(default)]
    pub removed_at: Option<u64>,
    /// The install that removed it.
    #[serde(default)]
    pub removed_by: Option<String>,
}

pub fn device_logical_id(install_id: &str) -> String {
    format!("{}:{}", DEVICE_ENTRY_TYPE, install_id)
}

/// A device (this install running this key) was removed from the identity.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DeviceRemoval {
    pub install_id: String,
    pub conductor_key: String,
    pub removed_at: u64,
    pub removed_by: String,
}

pub fn removal_logical_id(install_id: &str, conductor_key: &str) -> String {
    format!("{}:{}:{}", REMOVAL_ENTRY_TYPE, install_id, conductor_key)
}

/// How one device stands, seen from another. The page turns each into one
/// short line.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeviceState {
    ThisDevice,
    UpToDate,
    /// Holds everything up to this time (ms).
    LastSynced { at: u64 },
    NotSeenSince { at: u64 },
    /// On another network generation: it syncs again once it is updated.
    NeedsUpdate,
    Removed,
}

/// The state of `device` as the device `viewer_install_id` sees it now.
/// `viewer_latest_change` is the newest version time the viewer holds.
pub fn device_state(device: &DeviceRecord, viewer_install_id: &str, viewer_latest_change: u64, now_ms: u64) -> DeviceState {
    if device.removed_at.is_some() {
        return DeviceState::Removed;
    }
    if device.install_id == viewer_install_id {
        return DeviceState::ThisDevice;
    }
    if device.generation != NETWORK_GENERATION {
        return DeviceState::NeedsUpdate;
    }
    if now_ms.saturating_sub(device.seen_at) > NOT_SEEN_AFTER_MS {
        return DeviceState::NotSeenSince { at: device.seen_at };
    }
    if device.latest_change >= viewer_latest_change {
        DeviceState::UpToDate
    } else {
        DeviceState::LastSynced { at: device.seen_at }
    }
}

/// Whether a device should write its record again: when something about it
/// changed, or when the last one is a day old.
pub fn needs_refresh(existing: Option<&DeviceRecord>, current: &DeviceRecord) -> bool {
    let Some(existing) = existing else {
        return true;
    };
    if existing.removed_at.is_some() {
        // A removed device does not write itself back in. The same install
        // added again runs a new key: that is a new device.
        return existing.conductor_key != current.conductor_key;
    }
    existing.conductor_key != current.conductor_key
        || existing.name != current.name
        || existing.platform != current.platform
        || existing.vault_version != current.vault_version
        || existing.generation != current.generation
        || current.seen_at.saturating_sub(existing.seen_at) >= REFRESH_AFTER_MS
        || (current.latest_change > existing.latest_change
            && current.seen_at.saturating_sub(existing.seen_at) >= REFRESH_AFTER_CHANGE_MS)
}

/// Whether the records say this device (this install, running this key)
/// was removed from the identity.
pub fn removed_here(devices: &[DeviceRecord], install_id: &str, conductor_key: &str) -> bool {
    devices
        .iter()
        .any(|d| d.install_id == install_id && d.conductor_key == conductor_key && d.removed_at.is_some())
}

/// The newest version time among records that are not device records.
pub fn latest_change(records: &[SealedListItem]) -> u64 {
    records
        .iter()
        .filter(|r| r.entry_type != DEVICE_ENTRY_TYPE)
        .map(|r| r.updated_at)
        .max()
        .unwrap_or(0)
}

fn parse(item: &SealedListItem) -> Option<DeviceRecord> {
    if item.entry_type != DEVICE_ENTRY_TYPE {
        return None;
    }
    serde_json::from_value(item.body.clone()).ok()
}

/// Every device record in a listing, newest-added first, with removals
/// applied: a device whose key has a removal record reads as removed
/// whatever its own record says.
pub fn devices_in(records: &[SealedListItem]) -> Vec<DeviceRecord> {
    let removals: Vec<DeviceRemoval> = records
        .iter()
        .filter(|r| r.entry_type == REMOVAL_ENTRY_TYPE)
        .filter_map(|r| serde_json::from_value(r.body.clone()).ok())
        .collect();
    let mut devices: Vec<DeviceRecord> = records.iter().filter_map(parse).collect();
    for device in &mut devices {
        if device.removed_at.is_some() {
            continue;
        }
        if let Some(removal) = removals.iter().find(|x| x.install_id == device.install_id && x.conductor_key == device.conductor_key) {
            device.removed_at = Some(removal.removed_at);
            device.removed_by = Some(removal.removed_by.clone());
        }
    }
    devices.sort_by(|a, b| b.added_at.cmp(&a.added_at).then_with(|| a.install_id.cmp(&b.install_id)));
    devices
}

/// The conductor key of every device the identity has or had, as written
/// in its own records (removed devices and earlier keys of a device added
/// again included: what they signed is still this person's).
pub fn conductor_keys_ever(records: &[SealedListItem]) -> Vec<String> {
    let mut keys: Vec<String> = devices_in(records).into_iter().map(|d| d.conductor_key).collect();
    keys.extend(
        records
            .iter()
            .filter(|r| r.entry_type == REMOVAL_ENTRY_TYPE)
            .filter_map(|r| serde_json::from_value::<DeviceRemoval>(r.body.clone()).ok())
            .map(|x| x.conductor_key),
    );
    keys.sort();
    keys.dedup();
    keys
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn device_name() -> String {
    sysinfo::System::host_name()
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "This device".to_string())
}

/// This device's record as it stands now, keeping what an earlier record of
/// it fixed (when it was added, a name the person gave it).
fn own_record(state: &AppState, existing: Option<&DeviceRecord>, latest_change: u64) -> Result<DeviceRecord, String> {
    let install_id = crate::paths::install_id(&state.data_dir).ok_or("no install id")?;
    let conductor_key = {
        let config = state.vault_config.lock().unwrap();
        let seed = config
            .as_ref()
            .ok_or("vault_locked")?
            .conductor_seed_bytes()
            .ok_or("no conductor seed")?;
        crate::key_derivation::base64_standard_encode(&crate::key_derivation::holo_agent_pub_key_bytes(
            &crate::key_derivation::public_key_of_seed(&seed),
        ))
    };
    let now = now_ms();
    Ok(DeviceRecord {
        install_id,
        conductor_key,
        name: existing.map(|e| e.name.clone()).unwrap_or_else(device_name),
        platform: std::env::consts::OS.to_string(),
        vault_version: env!("CARGO_PKG_VERSION").to_string(),
        generation: NETWORK_GENERATION.to_string(),
        added_at: existing.map(|e| e.added_at).unwrap_or(now),
        seen_at: now,
        latest_change,
        removed_at: None,
        removed_by: None,
    })
}

/// A device as this one last saw it. Kept on this device only.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KnownDevice {
    pub install_id: String,
    pub conductor_key: String,
    pub removed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DeviceChange {
    Added(DeviceRecord),
    Removed(DeviceRecord),
}

fn known(devices: &[DeviceRecord]) -> Vec<KnownDevice> {
    devices
        .iter()
        .map(|d| KnownDevice { install_id: d.install_id.clone(), conductor_key: d.conductor_key.clone(), removed: d.removed_at.is_some() })
        .collect()
}

/// What changed among the identity's OTHER devices since this one last
/// looked: a device added after this one that it had not seen, or one
/// removed by another device. Devices that were there before this one
/// joined are not news when their records arrive.
/// `before` is `None` the first time (nothing to compare with).
pub fn changes_since(before: Option<&[KnownDevice]>, devices: &[DeviceRecord], me: &str) -> Vec<DeviceChange> {
    let Some(before) = before else {
        return Vec::new();
    };
    let my_added_at = devices.iter().find(|d| d.install_id == me).map(|d| d.added_at).unwrap_or(0);
    let mut changes = Vec::new();
    for device in devices.iter().filter(|d| d.install_id != me) {
        let seen = before
            .iter()
            .find(|k| k.install_id == device.install_id && k.conductor_key == device.conductor_key);
        match (seen, device.removed_at.is_some()) {
            (None, false) if device.added_at > my_added_at => changes.push(DeviceChange::Added(device.clone())),
            (Some(k), true) if !k.removed && device.removed_by.as_deref() != Some(me) => {
                changes.push(DeviceChange::Removed(device.clone()))
            }
            _ => {}
        }
    }
    changes
}

/// This device just added another one: it is not news here.
pub fn remember_added(state: &AppState, install_id: &str, device_public: &[u8; 32]) {
    let path = crate::paths::known_devices_path(&state.identity_root());
    let mut list: Vec<KnownDevice> = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    list.push(KnownDevice {
        install_id: install_id.to_string(),
        conductor_key: crate::key_derivation::base64_standard_encode(&crate::key_derivation::holo_agent_pub_key_bytes(device_public)),
        removed: false,
    });
    if let Ok(bytes) = serde_json::to_vec(&list) {
        let _ = std::fs::write(&path, bytes);
    }
}

/// Notice devices added or removed elsewhere: one Activity line each and a
/// `devices-changed` event for the page. Returns the changes.
pub async fn notice_changes(state: &Arc<AppState>) -> Result<Vec<DeviceChange>, String> {
    let devices = list(state).await?;
    let me = crate::paths::install_id(&state.data_dir).ok_or("no install id")?;
    let path = crate::paths::known_devices_path(&state.identity_root());
    let before: Option<Vec<KnownDevice>> = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let changes = changes_since(before.as_deref(), &devices, &me);
    for change in &changes {
        match change {
            DeviceChange::Added(d) => state.activity.record(
                "device_added_elsewhere",
                format!("{} was added to your identity", d.name),
                Some("Not you? Remove it in Settings, Devices.".into()),
                None,
                None,
            ),
            DeviceChange::Removed(d) => {
                state.activity.record("device_removed_elsewhere", format!("{} was removed from your devices", d.name), None, None, None)
            }
        }
    }
    let mut now = known(&devices);
    // A device this one added whose record has not arrived yet stays known.
    for earlier in before.as_deref().unwrap_or(&[]) {
        if !now.iter().any(|k| k.install_id == earlier.install_id && k.conductor_key == earlier.conductor_key) {
            now.push(earlier.clone());
        }
    }
    if before.as_deref() != Some(now.as_slice()) {
        if let Ok(bytes) = serde_json::to_vec(&now) {
            let _ = std::fs::write(&path, bytes);
        }
    }
    Ok(changes)
}

/// Whether this device reads itself as removed, from the records it holds now.
pub async fn removed_here_now(state: &Arc<AppState>) -> Result<bool, String> {
    let records = crate::sealed::sealed_list_inner(state).await?;
    let install_id = crate::paths::install_id(&state.data_dir).ok_or("no install id")?;
    let current = own_record(state, None, 0)?;
    Ok(removed_here(&devices_in(&records), &install_id, &current.conductor_key))
}

/// The identity's devices as this device knows them.
pub async fn list(state: &Arc<AppState>) -> Result<Vec<DeviceRecord>, String> {
    Ok(devices_in(&crate::sealed::sealed_list_inner(state).await?))
}

/// Write this device's record when it is missing, changed or a day old.
/// Returns whether a record was written.
pub async fn publish_own(state: &Arc<AppState>) -> Result<bool, String> {
    let records = crate::sealed::sealed_list_inner(state).await?;
    let install_id = crate::paths::install_id(&state.data_dir).ok_or("no install id")?;
    let existing_item = records
        .iter()
        .find(|r| r.entry_type == DEVICE_ENTRY_TYPE && r.id == device_logical_id(&install_id));
    let existing = existing_item.and_then(parse);
    let current = own_record(state, existing.as_ref(), latest_change(&records))?;
    if !needs_refresh(existing.as_ref(), &current) {
        return Ok(false);
    }
    let supersedes = existing_item.and_then(|item| {
        hex::decode(&item.action_hash)
            .ok()
            .filter(|b| b.len() == 39)
            .map(holochain_types::prelude::ActionHash::from_raw_39)
    });
    crate::sealed::sealed_store_spec(
        state,
        StoreSpec {
            entry_type: DEVICE_ENTRY_TYPE.to_string(),
            body: serde_json::to_value(&current).map_err(|e| e.to_string())?,
            refs: Vec::new(),
            created_at: current.added_at,
            id: Some(device_logical_id(&current.install_id)),
            updated_at: Some(current.seen_at),
            deleted: false,
        },
        supersedes,
    )
    .await?;
    Ok(true)
}

/// What a device that joined an identity can say about the first minutes:
/// which other devices it knows of and whether their records have arrived.
#[derive(Serialize, Debug, PartialEq)]
pub struct SiblingSync {
    /// This device was added to an identity that already existed.
    pub joined: bool,
    /// Names of the other devices whose records are here (removed ones left out).
    pub other_devices: Vec<String>,
    /// Records written by another device have arrived (anything, not only device records).
    pub records_arrived: bool,
}

pub fn sibling_sync_in(records: &[SealedListItem], me: &str, joined: bool) -> SiblingSync {
    let other_devices = devices_in(records)
        .into_iter()
        .filter(|d| d.install_id != me && d.removed_at.is_none())
        .map(|d| d.name)
        .collect();
    let records_arrived = records.iter().any(|r| r.device.as_deref().map(|d| d != me).unwrap_or(false));
    SiblingSync { joined, other_devices, records_arrived }
}

/// For the first minutes after a device joins: what has arrived.
#[tauri::command]
pub async fn sibling_sync(state: tauri::State<'_, Arc<AppState>>) -> Result<SiblingSync, String> {
    let joined = state.vault_config.lock().unwrap().as_ref().map(|c| c.joined_existing).unwrap_or(false);
    let me = crate::paths::install_id(&state.data_dir).ok_or("no install id")?;
    let records = crate::sealed::sealed_list_inner(&state).await?;
    Ok(sibling_sync_in(&records, &me, joined))
}

/// One row of Settings → Devices.
#[derive(Serialize)]
pub struct DeviceRow {
    pub install_id: String,
    pub name: String,
    pub platform: String,
    pub added_at: u64,
    #[serde(flatten)]
    pub state: DeviceState,
}

/// The identity's devices, this one first, as this device knows them.
#[tauri::command]
pub async fn devices_list(state: tauri::State<'_, Arc<AppState>>) -> Result<Vec<DeviceRow>, String> {
    devices_list_inner(state.inner()).await
}

pub(crate) async fn devices_list_inner(state: &Arc<AppState>) -> Result<Vec<DeviceRow>, String> {
    let records = crate::sealed::sealed_list_inner(state).await?;
    let me = crate::paths::install_id(&state.data_dir).ok_or("no install id")?;
    let mine = latest_change(&records);
    let now = now_ms();
    let mut rows: Vec<DeviceRow> = devices_in(&records)
        .into_iter()
        .map(|d| DeviceRow {
            state: device_state(&d, &me, mine, now),
            install_id: d.install_id,
            name: d.name,
            platform: d.platform,
            added_at: d.added_at,
        })
        .collect();
    rows.sort_by_key(|r| (r.state != DeviceState::ThisDevice, r.state == DeviceState::Removed));
    Ok(rows)
}

/// The 32-byte key (standard base64) inside a device record's conductor key.
fn key32_of(conductor_key: &str) -> Option<String> {
    let raw = crate::commands::base64_standard_decode(conductor_key).ok()?;
    (raw.len() == 39).then(|| crate::key_derivation::base64_standard_encode(&raw[3..35]))
}

/// Remove a device of this identity: it can no longer sign in, and its
/// record says so to every device (itself included, which then stands down).
#[tauri::command]
pub async fn device_remove(api_url: String, install_id: String, state: tauri::State<'_, Arc<AppState>>) -> Result<(), String> {
    device_remove_inner(api_url, install_id, state.inner()).await
}

pub(crate) async fn device_remove_inner(api_url: String, install_id: String, state: &Arc<AppState>) -> Result<(), String> {
    let records = crate::sealed::sealed_list_inner(state).await?;
    let me = crate::paths::install_id(&state.data_dir).ok_or("no install id")?;
    let device = devices_in(&records)
        .into_iter()
        .find(|d| d.install_id == install_id)
        .ok_or("unknown_device")?;
    if device.removed_at.is_some() {
        return Ok(());
    }
    // Flowsta's servers first: without them the device could still sign in.
    let target = key32_of(&device.conductor_key).ok_or("unknown_device")?;
    match crate::device_registry::remove_device(state, &api_url, &target).await {
        Ok(()) => {}
        // A device that never reached the servers has nothing to remove there.
        Err(e) if e.starts_with("unknown_device") => {}
        Err(e) => return Err(e),
    }
    let now = now_ms();
    // The removal is its own record (nothing the removed device writes can
    // overwrite it), and the device's record says so too.
    let removal = DeviceRemoval { install_id: device.install_id.clone(), conductor_key: device.conductor_key.clone(), removed_at: now, removed_by: me.clone() };
    crate::sealed::sealed_store_spec(
        state,
        StoreSpec {
            entry_type: REMOVAL_ENTRY_TYPE.to_string(),
            body: serde_json::to_value(&removal).map_err(|e| e.to_string())?,
            refs: Vec::new(),
            created_at: now,
            id: Some(removal_logical_id(&removal.install_id, &removal.conductor_key)),
            updated_at: Some(now),
            deleted: false,
        },
        None,
    )
    .await?;
    let removed = DeviceRecord { removed_at: Some(now), removed_by: Some(me), seen_at: device.seen_at, ..device.clone() };
    crate::sealed::sealed_store_spec(
        state,
        StoreSpec {
            entry_type: DEVICE_ENTRY_TYPE.to_string(),
            body: serde_json::to_value(&removed).map_err(|e| e.to_string())?,
            refs: Vec::new(),
            created_at: removed.added_at,
            id: Some(device_logical_id(&removed.install_id)),
            updated_at: Some(now),
            deleted: false,
        },
        None,
    )
    .await?;
    state.activity.record("device_removed", format!("Removed {} from your devices", device.name), None, None, None);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = REFRESH_AFTER_MS;

    fn device(install_id: &str) -> DeviceRecord {
        DeviceRecord {
            install_id: install_id.into(),
            conductor_key: "key".into(),
            name: "Office PC".into(),
            platform: "windows".into(),
            vault_version: "1.6.0".into(),
            generation: NETWORK_GENERATION.into(),
            added_at: 1_000,
            seen_at: 100 * DAY,
            latest_change: 500,
            removed_at: None,
            removed_by: None,
        }
    }

    #[test]
    fn each_device_reads_as_one_plain_state() {
        let now = 100 * DAY + 1000;
        let d = device("other");
        assert_eq!(device_state(&d, "other", 500, now), DeviceState::ThisDevice);
        assert_eq!(device_state(&d, "me", 500, now), DeviceState::UpToDate);
        assert_eq!(device_state(&d, "me", 400, now), DeviceState::UpToDate, "it holds newer than I do");
        assert_eq!(device_state(&d, "me", 900, now), DeviceState::LastSynced { at: 100 * DAY });
        assert_eq!(device_state(&d, "me", 900, now + 4 * DAY), DeviceState::NotSeenSince { at: 100 * DAY });
    }

    #[test]
    fn a_device_on_another_generation_needs_the_update_whatever_else_is_true() {
        let mut d = device("other");
        d.generation = "holochain-0.7".into();
        assert_eq!(device_state(&d, "me", 0, 100 * DAY), DeviceState::NeedsUpdate);
        assert_eq!(device_state(&d, "me", 0, 200 * DAY), DeviceState::NeedsUpdate, "not 'not seen': it may be in use every day");
    }

    #[test]
    fn a_removed_device_reads_as_removed_even_to_itself() {
        let mut d = device("other");
        d.removed_at = Some(5);
        assert_eq!(device_state(&d, "me", 0, 100 * DAY), DeviceState::Removed);
        assert_eq!(device_state(&d, "other", 0, 100 * DAY), DeviceState::Removed);
    }

    #[test]
    fn a_device_writes_its_record_when_new_changed_or_a_day_old() {
        let existing = device("me");
        let mut current = existing.clone();
        assert!(needs_refresh(None, &current));
        assert!(!needs_refresh(Some(&existing), &current), "nothing changed, written just now");
        current.seen_at = existing.seen_at + DAY - 1;
        assert!(!needs_refresh(Some(&existing), &current));
        current.seen_at = existing.seen_at + DAY;
        assert!(needs_refresh(Some(&existing), &current));
        // It holds something newer: said again, but not more often than every few minutes.
        let mut holds_more = existing.clone();
        holds_more.latest_change = existing.latest_change + 1;
        holds_more.seen_at = existing.seen_at + REFRESH_AFTER_CHANGE_MS - 1;
        assert!(!needs_refresh(Some(&existing), &holds_more));
        holds_more.seen_at = existing.seen_at + REFRESH_AFTER_CHANGE_MS;
        assert!(needs_refresh(Some(&existing), &holds_more));
        let mut renamed = existing.clone();
        renamed.vault_version = "1.6.1".into();
        assert!(needs_refresh(Some(&existing), &renamed));
        let mut rekeyed = existing.clone();
        rekeyed.conductor_key = "other".into();
        assert!(needs_refresh(Some(&existing), &rekeyed));
    }

    #[test]
    fn a_removed_device_does_not_write_itself_back_in() {
        let mut existing = device("me");
        existing.removed_at = Some(9);
        let mut current = device("me");
        current.seen_at = existing.seen_at + 10 * DAY;
        current.vault_version = "9.9.9".into();
        assert!(!needs_refresh(Some(&existing), &current));
        // Added again, the same install runs a new key: a new device.
        current.conductor_key = "new key".into();
        assert!(needs_refresh(Some(&existing), &current));
    }

    #[test]
    fn a_device_notices_one_added_or_removed_elsewhere_once() {
        let mine = device("me");
        let mut other = device("other");
        other.conductor_key = "other key".into();
        other.added_at = mine.added_at + 1;
        // A device that was there before this one joined is not news.
        let mut older = device("older");
        older.added_at = mine.added_at - 1;
        assert!(changes_since(Some(&known(&[mine.clone()])), &[mine.clone(), older], "me").is_empty());
        // The first look has nothing to compare with.
        assert!(changes_since(None, &[mine.clone(), other.clone()], "me").is_empty());
        // A device this one had not seen.
        let before = known(&[mine.clone()]);
        assert_eq!(changes_since(Some(&before), &[mine.clone(), other.clone()], "me"), vec![DeviceChange::Added(other.clone())]);
        // Seen once, it is not news again.
        let before = known(&[mine.clone(), other.clone()]);
        assert!(changes_since(Some(&before), &[mine.clone(), other.clone()], "me").is_empty());
        // Removed by a third device: news. Removed by this one: not.
        let mut removed = other.clone();
        removed.removed_at = Some(5);
        removed.removed_by = Some("third".into());
        assert_eq!(changes_since(Some(&before), &[mine.clone(), removed.clone()], "me"), vec![DeviceChange::Removed(removed.clone())]);
        removed.removed_by = Some("me".into());
        assert!(changes_since(Some(&before), &[mine.clone(), removed.clone()], "me").is_empty());
        // Its own record is never news; a device first seen already removed is not either.
        assert!(changes_since(Some(&[]), &[mine.clone(), removed], "me").is_empty());
    }

    #[test]
    fn a_device_reads_its_own_removal_and_nobody_elses() {
        let mut removed = device("me");
        removed.removed_at = Some(9);
        let other = device("other");
        assert!(removed_here(&[other.clone(), removed.clone()], "me", "key"));
        assert!(!removed_here(&[other.clone()], "me", "key"));
        assert!(!removed_here(&[removed.clone()], "other", "key"), "another install's removal");
        assert!(!removed_here(&[removed], "me", "new key"), "this install was added again with a new key");
        assert!(!removed_here(&[device("me")], "me", "key"));
    }

    #[test]
    fn the_key_to_remove_is_the_32_bytes_inside_the_devices_conductor_key() {
        let public = [9u8; 32];
        let conductor_key = crate::key_derivation::base64_standard_encode(&crate::key_derivation::holo_agent_pub_key_bytes(&public));
        assert_eq!(key32_of(&conductor_key), Some(crate::key_derivation::base64_standard_encode(&public)));
        assert_eq!(key32_of("AAAA"), None);
    }

    #[test]
    fn a_removal_holds_even_when_the_removed_device_writes_its_record_again() {
        let item = |entry_type: &str, body: serde_json::Value| SealedListItem {
            action_hash: String::new(),
            entry_type: entry_type.into(),
            created_at: 0,
            body,
            refs: vec![],
            id: String::new(),
            updated_at: 0,
            device: None,
        };
        // The removed device's record, refreshed AFTER the removal (its own
        // routine write before it heard): no removed_at on it.
        let fresh = device("other");
        let records = vec![
            item(DEVICE_ENTRY_TYPE, serde_json::to_value(&fresh).unwrap()),
            item(REMOVAL_ENTRY_TYPE, serde_json::json!({ "install_id": "other", "conductor_key": "key", "removed_at": 77, "removed_by": "me" })),
        ];
        let seen = devices_in(&records);
        assert_eq!(seen[0].removed_at, Some(77));
        assert_eq!(seen[0].removed_by.as_deref(), Some("me"));
        assert!(removed_here(&seen, "other", "key"));
        // The same install added again with a new key is not removed.
        let mut readded = device("other");
        readded.conductor_key = "new key".into();
        let records2 = vec![item(DEVICE_ENTRY_TYPE, serde_json::to_value(&readded).unwrap()), records[1].clone()];
        assert_eq!(devices_in(&records2)[0].removed_at, None);
    }

    #[test]
    fn a_joined_device_knows_when_its_siblings_records_have_arrived() {
        let item = |entry_type: &str, body: serde_json::Value, device: Option<&str>| SealedListItem {
            action_hash: String::new(),
            entry_type: entry_type.into(),
            created_at: 0,
            body,
            refs: vec![],
            id: String::new(),
            updated_at: 0,
            device: device.map(String::from),
        };
        let mine = item(DEVICE_ENTRY_TYPE, serde_json::to_value(device("me")).unwrap(), Some("me"));
        let early = sibling_sync_in(&[mine.clone()], "me", true);
        assert_eq!(early, SiblingSync { joined: true, other_devices: vec![], records_arrived: false });
        let mut other = device("other");
        other.name = "MacBook".into();
        let later = sibling_sync_in(&[mine, item(DEVICE_ENTRY_TYPE, serde_json::to_value(&other).unwrap(), Some("other")), item("user_profile", serde_json::json!({}), Some("other"))], "me", true);
        assert_eq!(later.other_devices, vec!["MacBook".to_string()]);
        assert!(later.records_arrived);
    }

    #[test]
    fn device_records_do_not_count_as_a_change_to_catch_up_on() {
        let item = |entry_type: &str, updated_at: u64| SealedListItem {
            action_hash: String::new(),
            entry_type: entry_type.into(),
            created_at: 0,
            body: serde_json::Value::Null,
            refs: vec![],
            id: String::new(),
            updated_at,
            device: None,
        };
        assert_eq!(latest_change(&[item("user_profile", 40), item(DEVICE_ENTRY_TYPE, 900), item("login_activity", 70)]), 70);
        assert_eq!(latest_change(&[item(DEVICE_ENTRY_TYPE, 900)]), 0);
    }
}
