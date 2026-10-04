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

/// A device refreshes its own record at most this often when nothing about
/// it changed: each refresh is a new entry every device keeps.
const REFRESH_AFTER_MS: u64 = 24 * 60 * 60 * 1000;

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
        // A removed device does not write itself back in.
        return false;
    }
    existing.conductor_key != current.conductor_key
        || existing.name != current.name
        || existing.platform != current.platform
        || existing.vault_version != current.vault_version
        || existing.generation != current.generation
        || current.seen_at.saturating_sub(existing.seen_at) >= REFRESH_AFTER_MS
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

/// Every device record in a listing, newest-added first.
pub fn devices_in(records: &[SealedListItem]) -> Vec<DeviceRecord> {
    let mut devices: Vec<DeviceRecord> = records.iter().filter_map(parse).collect();
    devices.sort_by(|a, b| b.added_at.cmp(&a.added_at).then_with(|| a.install_id.cmp(&b.install_id)));
    devices
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
