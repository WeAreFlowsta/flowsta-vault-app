//! App backups across the identity's devices.
//!
//! This device's own backups stay where they have always been and every
//! backup request answers from them as before. Beside them, each device
//! keeps a copy of the backups its sibling devices hold:
//!
//!   backups/<app>/<label>.enc                     this device's (unchanged)
//!   backups-from/<install id>/<app>/<label>.enc   copies of another device's
//!
//! Each device says what it holds in one sealed record per app (its index:
//! for every label a time, a size and the SHA-256 of the encrypted file).
//! A device makes its copies match the other devices' indexes: what an
//! index lists and is missing or different here is fetched, what an index
//! no longer lists is dropped. An index is the truth for its own device's
//! backups, and a device that is gone keeps its last index, so its copies
//! stay.
//!
//! The copies are the encrypted files as the other device wrote them. Both
//! backup keys are on every device of the identity, so they open here.

use crate::backup::BackupMeta;
use crate::sealed::SealedListItem;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const INDEX_ENTRY_TYPE: &str = "backup_index";

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

pub fn index_id(install_id: &str, client_id: &str) -> String {
    format!("{}:{}:{}", INDEX_ENTRY_TYPE, install_id, client_id)
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

/// Every device's index found in a listing of the identity's records.
pub fn indexes_in(records: &[SealedListItem]) -> Vec<AppIndex> {
    records
        .iter()
        .filter(|r| r.entry_type == INDEX_ENTRY_TYPE)
        .filter_map(|r| serde_json::from_value::<AppIndex>(r.body.clone()).ok())
        .filter(|i| is_install_id(&i.install_id))
        .collect()
}

/// The indexes this device should write: one per app whose index changed,
/// and an empty one for an app it no longer holds anything of.
pub fn indexes_to_write(mine: &[AppIndex], recorded: &[AppIndex], install_id: &str) -> Vec<AppIndex> {
    let mut out: Vec<AppIndex> = mine
        .iter()
        .filter(|index| !recorded.iter().any(|r| r == *index))
        .cloned()
        .collect();
    for old in recorded.iter().filter(|r| r.install_id == install_id && !r.slots.is_empty()) {
        if !mine.iter().any(|m| m.client_id == old.client_id) {
            out.push(AppIndex { slots: Vec::new(), ..old.clone() });
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
    let dir = crate::paths::backups_dir(identity_root).join(crate::backup::sanitize_id(client_id));
    let path = dir.join(format!("{}.enc", crate::backup::sanitize_id(&slot.label)));
    let bytes = std::fs::read(path).ok()?;
    (sha256_hex(&bytes) == slot.sha256).then_some(bytes)
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
pub fn newest_across_devices(identity_root: &Path, client_id: &str, label: &str) -> Option<Held> {
    held_across_devices(identity_root, client_id)
        .into_iter()
        .filter(|h| h.meta.label.as_deref() == Some(label))
        .max_by_key(|h| (h.meta.created_at, h.from_install.is_none()))
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
    fn an_index_is_written_only_when_it_changed_and_emptied_when_the_app_has_nothing_left() {
        let tmp = tempfile::tempdir().unwrap();
        write_own(tmp.path(), "app", "latest", 10, "one");
        let mine = local_index(tmp.path(), ME);
        assert_eq!(indexes_to_write(&mine, &[], ME), mine);
        assert!(indexes_to_write(&mine, &mine, ME).is_empty());
        // A new backup under the same label: the index changed.
        std::thread::sleep(std::time::Duration::from_millis(20));
        write_own(tmp.path(), "app", "latest", 11, "one-b");
        let changed = local_index(tmp.path(), ME);
        assert_eq!(indexes_to_write(&changed, &mine, ME), changed);
        // Everything deleted here: the index says so (once).
        let emptied = indexes_to_write(&[], &changed, ME);
        assert_eq!(emptied.len(), 1);
        assert!(emptied[0].slots.is_empty());
        assert!(indexes_to_write(&[], &emptied, ME).is_empty());
        // Another device's index is never rewritten from here.
        let theirs = AppIndex { install_id: OTHER.into(), ..changed[0].clone() };
        assert!(indexes_to_write(&[], &[theirs], ME).is_empty());
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
        assert!(newest_across_devices(here.path(), "app", "missing").is_none());
        assert!(held_across_devices(here.path(), "another_app").is_empty());

        // This device's own wins a tie.
        write_own(here.path(), "app", "recovery", 30, "mine again");
        assert_eq!(newest_across_devices(here.path(), "app", "recovery").unwrap().from_install, None);
    }
}
