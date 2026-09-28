//! The identities this Vault holds (Phase 4, the switcher).
//!
//! Each identity lives under `identities/<partition key>/` (Phase 2); a
//! pre-1.4.0 install may still hold one at the device root ("legacy").
//! Before unlock the Vault cannot read any of them, so each identity root
//! carries a small public label - display name, username, picture, the
//! agent key - written at every unlock. That is the same material the
//! public profile page shows, and it is what the unlock screen lists.
//!
//! Selecting an identity while locked only repoints the app state at that
//! root (`AppState::repoint_root`); nothing on disk changes until the
//! unlock succeeds, which writes the active-identity marker and bumps the
//! identity epoch as it always did. One conductor at a time by
//! construction: selecting is refused while unlocked or while a conductor
//! runs.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::commands::AppState;

pub const LABEL_FILE: &str = "label.json";
pub const LEGACY_KEY: &str = "legacy";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct IdentityLabel {
    pub agent_pub_key: String,
    pub display_name: Option<String>,
    pub username: Option<String>,
    pub profile_picture: Option<String>,
    pub email: Option<String>,
}

pub fn label_path(root: &Path) -> PathBuf {
    root.join(LABEL_FILE)
}

pub fn read_label(root: &Path) -> Option<IdentityLabel> {
    let s = std::fs::read_to_string(label_path(root)).ok()?;
    serde_json::from_str(&s).ok()
}

/// Written at unlock (the only moment the name is certain). Atomic, never fatal.
pub fn write_label(root: &Path, label: &IdentityLabel) {
    if let Ok(s) = serde_json::to_vec_pretty(label) {
        if let Err(e) = crate::vault::write_atomic(&label_path(root), &s) {
            log::warn!("could not write the identity label: {}", e);
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct IdentityEntry {
    /// The partition key (folder name), or `legacy` for the device root.
    pub key: String,
    pub root: String,
    /// The one the app state points at right now (what an unlock opens).
    pub active: bool,
    pub label: Option<IdentityLabel>,
    /// The vault file's plaintext envelope email (the unlock screen's
    /// "Welcome back" line), for identities that have no label yet.
    pub display_email: Option<String>,
}

fn entry(key: &str, root: &Path, current_root: &Path) -> IdentityEntry {
    let display_email = crate::vault::load_vault(&crate::paths::vault_file(root))
        .ok()
        .and_then(|e| e.display_email);
    IdentityEntry {
        key: key.to_string(),
        root: root.to_string_lossy().to_string(),
        active: root == current_root,
        label: read_label(root),
        display_email,
    }
}

/// Every identity on this device that has a vault file: the partitions,
/// plus the device root itself while it still holds a legacy layout.
pub fn list_on_disk(device_root: &Path, current_root: &Path) -> Vec<IdentityEntry> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(crate::paths::identities_dir(device_root)) {
        let mut dirs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
        dirs.sort();
        for dir in dirs {
            if crate::vault::vault_exists(&crate::paths::vault_file(&dir)) {
                let key = dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                out.push(entry(&key, &dir, current_root));
            }
        }
    }
    if crate::vault::vault_exists(&crate::paths::vault_file(device_root)) {
        out.push(entry(LEGACY_KEY, device_root, current_root));
    }
    out
}

fn root_for_key(device_root: &Path, key: &str) -> Option<PathBuf> {
    if key == LEGACY_KEY {
        return Some(device_root.to_path_buf());
    }
    if key.len() != crate::paths::PARTITION_KEY_LEN || !key.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(crate::paths::identity_root_for(device_root, key))
}

#[tauri::command]
pub fn list_identities(state: tauri::State<'_, Arc<AppState>>) -> Vec<IdentityEntry> {
    list_on_disk(&state.data_dir, &state.identity_root())
}

/// Point the locked Vault at another of its identities; the next unlock
/// opens that one. Refused while unlocked (lock first) - one live vault.
#[tauri::command]
pub fn select_identity(state: tauri::State<'_, Arc<AppState>>, key: String) -> Result<IdentityEntry, String> {
    select_identity_inner(state.inner(), &key)
}

pub(crate) fn select_identity_inner(state: &Arc<AppState>, key: &str) -> Result<IdentityEntry, String> {
    if state.vault_config.lock().unwrap().is_some() {
        return Err("Lock the Vault before switching identity.".into());
    }
    if state.conductor_handle.lock().unwrap().is_some() {
        return Err("The Vault is still shutting down. Try again in a moment.".into());
    }
    let root = root_for_key(&state.data_dir, key).ok_or("No such identity on this device.")?;
    if !crate::vault::vault_exists(&crate::paths::vault_file(&root)) {
        return Err("No such identity on this device.".into());
    }
    state.repoint_root(&root);
    log::info!("Identity selected at unlock: {} ({:?})", key, root);
    Ok(entry(key, &root, &root))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_identity(device_root: &Path, key: &str, name: &str) -> PathBuf {
        let root = crate::paths::identity_root_for(device_root, key);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(crate::paths::vault_file(&root), b"not really encrypted").unwrap();
        write_label(&root, &IdentityLabel { agent_pub_key: format!("uhCAk{}", key), display_name: Some(name.into()), ..Default::default() });
        root
    }

    #[test]
    fn lists_partitions_and_a_legacy_root_and_marks_the_current_one() {
        let dir = tempfile::tempdir().unwrap();
        let a = fake_identity(dir.path(), "aaaaaaaaaaaaaaaa", "A");
        let _b = fake_identity(dir.path(), "bbbbbbbbbbbbbbbb", "B");
        std::fs::write(crate::paths::vault_file(dir.path()), b"legacy").unwrap();
        let list = list_on_disk(dir.path(), &a);
        let keys: Vec<&str> = list.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, vec!["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", LEGACY_KEY]);
        assert!(list[0].active && !list[1].active && !list[2].active);
        assert_eq!(list[1].label.as_ref().unwrap().display_name.as_deref(), Some("B"));
        assert!(list[2].label.is_none());
    }

    #[test]
    fn selecting_repoints_a_locked_state_and_refuses_bad_keys() {
        let dir = tempfile::tempdir().unwrap();
        let a = fake_identity(dir.path(), "aaaaaaaaaaaaaaaa", "A");
        let b = fake_identity(dir.path(), "bbbbbbbbbbbbbbbb", "B");
        let state = Arc::new(AppState::new(dir.path().to_path_buf()));
        state.repoint_root(&a);
        assert_eq!(state.identity_root(), a);
        let picked = select_identity_inner(&state, "bbbbbbbbbbbbbbbb").unwrap();
        assert!(picked.active);
        assert_eq!(state.identity_root(), b);
        assert_eq!(*state.vault_path.lock().unwrap(), crate::paths::vault_file(&b));
        assert!(select_identity_inner(&state, "cccccccccccccccc").is_err(), "no vault there");
        assert!(select_identity_inner(&state, "../../etc").is_err(), "never a path");
        assert!(select_identity_inner(&state, LEGACY_KEY).is_err(), "no legacy vault in this fixture");
    }
}
