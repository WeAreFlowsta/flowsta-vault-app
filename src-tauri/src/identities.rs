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

/// An app agent that another identity ON THIS DEVICE already links.
pub struct LinkedElsewhere {
    /// How that identity is shown (display name, else @username, else
    /// "another identity").
    pub identity_name: String,
    pub app_name: String,
}

/// One app agent attests to ONE Flowsta identity. A second `/link-identity`
/// for the same app agent under a different identity would put an
/// `IsSamePersonEntry` for each on the app's public DHT - a claim that two
/// people are one. The Vault keeps linked apps per identity root, so the
/// rule is checked across every other root on the device (partitions and
/// the legacy root). The same agent linking again under the CURRENT
/// identity (reinstall, restore, changed client_id) is not "elsewhere".
/// Keys are compared by their raw bytes, whatever spelling was stored.
pub(crate) fn app_agent_linked_elsewhere(
    device_root: &Path,
    current_root: &Path,
    app_agent_pub_key: &str,
) -> Option<LinkedElsewhere> {
    let want = crate::key_derivation::decode_agent_pub_key_string(app_agent_pub_key);
    let same = |stored: &str| -> bool {
        match (want, crate::key_derivation::decode_agent_pub_key_string(stored)) {
            (Some(a), Some(b)) => a == b,
            _ => stored == app_agent_pub_key,
        }
    };
    for entry in list_on_disk(device_root, current_root) {
        if entry.active {
            continue;
        }
        let hit = crate::commands::load_linked_apps(Path::new(&entry.root))
            .into_iter()
            .find(|a| same(&a.app_agent_pub_key));
        if let Some(app) = hit {
            let identity_name = entry
                .label
                .as_ref()
                .and_then(|l| {
                    l.display_name
                        .clone()
                        .filter(|n| !n.trim().is_empty())
                        .or_else(|| l.username.clone().filter(|u| !u.trim().is_empty()).map(|u| format!("@{u}")))
                })
                .unwrap_or_else(|| "another identity".to_string());
            return Some(LinkedElsewhere { identity_name, app_name: app.app_name });
        }
    }
    None
}

/// Where a NEW identity's files go: its own partition, `identities/<pk>/`,
/// from birth (1.4.0 relocated at the first re-unlock instead). Adding an
/// identity to a Vault that already holds one needs the Vault locked with
/// no conductor running - one live vault. An identity already on this
/// device is refused: it is picked at unlock, never restored twice. A
/// fresh install whose partition path cannot host a key store socket
/// stays on the legacy root as before.
pub(crate) fn adopt_partition_before_setup(state: &Arc<AppState>, agent_pub_key: &str) -> Result<PathBuf, String> {
    let device_root = state.data_dir.clone();
    let current_root = state.identity_root();
    let current_has_vault = crate::vault::vault_exists(&crate::paths::vault_file(&current_root));
    let pk = crate::paths::partition_key(agent_pub_key).ok_or("agent key not decodable")?;
    let new_root = crate::paths::identity_root_for(&device_root, &pk);
    if crate::vault::vault_exists(&crate::paths::vault_file(&new_root)) {
        return Err("This identity is already in this Vault. Pick it at unlock instead.".into());
    }
    if current_has_vault {
        if state.vault_config.lock().unwrap().is_some() {
            return Err("Lock the Vault before adding an identity.".into());
        }
        // One conductor per Vault: the locked identity stops syncing.
        crate::commands::stop_syncing_while_locked(state);
        if state.conductor_handle.lock().unwrap().is_some() {
            return Err("The Vault is still shutting down. Try again in a moment.".into());
        }
        if !crate::paths::lair_socket_path_fits(&new_root) {
            return Err("This device's user folder path is too long to add a second identity.".into());
        }
    } else if !crate::paths::lair_socket_path_fits(&new_root) {
        log::warn!("partition path too long for the key store socket - the first identity stays on the legacy root");
        return Ok(crate::paths::vault_file(&current_root));
    }
    std::fs::create_dir_all(&new_root).map_err(|e| format!("cannot create {:?}: {}", new_root, e))?;
    state.repoint_root(&new_root);
    log::info!("New identity born partitioned at {:?}", new_root);
    Ok(crate::paths::vault_file(&new_root))
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
    // One conductor per Vault: the locked identity stops syncing.
    if root_for_key(&state.data_dir, key).as_deref() != Some(state.identity_root().as_path()) {
        crate::commands::stop_syncing_while_locked(state);
    }
    if state.conductor_handle.lock().unwrap().is_some() && state.kept_conductor.lock().unwrap().is_none() {
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
    fn an_app_agent_linked_under_another_identity_on_this_device_is_found_and_named() {
        let dir = tempfile::tempdir().unwrap();
        let a = fake_identity(dir.path(), "aaaaaaaaaaaaaaaa", "Alice");
        let b = fake_identity(dir.path(), "bbbbbbbbbbbbbbbb", "Bob");
        let x = "uhCAkm5MezrFZWbDD79kneFp60cS0a9REzlGDxcFVotCvWSl2thsd";
        let y = "uhCAk6oBoqygFqkDreZ0V0bH4R9cTN1OkcEG78OLxVptwypbiKzNl";
        let link = |root: &Path, key: &str| {
            let apps = vec![crate::commands::LinkedThirdPartyApp {
                app_name: "ChessChain".into(),
                app_agent_pub_key: key.into(),
                linked_at: 1,
                client_id: Some("flowsta_app_x".into()),
                origin: None,
            }];
            std::fs::write(crate::paths::store_path(root, crate::paths::LINKED_APPS), serde_json::to_vec(&apps).unwrap()).unwrap();
        };
        link(&a, x);
        // current = B: X is Alice's, Y is nobody's
        let hit = app_agent_linked_elsewhere(dir.path(), &b, x).expect("found under Alice");
        assert_eq!(hit.identity_name, "Alice");
        assert_eq!(hit.app_name, "ChessChain");
        assert!(app_agent_linked_elsewhere(dir.path(), &b, y).is_none());
        // current = A: X is ours, not elsewhere (re-link allowed)
        assert!(app_agent_linked_elsewhere(dir.path(), &a, x).is_none());
        // the legacy root counts as an identity too
        std::fs::write(crate::paths::vault_file(dir.path()), b"legacy").unwrap();
        link(dir.path(), y);
        let hit = app_agent_linked_elsewhere(dir.path(), &b, y).expect("found under the legacy root");
        assert_eq!(hit.identity_name, "another identity");
    }

    #[test]
    fn removing_one_of_two_identities_selects_the_other_and_erase_clears_the_device() {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(AppState::new(dir.path().to_path_buf()));
        // Real agent keys: the marker is read back through the key parser.
        let agent_a = crate::key_derivation::construct_agent_pub_key_string(&[7u8; 32]);
        let agent_b = crate::key_derivation::construct_agent_pub_key_string(&[9u8; 32]);
        let pk_a = crate::paths::partition_key(&agent_a).unwrap();
        let pk_b = crate::paths::partition_key(&agent_b).unwrap();
        let a = fake_identity(dir.path(), &pk_a, "Alice");
        let b = fake_identity(dir.path(), &pk_b, "Bob");
        write_label(&a, &IdentityLabel { agent_pub_key: agent_a.clone(), display_name: Some("Alice".into()), ..Default::default() });
        write_label(&b, &IdentityLabel { agent_pub_key: agent_b.clone(), display_name: Some("Bob".into()), ..Default::default() });
        // B is the selected identity; its marker names B's agent key.
        state.repoint_root(&b);
        crate::commands::write_active_identity_marker(dir.path(), &agent_b);
        let remaining = crate::commands::remove_identity_inner(&state).unwrap();
        assert_eq!(remaining, 1);
        assert!(!b.exists(), "B's folder is gone");
        assert!(a.exists(), "A stays");
        assert_eq!(state.identity_root(), a, "A is selected for this session");
        assert_eq!(crate::paths::read_active_identity(dir.path()).as_deref(), Some(agent_a.as_str()), "the marker points at A for the next launch");
        assert_eq!(crate::paths::select_identity_root(dir.path()), a);
        // Erase everything: nothing left, layout back to the device root.
        crate::commands::erase_device_inner(&state).unwrap();
        assert!(!a.exists());
        assert!(crate::paths::read_active_identity(dir.path()).is_none());
        assert!(list_on_disk(dir.path(), dir.path()).is_empty());
        assert_eq!(state.identity_root(), dir.path());
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
    fn a_new_identity_is_born_in_its_own_partition_and_a_second_one_needs_a_locked_vault() {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(AppState::new(dir.path().to_path_buf()));
        let key_a = crate::key_derivation::construct_agent_pub_key_string(&[7u8; 32]);
        let key_b = crate::key_derivation::construct_agent_pub_key_string(&[9u8; 32]);
        // fresh install: the first identity lands in identities/<pk>/, not the device root
        let path_a = adopt_partition_before_setup(&state, &key_a).unwrap();
        let pk_a = crate::paths::partition_key(&key_a).unwrap();
        assert_eq!(path_a, crate::paths::vault_file(&crate::paths::identity_root_for(dir.path(), &pk_a)));
        assert_eq!(state.identity_root(), crate::paths::identity_root_for(dir.path(), &pk_a));
        std::fs::write(&path_a, b"vault a").unwrap();
        // the same identity again: refused
        assert!(adopt_partition_before_setup(&state, &key_a).unwrap_err().contains("already in this Vault"));
        // a second identity while locked: its own partition
        let path_b = adopt_partition_before_setup(&state, &key_b).unwrap();
        assert_ne!(path_b, path_a);
        assert!(path_b.to_string_lossy().contains(&crate::paths::partition_key(&key_b).unwrap()));
        assert!(crate::vault::vault_exists(&path_a), "the first identity is untouched");
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
