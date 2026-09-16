//! One-time move of a legacy single-identity layout into
//! `<device root>/identities/<partition key>/` (Phase 2 of the identity
//! switcher; build-docs current/VAULT_1_4_0_PHASE2_BUILD.md step 5).
//!
//! Runs inside the unlock path, right after the vault file decrypted and
//! before anything is written or the conductor is started - the only moment
//! when the identity is certain AND the conductor and key store are stopped.
//!
//! What the 2026-09-16 drive established and this module encodes:
//! - the conductor's databases carry no absolute paths, so `conductor/`
//!   moves by rename and comes up in place;
//! - the key store does not: `lair-keystore-config.yaml` pins absolute paths
//!   and lair will silently keep using, or even recreate, the old directory.
//!   So `lair/` is never renamed into the new root - it is set aside as
//!   `lair.old-<ts>` beside the new root and the next start re-initialises a
//!   fresh key store there from the device seed (the same path a password
//!   change already uses). The old copy is swept on a later start.
//! - a half-moved tree reads as a fresh identity to every reader, so the
//!   move is all-or-nothing: same-filesystem renames, backup writes held,
//!   full rollback on any failure, the marker written last.
use std::path::{Path, PathBuf};
use crate::commands::AppState;
use crate::paths;

#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// The identity root already is a partition; nothing to do.
    AlreadyPartitioned,
    /// Moved into this partition root.
    Relocated(PathBuf),
    /// Left the legacy layout in place (reason logged); the vault works as before.
    StayedLegacy(String),
}

/// Files and directories that move by rename, in order. `lair/` is handled
/// separately (set aside, not moved).
fn movable_entries(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    // the identity itself first, then its stores, then the conductor
    for name in paths::IDENTITY_STORE_FILES {
        let p = root.join(name);
        if p.exists() { out.push(p); }
        let bak = root.join(format!("{}.bak", name));
        if bak.exists() { out.push(bak); }
    }
    let backups = paths::backups_dir(root);
    if backups.exists() { out.push(backups); }
    // quarantine files (`<name>.corrupt-<ts>`) belong to this identity's stores
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.contains(".corrupt-") && e.path().is_file() { out.push(e.path()); }
        }
    }
    let conductor = paths::conductor_dir(root);
    if conductor.exists() { out.push(conductor); }
    out
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Move a legacy layout under its partition root if this install still has
/// one. Safe to call on every unlock: a partitioned install returns
/// `AlreadyPartitioned` at once.
pub fn relocate_if_legacy(state: &AppState, agent_pub_key: &str) -> Outcome {
    let device_root = state.data_dir.clone();
    let current_root = state.identity_root();
    if current_root != device_root {
        return Outcome::AlreadyPartitioned;
    }
    if state.conductor_handle.lock().unwrap().is_some() {
        return stay("conductor is running");
    }
    let Some(pk) = paths::partition_key(agent_pub_key) else {
        return stay("agent key not decodable");
    };
    let new_root = paths::identity_root_for(&device_root, &pk);
    if !paths::lair_socket_path_fits(&new_root) {
        return stay(&format!("partition path too long for the key store socket ({} bytes)", new_root.as_os_str().len()));
    }
    if paths::vault_file(&new_root).exists() {
        return stay(&format!("{:?} already holds a vault", new_root));
    }
    if let Err(e) = std::fs::create_dir_all(&new_root) {
        return stay(&format!("cannot create {:?}: {}", new_root, e));
    }

    // Hold backup writes for the duration (see backup.rs).
    state.relocating.store(true, std::sync::atomic::Ordering::SeqCst);
    let result = move_everything(&device_root, &new_root);
    state.relocating.store(false, std::sync::atomic::Ordering::SeqCst);

    match result {
        Ok(()) => {
            *state.identity_root.lock().unwrap() = new_root.clone();
            *state.vault_path.lock().unwrap() = paths::vault_file(&new_root);
            state.activity.set_root(&new_root);
            // Marker last: from here on startup selects the partition.
            crate::commands::write_active_identity_marker(&device_root, agent_pub_key);
            log::info!("Identity relocated into {:?}", new_root);
            Outcome::Relocated(new_root)
        }
        Err(e) => {
            let _ = std::fs::remove_dir(&new_root); // only if empty
            stay(&e)
        }
    }
}

fn stay(reason: &str) -> Outcome {
    log::warn!("Identity relocation skipped: {} - staying on the legacy layout", reason);
    Outcome::StayedLegacy(reason.to_string())
}

/// All-or-nothing: rename each entry into the new root; on the first failure
/// rename everything back in reverse order. The key store is set aside as
/// `<new root>/lair.old-<ts>` (never renamed into place, see the module doc);
/// leftover `lair.old-*` / `lair.broken-*` at the legacy root follow it.
fn move_everything(device_root: &Path, new_root: &Path) -> Result<(), String> {
    let mut done: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut plan: Vec<(PathBuf, PathBuf)> = movable_entries(device_root)
        .into_iter()
        .map(|from| { let to = new_root.join(from.file_name().unwrap()); (from, to) })
        .collect();
    let ts = unix_now();
    let lair = paths::lair_dir(device_root);
    if lair.exists() {
        plan.push((lair, paths::lair_old_dir(new_root, ts)));
    }
    if let Ok(rd) = std::fs::read_dir(device_root) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if paths::is_lair_leftover_name(&name) && e.path().is_dir() {
                plan.push((e.path(), new_root.join(&name)));
            }
        }
    }
    for (from, to) in plan {
        if to.exists() {
            rollback(&done);
            return Err(format!("{:?} already exists in the partition", to));
        }
        if let Err(e) = std::fs::rename(&from, &to) {
            rollback(&done);
            return Err(format!("could not move {:?}: {}", from, e));
        }
        done.push((from, to));
    }
    Ok(())
}

fn rollback(done: &[(PathBuf, PathBuf)]) {
    for (from, to) in done.iter().rev() {
        if let Err(e) = std::fs::rename(to, from) {
            log::error!("relocation rollback: could not restore {:?}: {}", from, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_install(root: &Path) -> String {
        let key = crate::key_derivation::construct_agent_pub_key_string(&[5u8; 32]);
        std::fs::write(paths::vault_file(root), b"enc").unwrap();
        std::fs::write(root.join("vault.enc.bak"), b"enc-bak").unwrap();
        std::fs::write(paths::store_path(root, paths::LINKED_APPS), b"[]").unwrap();
        std::fs::write(paths::activity_path(root), b"[]").unwrap();
        std::fs::write(root.join("linked-apps.json.corrupt-1"), b"x").unwrap();
        std::fs::create_dir_all(paths::backups_dir(root).join("app")).unwrap();
        std::fs::write(paths::backups_dir(root).join("app/latest.enc"), b"b").unwrap();
        std::fs::create_dir_all(paths::conductor_dir(root).join("databases")).unwrap();
        std::fs::write(paths::db_key_path(root), b"k").unwrap();
        std::fs::create_dir_all(paths::lair_dir(root)).unwrap();
        std::fs::write(paths::lair_dir(root).join("lair-keystore-config.yaml"), b"connectionUrl: unix:///old/path").unwrap();
        std::fs::create_dir_all(root.join("lair.broken-7")).unwrap();
        // device-level files stay put
        std::fs::write(paths::settings_path(root), b"{}").unwrap();
        std::fs::write(paths::autostart_marker_path(root), b"1").unwrap();
        key
    }

    #[test]
    fn legacy_layout_moves_as_one_unit_and_is_selected_on_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let key = legacy_install(root);
        let state = AppState::new(root.to_path_buf());
        assert_eq!(state.identity_root(), root);

        let out = relocate_if_legacy(&state, &key);
        let pk = paths::partition_key(&key).unwrap();
        let new_root = paths::identity_root_for(root, &pk);
        assert_eq!(out, Outcome::Relocated(new_root.clone()));

        // moved
        for rel in ["vault.enc", "vault.enc.bak", "linked-apps.json", "activity.json", "linked-apps.json.corrupt-1", "backups/app/latest.enc", "conductor/databases/db.key", "lair.broken-7"] {
            assert!(new_root.join(rel).exists(), "{} should be in the partition", rel);
            assert!(!root.join(rel).exists(), "{} should have left the legacy root", rel);
        }
        // lair set aside, never in place: the next start re-initialises it
        assert!(!paths::lair_dir(&new_root).exists());
        assert!(!paths::lair_dir(root).exists());
        let set_aside: Vec<_> = std::fs::read_dir(&new_root).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().starts_with(paths::LAIR_OLD_PREFIX)).collect();
        assert_eq!(set_aside.len(), 1);
        // device-level stayed
        assert!(paths::settings_path(root).exists() && paths::autostart_marker_path(root).exists());
        // state follows
        assert_eq!(state.identity_root(), new_root);
        assert_eq!(*state.vault_path.lock().unwrap(), paths::vault_file(&new_root));
        assert!(!state.relocating.load(std::sync::atomic::Ordering::SeqCst));
        // marker written → a fresh AppState selects the partition before unlock
        assert_eq!(paths::read_active_identity(root).as_deref(), Some(key.as_str()));
        let again = AppState::new(root.to_path_buf());
        assert_eq!(again.identity_root(), new_root);
        assert_eq!(relocate_if_legacy(&again, &key), Outcome::AlreadyPartitioned);
    }

    #[test]
    fn a_root_too_deep_for_the_socket_stays_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let deep = dir.path().join("y".repeat(90));
        std::fs::create_dir_all(&deep).unwrap();
        let key = legacy_install(&deep);
        let state = AppState::new(deep.clone());
        assert!(matches!(relocate_if_legacy(&state, &key), Outcome::StayedLegacy(_)));
        assert!(paths::vault_file(&deep).exists() && paths::lair_dir(&deep).exists());
        assert!(!paths::identities_dir(&deep).exists() || std::fs::read_dir(paths::identities_dir(&deep)).map(|r| r.count() == 0).unwrap_or(true));
    }

    #[test]
    fn a_conflicting_partition_leaves_the_legacy_layout_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let key = legacy_install(root);
        let pk = paths::partition_key(&key).unwrap();
        let new_root = paths::identity_root_for(root, &pk);
        std::fs::create_dir_all(&new_root).unwrap();
        std::fs::write(paths::vault_file(&new_root), b"someone else").unwrap();
        let state = AppState::new(root.to_path_buf());
        let out = relocate_if_legacy(&state, &key);
        assert!(matches!(out, Outcome::StayedLegacy(_)));
        assert!(paths::vault_file(root).exists() && paths::conductor_dir(root).exists() && paths::lair_dir(root).exists());
        assert_eq!(state.identity_root(), root);
        assert_eq!(paths::read_active_identity(root), None, "no marker written on a skipped move");
    }

    #[test]
    fn a_failed_rename_rolls_everything_back() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let key = legacy_install(root);
        let pk = paths::partition_key(&key).unwrap();
        let new_root = paths::identity_root_for(root, &pk);
        // A pre-existing conductor dir in the partition makes that rename refuse.
        std::fs::create_dir_all(paths::conductor_dir(&new_root)).unwrap();
        let state = AppState::new(root.to_path_buf());
        let out = relocate_if_legacy(&state, &key);
        assert!(matches!(out, Outcome::StayedLegacy(_)));
        for rel in ["vault.enc", "vault.enc.bak", "linked-apps.json", "activity.json", "backups/app/latest.enc", "conductor/databases/db.key", "lair/lair-keystore-config.yaml", "lair.broken-7"] {
            assert!(root.join(rel).exists(), "{} must be back at the legacy root", rel);
        }
        assert_eq!(state.identity_root(), root);
    }
}
