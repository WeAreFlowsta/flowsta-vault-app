//! Every file the Vault writes, named in one place.
//!
//! Two roots: the **device root** (Tauri's app data dir) holds device-level
//! files - the active-identity marker, settings, the autostart marker,
//! download caches. The **identity root** holds everything that belongs to
//! one identity: the vault file, the key store, the conductor, backups, the
//! app-link stores, activity, MAU and quota state.
//!
//! Today the identity root IS the device root. Phase 2 of the identity
//! switcher (build-docs current/VAULT_1_4_0_PHASE2_BUILD.md) moves it to
//! `<device root>/identities/<partition key>/`; every caller already goes
//! through these helpers so that change lands here and nowhere else.
//!
//! No other module may spell one of these names.
use std::path::{Path, PathBuf};

// ---- identity-scoped -------------------------------------------------------
pub const VAULT_FILE: &str = "vault.enc";
pub const LAIR_DIR: &str = "lair";
/// Key store set aside by a password change; `sweep_old_lair_dirs` removes them.
pub const LAIR_OLD_PREFIX: &str = "lair.old-";
/// Key store quarantined after it failed to start.
pub const LAIR_BROKEN_PREFIX: &str = "lair.broken-";
pub const CONDUCTOR_DIR: &str = "conductor";
pub const BACKUPS_DIR: &str = "backups";
pub const LINKED_APPS: &str = "linked-apps.json";
pub const LINKED_APP_SCOPES: &str = "linked-app-scopes.json";
pub const VERIFIED_APPS: &str = "verified-apps.json";
pub const APPROVED_SITES: &str = "approved-sites.json";
pub const EMAIL_GRANTS: &str = "email-grants.json";
pub const MAU_EVENTS: &str = "mau-events.enc";
pub const QUOTA_CACHE: &str = "quota_cache.json";
pub const QUOTA_KEY: &str = ".quota.key";
pub const ACTIVITY_FILE: &str = "activity.json";
/// Set when a vault was created by restoring an identity; while present,
/// third-party `/backup` writes are refused. See commands.rs.
pub const RESTORE_CHOICE_MARKER: &str = "restore-choice-pending";

// ---- device-level ----------------------------------------------------------
/// Plaintext marker with the active identity's agent key; selects the
/// identity root and answers locked-state identity checks.
pub const ACTIVE_IDENTITY_MARKER: &str = "active-identity";
pub const SETTINGS_FILE: &str = "settings.json";
#[allow(dead_code)] // used by the autostart setup, which is compiled only where Tauri autostart is enabled
pub const AUTOSTART_MARKER: &str = "autostart-initialized";

/// Every identity-scoped single file (not the directories). This is the
/// list a relocation moves and a full erase removes - one list, so the two
/// can never disagree. Directories: `LAIR_DIR`, `CONDUCTOR_DIR`, `BACKUPS_DIR`.
#[allow(dead_code)] // consumed by the Phase 2 relocation (step 5) and the widened erase (step 6)
pub const IDENTITY_STORE_FILES: &[&str] = &[
    VAULT_FILE,
    LINKED_APPS,
    LINKED_APP_SCOPES,
    VERIFIED_APPS,
    APPROVED_SITES,
    EMAIL_GRANTS,
    MAU_EVENTS,
    QUOTA_CACHE,
    QUOTA_KEY,
    ACTIVITY_FILE,
    RESTORE_CHOICE_MARKER,
];

// ---- identity-root helpers -------------------------------------------------
pub fn vault_file(root: &Path) -> PathBuf { root.join(VAULT_FILE) }
pub fn lair_dir(root: &Path) -> PathBuf { root.join(LAIR_DIR) }
pub fn lair_old_dir(root: &Path, unix_secs: u64) -> PathBuf { root.join(format!("{}{}", LAIR_OLD_PREFIX, unix_secs)) }
pub fn lair_broken_dir(parent: &Path, unix_secs: u64) -> PathBuf { parent.join(format!("{}{}", LAIR_BROKEN_PREFIX, unix_secs)) }
pub fn is_lair_leftover_name(name: &str) -> bool { name.starts_with(LAIR_OLD_PREFIX) || name.starts_with(LAIR_BROKEN_PREFIX) }
pub fn conductor_dir(root: &Path) -> PathBuf { root.join(CONDUCTOR_DIR) }
pub fn db_key_path(root: &Path) -> PathBuf { conductor_dir(root).join("databases").join("db.key") }
pub fn backups_dir(root: &Path) -> PathBuf { root.join(BACKUPS_DIR) }
/// One of the JSON/enc stores by its constant name.
pub fn store_path(root: &Path, name: &str) -> PathBuf { root.join(name) }
pub fn mau_store_path(root: &Path) -> PathBuf { root.join(MAU_EVENTS) }
pub fn quota_cache_path(root: &Path) -> PathBuf { root.join(QUOTA_CACHE) }
pub fn quota_key_path(root: &Path) -> PathBuf { root.join(QUOTA_KEY) }
pub fn activity_path(root: &Path) -> PathBuf { root.join(ACTIVITY_FILE) }
pub fn restore_choice_path(root: &Path) -> PathBuf { root.join(RESTORE_CHOICE_MARKER) }

// ---- partitions ------------------------------------------------------------
/// Folder under the device root that holds one sub-folder per identity.
pub const IDENTITIES_DIR: &str = "identities";

/// Partition key for an identity: the first 16 lowercase hex characters (64
/// bits) of sha256 over the 39-byte agent key (decision D4). A hash, not the
/// key string: agent-key strings are case-sensitive base64url and would
/// collide on case-insensitive filesystems (macOS, Windows defaults). Short,
/// because the key store's Unix socket lives under this folder and socket
/// paths are limited to ~104 bytes (the 2026-09-16 drive hit that limit with
/// the full 64-character hash). 64 bits is ample for the handful of
/// identities one device holds. `None` when the string is not an agent key
/// in either known encoding.
pub const PARTITION_KEY_LEN: usize = 16;

pub fn partition_key(agent_pub_key: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = crate::key_derivation::decode_agent_pub_key_flexible(agent_pub_key.trim())?;
    let full = hex::encode(Sha256::digest(bytes));
    Some(full[..PARTITION_KEY_LEN].to_string())
}

/// Unix-socket path budget for the key store: Linux 108, macOS 104, minus
/// a safety margin. Windows key stores use named pipes (no limit).
#[cfg(not(windows))]
pub fn socket_path_budget() -> usize {
    let limit: usize = if cfg!(target_os = "macos") { 104 } else { 108 };
    limit.saturating_sub(4)
}

#[cfg(not(windows))]
pub fn socket_fits(path: &Path) -> bool { path.as_os_str().len() + 1 <= socket_path_budget() }

/// Whether lair's default socket (inside its own directory under `root`)
/// fits. On macOS it does NOT for any partitioned Vault: `~/Library/
/// Application Support/<id>/identities/<key>/lair/socket` is ~103 bytes
/// against a 104 limit (found on the 2026-09-16 Mac drive).
pub fn in_root_socket_fits(root: &Path) -> bool {
    #[cfg(windows)]
    { let _ = root; true }
    #[cfg(not(windows))]
    { socket_fits(&lair_dir(root).join("socket")) }
}

/// A short, per-user, private directory for key store sockets whose
/// in-root path does not fit: macOS `$TMPDIR` (per-user, mode 700), Linux
/// `$XDG_RUNTIME_DIR`, else `/tmp/fv-<uid>` (created mode 700).
#[cfg(not(windows))]
pub fn short_socket_dir() -> PathBuf {
    let base = if cfg!(target_os = "macos") { std::env::var_os("TMPDIR") } else { std::env::var_os("XDG_RUNTIME_DIR") };
    if let Some(b) = base {
        let b = PathBuf::from(b);
        if b.is_absolute() && b.is_dir() { return b.join("fv"); }
    }
    // SAFETY: getuid has no preconditions and cannot fail.
    PathBuf::from(format!("/tmp/fv-{}", unsafe { libc::getuid() }))
}

/// The short socket path for the key store under `root`: one name per
/// root (16 hex of sha256 over the root path), so two instances never
/// share a socket.
#[cfg(not(windows))]
pub fn short_socket_path(root: &Path) -> PathBuf {
    use sha2::{Digest, Sha256};
    let h = hex::encode(Sha256::digest(root.to_string_lossy().as_bytes()));
    short_socket_dir().join(format!("{}.sock", &h[..16]))
}

/// Whether a key store under `root` can be started at all: its default
/// socket fits, or the short runtime socket does. A root where neither
/// fits stays on the legacy layout rather than producing a key store that
/// cannot start ("path must be shorter than SUN_LEN").
pub fn lair_socket_path_fits(root: &Path) -> bool {
    #[cfg(windows)]
    { let _ = root; true }
    #[cfg(not(windows))]
    { in_root_socket_fits(root) || socket_fits(&short_socket_path(root)) }
}

pub fn identities_dir(device_root: &Path) -> PathBuf { device_root.join(IDENTITIES_DIR) }
pub fn identity_root_for(device_root: &Path, partition_key: &str) -> PathBuf { identities_dir(device_root).join(partition_key) }

/// The agent key in the active-identity marker, if the marker exists and
/// holds a decodable key. A missing, empty or garbled marker reads as `None`
/// so callers fall back to the legacy layout rather than fail.
pub fn read_active_identity(device_root: &Path) -> Option<String> {
    let s = std::fs::read_to_string(active_identity_path(device_root)).ok()?;
    let key = s.trim();
    if key.is_empty() || crate::key_derivation::decode_agent_pub_key_flexible(key).is_none() { return None; }
    Some(key.to_string())
}

/// Where this identity's files are, decided before unlock:
/// the marker names an identity AND its partition folder exists → that
/// folder; otherwise the device root itself (the single-identity legacy
/// layout, and every install until the relocation has run).
pub fn select_identity_root(device_root: &Path) -> PathBuf {
    if let Some(key) = read_active_identity(device_root) {
        if let Some(pk) = partition_key(&key) {
            let root = identity_root_for(device_root, &pk);
            if root.is_dir() { return root; }
        }
    }
    device_root.to_path_buf()
}

// ---- device-root helpers ---------------------------------------------------
pub fn active_identity_path(device_root: &Path) -> PathBuf { device_root.join(ACTIVE_IDENTITY_MARKER) }
pub fn settings_path(device_root: &Path) -> PathBuf { device_root.join(SETTINGS_FILE) }
#[allow(dead_code)]
pub fn autostart_marker_path(device_root: &Path) -> PathBuf { device_root.join(AUTOSTART_MARKER) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn store_list_has_no_duplicates_and_no_directories() {
        let mut seen = std::collections::HashSet::new();
        for n in IDENTITY_STORE_FILES {
            assert!(seen.insert(*n), "duplicate {}", n);
            assert!(![LAIR_DIR, CONDUCTOR_DIR, BACKUPS_DIR].contains(n));
        }
        assert!(IDENTITY_STORE_FILES.contains(&VAULT_FILE));
        assert!(!IDENTITY_STORE_FILES.contains(&ACTIVE_IDENTITY_MARKER), "the marker selects the root; it cannot live in it");
        assert!(!IDENTITY_STORE_FILES.contains(&SETTINGS_FILE));
    }
    #[test]
    fn partition_selection_falls_back_to_the_legacy_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // no marker
        assert_eq!(select_identity_root(root), root);
        // garbled marker
        std::fs::write(active_identity_path(root), "not a key").unwrap();
        assert_eq!(read_active_identity(root), None);
        assert_eq!(select_identity_root(root), root);
        // valid marker, no partition folder yet
        let key = crate::key_derivation::construct_agent_pub_key_string(&[3u8; 32]);
        std::fs::write(active_identity_path(root), &key).unwrap();
        assert_eq!(read_active_identity(root).as_deref(), Some(key.as_str()));
        assert_eq!(select_identity_root(root), root);
        // partition folder present → selected
        let pk = partition_key(&key).unwrap();
        assert_eq!(pk.len(), PARTITION_KEY_LEN);
        assert_eq!(pk, pk.to_lowercase());
        assert_eq!(partition_key(&format!("  {}\n", key)), Some(pk.clone()), "whitespace-tolerant, deterministic");
        std::fs::create_dir_all(identity_root_for(root, &pk)).unwrap();
        assert_eq!(select_identity_root(root), identity_root_for(root, &pk));
        // a different key never maps to the same folder
        let other = crate::key_derivation::construct_agent_pub_key_string(&[4u8; 32]);
        assert_ne!(partition_key(&other).unwrap(), pk);
    }

    #[test]
    #[cfg(not(windows))]
    fn socket_budget_falls_back_to_the_short_runtime_socket() {
        let shallow = Path::new("/home/user/.local/share/com.flowsta.vault/identities/0123456789abcdef");
        assert!(in_root_socket_fits(shallow));
        // the macOS shape: ~/Library/Application Support/<id>/identities/<key>
        let mac = Path::new("/Users/zoe/Library/Application Support/com.flowsta.vault.staging/identities/0123456789abcdef");
        assert!(!socket_fits(&lair_dir(mac).join("socket").as_path().to_path_buf()) || cfg!(not(target_os = "macos")));
        let deep = format!("/{}", "x".repeat(120));
        assert!(!in_root_socket_fits(Path::new(&deep)));
        // the fallback keeps every such root startable
        assert!(lair_socket_path_fits(Path::new(&deep)));
        let s = short_socket_path(Path::new(&deep));
        assert!(socket_fits(&s), "{:?}", s);
        assert!(s.to_string_lossy().ends_with(".sock"));
        assert_ne!(s, short_socket_path(mac), "one socket per root");
        assert_eq!(s, short_socket_path(Path::new(&deep)), "deterministic");
    }

    #[test]
    fn helpers_compose_under_the_root() {
        let r = Path::new("/r");
        assert_eq!(db_key_path(r), Path::new("/r/conductor/databases/db.key"));
        assert_eq!(lair_old_dir(r, 7), Path::new("/r/lair.old-7"));
        assert!(is_lair_leftover_name("lair.broken-1") && !is_lair_leftover_name("lair"));
    }
}
