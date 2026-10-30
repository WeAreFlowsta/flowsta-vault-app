//! The Vault's key stores, one per line, through flowsta-hc-lines: the
//! conductor start runs them (`supervisor::start_line`); what stays here is
//! the Vault's wording for a person, its leftover-folder names and the
//! quarantine of a store that will not start. The single-step calls below
//! serve the live tests, which start key stores by hand.
//!
//! The device seed is imported under one tag into both lines' stores, so
//! the agent key is the same on 0.6 and 0.7.

use flowsta_hc_lines::keystore::KeyStoreError;
use std::path::Path;
#[cfg(test)]
use {crate::process_ext::SidecarChild, flowsta_hc_lines::keystore, lair_keystore_api::prelude::LairClient, std::time::Duration};

#[cfg(test)]
/// Import a 32-byte seed into the running 0.6 lair under `tag` and return
/// its Ed25519 public key. A tag already present is reused only when it
/// holds this seed.
pub async fn import_seed_to_lair(client: &LairClient, seed_bytes: &[u8; 32], tag: &str) -> Result<[u8; 32], String> {
    Ok(keystore::v06::import_seed(client, seed_bytes, tag).await?)
}

#[cfg(test)]
/// The same for the 0.7 lair; the key must equal the 0.6 line's.
pub async fn import_seed_to_lair_07(
    client: &lair_keystore_api_07::prelude::LairClient,
    seed_bytes: &[u8; 32],
    tag: &str,
) -> Result<[u8; 32], String> {
    Ok(keystore::v07::import_seed(client, seed_bytes, tag).await?)
}

#[cfg(test)]
/// Start a key store from the named sidecar: `vault-lair-keystore` (0.6.3,
/// for the 0.6 conductor) or `vault-lair-keystore-07` (0.7.1, for the 0.7
/// one). A conductor accepts only a lair of its own version.
pub fn start_lair_process_with(lair_dir: &Path, passphrase: &str, binary: &str) -> Result<(SidecarChild, String), String> {
    let bin = crate::resolve_sidecar_bin(binary);
    Ok(keystore::start(lair_dir, &bin, passphrase, &crate::paths::socket_plan())?)
}

#[cfg(test)]
/// Wait for lair to come up, watching the process the whole time (lair
/// binds its socket before it checks the passphrase).
pub async fn wait_for_lair_socket(
    connection_url: &str,
    timeout_secs: u64,
    child: &mut SidecarChild,
    lair_dir: &Path,
) -> Result<(), String> {
    keystore::wait_ready(connection_url, Duration::from_secs(timeout_secs), child, lair_dir)
        .await
        .map_err(vault_text)
}

#[cfg(test)]
/// Connect to a running 0.6 lair (30 s timeout).
pub async fn connect_to_lair(connection_url: &str, passphrase: &str) -> Result<LairClient, String> {
    keystore::v06::connect(connection_url, passphrase, Duration::from_secs(30))
        .await
        .map_err(|e| connect_text(e, "lair"))
}

#[cfg(test)]
/// Connect to a running 0.7 lair (30 s timeout).
pub async fn connect_to_lair_07(
    connection_url: &str,
    passphrase: &str,
) -> Result<lair_keystore_api_07::prelude::LairClient, String> {
    keystore::v07::connect(connection_url, passphrase, Duration::from_secs(30))
        .await
        .map_err(|e| connect_text(e, "lair (0.7)"))
}

/// A line start's failure (flowsta-hc-lines `start_line`) in the Vault's
/// words: the stopped-key-store marker, the connect timeout a person can
/// act on.
pub fn start_error_text(e: flowsta_hc_lines::Error, line: crate::hc::Line) -> String {
    connect_text(e, if line == crate::hc::Line::V06 { "lair" } else { "lair (0.7)" })
}

/// A connect failure in the Vault's words. A timeout is the case a person
/// can act on.
fn connect_text(e: flowsta_hc_lines::Error, which: &str) -> String {
    match e {
        flowsta_hc_lines::Error::KeyStore(KeyStoreError::ConnectTimeout { .. }) if which == "lair" => {
            "The local key store is running but did not answer within 30 seconds. \
             Restart your device and open Flowsta Vault again; if it keeps \
             happening, reinstall Flowsta Vault."
                .to_string()
        }
        flowsta_hc_lines::Error::KeyStore(KeyStoreError::ConnectTimeout { .. }) => {
            "The 0.7 key store is running but did not answer within 30 seconds".to_string()
        }
        flowsta_hc_lines::Error::KeyStore(KeyStoreError::Connect(detail)) => format!("Failed to connect to {which}: {detail}"),
        other => vault_text(other),
    }
}

/// Remove leftover `lair.old-*` / `lair.broken-*` directories. A password
/// change moves the previous keystore to `lair.old-<ts>` and deletes it
/// once the new stack is up; a keystore that would not start is set aside
/// as `lair.broken-<ts>`. Anything still there at the next UNLOCK is
/// garbage. Called from the unlock-time conductor start only - never from
/// the start that follows a change, which still needs `lair.old-*` for its
/// rollback.
pub fn sweep_old_lair_dirs(data_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(data_dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if crate::paths::is_lair_leftover_name(&name) && entry.path().is_dir() {
            match std::fs::remove_dir_all(entry.path()) {
                Ok(()) => log::info!("Removed leftover keystore {:?}", entry.path()),
                Err(e) => log::warn!("Could not remove leftover keystore {:?}: {}", entry.path(), e),
            }
        }
    }
}

#[cfg(test)]
mod dir_tests {
    use super::*;
    #[test]
    fn sweep_removes_leftovers_but_never_the_live_store() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for d in ["lair", "lair.old-1", "lair.broken-2", "unrelated"] { std::fs::create_dir_all(root.join(d)).unwrap(); }
        std::fs::write(root.join("lair/store_file"), b"s").unwrap();
        sweep_old_lair_dirs(root);
        assert!(root.join("lair/store_file").exists());
        assert!(root.join("unrelated").exists());
        assert!(!root.join("lair.old-1").exists() && !root.join("lair.broken-2").exists());
    }
    #[test]
    fn quarantine_sets_the_store_aside_beside_its_parent() {
        let dir = tempfile::tempdir().unwrap();
        let lair = crate::paths::lair_dir(dir.path());
        std::fs::create_dir_all(&lair).unwrap();
        std::fs::write(lair.join("lair-keystore-config.yaml"), b"x").unwrap();
        let moved = quarantine_lair_dir(&lair).unwrap();
        assert!(!lair.exists());
        assert!(moved.file_name().unwrap().to_string_lossy().starts_with(crate::paths::LAIR_BROKEN_PREFIX));
        assert!(moved.join("lair-keystore-config.yaml").exists());
    }
}

/// Prefix of every "lair exited" error - `start_holochain` matches on it to
/// rebuild the keystore before its second attempt.
pub const LAIR_STOPPED_MARKER: &str = "The local key store stopped right after starting";

/// A key store error in the Vault's words. A lair that exits right after
/// starting gets the marker `start_holochain` matches on, plus the one
/// cause that produces this in the field: lair checks its passphrase only
/// after binding its socket, so a passphrase mismatch (a vault file
/// re-saved under a different password than the keystore was created with)
/// shows up as an immediate exit, never as a connect error.
fn vault_text(e: flowsta_hc_lines::Error) -> String {
    match e {
        flowsta_hc_lines::Error::KeyStore(KeyStoreError::Stopped { status, log_tail }) => format!(
            "{} (status {}). Lock the Vault and unlock it again; if it keeps happening, \
             restart your device or reinstall Flowsta Vault. Details: {}",
            LAIR_STOPPED_MARKER, status, log_tail
        ),
        other => other.to_string(),
    }
}

/// Set a keystore that will not start aside as `lair.broken-<ts>` so the
/// next start re-initializes a fresh one. Safe: lair holds only the device
/// seed (re-imported from the vault's own seed on every start) and its
/// import helper, so nothing is lost. The directory is swept at the next
/// unlock like `lair.old-*`.
pub fn quarantine_lair_dir(lair_dir: &Path) -> Result<std::path::PathBuf, String> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let parent = lair_dir.parent().ok_or("lair dir has no parent")?;
    let target = crate::paths::lair_broken_dir(parent, ts);
    std::fs::rename(lair_dir, &target)
        .map_err(|e| format!("Could not set the broken key store aside: {}", e))?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_derivation::{derive_seed, DEVICE_1_CONSTANT};
    use lair_keystore_api::dependencies::sodoken;
    use lair_keystore_api::prelude::*;
    use std::sync::Arc;
    use ed25519_dalek::SigningKey;
    use lair_keystore_api::in_proc_keystore::InProcKeystore;

    /// Standard BIP-39 test mnemonic (all "abandon" + "art"). DO NOT use in production.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    /// Create an in-memory lair keystore + client for testing.
    /// No external lair-keystore binary needed.
    async fn create_test_keystore() -> (InProcKeystore, LairClient) {
        let passphrase: SharedLockedArray = Arc::new(std::sync::Mutex::new(
            sodoken::LockedArray::from(b"test-passphrase".to_vec()),
        ));

        let tmp = std::env::temp_dir().join(format!(
            "lair-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let config = Arc::new(
            PwHashLimits::Interactive
                .with_exec(|| LairServerConfigInner::new(&tmp, passphrase.clone()))
                .await
                .unwrap(),
        );

        let keystore = InProcKeystore::new(
            config,
            lair_keystore_api::mem_store::create_mem_store_factory(),
            passphrase.clone(),
        )
        .await
        .unwrap();

        let client = keystore.new_client().await.unwrap();
        (keystore, client)
    }

    /// THE CRITICAL TEST: Importing our HMAC-derived seed into lair must produce
    /// the same Ed25519 public key as deriving it directly with ed25519_dalek.
    #[tokio::test]
    async fn test_lair_seed_import_matches_ed25519_dalek() {
        let (_keystore, client) = create_test_keystore().await;

        // Derive the same 32-byte device seed our vault uses.
        let device_seed = derive_seed(TEST_MNEMONIC, DEVICE_1_CONSTANT).unwrap();

        // Import into lair via crypto_box wrapping.
        let lair_pub = import_seed_to_lair(&client, &device_seed, "flowsta-device-1")
            .await
            .unwrap();

        // Derive the same key directly with ed25519_dalek.
        let signing_key = SigningKey::from_bytes(&device_seed);
        let expected_pub = signing_key.verifying_key();

        // Compare: lair's derived pub key must match ed25519_dalek's.
        let lair_pub_bytes: &[u8; 32] = &lair_pub;
        assert_eq!(
            lair_pub_bytes,
            expected_pub.as_bytes(),
            "Lair import_seed must produce the same Ed25519 pub key as ed25519_dalek.\n\
             Lair:    {}\n\
             Dalek:   {}",
            hex::encode(lair_pub_bytes),
            hex::encode(expected_pub.as_bytes()),
        );

        // Also verify against our known cross-language test vector.
        assert_eq!(
            hex::encode(lair_pub_bytes),
            "efc0b35169dd2750c4f83712e4655b822e40b141dc08bb9200c9b005268cc2e8",
            "Lair pub key must match the cross-language test vector"
        );
    }

    /// Bonus: sign a payload via lair and verify with ed25519_dalek.
    #[tokio::test]
    async fn a_tag_is_never_reused_for_a_different_seed() {
        let (_keystore, client) = create_test_keystore().await;
        let first = [3u8; 32];
        let again = import_seed_to_lair(&client, &first, "flowsta-conductor-test").await.expect("first import");
        let same = import_seed_to_lair(&client, &first, "flowsta-conductor-test").await.expect("the same seed is reused");
        assert_eq!(again, same);
        let other = import_seed_to_lair(&client, &[4u8; 32], "flowsta-conductor-test").await;
        assert!(other.is_err(), "a different seed under the same tag must be refused");
    }

    #[tokio::test]
    async fn test_lair_sign_verified_by_ed25519_dalek() {
        let (_keystore, client) = create_test_keystore().await;

        let device_seed = derive_seed(TEST_MNEMONIC, DEVICE_1_CONSTANT).unwrap();
        let lair_pub = import_seed_to_lair(&client, &device_seed, "flowsta-device-1")
            .await
            .unwrap();

        // Sign via lair.
        let payload = b"test payload for lair signing";
        let signature = client
            .sign_by_pub_key(
                BinDataSized::from(lair_pub),
                None,
                payload.to_vec().into(),
            )
            .await
            .unwrap();

        // Verify with ed25519_dalek.
        let signing_key = SigningKey::from_bytes(&device_seed);
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&*signature.0);
        assert!(
            verifying_key.verify_strict(payload, &sig).is_ok(),
            "Lair-produced signature must be verifiable by ed25519_dalek"
        );
    }
}
