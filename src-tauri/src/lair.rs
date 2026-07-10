//! Lair-keystore integration for seed import.
//!
//! Provides functions to import our HMAC-derived device seed into lair-keystore,
//! enabling the Holochain conductor to use the same agent identity as the vault.
//!
//! The lair `import_seed` API requires seeds to be encrypted via x25519 crypto_box
//! (xsalsa20poly1305) for transport security. The `import_seed_to_lair` function
//! handles this wrapping transparently, following the pattern from lair's official
//! `deterministic-keys.rs` example.

use crate::process_ext::CommandExt;
use lair_keystore_api::dependencies::sodoken;
use lair_keystore_api::prelude::*;
use percent_encoding::percent_decode_str;
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

/// Import a 32-byte seed into a running lair keystore.
///
/// Handles the x25519 crypto_box encryption wrapping required by lair's
/// `import_seed` API. Returns `SeedInfo` containing the Ed25519 and X25519
/// public keys derived from the imported seed.
///
/// # Arguments
/// * `client` - Connected LairClient
/// * `seed_bytes` - 32-byte seed (e.g. from HMAC-SHA256 derivation)
/// * `tag` - Identifier for the seed in lair (e.g. "flowsta-device-1")
pub async fn import_seed_to_lair(
    client: &LairClient,
    seed_bytes: &[u8; 32],
    tag: &str,
) -> LairResult<SeedInfo> {
    // Check if this seed tag already exists (e.g. re-unlock after previous import).
    // If so, just return the existing seed info.
    match client.get_entry(tag.into()).await {
        Ok(LairEntryInfo::Seed { seed_info, .. }) => {
            log::info!("Seed '{}' already exists in lair, reusing", tag);
            return Ok(seed_info);
        }
        _ => {} // Not found or different entry type - proceed with import
    }

    // 1. Create a helper seed in lair to get a recipient x25519 public key.
    //    Lair requires the import payload to be encrypted to a key it controls.
    let helper = match client
        .new_seed("_import_helper".into(), None, false)
        .await
    {
        Ok(h) => h,
        Err(_) => {
            // Helper may already exist from a previous run - fetch it instead
            match client.get_entry("_import_helper".into()).await {
                Ok(LairEntryInfo::Seed { seed_info, .. }) => seed_info,
                _ => return Err(lair_keystore_api::dependencies::one_err::OneErr::new("Failed to create or fetch _import_helper seed")),
            }
        }
    };

    // 2. Generate ephemeral x25519 keypair for the sender side of crypto_box.
    let mut sender_pub = [0u8; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
    let mut sender_sec =
        sodoken::SizedLockedArray::<{ sodoken::crypto_box::XSALSA_SECRETKEYBYTES }>::new()?;
    sodoken::crypto_box::xsalsa_keypair(&mut sender_pub, &mut *sender_sec.lock())?;

    // 3. Generate random nonce (24 bytes).
    let mut nonce = [0u8; sodoken::crypto_box::XSALSA_NONCEBYTES];
    sodoken::random::randombytes_buf(&mut nonce)?;

    // 4. Encrypt our seed with crypto_box(nonce, seed, helper_pub, ephemeral_sec).
    let recipient_pub_bytes: &[u8; 32] = &*helper.x25519_pub_key.0;
    let mut cipher = vec![0u8; seed_bytes.len() + sodoken::crypto_box::XSALSA_MACBYTES];
    sodoken::crypto_box::xsalsa_easy(
        &mut cipher,
        seed_bytes,
        &nonce,
        recipient_pub_bytes,
        &*sender_sec.lock(),
    )?;

    // 5. Import the encrypted seed into lair.
    //    Lair decrypts using the helper seed's x25519 private key and stores our seed.
    let sender_pub_key = BinDataSized(Arc::new(sender_pub));
    let seed_info = client
        .import_seed(
            sender_pub_key,
            helper.x25519_pub_key,
            None,
            nonce,
            cipher.into(),
            tag.into(),
            false,
        )
        .await?;

    Ok(seed_info)
}

// ── Process Lifecycle ───────────────────────────────────────────────
//
// Functions for managing an external lair-keystore process.
// In production, these will use Tauri's sidecar API.
// For development, we use std::process::Command with the cargo-installed binary.

/// Start a lair-keystore process.
///
/// On first run (no config file), initializes the keystore.
/// Then starts the server process.
/// Returns the child process handle and the connection URL.
pub fn start_lair_process(
    lair_dir: &Path,
    passphrase: &str,
) -> Result<(Child, String), String> {
    std::fs::create_dir_all(lair_dir)
        .map_err(|e| format!("Failed to create lair directory: {}", e))?;

    let config_path = lair_dir.join("lair-keystore-config.yaml");
    let is_first_run = !config_path.exists();

    let lair_bin = crate::resolve_sidecar_bin("vault-lair-keystore");
    log::info!("Using lair-keystore binary: {:?}", lair_bin);

    if is_first_run {
        log::info!("[lair:init] first run - initializing lair-keystore");
        let init_start = std::time::Instant::now();
        let mut child = Command::new(&lair_bin)
            .arg("init")
            .arg("--piped")
            .current_dir(lair_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .tie_to_parent()
            .spawn_hidden()
            .map_err(|e| format!("Failed to spawn lair-keystore init: {}", e))?;
        log::info!("[lair:init] spawned pid {}", child.id());

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(format!("{}\n", passphrase).as_bytes())
                .map_err(|e| format!("Failed to write passphrase to lair init: {}", e))?;
        }

        let status = child
            .wait()
            .map_err(|e| format!("Failed to wait for lair init: {}", e))?;
        if !status.success() {
            return Err(format!("lair-keystore init failed with status: {}", status));
        }
        log::info!(
            "[lair:init] completed in {}ms",
            init_start.elapsed().as_millis()
        );
    }

    // Read connection URL from config file.
    let connection_url = read_connection_url(&config_path)?;

    // Clean up stale socket file from a previous run (e.g. if lair was killed without cleanup).
    // Without this, the new lair process can't bind and exits immediately.
    let socket_path = lair_dir.join("socket");
    if socket_path.exists() {
        log::info!("Removing stale lair socket: {:?}", socket_path);
        let _ = std::fs::remove_file(&socket_path);
    }

    // Start the lair server.
    log::info!("[lair:server] starting lair-keystore server");
    let spawn_start = std::time::Instant::now();
    let mut child = Command::new(&lair_bin)
        .arg("server")
        .arg("--piped")
        .current_dir(lair_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .tie_to_parent()
        .spawn_hidden()
        .map_err(|e| format!("Failed to spawn lair-keystore server: {}", e))?;

    // Pipe passphrase to stdin.
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(format!("{}\n", passphrase).as_bytes())
            .map_err(|e| format!("Failed to write passphrase to lair server: {}", e))?;
    }

    log::info!(
        "[lair:server] started (pid {}) in {}ms",
        child.id(),
        spawn_start.elapsed().as_millis()
    );
    Ok((child, connection_url))
}

/// Read the connection URL from lair's config file.
fn read_connection_url(config_path: &Path) -> Result<String, String> {
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read lair config at {:?}: {}", config_path, e))?;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("connectionUrl:") {
            let url = line
                .strip_prefix("connectionUrl:")
                .unwrap()
                .trim()
                .to_string();
            return Ok(url);
        }
    }

    Err(format!(
        "No connectionUrl found in lair config: {:?}",
        config_path
    ))
}

/// Connect to a running lair-keystore via its connection URL.
///
/// The connection URL comes from lair's config file (e.g. `unix:///path/to/socket?k=...`).
/// Returns a LairClient for seed import and signing operations.
pub async fn connect_to_lair(
    connection_url: &str,
    passphrase: &str,
) -> Result<LairClient, String> {
    let url = lair_keystore_api::dependencies::url::Url::parse(connection_url)
        .map_err(|e| format!("Invalid lair connection URL: {}", e))?;
    let passphrase_array: SharedLockedArray = Arc::new(std::sync::Mutex::new(
        sodoken::LockedArray::from(passphrase.as_bytes().to_vec()),
    ));
    // Wrap in a timeout so the user gets a clear error instead of an
    // indefinite spinner if the IPC handshake hangs (e.g., a runtime-library
    // mismatch between our embedded lair_keystore_api and the bundled
    // lair-keystore binary on certain Linux setups).
    let connect = lair_keystore_api::ipc_keystore_connect(url, passphrase_array);
    match tokio::time::timeout(std::time::Duration::from_secs(30), connect).await {
        Ok(Ok(client)) => Ok(client),
        Ok(Err(e)) => Err(format!("Failed to connect to lair: {}", e)),
        Err(_) => Err(
            "Timed out connecting to the local key store. \
             Try reinstalling Flowsta Vault, or restart your computer if \
             the problem persists."
                .to_string(),
        ),
    }
}

/// Wait for the lair connection to be ready.
/// On Unix, polls until the socket file exists.
/// On Windows, lair uses named pipes - poll by attempting a TCP-like connect.
pub async fn wait_for_lair_socket(connection_url: &str, timeout_secs: u64) -> Result<(), String> {
    // On Windows, lair uses named pipes which don't have a socket file to poll.
    // Instead, just wait a fixed period for lair to initialize.
    if cfg!(target_os = "windows") {
        log::info!("Windows: waiting for lair-keystore to initialize...");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        return Ok(());
    }

    // Unix: Extract socket path from URL like "unix:///path/to/socket?k=..."
    let url = lair_keystore_api::dependencies::url::Url::parse(connection_url)
        .map_err(|e| format!("Invalid connection URL: {}", e))?;
    // url.path() returns percent-encoded path (e.g. %20 for spaces).
    // Decode it so we match the actual filesystem path.
    let decoded_path = percent_decode_str(url.path()).decode_utf8_lossy();
    let socket_path = std::path::PathBuf::from(decoded_path.as_ref());

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    while std::time::Instant::now() < deadline {
        if socket_path.exists() {
            log::info!("Lair socket ready at {:?}", socket_path);
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    Err(format!(
        "Lair socket not ready after {}s: {:?}",
        timeout_secs, socket_path
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_derivation::{derive_seed, DEVICE_1_CONSTANT};
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
        let seed_info = import_seed_to_lair(&client, &device_seed, "flowsta-device-1")
            .await
            .unwrap();

        // Derive the same key directly with ed25519_dalek.
        let signing_key = SigningKey::from_bytes(&device_seed);
        let expected_pub = signing_key.verifying_key();

        // Compare: lair's derived pub key must match ed25519_dalek's.
        let lair_pub_bytes: &[u8; 32] = &*seed_info.ed25519_pub_key.0;
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
    async fn test_lair_sign_verified_by_ed25519_dalek() {
        let (_keystore, client) = create_test_keystore().await;

        let device_seed = derive_seed(TEST_MNEMONIC, DEVICE_1_CONSTANT).unwrap();
        let seed_info = import_seed_to_lair(&client, &device_seed, "flowsta-device-1")
            .await
            .unwrap();

        // Sign via lair.
        let payload = b"test payload for lair signing";
        let signature = client
            .sign_by_pub_key(
                seed_info.ed25519_pub_key.clone(),
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
