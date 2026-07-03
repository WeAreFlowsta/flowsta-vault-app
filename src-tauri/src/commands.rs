use crate::key_derivation::{
    base64_standard_encode, build_sorted_agent_pair_payload, construct_agent_pub_key_bytes,
    construct_agent_pub_key_string, derive_device_keypair, derive_recovery_lookup_hash,
    derive_seed, msgpack_encode_bytes, sign_with_device_seed, validate_mnemonic,
    DEVICE_1_CONSTANT,
};
use crate::conductor::{ConductorHandle, ConductorStatus};
use crate::vault::{
    decrypt_vault, encrypt_vault, load_vault, save_vault, vault_exists, VaultConfig,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tauri::{Emitter, Manager, State};

/// AppWebsocket request timeout for the signature-fetch + sign / revoke /
/// amend paths. The holochain_websocket default is **60 s** — fine for a
/// warm conductor, but on first launch with a returning agent the DHT
/// hasn't yet gossiped the agent's history in, and `get_links` / `get`
/// calls inside the signing zome can easily exceed a minute waiting for
/// peer data. The Vault log "Websocket error: Timeout" is exactly this
/// firing. 300 s covers realistic cold-start DHT warmup; the loading UX
/// holds the user with a progress message while it runs.
pub(crate) fn long_request_ws_config() -> Arc<holochain_client::WebsocketConfig> {
    let mut cfg = holochain_client::WebsocketConfig::CLIENT_DEFAULT;
    cfg.default_request_timeout = std::time::Duration::from_secs(300);
    Arc::new(cfg)
}

// ── Connected Sites tracking ────────────────────────────────────────

/// A site (browser origin) that has made requests to the IPC server.
#[derive(Clone, Serialize)]
pub struct ConnectedSite {
    pub origin: String,
    pub first_seen: i64,
    pub last_request: i64,
    pub request_count: u64,
    pub last_action: String,
    /// Whether this origin has ever used the /authenticate endpoint.
    pub has_authenticated: bool,
    /// Whether this origin is auto-approved for /authenticate (populated at query time).
    pub trusted: bool,
}

/// Serializable info about a pending auth request (without the channel sender).
#[derive(Clone, Serialize)]
pub struct AuthRequestInfo {
    pub id: String,
    pub app_name: String,
    pub origin: Option<String>,
    pub reason: Option<String>,
}

/// A pending authentication request awaiting user approval.
pub struct PendingAuthRequest {
    pub info: AuthRequestInfo,
    /// The base64-encoded challenge to sign (read by ipc_server).
    #[allow(dead_code)]
    pub challenge: Option<String>,
    pub responder: tokio::sync::oneshot::Sender<bool>,
}

/// API-verified app info returned by /api/v1/apps/verify.
#[derive(Clone, Serialize, Deserialize)]
pub struct VerifiedAppInfo {
    pub name: String,
    pub description: Option<String>,
    pub app_type: String,
    pub logo_url: Option<String>,
    pub scopes: Vec<String>,
    pub organization_name: Option<String>,
}

/// A pending identity link request awaiting user approval.
/// Used by the POST /link-identity endpoint for third-party Holochain apps.
pub struct PendingLinkIdentityRequest {
    pub id: String,
    pub app_name: String,
    pub organization_name: Option<String>,
    pub scopes: Vec<String>,
    pub description: Option<String>,
    pub logo_url: Option<String>,
    pub origin: Option<String>,
    pub replacing_existing: bool,
    pub responder: tokio::sync::oneshot::Sender<bool>,
}

/// A pending document sign request awaiting user approval.
/// Used by the POST /sign-document endpoint for Sign It.
pub struct PendingDocumentSignRequest {
    pub id: String,
    pub app_name: String,
    pub file_hash: String,
    pub label: Option<String>,
    pub origin: Option<String>,
    pub responder: tokio::sync::oneshot::Sender<bool>,
}

/// A third-party app that has been linked via /link-identity.
#[derive(Clone, Serialize, Deserialize)]
pub struct LinkedThirdPartyApp {
    pub app_name: String,
    pub app_agent_pub_key: String,
    pub linked_at: i64,
    /// Developer client_id from dev.flowsta.com (for MAU tracking).
    #[serde(default)]
    pub client_id: Option<String>,
    /// The HTTP origin that made the /link-identity request.
    /// Used by /status to match caller origin → client_id → granted scopes.
    #[serde(default)]
    pub origin: Option<String>,
}

/// Application state shared across commands.
pub struct AppState {
    /// The decrypted vault config (None = locked).
    pub vault_config: Mutex<Option<VaultConfig>>,
    /// Path to the vault file.
    pub vault_path: Mutex<std::path::PathBuf>,
    /// App data directory (parent of vault file, lair dir, conductor dir).
    pub data_dir: std::path::PathBuf,
    /// Sites that have connected via the IPC server (origin → info).
    pub connected_sites: Mutex<HashMap<String, ConnectedSite>>,
    /// A pending /authenticate request waiting for user approval.
    pub pending_auth: Mutex<Option<PendingAuthRequest>>,
    /// A pending /link-identity request waiting for user approval.
    pub pending_link_identity: Mutex<Option<PendingLinkIdentityRequest>>,
    /// A pending /sign-document request waiting for user approval.
    pub pending_document_sign: Mutex<Option<PendingDocumentSignRequest>>,
    /// Origins the user has chosen to auto-approve for /authenticate.
    pub approved_apps: Mutex<Vec<String>>,
    /// Third-party apps linked via /link-identity.
    pub linked_third_party_apps: Mutex<Vec<LinkedThirdPartyApp>>,
    /// Handle to the running conductor + lair processes (None = not running).
    pub conductor_handle: Mutex<Option<ConductorHandle>>,
    /// Current conductor status (for frontend polling).
    pub conductor_status: Mutex<ConductorStatus>,
    /// MAU tracking state (loaded on unlock, encrypted on disk).
    pub mau_state: crate::mau::MauState,
    /// Cache of API-verified apps (client_id → app info). Enables offline re-linking.
    pub verified_apps: Mutex<HashMap<String, VerifiedAppInfo>>,
    /// Scopes granted to each linked app at link time (client_id → scopes).
    /// Persisted to linked-app-scopes.json. Used by /status for scope-filtered responses.
    pub linked_app_scopes: Mutex<HashMap<String, Vec<String>>>,
    /// Derived backup encryption key — persists through vault lock so apps
    /// can store backups while the vault is locked. Derived from device_seed
    /// via HMAC (cannot recover seed or sign).
    pub backup_key: Mutex<Option<[u8; 32]>>,
    /// Web agent key from auto-link (base64 39-byte AgentPubKey).
    /// Cached here so get_my_signatures can query linked agent's signatures
    /// without waiting for identity DNA gossip.
    pub linked_web_agent_key: Mutex<Option<String>>,
    /// Files passed to the app via the OS file-explorer integration
    /// ("Sign with Flowsta Vault" right-click) before the frontend was ready
    /// to handle them. Drained by `take_pending_sign_paths`.
    pub pending_sign_paths: Mutex<Vec<std::path::PathBuf>>,
    /// A relay-login code that arrived via flowsta:// while the vault was
    /// locked or before the frontend mounted — drained by
    /// `take_pending_relay_code`.
    pub pending_relay_code: Mutex<Option<String>>,
    /// The claimed relay session between claim and approve/deny.
    /// Held Rust-side so approve signs the server-issued challenge, never a
    /// frontend-supplied one.
    pub pending_relay_claim: Mutex<Option<crate::relay_login::RelayClaim>>,
    /// Lair-keystore passphrase, held while the vault is unlocked so the
    /// runtime watchdog can restart the conductor without re-prompting
    /// the user. Stored in a `sodoken::LockedArray` (memory-locked pages,
    /// zeroed on drop). `None` when locked.
    pub unlock_passphrase: Mutex<Option<lair_keystore_api::dependencies::sodoken::LockedArray>>,
    /// Serializes concurrent watchdog restart attempts. Two commands that
    /// fail simultaneously and call `ensure_conductor_alive` should not
    /// both spawn a fresh conductor — the first one wins, the others
    /// observe the recovered state.
    pub conductor_restart_lock: tokio::sync::Mutex<()>,
}

impl AppState {
    pub fn new(data_dir: std::path::PathBuf) -> Self {
        let vault_path = data_dir.join("vault.enc");

        // Load persisted linked apps, verified apps cache, and granted scopes
        let linked_apps = load_linked_apps(&data_dir);
        let verified_apps = load_verified_apps(&data_dir);
        let linked_app_scopes = load_linked_app_scopes(&data_dir);

        Self {
            vault_config: Mutex::new(None),
            vault_path: Mutex::new(vault_path),
            data_dir,
            connected_sites: Mutex::new(HashMap::new()),
            pending_auth: Mutex::new(None),
            pending_link_identity: Mutex::new(None),
            pending_document_sign: Mutex::new(None),
            approved_apps: Mutex::new(Vec::new()),
            linked_third_party_apps: Mutex::new(linked_apps),
            conductor_handle: Mutex::new(None),
            conductor_status: Mutex::new(ConductorStatus::Stopped),
            mau_state: crate::mau::MauState::new(),
            verified_apps: Mutex::new(verified_apps),
            linked_app_scopes: Mutex::new(linked_app_scopes),
            backup_key: Mutex::new(None),
            linked_web_agent_key: Mutex::new(None),
            pending_sign_paths: Mutex::new(Vec::new()),
            pending_relay_code: Mutex::new(None),
            pending_relay_claim: Mutex::new(None),
            unlock_passphrase: Mutex::new(None),
            conductor_restart_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Persist the verified apps cache to disk.
    pub fn save_verified_apps(&self) {
        let apps = self.verified_apps.lock().unwrap();
        let path = self.data_dir.join("verified-apps.json");
        if let Ok(json) = serde_json::to_string_pretty(&*apps) {
            let _ = std::fs::write(path, json);
        }
    }

    /// Persist the current linked apps list to disk.
    pub fn save_linked_apps(&self) {
        // Serialize under the lock, then RELEASE it before the blocking
        // disk write — holding a std Mutex across std::fs::write makes
        // concurrent readers (e.g. /status polling get_scopes_for_origin)
        // block worker threads, which under load can starve the IPC
        // accept loop. Clone-then-write keeps the critical section tiny.
        let json = {
            let apps = self.linked_third_party_apps.lock().unwrap();
            serde_json::to_string_pretty(&*apps)
        };
        if let Ok(json) = json {
            let _ = std::fs::write(self.data_dir.join("linked-apps.json"), json);
        }
    }

    /// Persist the granted scopes store to disk.
    pub fn save_linked_app_scopes(&self) {
        let json = {
            let scopes = self.linked_app_scopes.lock().unwrap();
            serde_json::to_string_pretty(&*scopes)
        };
        if let Ok(json) = json {
            let _ = std::fs::write(self.data_dir.join("linked-app-scopes.json"), json);
        }
    }
}

fn load_linked_apps(data_dir: &std::path::Path) -> Vec<LinkedThirdPartyApp> {
    let path = data_dir.join("linked-apps.json");
    match std::fs::read_to_string(&path) {
        Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn load_linked_app_scopes(data_dir: &std::path::Path) -> HashMap<String, Vec<String>> {
    let path = data_dir.join("linked-app-scopes.json");
    match std::fs::read_to_string(&path) {
        Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

fn load_verified_apps(data_dir: &std::path::Path) -> HashMap<String, VerifiedAppInfo> {
    let path = data_dir.join("verified-apps.json");
    match std::fs::read_to_string(&path) {
        Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

#[derive(Serialize)]
pub struct VaultStatus {
    pub initialized: bool,
    pub unlocked: bool,
    pub version: String,
    pub agent_pub_key: Option<String>,
    pub did: Option<String>,
}

/// Get the current vault status.
#[tauri::command]
pub fn get_vault_status(state: State<'_, Arc<AppState>>) -> VaultStatus {
    let vault_path = state.vault_path.lock().unwrap();
    let config = state.vault_config.lock().unwrap();

    VaultStatus {
        initialized: vault_exists(&vault_path),
        unlocked: config.is_some(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        agent_pub_key: config.as_ref().map(|c| c.agent_pub_key.clone()),
        did: config.as_ref().map(|c| c.did.clone()),
    }
}

#[derive(Serialize)]
pub struct SetupResult {
    pub agent_pub_key: String,
    pub did: String,
}

/// Set up a new vault from a recovery phrase and web account password.
/// The web login password is used to encrypt the vault on disk.
/// After setup, spawns the Holochain conductor in the background.
#[tauri::command]
pub fn setup_vault(
    mnemonic: String,
    password: String,
    web_agent_pub_key: Option<String>,
    web_email: Option<String>,
    web_username: Option<String>,
    display_name: Option<String>,
    profile_picture: Option<String>,
    hosting_model: Option<String>,
    app_handle: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<SetupResult, String> {
    // Validate mnemonic
    if !validate_mnemonic(&mnemonic) {
        return Err("Invalid recovery phrase".into());
    }

    // Check not already initialized
    let vault_path = state.vault_path.lock().unwrap();
    if vault_exists(&vault_path) {
        return Err("Vault already exists. Use unlock instead.".into());
    }

    // Derive device keypair
    let signing_key =
        derive_device_keypair(&mnemonic).map_err(|e| format!("Key derivation failed: {}", e))?;

    let verifying_key = signing_key.verifying_key();
    let pub_key_bytes = verifying_key.as_bytes();

    // Proper 39-byte Holochain AgentPubKey (with DHT location)
    let agent_pub_key = construct_agent_pub_key_string(pub_key_bytes);
    let did = format!("did:flowsta:{}", agent_pub_key);

    // Full 39-byte key as standard base64 (for API zome calls)
    let agent_pub_key_39 = construct_agent_pub_key_bytes(pub_key_bytes);
    let agent_pub_key_raw_b64 = base64_standard_encode(&agent_pub_key_39);

    // Derive device seed (stored encrypted for agent linking signing)
    let device_seed = derive_seed(&mnemonic, DEVICE_1_CONSTANT)
        .map_err(|e| format!("Device seed derivation failed: {}", e))?;

    // Derive recovery lookup hash (for API agent key discovery)
    let lookup_hash = derive_recovery_lookup_hash(&mnemonic)
        .map_err(|e| format!("Lookup hash derivation failed: {}", e))?;

    // Derive the private DNA v2 material while the mnemonic is in hand
    // (it is never stored): the symmetric Sealed-record key and the
    // per-user network seed. Same values on every device from this phrase.
    let data_key = crate::key_derivation::derive_data_encryption_key(&mnemonic)
        .map_err(|e| format!("Data key derivation failed: {}", e))?;
    let private_network_seed = crate::key_derivation::derive_private_network_seed(&mnemonic)
        .map_err(|e| format!("Network seed derivation failed: {}", e))?;

    // Create vault config
    let config = VaultConfig {
        agent_pub_key: agent_pub_key.clone(),
        did: did.clone(),
        installed_app_ids: vec![],
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        device_seed: Some(device_seed.to_vec()),
        recovery_lookup_hash: Some(lookup_hash),
        agent_pub_key_raw_b64: Some(agent_pub_key_raw_b64),
        web_agent_pub_key,
        web_email: web_email.clone(),
        web_username,
        display_name,
        profile_picture,
        // Set initial DNA versions to the bundled defaults
        private_dna_version: Some(crate::dna::BUNDLED_PRIVATE_VERSION.to_string()),
        identity_dna_version: Some(crate::dna::BUNDLED_IDENTITY_VERSION.to_string()),
        conductor_version: Some("0.6.0".to_string()),
        hosting_model,
        data_key: Some(data_key.to_vec()),
        private_network_seed: Some(private_network_seed),
    };

    // Encrypt and save (with unencrypted display identifier for unlock screen)
    let mut encrypted =
        encrypt_vault(&config, &password).map_err(|e| format!("Encryption failed: {}", e))?;
    encrypted.display_email = config.web_email.clone().or(config.web_username.clone());
    save_vault(&vault_path, &encrypted).map_err(|e| format!("Save failed: {}", e))?;

    // Extract conductor startup params before storing config
    let conductor_seed = config.device_seed.clone();
    let conductor_data_dir = state.data_dir.clone();
    let conductor_passphrase = password.clone();

    // Store decrypted config in app state (vault is now unlocked)
    {
        let mut state_config = state.vault_config.lock().unwrap();
        *state_config = Some(config);
    }

    // Derive and cache backup encryption key (persists through lock)
    {
        let mut bk = state.backup_key.lock().unwrap();
        *bk = Some(crate::backup::derive_backup_key_from_seed(&device_seed));
    }

    log::info!("Vault created and unlocked. Agent: {}", &agent_pub_key);

    // Load MAU state (fresh store for new vault)
    crate::mau::load_mau_state(&state);

    // Cache the lair passphrase in a memory-locked, zero-on-drop buffer so
    // the runtime watchdog can restart the conductor without re-prompting.
    *state.unlock_passphrase.lock().unwrap() = Some(
        lair_keystore_api::dependencies::sodoken::LockedArray::from(
            conductor_passphrase.as_bytes().to_vec(),
        ),
    );

    // Spawn conductor startup in background
    spawn_conductor_startup(
        conductor_seed,
        conductor_data_dir,
        conductor_passphrase,
        app_handle,
        state.inner().clone(),
    );

    Ok(SetupResult {
        agent_pub_key,
        did,
    })
}

/// Unlock an existing vault with the master password.
/// After unlock, spawns the Holochain conductor in the background.
#[tauri::command]
pub fn unlock_vault(
    password: String,
    app_handle: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<SetupResult, String> {
    let vault_path = state.vault_path.lock().unwrap();

    if !vault_exists(&vault_path) {
        return Err("No vault found. Run setup first.".into());
    }

    // Load and decrypt
    let encrypted =
        load_vault(&vault_path).map_err(|e| format!("Failed to read vault: {}", e))?;
    let config = decrypt_vault(&encrypted, &password)
        .map_err(|_| "Wrong password or corrupted vault".to_string())?;

    let result = SetupResult {
        agent_pub_key: config.agent_pub_key.clone(),
        did: config.did.clone(),
    };

    // Extract conductor startup params before storing config
    let device_seed = config.device_seed.clone();
    let data_dir = state.data_dir.clone();
    let passphrase = password.clone();

    // Store decrypted config in app state
    {
        let mut state_config = state.vault_config.lock().unwrap();
        *state_config = Some(config);
    }

    // Derive and cache backup encryption key (persists through lock)
    if let Some(ref seed_vec) = device_seed {
        if seed_vec.len() == 32 {
            let mut seed_arr = [0u8; 32];
            seed_arr.copy_from_slice(seed_vec);
            let mut bk = state.backup_key.lock().unwrap();
            *bk = Some(crate::backup::derive_backup_key_from_seed(&seed_arr));
        }
    }

    log::info!("Vault unlocked.");

    // Load MAU state from encrypted disk storage
    crate::mau::load_mau_state(&state);

    // Cache the lair passphrase in a memory-locked, zero-on-drop buffer so
    // the runtime watchdog can restart the conductor without re-prompting.
    *state.unlock_passphrase.lock().unwrap() = Some(
        lair_keystore_api::dependencies::sodoken::LockedArray::from(
            passphrase.as_bytes().to_vec(),
        ),
    );

    // Spawn conductor startup in background (if device seed is available)
    spawn_conductor_startup(device_seed, data_dir, passphrase, app_handle, state.inner().clone());

    Ok(result)
}

/// Lock the vault (clear in-memory config and stop conductor).
#[tauri::command]
pub fn lock_vault(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    // Cancel any open approval dialog: deny the waiting IPC request so it
    // returns immediately instead of hanging (and can never be approved
    // against a now-locked vault). The calling app sees a clean denial.
    if let Some(req) = state.pending_auth.lock().unwrap().take() {
        let _ = req.responder.send(false);
    }
    if let Some(req) = state.pending_document_sign.lock().unwrap().take() {
        let _ = req.responder.send(false);
    }

    // Session approvals don't outlive an unlock session.
    state.approved_apps.lock().unwrap().clear();

    // Clear MAU state before clearing vault config (needs device_seed)
    crate::mau::clear_mau_state(&state);

    let mut config = state.vault_config.lock().unwrap();
    *config = None;

    // Shutdown conductor + lair if running
    if let Some(handle) = state.conductor_handle.lock().unwrap().take() {
        handle.shutdown();
    }
    *state.conductor_status.lock().unwrap() = ConductorStatus::Stopped;

    // Drop the cached passphrase. `LockedArray::Drop` zeroes the bytes
    // and unlocks the memory pages.
    *state.unlock_passphrase.lock().unwrap() = None;

    log::info!("Vault locked.");
    Ok(())
}

/// Get the current conductor status (for frontend polling).
#[tauri::command]
pub fn get_conductor_status(state: State<'_, Arc<AppState>>) -> ConductorStatus {
    state.conductor_status.lock().unwrap().clone()
}

/// Runtime conductor watchdog. Checks whether the conductor process is
/// still alive; if it has exited, runs the full `start_holochain` flow
/// again using the cached unlock-time credentials so the user doesn't
/// have to re-enter their password.
///
/// On Windows specifically, holochain.exe occasionally crashes mid-session
/// (`STATUS_ACCESS_VIOLATION` 0xc0000005) when admin calls touch the
/// signing cell. The startup auto-restart in `conductor::start_holochain`
/// only covers crashes during DNA install — runtime crashes are caught
/// here.
///
/// Concurrent callers are serialised by `conductor_restart_lock`: the
/// first to arrive does the restart, others wait and then observe the
/// recovered handle on a re-check.
async fn ensure_conductor_alive(
    state: &Arc<AppState>,
    app_handle: &tauri::AppHandle,
) -> Result<(), String> {
    // Serialise restart attempts so two failed commands don't both try
    // to bring the conductor up.
    let _guard = state.conductor_restart_lock.lock().await;

    // Re-check liveness inside the lock. If a previous holder of the
    // lock already restarted, we have nothing to do.
    let needs_restart = {
        let mut handle_guard = state.conductor_handle.lock().unwrap();
        match handle_guard.as_mut() {
            Some(h) => match h.conductor_child.try_wait() {
                Ok(Some(status)) => {
                    log::warn!(
                        "[watchdog] conductor process exited (status: {}) — will restart",
                        status,
                    );
                    true
                }
                Ok(None) => false, // process still alive
                Err(e) => {
                    log::warn!("[watchdog] try_wait failed: {} — assuming dead", e);
                    true
                }
            },
            None => true, // no handle at all
        }
    };

    if !needs_restart {
        log::info!("[watchdog] conductor is alive (recovered by an earlier caller)");
        return Ok(());
    }

    // Take the old (dead) handle and shut it down — this kills any
    // leftover lair-keystore process so the new conductor can take its
    // socket / port cleanly.
    if let Some(old) = state.conductor_handle.lock().unwrap().take() {
        log::info!("[watchdog] cleaning up old handle");
        old.shutdown();
    }
    *state.conductor_status.lock().unwrap() = ConductorStatus::Starting {
        message: "Recovering conductor...".into(),
    };
    let _ = app_handle.emit(
        "conductor-status",
        ConductorStatus::Starting {
            message: "Recovering conductor...".into(),
        },
    );

    // Extract the cached passphrase. Briefly copies the bytes into a
    // `String` for the duration of the start_holochain call; the
    // long-lived copy stays in the `LockedArray`.
    let passphrase = {
        let mut guard = state.unlock_passphrase.lock().unwrap();
        let arr = guard
            .as_mut()
            .ok_or("[watchdog] cannot restart: vault is locked (no cached passphrase)")?;
        let bytes_locked = arr.lock();
        String::from_utf8(bytes_locked.to_vec())
            .map_err(|e| format!("[watchdog] passphrase utf8 error: {}", e))?
    };

    // Pull device_seed out of vault_config.
    let device_seed: [u8; 32] = {
        let cfg_guard = state.vault_config.lock().unwrap();
        let cfg = cfg_guard
            .as_ref()
            .ok_or("[watchdog] vault config not available")?;
        let seed_vec = cfg
            .device_seed
            .as_ref()
            .ok_or("[watchdog] no device seed in vault config")?;
        if seed_vec.len() != 32 {
            return Err(format!(
                "[watchdog] device seed wrong length ({} bytes)",
                seed_vec.len()
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_vec);
        seed
    };

    let data_dir = state.data_dir.clone();
    #[cfg(debug_assertions)]
    let resource_dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources");
    #[cfg(not(debug_assertions))]
    let resource_dir = app_handle
        .path()
        .resource_dir()
        .map(|d| d.join("resources"))
        .unwrap_or_else(|_| data_dir.clone());

    log::info!("[watchdog] running start_holochain to bring conductor back");
    let new_handle = crate::conductor::start_holochain(
        app_handle.clone(),
        data_dir,
        resource_dir,
        passphrase,
        device_seed,
    )
    .await
    .map_err(|e| format!("[watchdog] restart failed: {}", e))?;

    log::info!(
        "[watchdog] conductor recovered (admin port {})",
        new_handle.admin_port,
    );
    let port = new_handle.admin_port;
    *state.conductor_handle.lock().unwrap() = Some(new_handle);
    *state.conductor_status.lock().unwrap() = ConductorStatus::Ready { admin_port: port };
    let _ = app_handle.emit(
        "conductor-status",
        ConductorStatus::Ready { admin_port: port },
    );
    Ok(())
}

/// Spawn the conductor startup sequence in a background task.
/// Called after vault unlock or setup.
fn spawn_conductor_startup(
    device_seed: Option<Vec<u8>>,
    data_dir: std::path::PathBuf,
    passphrase: String,
    app_handle: tauri::AppHandle,
    state: Arc<AppState>,
) {
    if let Some(seed_vec) = device_seed {
        if seed_vec.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_vec);

            *state.conductor_status.lock().unwrap() = ConductorStatus::Starting {
                message: "Initializing...".into(),
            };

            // Resolve the resource directory where bundled .happ files live.
            // In dev mode, Tauri doesn't copy resources to target/debug/, so we
            // point directly at the source resources/ folder.
            #[cfg(debug_assertions)]
            let resource_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("resources");
            #[cfg(not(debug_assertions))]
            let resource_dir = app_handle
                .path()
                .resource_dir()
                .map(|d| d.join("resources"))
                .unwrap_or_else(|_| data_dir.clone());

            tauri::async_runtime::spawn(async move {
                let app_handle_ref = app_handle.clone();
                let passphrase_for_sync = passphrase.clone();
                match crate::conductor::start_holochain(
                    app_handle,
                    data_dir.clone(),
                    resource_dir,
                    passphrase,
                    seed,
                )
                .await
                {
                    Ok(handle) => {
                        let port = handle.admin_port;
                        log::info!("Conductor started successfully on port {}", port);
                        *state.conductor_handle.lock().unwrap() = Some(handle);
                        let ready_status = ConductorStatus::Ready {
                            admin_port: port,
                        };
                        *state.conductor_status.lock().unwrap() = ready_status.clone();
                        // Emit ready event — conductor.rs also emits this, but the
                        // frontend listener may not be registered yet if startup is fast.
                        let _ = app_handle_ref.emit("conductor-status", ready_status);

                        // Check for DNA updates from the server.
                        // Non-fatal — if offline or update fails, continue with current DNAs.
                        // Downloads go to data_dir (not resource_dir) to avoid triggering
                        // Tauri dev-mode hot-reload and to use a writable location in production.
                        let identity_was_updated = check_dna_updates(
                            &state,
                            &app_handle_ref,
                            port,
                            &data_dir,
                            &passphrase_for_sync,
                        ).await;

                        // Auto-link with web account if not yet linked on DHT.
                        // Always attempt after identity DNA update (attestation is on old network).
                        let should_link = {
                            let config = state.vault_config.lock().unwrap();
                            if let Some(cfg) = config.as_ref() {
                                // Device-hosted identities have no separate web
                                // agent to link to (the device key IS the account
                                // key) — auto-link would resolve its own key and
                                // try to link an agent to itself.
                                cfg.hosting_model.as_deref() != Some("device-hosted")
                                    && cfg.recovery_lookup_hash.is_some()
                                    && cfg.device_seed.is_some()
                                    && cfg.agent_pub_key_raw_b64.is_some()
                            } else {
                                false
                            }
                        };

                        if should_link {
                            if identity_was_updated {
                                log::info!("Identity DNA was updated — re-establishing agent link on new network...");
                            } else {
                                log::info!("Auto-linking desktop agent with web account...");
                            }
                            match auto_link_web_account(&state, &passphrase_for_sync).await {
                                Ok(result) => {
                                    if result.success {
                                        log::info!("Auto-link succeeded: {}", result.message);
                                        // Cache the web agent key for cross-agent signature lookup
                                        if let Some(ref key) = result.web_agent_key {
                                            let mut cached = state.linked_web_agent_key.lock().unwrap();
                                            *cached = Some(key.clone());
                                            log::info!("Cached web agent key for cross-agent signatures");
                                        }
                                    } else {
                                        log::warn!("Auto-link returned failure: {}", result.message);
                                    }
                                    // Notify frontend to refresh profile (profile data synced during auto-link)
                                    let _ = app_handle_ref.emit("profile-synced", ());
                                }
                                Err(e) => {
                                    // Non-fatal — user can retry manually from Identities page
                                    log::warn!("Auto-link failed (non-fatal): {}", e);
                                }
                            }
                        }

                        // Start periodic MAU sync (non-fatal if it fails)
                        crate::mau::spawn_mau_sync_task(state.clone());
                    }
                    Err(e) => {
                        log::error!("Conductor startup failed: {}", e);
                        let status = ConductorStatus::Error {
                            message: e,
                        };
                        let _ = app_handle_ref.emit("conductor-status", status.clone());
                        *state.conductor_status.lock().unwrap() = status;
                    }
                }
            });
        } else {
            log::warn!("Device seed is {} bytes, expected 32 — skipping conductor", seed_vec.len());
        }
    } else {
        log::info!("No device seed in vault — conductor not started");
    }
}

/// Check for DNA updates from the server and apply them.
///
/// Called after conductor startup. Non-fatal — returns `false` on any error
/// so the vault continues with its current DNAs.
/// Returns `true` if the identity DNA was updated (caller should re-link).
async fn check_dna_updates(
    state: &Arc<AppState>,
    app_handle: &tauri::AppHandle,
    admin_port: u16,
    download_dir: &std::path::Path,
    password: &str,
) -> bool {
    // Extract needed values from VaultConfig.
    let (recovery_lookup_hash, current_private_ver, current_identity_ver, agent_key_raw_b64) = {
        let config = state.vault_config.lock().unwrap();
        let cfg = match config.as_ref() {
            Some(c) => c,
            None => {
                log::warn!("VaultConfig not available for DNA update check");
                return false;
            }
        };
        let rlh = match &cfg.recovery_lookup_hash {
            Some(h) => h.clone(),
            None => {
                log::info!("No recovery_lookup_hash — skipping DNA update check");
                return false;
            }
        };
        let priv_ver = cfg
            .private_dna_version
            .clone()
            .unwrap_or_else(|| crate::dna::BUNDLED_PRIVATE_VERSION.to_string());
        let id_ver = cfg
            .identity_dna_version
            .clone()
            .unwrap_or_else(|| crate::dna::BUNDLED_IDENTITY_VERSION.to_string());
        let agent_b64 = cfg.agent_pub_key_raw_b64.clone();
        (rlh, priv_ver, id_ver, agent_b64)
    };

    // Prefer the AgentPubKey that lair actually has for the device seed.
    // The config's stored agent_pub_key_raw_b64 can drift from lair's key if
    // the vault was set up on an older derivation, so we authoritatively use
    // what lair reports — that's what the already-installed cells use, and
    // what install_app needs to be able to sign genesis records.
    let lair_agent_key = {
        let handle_guard = state.conductor_handle.lock().unwrap();
        handle_guard
            .as_ref()
            .map(|h| holochain_types::prelude::AgentPubKey::from_raw_32(
                h.seed_info.ed25519_pub_key.0.to_vec(),
            ))
    };

    let agent_key = if let Some(k) = lair_agent_key {
        k
    } else {
        // Fallback to config value if conductor handle not available for some
        // reason. Shouldn't happen in practice because DNA update runs after
        // conductor startup succeeds.
        match agent_key_raw_b64 {
            Some(b64) => match base64_standard_decode(&b64) {
                Ok(bytes) if bytes.len() == 39 => {
                    holochain_types::prelude::AgentPubKey::from_raw_39(bytes)
                }
                Ok(bytes) => {
                    log::warn!("Agent key is {} bytes, expected 39", bytes.len());
                    return false;
                }
                Err(_) => {
                    log::warn!("Failed to decode agent_pub_key_raw_b64");
                    return false;
                }
            },
            None => {
                log::info!("No agent_pub_key_raw_b64 — skipping DNA update check");
                return false;
            }
        }
    };

    // Emit update check status.
    let _ = app_handle.emit(
        "dna-update-status",
        serde_json::json!({"status": "checking"}),
    );

    let current_signing_ver = crate::dna::BUNDLED_SIGNING_VERSION.to_string();

    let result = crate::dna_updater::check_and_update_dnas(
        admin_port,
        download_dir,
        &recovery_lookup_hash,
        &current_private_ver,
        &current_identity_ver,
        &current_signing_ver,
        agent_key,
    )
    .await;

    let mut identity_updated = false;

    match &result {
        crate::dna_updater::UpdateResult::UpToDate => {
            log::info!("DNA update check: already up to date");
        }
        crate::dna_updater::UpdateResult::Offline => {
            log::info!("DNA update check: offline, continuing with current DNAs");
        }
        crate::dna_updater::UpdateResult::Updated {
            private_updated,
            identity_updated: id_upd,
            signing_updated,
        } => {
            // Persist new versions to VaultConfig.
            let mut config_guard = state.vault_config.lock().unwrap();
            if let Some(cfg) = config_guard.as_mut() {
                if let Some(change) = private_updated {
                    log::info!("Private DNA updated: {} → {}", change.from, change.to);
                    cfg.private_dna_version = Some(change.to.clone());
                }
                if let Some(change) = id_upd {
                    log::info!("Identity DNA updated: {} → {}", change.from, change.to);
                    cfg.identity_dna_version = Some(change.to.clone());
                    identity_updated = true;
                }
                if let Some(change) = signing_updated {
                    log::info!("Signing DNA updated: {} → {}", change.from, change.to);
                }

                // Re-encrypt and save vault with updated versions.
                let vault_path = state.vault_path.lock().unwrap();
                if let Ok(mut encrypted) = encrypt_vault(cfg, password) {
                    encrypted.display_email =
                        cfg.web_email.clone().or(cfg.web_username.clone());
                    let _ = save_vault(&vault_path, &encrypted);
                    log::info!("VaultConfig saved with updated DNA versions");
                }
            }
        }
        crate::dna_updater::UpdateResult::AppUpdateRequired { min_vault_version } => {
            log::warn!(
                "Vault app update required (min version: {})",
                min_vault_version
            );
            let _ = app_handle.emit(
                "dna-update-status",
                serde_json::json!({
                    "status": "app_update_required",
                    "min_vault_version": min_vault_version,
                }),
            );
        }
        crate::dna_updater::UpdateResult::Failed { error } => {
            log::error!("DNA update failed: {}", error);
        }
    }

    let _ = app_handle.emit(
        "dna-update-status",
        serde_json::json!({"status": "done"}),
    );

    identity_updated
}

/// Delete the vault file and clear in-memory state.
/// Returns the app to the "not initialized" state.
#[tauri::command]
pub fn reset_vault(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    // Stop conductor + lair before touching their data dirs. Without
    // this we'd leak processes and (on Windows) the dir delete would
    // fail on the still-open lair socket / conductor files.
    let handle = state.conductor_handle.lock().unwrap().take();
    if let Some(h) = handle {
        h.shutdown();
    }

    // Clear in-memory config
    {
        let mut config = state.vault_config.lock().unwrap();
        *config = None;
    }

    // Delete vault file from disk
    let vault_path = state.vault_path.lock().unwrap().clone();
    if vault_path.exists() {
        std::fs::remove_file(&vault_path)
            .map_err(|e| format!("Failed to delete vault file: {}", e))?;
    }

    // Delete lair keystore directory — otherwise the next vault create
    // reuses the old encrypted lair store with a mismatched passphrase,
    // producing "early eof" failures on lair IPC handshake. The same
    // device seed also gets reused, which silently breaks isolation
    // between what should be different identities on the machine.
    let lair_dir = state.data_dir.join("lair");
    if lair_dir.exists() {
        std::fs::remove_dir_all(&lair_dir)
            .map_err(|e| format!("Failed to delete lair dir: {}", e))?;
    }

    // Delete conductor data — source chains, installed apps, DHT cache.
    // Leaving these behind across a reset produces CellDisabled /
    // agent-key-mismatch errors on the next setup because the cells
    // are keyed to the prior identity.
    let conductor_dir = state.data_dir.join("conductor");
    if conductor_dir.exists() {
        std::fs::remove_dir_all(&conductor_dir)
            .map_err(|e| format!("Failed to delete conductor dir: {}", e))?;
    }

    // Full erase: also remove the local app data so a reset is a true clean
    // slate, not just an identity reset. `backups/` holds OTHER apps' user data
    // (e.g. a linked app's exported records) and these JSON files list which
    // apps are connected and what they can access — none of it should survive a
    // wipe the user intends as "erase everything from this device".
    for name in [
        "linked-apps.json",
        "verified-apps.json",
        "linked-app-scopes.json",
        "mau-events.enc",
        "quota_cache.json",
        ".quota.key",
    ] {
        let p = state.data_dir.join(name);
        if p.exists() {
            if let Err(e) = std::fs::remove_file(&p) {
                log::warn!("reset: failed to remove {}: {}", name, e);
            }
        }
    }
    let backups_dir = state.data_dir.join("backups");
    if backups_dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&backups_dir) {
            log::warn!("reset: failed to remove backups dir: {}", e);
        }
    }

    // Clear the matching in-memory state so the UI reflects the wipe at once.
    state.connected_sites.lock().unwrap().clear();
    state.approved_apps.lock().unwrap().clear();
    state.linked_third_party_apps.lock().unwrap().clear();
    state.verified_apps.lock().unwrap().clear();
    state.linked_app_scopes.lock().unwrap().clear();
    *state.linked_web_agent_key.lock().unwrap() = None;

    log::info!("Vault fully erased — identity, keys, conductor data, app links, scopes, and backups cleared.");
    Ok(())
}

/// Get the identity info (only when unlocked).
#[tauri::command]
pub fn get_identity(state: State<'_, Arc<AppState>>) -> Result<VaultIdentity, String> {
    let config = state.vault_config.lock().unwrap();
    let config = config.as_ref().ok_or("Vault is locked")?;

    // Prefer the in-memory linked_web_agent_key (populated by auto-link on unlock)
    // over the config field, which is often stale or None for users who linked
    // after vault setup.
    let web_agent_pub_key = {
        let cached = state.linked_web_agent_key.lock().unwrap();
        cached.clone().or_else(|| config.web_agent_pub_key.clone())
    };

    Ok(VaultIdentity {
        agent_pub_key: config.agent_pub_key.clone(),
        did: config.did.clone(),
        installed_app_ids: config.installed_app_ids.clone(),
        created_at: config.created_at,
        display_name: config.display_name.clone(),
        profile_picture: config.profile_picture.clone(),
        web_email: config.web_email.clone(),
        web_username: config.web_username.clone(),
        web_agent_pub_key,
    })
}

#[derive(Serialize)]
pub struct VaultIdentity {
    pub agent_pub_key: String,
    pub did: String,
    pub installed_app_ids: Vec<String>,
    pub created_at: i64,
    pub display_name: Option<String>,
    pub profile_picture: Option<String>,
    pub web_email: Option<String>,
    pub web_username: Option<String>,
    pub web_agent_pub_key: Option<String>,
}

/// Validate a recovery phrase without storing it.
#[tauri::command]
pub fn validate_recovery_phrase(mnemonic: String) -> bool {
    validate_mnemonic(&mnemonic)
}

// ── Web Authentication Commands ─────────────────────────────────────

#[derive(Serialize)]
pub struct AuthResult {
    pub success: bool,
    pub requires_2fa: bool,
    pub temp_token: Option<String>,
    pub token: Option<String>,
    pub email: Option<String>,
    pub username: Option<String>,
    pub agent_pub_key: Option<String>,
    pub display_name: Option<String>,
    pub profile_picture: Option<String>,
}

/// Authenticate against the Flowsta web API.
/// Returns user info + JWT on success, or requires_2fa + temp_token for 2FA accounts.
#[tauri::command]
pub async fn authenticate_web_account(
    api_url: String,
    email_or_username: String,
    password: String,
) -> Result<AuthResult, String> {
    let client = reqwest::Client::new();
    let url = format!("{}/auth/login", api_url.trim_end_matches('/'));

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "emailOrUsername": email_or_username,
            "password": password,
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Invalid API response: {}", e))?;

    if !status.is_success() {
        let err = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("Login failed");
        return Err(err.to_string());
    }

    // Check if 2FA is required
    if body.get("requires2FA").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Ok(AuthResult {
            success: true,
            requires_2fa: true,
            temp_token: body.get("tempToken").and_then(|v| v.as_str()).map(String::from),
            token: None,
            email: None,
            username: None,
            agent_pub_key: None,
            display_name: None,
            profile_picture: None,
        });
    }

    // Successful login
    let user = body.get("user");
    Ok(AuthResult {
        success: true,
        requires_2fa: false,
        temp_token: None,
        token: body.get("token").and_then(|v| v.as_str()).map(String::from),
        email: user.and_then(|u| u.get("email")).and_then(|v| v.as_str()).map(String::from),
        username: user.and_then(|u| u.get("username")).and_then(|v| v.as_str()).map(String::from),
        agent_pub_key: user.and_then(|u| u.get("agentPubKey")).and_then(|v| v.as_str()).map(String::from),
        display_name: user.and_then(|u| u.get("displayName")).and_then(|v| v.as_str()).map(String::from),
        profile_picture: user.and_then(|u| u.get("profilePicture")).and_then(|v| v.as_str()).map(String::from),
    })
}

/// Complete 2FA authentication.
#[tauri::command]
pub async fn authenticate_2fa(
    api_url: String,
    temp_token: String,
    code: String,
) -> Result<AuthResult, String> {
    let client = reqwest::Client::new();
    let url = format!("{}/auth/login/2fa", api_url.trim_end_matches('/'));

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "tempToken": temp_token,
            "code": code,
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Invalid API response: {}", e))?;

    if !status.is_success() {
        let err = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("2FA verification failed");
        return Err(err.to_string());
    }

    let user = body.get("user");
    Ok(AuthResult {
        success: true,
        requires_2fa: false,
        temp_token: None,
        token: body.get("token").and_then(|v| v.as_str()).map(String::from),
        email: user.and_then(|u| u.get("email")).and_then(|v| v.as_str()).map(String::from),
        username: user.and_then(|u| u.get("username")).and_then(|v| v.as_str()).map(String::from),
        agent_pub_key: user.and_then(|u| u.get("agentPubKey")).and_then(|v| v.as_str()).map(String::from),
        display_name: user.and_then(|u| u.get("displayName")).and_then(|v| v.as_str()).map(String::from),
        profile_picture: user.and_then(|u| u.get("profilePicture")).and_then(|v| v.as_str()).map(String::from),
    })
}

/// Check if the authenticated user has set up a recovery phrase.
/// Calls GET /auth/recovery-phrase-status with the JWT token.
#[derive(Serialize)]
pub struct RecoveryPhraseStatus {
    pub has_recovery_phrase: bool,
    pub verified: bool,
}

#[tauri::command]
pub async fn check_recovery_phrase_status(
    api_url: String,
    jwt: String,
) -> Result<RecoveryPhraseStatus, String> {
    let client = reqwest::Client::new();
    let url = format!(
        "{}/auth/recovery-phrase-status",
        api_url.trim_end_matches('/')
    );

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;

    if !resp.status().is_success() {
        return Err("Could not check recovery phrase status".into());
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Invalid response: {}", e))?;

    Ok(RecoveryPhraseStatus {
        has_recovery_phrase: body
            .get("hasRecoveryPhrase")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        verified: body
            .get("verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

/// Cross-verify that a recovery phrase belongs to a Flowsta account
/// by checking the derived recovery lookup hash against the API.
///
/// The API stores a lookup hash per user (derived from their mnemonic).
/// We derive the same hash locally and ask the API if a user exists with it.
/// Cross-verify that a recovery phrase belongs to the signed-in Flowsta account.
///
/// 1. Derives the recovery lookup hash from the mnemonic
/// 2. Asks the API for the agent key associated with that hash
/// 3. Compares against the expected web agent key from sign-in
#[tauri::command]
pub async fn verify_phrase_matches_web_key(
    api_url: String,
    mnemonic: String,
    expected_web_agent_key: String,
) -> Result<bool, String> {
    // Derive the recovery lookup hash from the mnemonic
    let lookup_hash = derive_recovery_lookup_hash(&mnemonic)
        .map_err(|e| format!("Hash derivation failed: {}", e))?;

    // Ask the API if a user exists with this lookup hash
    let client = reqwest::Client::new();
    let url = format!(
        "{}/auth/agent-key-by-lookup-hash?hash={}",
        api_url.trim_end_matches('/'),
        lookup_hash
    );

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;

    if !resp.status().is_success() {
        // 404 = phrase doesn't match any account
        return Ok(false);
    }

    let body: AgentKeyLookupResponse = resp
        .json()
        .await
        .map_err(|e| format!("Invalid API response: {}", e))?;

    let returned_b64 = match body.agent_pub_key {
        Some(s) => s,
        None => return Ok(false),
    };

    // The two endpoints encode the same 39-byte agent key in different formats:
    //   /auth/agent-key-by-lookup-hash → standard base64
    //   /auth/login                    → literal "uhCAk" prefix + base58
    //                                    (publicKeyToAgentPubKey in api/src/services/crypto.js)
    // Decode both to raw bytes and compare.
    let returned_bytes = base64_standard_decode(&returned_b64)
        .map_err(|_| "Invalid agent_pub_key base64".to_string())?;

    let expected_after_prefix = expected_web_agent_key
        .strip_prefix("uhCAk")
        .ok_or_else(|| "expected_web_agent_key missing 'uhCAk' prefix".to_string())?;
    let expected_bytes = bs58::decode(expected_after_prefix)
        .into_vec()
        .map_err(|e| format!("Invalid expected_web_agent_key base58: {}", e))?;

    Ok(returned_bytes == expected_bytes)
}

/// Fetch user profile (displayName, profilePicture) from the web API.
/// Calls GET /auth/me with the JWT token.
#[derive(Serialize)]
pub struct WebProfile {
    pub display_name: Option<String>,
    pub profile_picture: Option<String>,
}

#[tauri::command]
pub async fn fetch_web_profile(
    api_url: String,
    jwt: String,
) -> Result<WebProfile, String> {
    let client = reqwest::Client::new();
    let url = format!("{}/auth/me", api_url.trim_end_matches('/'));

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;

    if !resp.status().is_success() {
        return Err("Could not fetch profile".into());
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Invalid response: {}", e))?;

    let user = body.get("user");
    Ok(WebProfile {
        display_name: user
            .and_then(|u| u.get("displayName"))
            .and_then(|v| v.as_str())
            .map(String::from),
        profile_picture: user
            .and_then(|u| u.get("profilePicture"))
            .and_then(|v| v.as_str())
            .map(String::from),
    })
}

/// Refresh profile fields (username, display_name, profile_picture) from the API
/// using the user's current password. Called silently after vault unlock so that
/// changes made on the website are reflected without requiring a vault reset.
///
/// Fails silently — any error is non-fatal.
#[tauri::command]
pub async fn refresh_cached_profile(
    api_url: String,
    password: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    // Get the login identifier (email or username) from the current in-memory config.
    let (identifier, vault_path) = {
        let config = state.vault_config.lock().unwrap();
        let cfg = config.as_ref().ok_or("Vault is locked")?;
        let id = cfg
            .web_email
            .clone()
            .or_else(|| cfg.web_username.clone())
            .ok_or("No web account linked")?;
        let path = state.vault_path.lock().unwrap().clone();
        (id, path)
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .post(format!("{}/auth/login", api_url.trim_end_matches('/')))
        .json(&serde_json::json!({
            "emailOrUsername": identifier,
            "password": password,
        }))
        .send()
        .await
        .map_err(|_| "offline")?;

    // 2FA accounts return 200 with requires2FA — treat as non-fatal skip.
    if !resp.status().is_success() {
        return Ok(());
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    if body.get("requires2FA").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Ok(());
    }

    let user = match body.get("user") {
        Some(u) => u,
        None => return Ok(()),
    };

    let new_username = user.get("username").and_then(|v| v.as_str()).map(String::from);
    let new_display_name = user
        .get("displayName")
        .and_then(|v| v.as_str())
        .map(String::from);
    let new_profile_picture = user
        .get("profilePicture")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Update in-memory config and re-save to disk (re-encrypted with the same password).
    {
        let mut config = state.vault_config.lock().unwrap();
        if let Some(cfg) = config.as_mut() {
            if new_username.is_some() {
                cfg.web_username = new_username;
            }
            if new_display_name.is_some() {
                cfg.display_name = new_display_name;
            }
            if new_profile_picture.is_some() {
                cfg.profile_picture = new_profile_picture;
            }

            if let Ok(mut encrypted) = encrypt_vault(cfg, &password) {
                encrypted.display_email = cfg.web_email.clone().or_else(|| cfg.web_username.clone());
                let _ = save_vault(&vault_path, &encrypted);
            }
        }
    }

    Ok(())
}

/// Get unencrypted vault metadata (email) for the unlock screen.
#[derive(Serialize)]
pub struct VaultDisplayInfo {
    pub display_email: Option<String>,
}

#[tauri::command]
pub fn get_vault_display_info(
    state: State<'_, Arc<AppState>>,
) -> Result<VaultDisplayInfo, String> {
    let vault_path = state.vault_path.lock().unwrap();
    if !vault_exists(&vault_path) {
        return Err("No vault found".into());
    }
    let encrypted =
        load_vault(&vault_path).map_err(|e| format!("Failed to read vault: {}", e))?;
    Ok(VaultDisplayInfo {
        display_email: encrypted.display_email,
    })
}

/// Check if a password still works against the web API.
/// Used after vault unlock to detect if the user changed their web password.
#[tauri::command]
pub async fn check_web_password(
    api_url: String,
    email: String,
    password: String,
) -> Result<bool, String> {
    let client = reqwest::Client::new();
    let url = format!("{}/auth/login", api_url.trim_end_matches('/'));

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "emailOrUsername": email,
            "password": password,
        }))
        .send()
        .await;

    match resp {
        Ok(r) => Ok(r.status().is_success()),
        Err(_) => Err("offline".into()),
    }
}

/// Check if the Flowsta API is reachable.
/// Returns true if any HTTP response is received (even an error), false if unreachable.
#[tauri::command]
pub async fn check_api_connectivity(api_url: String) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    client
        .get(format!("{}/health", api_url.trim_end_matches('/')))
        .send()
        .await
        .is_ok()
}

/// Re-encrypt the vault with a new password (after web password change).
/// Vault must be unlocked (decrypted config in memory).
#[tauri::command]
pub fn re_encrypt_vault(
    new_password: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let vault_path = state.vault_path.lock().unwrap();
    let config = state.vault_config.lock().unwrap();
    let config = config.as_ref().ok_or("Vault is locked")?;

    let mut encrypted =
        encrypt_vault(config, &new_password).map_err(|e| format!("Encryption failed: {}", e))?;
    encrypted.display_email = config.web_email.clone().or(config.web_username.clone());
    save_vault(&vault_path, &encrypted).map_err(|e| format!("Save failed: {}", e))?;

    log::info!("Vault re-encrypted with new password.");
    Ok(())
}

/// Get the auto-lock timeout in minutes (0 = never).
#[tauri::command]
pub fn get_auto_lock_minutes(state: State<'_, Arc<AppState>>) -> Result<u32, String> {
    let settings_path = {
        let vault_path = state.vault_path.lock().unwrap();
        vault_path.with_file_name("settings.json")
    };
    if settings_path.exists() {
        let data = std::fs::read_to_string(&settings_path)
            .map_err(|e| format!("Failed to read settings: {}", e))?;
        let val: serde_json::Value = serde_json::from_str(&data).unwrap_or_default();
        Ok(val
            .get("auto_lock_minutes")
            .and_then(|v| v.as_u64())
            .unwrap_or(15) as u32)
    } else {
        Ok(15)
    }
}

/// Set the auto-lock timeout and persist to disk.
/// Stored in a separate unencrypted file — no password needed.
#[tauri::command]
pub fn set_auto_lock_minutes(
    minutes: u32,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let settings_path = {
        let vault_path = state.vault_path.lock().unwrap();
        vault_path.with_file_name("settings.json")
    };

    // Read existing settings or start fresh
    let mut settings: serde_json::Value = if settings_path.exists() {
        let data = std::fs::read_to_string(&settings_path).unwrap_or_default();
        serde_json::from_str(&data).unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    settings["auto_lock_minutes"] = serde_json::json!(minutes);

    let data = serde_json::to_string_pretty(&settings)
        .map_err(|e| format!("Serialization failed: {}", e))?;
    std::fs::write(&settings_path, data)
        .map_err(|e| format!("Failed to save settings: {}", e))?;

    log::info!("Auto-lock set to {} minutes.", minutes);
    Ok(())
}

/// Change the Flowsta account password (web + local vault).
///
/// Flow:
/// 1. Login with current password to get a JWT
/// 2. Call POST /auth/change-password with the JWT
/// 3. Re-encrypt the local vault with the new password
#[tauri::command]
pub async fn change_password(
    api_url: String,
    current_password: String,
    new_password: String,
    email_or_username: Option<String>,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    // Use provided email_or_username override, or read from vault config
    let login_identifier = if let Some(ref provided) = email_or_username {
        if !provided.is_empty() {
            provided.clone()
        } else {
            return Err("NEEDS_EMAIL".into());
        }
    } else {
        let config = state.vault_config.lock().unwrap();
        let config = config.as_ref().ok_or("Vault is locked")?;

        // Try web_email first (must look like an actual email, not a hash)
        if let Some(ref email) = config.web_email {
            if email.contains('@') {
                email.clone()
            } else if let Some(ref username) = config.web_username {
                username.clone()
            } else {
                return Err("NEEDS_EMAIL".into());
            }
        } else if let Some(ref username) = config.web_username {
            username.clone()
        } else {
            return Err("No web account linked to this vault. Link your account from the Identities page first.".into());
        }
    };

    log::info!("Changing password for account: {}", login_identifier);

    // Step 1: Login to get a JWT
    let client = reqwest::Client::new();
    let login_url = format!("{}/auth/login", api_url.trim_end_matches('/'));

    let login_resp = client
        .post(&login_url)
        .json(&serde_json::json!({
            "emailOrUsername": login_identifier,
            "password": current_password,
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;

    if !login_resp.status().is_success() {
        let body: serde_json::Value = login_resp.json().await.unwrap_or_default();
        let err = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("Current password is incorrect");
        return Err(err.to_string());
    }

    let login_body: serde_json::Value = login_resp
        .json()
        .await
        .map_err(|e| format!("Invalid login response: {}", e))?;

    // Handle 2FA — password change from vault doesn't support 2FA re-auth
    if login_body
        .get("requires2FA")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Err("Password change requires completing 2FA. Please change your password on the web dashboard instead.".into());
    }

    let token = login_body
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or("Login succeeded but no token returned")?;

    // Fix vault email if it was missing or invalid (self-healing for legacy vaults)
    let real_email = login_body
        .get("user")
        .and_then(|u| u.get("email"))
        .and_then(|v| v.as_str())
        .map(String::from);
    if let Some(ref email) = real_email {
        let mut config = state.vault_config.lock().unwrap();
        if let Some(ref mut cfg) = *config {
            let needs_fix = cfg
                .web_email
                .as_ref()
                .map(|e| !e.contains('@'))
                .unwrap_or(true);
            if needs_fix {
                log::info!("Fixing vault web_email from API response");
                cfg.web_email = Some(email.clone());
            }
        }
    }

    // Step 2: Call change-password API
    let change_url = format!("{}/auth/change-password", api_url.trim_end_matches('/'));

    let change_resp = client
        .post(&change_url)
        .header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({
            "currentPassword": current_password,
            "newPassword": new_password,
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;

    if !change_resp.status().is_success() {
        let body: serde_json::Value = change_resp.json().await.unwrap_or_default();
        let err = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("Password change failed");
        return Err(err.to_string());
    }

    let change_body: serde_json::Value = change_resp
        .json()
        .await
        .map_err(|e| format!("Invalid change-password response: {}", e))?;

    // Step 3: Re-encrypt local vault with new password
    {
        let vault_path = state.vault_path.lock().unwrap();
        let config = state.vault_config.lock().unwrap();
        let config = config.as_ref().ok_or("Vault is locked")?;

        let mut encrypted = encrypt_vault(config, &new_password)
            .map_err(|e| format!("Local vault re-encryption failed: {}", e))?;
        encrypted.display_email = config.web_email.clone().or(config.web_username.clone());
        save_vault(&vault_path, &encrypted)
            .map_err(|e| format!("Failed to save re-encrypted vault: {}", e))?;
    }

    log::info!("Password changed (web + local vault).");

    let message = change_body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("Password changed successfully")
        .to_string();

    Ok(message)
}

// ── Agent Linking Commands ──────────────────────────────────────────

#[derive(Serialize)]
pub struct LinkResult {
    pub success: bool,
    pub web_agent_key: Option<String>,
    pub message: String,
}

#[derive(Deserialize)]
struct AgentKeyLookupResponse {
    agent_pub_key: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct ProfileLookupResponse {
    display_name: Option<String>,
    profile_picture: Option<String>,
}

#[derive(Deserialize)]
struct LinkDesktopResponse {
    success: Option<bool>,
    web_agent_key: Option<String>,
    message: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct LinkedAgentsResponse {
    linked_agents: Option<Vec<String>>,
    error: Option<String>,
}

/// Auto-link desktop agent with web account after conductor startup.
/// Called from spawn_conductor_startup — non-fatal on failure.
async fn auto_link_web_account(state: &Arc<AppState>, password: &str) -> Result<LinkResult, String> {
    let api_url = option_env!("FLOWSTA_API_URL")
        .unwrap_or("https://auth-api.flowsta.com");

    let (device_seed, recovery_lookup_hash, agent_pub_key_raw_b64) = {
        let config = state.vault_config.lock().unwrap();
        let config = config.as_ref().ok_or("Vault is locked")?;

        let seed = config
            .device_seed
            .as_ref()
            .ok_or("No device seed")?;
        let hash = config
            .recovery_lookup_hash
            .as_ref()
            .ok_or("No recovery lookup hash")?;
        let raw_b64 = config
            .agent_pub_key_raw_b64
            .as_ref()
            .ok_or("No raw agent pub key")?;

        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(seed);

        (seed_arr, hash.clone(), raw_b64.clone())
    };

    // Discover web agent key via API
    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{}/auth/agent-key-by-lookup-hash?hash={}",
            api_url, recovery_lookup_hash
        ))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("API returned {}: {}", status, body));
    }

    let lookup: AgentKeyLookupResponse = resp
        .json()
        .await
        .map_err(|e| format!("Invalid API response: {}", e))?;

    // Sync profile data from web account via separate endpoint
    {
        let profile_resp = client
            .get(format!(
                "{}/auth/profile-by-lookup-hash?hash={}",
                api_url, recovery_lookup_hash
            ))
            .send()
            .await;

        if let Ok(resp) = profile_resp {
            if resp.status().is_success() {
                if let Ok(profile) = resp.json::<ProfileLookupResponse>().await {
                    let mut profile_updated = false;
                    {
                        let mut config = state.vault_config.lock().unwrap();
                        if let Some(config) = config.as_mut() {
                            if profile.display_name.is_some()
                                && profile.display_name != config.display_name
                            {
                                config.display_name = profile.display_name.clone();
                                profile_updated = true;
                            }
                            if profile.profile_picture.is_some()
                                && profile.profile_picture != config.profile_picture
                            {
                                config.profile_picture = profile.profile_picture.clone();
                                profile_updated = true;
                            }
                        }
                    }
                    if profile_updated {
                        let config = state.vault_config.lock().unwrap();
                        if let Some(config) = config.as_ref() {
                            let vault_path = state.vault_path.lock().unwrap();
                            if let Ok(mut encrypted) = encrypt_vault(config, password) {
                                encrypted.display_email =
                                    config.web_email.clone().or(config.web_username.clone());
                                let _ = save_vault(&vault_path, &encrypted);
                                log::info!("Profile data synced from web account.");
                            }
                        }
                    }
                }
            }
        }
    }

    let web_agent_key_b64 = lookup
        .agent_pub_key
        .ok_or("API response missing agent_pub_key")?;

    // Decode web agent key — API returns raw 32-byte key as base64.
    // Construct the 39-byte AgentPubKey (3-byte header + 32-byte key + 4-byte DHT location).
    let web_agent_bytes = base64_standard_decode(&web_agent_key_b64)
        .map_err(|_| "Failed to decode web agent key")?;
    let web_39 = if web_agent_bytes.len() == 32 {
        let mut key_32 = [0u8; 32];
        key_32.copy_from_slice(&web_agent_bytes);
        construct_agent_pub_key_bytes(&key_32)
    } else if web_agent_bytes.len() == 39 {
        let mut key_39 = [0u8; 39];
        key_39.copy_from_slice(&web_agent_bytes);
        key_39
    } else {
        return Err(format!("Web agent key is {} bytes, expected 32 or 39", web_agent_bytes.len()));
    };

    let desktop_bytes = base64_standard_decode(&agent_pub_key_raw_b64)
        .map_err(|_| "Failed to decode desktop agent key")?;
    if desktop_bytes.len() != 39 {
        return Err(format!("Desktop agent key is {} bytes, expected 39", desktop_bytes.len()));
    }
    let mut desktop_39 = [0u8; 39];
    desktop_39.copy_from_slice(&desktop_bytes);

    let raw_payload = build_sorted_agent_pair_payload(&desktop_39, &web_39);
    // MessagePack-encode before signing: Holochain's verify_signature() serializes
    // via MessagePack internally, so the signature must be over the encoded form.
    let msgpack_payload = msgpack_encode_bytes(&raw_payload);
    let signature = sign_with_device_seed(&device_seed, &msgpack_payload);

    // Submit to API
    let resp = client
        .post(format!("{}/auth/link-desktop-agent", api_url))
        .json(&serde_json::json!({
            "desktop_agent_key": base64_standard_encode(&desktop_39),
            "recovery_lookup_hash": recovery_lookup_hash,
            "signature": base64_standard_encode(&signature),
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Link failed ({}): {}", status, body));
    }

    let link_resp: LinkDesktopResponse = resp
        .json()
        .await
        .map_err(|e| format!("Invalid API response: {}", e))?;

    if let Some(err) = link_resp.error {
        return Err(format!("Link error: {}", err));
    }

    // Always include the web agent key (base64 of 39-byte AgentPubKey)
    // so it can be cached for cross-agent signature lookup.
    let web_key_str = base64_standard_encode(&web_39);

    Ok(LinkResult {
        success: link_resp.success.unwrap_or(false),
        web_agent_key: Some(web_key_str),
        message: link_resp
            .message
            .unwrap_or_else(|| "Linked successfully".to_string()),
    })
}

/// Link this desktop identity with the web account.
///
/// Flow:
/// 1. Uses stored recovery_lookup_hash to discover the web agent's key via API
/// 2. Decodes the web agent's 39-byte AgentPubKey
/// 3. Constructs the sorted 78-byte payload (matching the integrity zome)
/// 4. Signs the payload with the device's Ed25519 key
/// 5. Sends the signature + desktop key to the API, which calls create_direct_link
#[tauri::command]
pub async fn link_web_account(
    api_url: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<LinkResult, String> {
    // Get vault config
    let (device_seed, recovery_lookup_hash, agent_pub_key_raw_b64) = {
        let config = state.vault_config.lock().unwrap();
        let config = config.as_ref().ok_or("Vault is locked")?;

        let seed = config
            .device_seed
            .as_ref()
            .ok_or("Vault was created before agent linking support. Please re-create it.")?;
        let hash = config
            .recovery_lookup_hash
            .as_ref()
            .ok_or("Vault missing recovery lookup hash")?;
        let raw_b64 = config
            .agent_pub_key_raw_b64
            .as_ref()
            .ok_or("Vault missing raw agent pub key")?;

        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(seed);

        (seed_arr, hash.clone(), raw_b64.clone())
    };

    // Step 1: Discover web agent key via API
    let client = reqwest::Client::new();
    let lookup_url = format!(
        "{}/auth/agent-key-by-lookup-hash?hash={}",
        api_url.trim_end_matches('/'),
        recovery_lookup_hash
    );

    let resp = client
        .get(&lookup_url)
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("API returned {}: {}", status, body));
    }

    let lookup: AgentKeyLookupResponse = resp
        .json()
        .await
        .map_err(|e| format!("Invalid API response: {}", e))?;

    if let Some(err) = lookup.error {
        return Err(format!("API error: {}", err));
    }

    let web_agent_key_b64 = lookup
        .agent_pub_key
        .ok_or("API response missing agent_pub_key")?;

    // Step 2: Decode web agent key — API returns raw 32-byte key as base64.
    // Construct the 39-byte AgentPubKey if needed.
    let web_agent_bytes = base64_standard_decode(&web_agent_key_b64)
        .map_err(|_| "Failed to decode web agent key from base64")?;

    let web_39 = if web_agent_bytes.len() == 32 {
        let mut key_32 = [0u8; 32];
        key_32.copy_from_slice(&web_agent_bytes);
        construct_agent_pub_key_bytes(&key_32)
    } else if web_agent_bytes.len() == 39 {
        let mut key_39 = [0u8; 39];
        key_39.copy_from_slice(&web_agent_bytes);
        key_39
    } else {
        return Err(format!("Web agent key is {} bytes, expected 32 or 39", web_agent_bytes.len()));
    };

    // Step 3: Decode desktop's own 39-byte key
    let desktop_bytes = base64_standard_decode(&agent_pub_key_raw_b64)
        .map_err(|_| "Failed to decode desktop agent key from base64")?;

    if desktop_bytes.len() != 39 {
        return Err(format!(
            "Desktop agent key is {} bytes, expected 39",
            desktop_bytes.len()
        ));
    }

    let mut desktop_39 = [0u8; 39];
    desktop_39.copy_from_slice(&desktop_bytes);

    // Step 4: Build sorted payload, MessagePack-encode, and sign
    let raw_payload = build_sorted_agent_pair_payload(&desktop_39, &web_39);
    // MessagePack-encode before signing: Holochain's verify_signature() serializes
    // via MessagePack internally, so the signature must be over the encoded form.
    let msgpack_payload = msgpack_encode_bytes(&raw_payload);
    let signature = sign_with_device_seed(&device_seed, &msgpack_payload);

    // Step 5: Send to API
    let link_url = format!(
        "{}/auth/link-desktop-agent",
        api_url.trim_end_matches('/')
    );

    let resp = client
        .post(&link_url)
        .json(&serde_json::json!({
            "desktop_agent_key": base64_standard_encode(&desktop_39),
            "recovery_lookup_hash": recovery_lookup_hash,
            "signature": base64_standard_encode(&signature),
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Link failed ({}): {}", status, body));
    }

    let link_resp: LinkDesktopResponse = resp
        .json()
        .await
        .map_err(|e| format!("Invalid API response: {}", e))?;

    if let Some(err) = link_resp.error {
        return Err(format!("Link error: {}", err));
    }

    Ok(LinkResult {
        success: link_resp.success.unwrap_or(false),
        web_agent_key: link_resp.web_agent_key,
        message: link_resp
            .message
            .unwrap_or_else(|| "Linked successfully".to_string()),
    })
}

/// Get agents linked to this desktop identity.
#[tauri::command]
pub async fn get_linked_agents(
    api_url: String,
    jwt: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<Vec<String>, String> {
    // Verify vault is unlocked
    {
        let config = state.vault_config.lock().unwrap();
        if config.is_none() {
            return Err("Vault is locked".into());
        }
    }

    let client = reqwest::Client::new();
    let url = format!(
        "{}/auth/linked-agents",
        api_url.trim_end_matches('/')
    );

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("API returned {}: {}", status, body));
    }

    let data: LinkedAgentsResponse = resp
        .json()
        .await
        .map_err(|e| format!("Invalid API response: {}", e))?;

    if let Some(err) = data.error {
        return Err(format!("API error: {}", err));
    }

    Ok(data.linked_agents.unwrap_or_default())
}

// ── Connected Sites + Auth Commands ─────────────────────────────────

/// Get all sites that have connected to the IPC server.
/// Populates the `trusted` field from the approved_apps list.
#[tauri::command]
pub fn get_connected_sites(
    state: State<'_, Arc<AppState>>,
) -> Vec<ConnectedSite> {
    let sites = state.connected_sites.lock().unwrap();
    let approved = state.approved_apps.lock().unwrap();
    let mut list: Vec<ConnectedSite> = sites
        .values()
        .map(|s| {
            let mut site = s.clone();
            site.trusted = approved.contains(&s.origin);
            site
        })
        .collect();
    list.sort_by(|a, b| b.last_request.cmp(&a.last_request));
    list
}

/// Remove a connected site from the tracking list.
#[tauri::command]
pub fn revoke_site(
    origin: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let mut sites = state.connected_sites.lock().unwrap();
    sites.remove(&origin);
    // Also remove from approved apps if present
    let mut approved = state.approved_apps.lock().unwrap();
    approved.retain(|o| o != &origin);
    Ok(())
}

/// Get info about the current pending auth request (if any).
#[tauri::command]
pub fn get_pending_auth(
    state: State<'_, Arc<AppState>>,
) -> Option<AuthRequestInfo> {
    let pending = state.pending_auth.lock().unwrap();
    pending.as_ref().map(|p| p.info.clone())
}

/// Respond to a pending auth request (approve or deny).
#[tauri::command]
pub fn respond_auth_request(
    approved: bool,
    remember: bool,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let mut pending = state.pending_auth.lock().unwrap();
    let req = pending.take().ok_or("No pending auth request")?;

    // If user chose to remember and approved, save the origin
    if approved && remember {
        if let Some(ref origin) = req.info.origin {
            let mut apps = state.approved_apps.lock().unwrap();
            if !apps.contains(origin) {
                apps.push(origin.clone());
            }
        }
    }

    // Send the response — ignore error if receiver was dropped (timeout)
    let _ = req.responder.send(approved);
    Ok(())
}

/// Get info about the current pending link-identity request (if any).
#[tauri::command]
pub fn get_pending_link_identity(
    state: State<'_, Arc<AppState>>,
) -> Option<LinkIdentityRequestInfo> {
    let pending = state.pending_link_identity.lock().unwrap();
    pending.as_ref().map(|p| LinkIdentityRequestInfo {
        id: p.id.clone(),
        app_name: p.app_name.clone(),
        origin: p.origin.clone(),
    })
}

/// Serializable info about a pending link-identity request (without the channel sender).
#[derive(Clone, Serialize)]
pub struct LinkIdentityRequestInfo {
    pub id: String,
    pub app_name: String,
    pub origin: Option<String>,
}

/// Respond to a pending link-identity request (approve or deny).
#[tauri::command]
pub fn respond_link_identity_request(
    approved: bool,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let mut pending = state.pending_link_identity.lock().unwrap();
    let req = pending.take().ok_or("No pending link-identity request")?;

    // Send the response — ignore error if receiver was dropped (timeout)
    let _ = req.responder.send(approved);
    Ok(())
}

/// Respond to a pending document-sign request (approve or deny).
#[tauri::command]
pub fn respond_document_sign_request(
    approved: bool,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let mut pending = state.pending_document_sign.lock().unwrap();
    let req = pending.take().ok_or("No pending document-sign request")?;

    let _ = req.responder.send(approved);
    Ok(())
}

/// Get the pending document-sign request info (for the approval dialog).
#[tauri::command]
pub fn get_pending_document_sign(
    state: State<'_, Arc<AppState>>,
) -> Option<DocumentSignRequestInfo> {
    let pending = state.pending_document_sign.lock().unwrap();
    pending.as_ref().map(|p| DocumentSignRequestInfo {
        id: p.id.clone(),
        app_name: p.app_name.clone(),
        file_hash: p.file_hash.clone(),
        label: p.label.clone(),
        origin: p.origin.clone(),
    })
}

/// Serializable info about a pending document-sign request (for frontend).
#[derive(Clone, Serialize, Deserialize)]
pub struct DocumentSignRequestInfo {
    pub id: String,
    pub app_name: String,
    pub file_hash: String,
    pub label: Option<String>,
    pub origin: Option<String>,
}

/// Get all third-party apps that have been linked via /link-identity.
#[tauri::command]
pub fn get_linked_third_party_apps(
    state: State<'_, Arc<AppState>>,
) -> Vec<LinkedThirdPartyApp> {
    state.linked_third_party_apps.lock().unwrap().clone()
}

/// Get all granted scopes for linked apps (client_id → scopes).
/// Used by the Vault UI to display what data each app can access.
#[tauri::command]
pub fn get_all_linked_app_scopes(
    state: State<'_, Arc<AppState>>,
) -> HashMap<String, Vec<String>> {
    state.linked_app_scopes.lock().unwrap().clone()
}

/// Remove a linked third-party app by its agent public key.
#[tauri::command]
pub fn revoke_linked_third_party_app(
    app_agent_pub_key: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    // Capture client_id before removing the entry so we can purge its scopes.
    let client_id_to_remove = {
        let apps = state.linked_third_party_apps.lock().unwrap();
        apps.iter()
            .find(|a| a.app_agent_pub_key == app_agent_pub_key)
            .and_then(|a| a.client_id.clone())
    };

    {
        let mut apps = state.linked_third_party_apps.lock().unwrap();
        let before = apps.len();
        apps.retain(|a| a.app_agent_pub_key != app_agent_pub_key);
        if apps.len() == before {
            return Err("No linked app found with that agent key".into());
        }
    }
    state.save_linked_apps();

    if let Some(cid) = client_id_to_remove {
        state.linked_app_scopes.lock().unwrap().remove(&cid);
        state.save_linked_app_scopes();
    }

    Ok(())
}

/// Toggle whether a connected site is trusted (auto-approved for /authenticate).
#[tauri::command]
pub fn toggle_site_trust(
    origin: String,
    trusted: bool,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let mut apps = state.approved_apps.lock().unwrap();
    if trusted {
        if !apps.contains(&origin) {
            apps.push(origin);
        }
    } else {
        apps.retain(|o| o != &origin);
    }
    Ok(())
}

/// Get the list of auto-approved app origins.
#[tauri::command]
pub fn get_approved_apps(
    state: State<'_, Arc<AppState>>,
) -> Vec<String> {
    state.approved_apps.lock().unwrap().clone()
}

/// Remove an origin from the auto-approved list.
#[tauri::command]
pub fn revoke_approved_app(
    origin: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let mut apps = state.approved_apps.lock().unwrap();
    apps.retain(|o| o != &origin);
    Ok(())
}

// ── Backup commands ────────────────────────────────────────────────

/// Get backup stats for all apps (for Your Data page).
#[tauri::command]
pub fn get_backup_stats(
    state: State<'_, Arc<AppState>>,
) -> crate::backup::BackupStats {
    crate::backup::get_backup_stats(&state.data_dir)
}

/// Delete all backups for a specific app.
#[tauri::command]
pub fn delete_app_backup(
    client_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<usize, String> {
    crate::backup::delete_app_backups(&state.data_dir, &client_id)
}

/// Export all vault data (identity + backups + signatures) as JSON.
/// CAL-compliant export: everything needed to recreate the user's identity,
/// data, and signature history independently.
#[tauri::command]
pub async fn export_all_data(
    state: State<'_, Arc<AppState>>,
    app_handle: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    // Fetch the user's Sign It signatures from the local signing DNAs.
    // Non-fatal if it fails — export without signatures rather than blocking.
    let signatures = match get_my_signatures(state.clone(), app_handle).await {
        Ok(sigs) => Some(sigs),
        Err(e) => {
            log::warn!("export_all_data: failed to fetch signatures: {}", e);
            None
        }
    };
    crate::backup::export_all_data(&state, signatures)
}

/// List individual backup metadata for a specific app.
#[tauri::command]
pub fn list_app_backup_details(
    client_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<crate::backup::BackupMeta>, String> {
    crate::backup::list_app_backups(&state.data_dir, &client_id)
}

/// Export (decrypt) a single app's backup, packaged to help the user
/// exercise their CAL §4.2.1 portability rights — **for any Holochain app
/// that backs up to Flowsta Vault**, not just Flowsta's own apps.
///
/// The Cryptographic Autonomy License obligates every app shipping under it
/// to provide users a portable copy of their User Data along with the
/// cryptographic seeds/keys needed to use the data independently. Vault is
/// the storage layer for third-party Holochain apps' backups; this export
/// gives those apps' users a self-contained file that includes:
///   - the user's Flowsta device seed + agent public key (these are
///     what Vault holds and the obligation Vault discharges directly),
///   - the app metadata (name + client_id),
///   - the backup itself with the canonical-shape `human_readable` view of
///     each record promoted to plain JSON, and
///   - per-section `_readme` text + the CAL-1.0 citation.
///
/// What this export does NOT include is any private key the third-party app
/// generated outside Vault — e.g. an independent Holochain agent key that
/// authored the records but was never derived from the Flowsta seed. If an
/// app needs to expose such keys to satisfy its own CAL §4.2.1 obligation
/// it must include them in the canonical backup payload it sends to Vault;
/// the SDK passes through arbitrary top-level fields (alongside `cells[]`
/// and `_summary`) so an app can add e.g. an `app_keys` block and Vault
/// will inline it here verbatim under `backup.data`.
#[tauri::command]
pub fn export_single_backup(
    client_id: String,
    label: Option<String>,
    state: State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let label_ref = label.as_deref();
    let (data, meta) = crate::backup::retrieve_backup(&state, &client_id, label_ref)?;

    // Vault identity + keys, same source as export_all_data.
    let config = {
        let config = state.vault_config.lock().unwrap();
        config.as_ref().ok_or("Vault is locked")?.clone()
    };
    let device_seed_hex = config.device_seed.as_ref().map(hex::encode);

    // Parse the backup data + canonicalise the human-readable view if it
    // follows the SDK's canonical shape; otherwise pass through unchanged.
    let parsed_data = if meta.content_type.contains("json") {
        serde_json::from_slice::<serde_json::Value>(&data).ok()
    } else {
        None
    };
    let data_value = match parsed_data {
        Some(json) if crate::backup::is_canonical_backup(&json) => {
            crate::backup::canonicalize_for_export(&json)
        }
        Some(json) => json,
        None => serde_json::Value::String(hex::encode(&data)),
    };

    Ok(serde_json::json!({
        "_readme": concat!(
            "This file is a single-app export of your data from Flowsta Vault. ",
            "It contains the cryptographic keys you need to use this data ",
            "on any other Holochain conductor, plus the data itself in ",
            "plain-readable JSON. KEEP THIS FILE SAFE — anyone with the ",
            "device_seed can sign as you on the Holochain network.",
        ),
        "format": {
            "version": "1.0",
            "exported_at": crate::backup::iso_now(),
            "license": "Cryptographic Autonomy License v1.0 (CAL-1.0)",
            "license_clause": "§4.2.1 No Withholding User Data",
        },
        "you": {
            "_readme": "Your Flowsta identity. The DID is your decentralised identifier; the agent_pub_key is your Holochain network address.",
            "display_name": config.display_name,
            "did": config.did,
            "agent_pub_key": config.agent_pub_key,
        },
        "keys": {
            "_readme": concat!(
                "Your private cryptographic keys. With this seed you can ",
                "recreate the same Holochain identity on any conductor and ",
                "re-author backed-up data. NEVER share these.",
            ),
            "device_seed_hex": device_seed_hex,
            "agent_pub_key_full_b64": config.agent_pub_key_raw_b64,
        },
        "app": {
            "_readme": "The app this backup belongs to.",
            "name": meta.app_name,
            "client_id": client_id,
        },
        "backup": {
            "_readme": "Your app data backup. Each record below is one thing you authored.",
            "label": meta.label,
            "saved_at": meta.created_at,
            "size_bytes": meta.data_size,
            "content_type": meta.content_type,
            "data": data_value,
        },
    }))
}


/// Delete a single backup by client_id + label.
#[tauri::command]
pub fn delete_single_backup(
    client_id: String,
    label: Option<String>,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    crate::backup::delete_backup(&state.data_dir, &client_id, label.as_deref())
}

/// Write JSON content to a file path (used with save dialog from frontend).
#[tauri::command]
pub fn write_json_file(
    path: String,
    content: String,
) -> Result<(), String> {
    std::fs::write(&path, &content).map_err(|e| format!("Failed to write file: {}", e))
}

/// Standard base64 decoding (with + / and padding).
fn base64_standard_decode(input: &str) -> Result<Vec<u8>, ()> {
    fn val(c: u8) -> Result<u32, ()> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(()),
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        out.push(((a << 2) | (b >> 4)) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' {
            let c = val(chunk[2])?;
            out.push((((b & 0xF) << 4) | (c >> 2)) as u8);
            if chunk.len() > 3 && chunk[3] != b'=' {
                let d = val(chunk[3])?;
                out.push((((c & 0x3) << 6) | d) as u8);
            }
        }
    }
    Ok(out)
}

// ── Sign It commands ────────────────────────────────────────────────

// Cancel flag for the in-flight hash. Single-flight is enforced by the UI
// (one file at a time, batch is sequential). Each new hash_file call resets
// this flag at the start; cancel_hash flips it to true.
static HASH_CANCEL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Returns the size of a file in bytes. Cheap metadata read used by the
/// frontend to gate progress UI + integrity-analysis tier without hitting
/// the slower hash path first.
#[tauri::command]
pub fn get_file_size(path: String) -> Result<u64, String> {
    std::fs::metadata(&path)
        .map(|m| m.len())
        .map_err(|e| format!("Failed to read file metadata: {}", e))
}

/// Cancel the currently-running hash_file call (if any). The cancel flag is
/// checked between every 64KB read chunk inside the streaming hasher.
#[tauri::command]
pub fn cancel_hash() {
    HASH_CANCEL.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Drain any files queued by the OS file-explorer integration (Linux
/// .desktop, Windows registry, macOS Service / Apple Event). Called by the
/// frontend on dashboard mount + on `sign-files-requested` events.
#[tauri::command]
pub fn take_pending_sign_paths(state: State<'_, Arc<AppState>>) -> Vec<String> {
    let mut queue = state.pending_sign_paths.lock().unwrap();
    let paths: Vec<String> = queue
        .drain(..)
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    paths
}

/// Filter a list of incoming OS args / Apple Event URLs down to existing
/// readable file paths. Used by the CLI / single-instance / `RunEvent::Opened`
/// handlers to keep the same validation logic in one place.
pub fn extract_sign_paths_from_args<I, S>(args: I) -> Vec<std::path::PathBuf>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .map(|s| s.as_ref().to_string())
        // Strip a `file://` prefix if present (RunEvent::Opened can deliver
        // file URLs on macOS / Windows).
        .map(|s| s.strip_prefix("file://").map(|t| t.to_string()).unwrap_or(s))
        // Skip flags / option args that aren't paths.
        .filter(|s| !s.starts_with("--") && !s.starts_with('-'))
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_file())
        .collect()
}

/// Hash a file using SHA-256. Returns hex-encoded hash string. Emits
/// `hash-progress` events with `{ hashed, total }` (bytes) throttled to
/// ~10 fps so UIs can show progress without IPC spam.
///
/// Runs on the blocking thread pool — file I/O of multi-GB files would
/// otherwise freeze the main thread (OS marks the app "not responding").
#[tauri::command]
pub async fn hash_file(path: String, app: tauri::AppHandle) -> Result<String, String> {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    use tauri::Emitter;

    HASH_CANCEL.store(false, Ordering::Relaxed);

    tokio::task::spawn_blocking(move || {
        let mut last_emit = Instant::now() - Duration::from_secs(1); // emit immediately
        crate::file_analyzer::hash_file_with_progress(
            std::path::Path::new(&path),
            |hashed, total| {
                if HASH_CANCEL.load(Ordering::Relaxed) {
                    return false;
                }
                // Always emit the first event (so the UI sees `total`) and the
                // final completion event; throttle the middle to ~10 fps.
                let is_done = hashed == total;
                if is_done || last_emit.elapsed() >= Duration::from_millis(100) {
                    let _ = app.emit(
                        "hash-progress",
                        serde_json::json!({ "hashed": hashed, "total": total }),
                    );
                    last_emit = Instant::now();
                }
                true
            },
        )
    })
    .await
    .map_err(|e| format!("Hash task panicked: {}", e))?
}

/// Run integrity checks on a file. Returns an IntegrityReport.
/// Runs on the blocking thread pool — analyze_file reads the full file into
/// RAM and runs CPU-bound steg checks.
#[tauri::command]
pub async fn analyze_file(path: String) -> Result<crate::file_analyzer::IntegrityReport, String> {
    tokio::task::spawn_blocking(move || {
        crate::file_analyzer::analyze_file(std::path::Path::new(&path))
    })
    .await
    .map_err(|e| format!("Analyze task panicked: {}", e))?
}

/// Generate a perceptual hash for a file (for fuzzy matching).
/// Returns None for file types that don't support perceptual hashing.
/// Runs on the blocking thread pool — full-file read + image/audio decode.
#[tauri::command]
pub async fn generate_perceptual_hash(
    path: String,
) -> Result<Option<crate::file_analyzer::PerceptualHash>, String> {
    tokio::task::spawn_blocking(move || {
        let data = std::fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
        Ok(crate::file_analyzer::generate_perceptual_hash(&data))
    })
    .await
    .map_err(|e| format!("Perceptual hash task panicked: {}", e))?
}

/// Generate a thumbnail for an image file.
/// Returns a base64 JPEG data URI for images, None for other file types.
/// Runs on the blocking thread pool — full-file read + image decode + resize.
#[tauri::command]
pub async fn generate_thumbnail(path: String) -> Result<Option<String>, String> {
    tokio::task::spawn_blocking(move || {
        let data = std::fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
        Ok(crate::file_analyzer::generate_image_thumbnail(&data))
    })
    .await
    .map_err(|e| format!("Thumbnail task panicked: {}", e))?
}

/// Sign a file hash and commit the SignatureRecord to the signing DNA.
///
/// This command:
/// 1. Signs the SHA-256 hash with the device Ed25519 key
/// 2. Commits a SignatureRecord entry to the signing DNA via the local conductor
/// 3. Returns the signature, agent key, and DHT action hash
#[tauri::command]
pub async fn sign_file(
    file_hash: String,
    intent: Option<String>,
    ai_generation: Option<String>,
    content_rights: Option<serde_json::Value>,
    integrity_report: Option<serde_json::Value>,
    perceptual_hash: Option<serde_json::Value>,
    // v1.3+ fields. comment is the signer-declared note; supersedes is
    // the previous version's action_hash (hex) when amending an existing
    // signature into a new chain entry.
    comment: Option<String>,
    supersedes: Option<String>,
    state: State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    // 1. Decode and validate file hash
    let hash_bytes =
        hex::decode(&file_hash).map_err(|_| "file_hash must be valid hex".to_string())?;
    if hash_bytes.len() != 32 {
        return Err("file_hash must be exactly 64 hex characters (32 bytes)".to_string());
    }

    // 2. Sign with device seed
    let (signature_bytes, agent_pub_key_str) = {
        let config = state.vault_config.lock().unwrap();
        let config = config.as_ref().ok_or("Vault is locked")?;
        let device_seed = config
            .device_seed
            .as_ref()
            .ok_or("No device seed available")?;

        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(device_seed);

        let signature =
            crate::key_derivation::sign_with_device_seed(&seed_arr, &hash_bytes);
        let pub_key = {
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_arr);
            *signing_key.verifying_key().as_bytes()
        };
        let agent_key = crate::key_derivation::construct_agent_pub_key_string(&pub_key);
        (signature, agent_key)
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let signature_b64 = crate::key_derivation::base64_standard_encode(&signature_bytes);

    // 3. Commit SignatureRecord to signing DNA via conductor zome call
    // Extract ports from conductor handle (drop MutexGuard before any await)
    let conductor_ports = {
        let conductor = state.conductor_handle.lock().unwrap();
        conductor.as_ref().map(|h| (h.admin_port, h.app_port))
    };

    // Decode supersedes hex to bytes once (any error → reject upfront so
    // we never commit a partial-payload signature).
    let supersedes_bytes = if let Some(hex_str) = supersedes.as_deref() {
        match hex::decode(hex_str) {
            Ok(bytes) => Some(bytes),
            Err(_) => return Err("supersedes must be a hex-encoded action_hash".to_string()),
        }
    } else {
        None
    };

    let action_hash = if let Some((admin_port, app_port)) = conductor_ports {
        match commit_signature_to_dht(
            admin_port,
            app_port,
            &hash_bytes,
            &signature_bytes,
            now_ms,
            intent.as_deref(),
            ai_generation.as_deref(),
            content_rights.as_ref(),
            integrity_report.as_ref(),
            perceptual_hash.as_ref(),
            comment.as_deref(),
            supersedes_bytes.as_deref(),
        )
        .await
        {
            Ok(hash) => Some(hash),
            Err(e) => {
                log::error!("Failed to commit signature to DHT: {}", e);
                None
            }
        }
    } else {
        log::warn!("Conductor not running — signature created locally only");
        None
    };

    Ok(serde_json::json!({
        "success": true,
        "file_hash": file_hash,
        "signature": signature_b64,
        "agent_pub_key": agent_pub_key_str,
        "signed_at": now_ms,
        "action_hash": action_hash,
        // The bundled signing-DNA app id (e.g. "flowsta_signing_v1_4") —
        // matches what `commit_signature_to_dht` writes to and what
        // `build_own_signature_json` returns from `get_my_signatures`. The
        // frontend uses this field to decide which per-signature actions to
        // show (Edit Thumbnail is gated on v1.3+); without it, freshly-signed
        // entries spliced into the list lose those actions.
        "signing_app_id": crate::dna::make_app_id("signing", crate::dna::BUNDLED_SIGNING_VERSION),
        "intent": intent,
        "ai_generation": ai_generation,
        "content_rights": content_rights,
        "integrity_report": integrity_report,
        "comment": comment,
        "supersedes": supersedes,
    }))
}

/// SignatureEntry as committed by the signing DNA. Shared by own + linked
/// signature queries.
#[derive(serde::Deserialize, serde::Serialize)]
struct SignatureEntry {
    file_hash: Vec<u8>,
    signature: Vec<u8>,
    signer: holochain_types::prelude::AgentPubKey,
    signed_at: i64,
    intent: Option<String>,
    ai_generation: Option<String>,
    content_rights: Option<serde_json::Value>,
    integrity_report: Option<serde_json::Value>,
    perceptual_hash: Option<serde_json::Value>,
    // v1.3+ fields. Serde defaults keep deserialization working for
    // pre-v1.3 records (signing v1.0 / v1.1 / v1.2) that don't have them.
    // `supersedes` decoded as raw bytes to side-step HoloHash-via-msgpack
    // serde quirks; we hex-encode it for the JSON output ourselves.
    #[serde(default)]
    supersedes: Option<Vec<u8>>,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    comment: Option<String>,
}

/// Best-effort revocation lookup for one signature. Returns
/// `(false, None, None)` if no revocation records exist or the lookup fails;
/// `(true, ...)` if at least one revocation record exists, with metadata
/// populated when it parses cleanly.
async fn fetch_revocation_for_action(
    app_ws: &holochain_client::AppWebsocket,
    role_name: &str,
    action_hash: &holochain_types::prelude::ActionHash,
) -> (bool, Option<i64>, Option<String>) {
    use holochain_client::ZomeCallTarget;
    use holochain_types::prelude::{Entry, ExternIO, Record};

    let payload = match rmp_serde::to_vec_named(action_hash) {
        Ok(p) => p,
        Err(_) => return (false, None, None),
    };
    // 15s timeout: enrichment is per-sig and DHT-bound. On cold start
    // every call would otherwise wait up to 240s (kitsune2 request
    // timeout) before returning defaults — that's what made beta8 sit
    // at "Syncing" for an extra 2 min after the primary records came
    // back (Vault(14) log on 2026-05-24). 15 s is well above warm-DHT
    // response time (~ms) and well below the cold-DHT wall. Defaults
    // (not-revoked, no thumbnail) on a timeout fill in on the next
    // refresh once the DHT has gossiped them.
    let call = app_ws.call_zome(
        ZomeCallTarget::RoleName(role_name.into()),
        "signing".into(),
        "get_revocations_for_signature".into(),
        ExternIO::from(payload),
    );
    let result = match tokio::time::timeout(std::time::Duration::from_secs(15), call).await {
        Ok(Ok(r)) => r,
        _ => return (false, None, None),
    };
    let records: Vec<Record> = match rmp_serde::from_slice(result.as_bytes()) {
        Ok(r) => r,
        Err(_) => return (false, None, None),
    };
    let first = match records.first() {
        Some(f) => f,
        None => return (false, None, None),
    };
    if let Some(Entry::App(rev_entry)) = first.entry().as_option() {
        #[derive(serde::Deserialize)]
        struct RevEntry { revoked_at: i64, reason: Option<String> }
        if let Ok(rev) = rmp_serde::from_slice::<RevEntry>(rev_entry.bytes()) {
            return (true, Some(rev.revoked_at), rev.reason);
        }
    }
    (true, None, None)
}

/// Best-effort thumbnail lookup. Returns None if missing, timed out, or
/// any step fails. The 15 s timeout matches `fetch_revocation_for_action`
/// — see that doc for the cold-DHT rationale.
async fn fetch_thumbnail_for_action(
    app_ws: &holochain_client::AppWebsocket,
    role_name: &str,
    action_hash: &holochain_types::prelude::ActionHash,
) -> Option<String> {
    use holochain_client::ZomeCallTarget;
    use holochain_types::prelude::{Entry, ExternIO, Record};

    let payload = rmp_serde::to_vec_named(action_hash).ok()?;
    let call = app_ws.call_zome(
        ZomeCallTarget::RoleName(role_name.into()),
        "signing".into(),
        "get_thumbnail".into(),
        ExternIO::from(payload),
    );
    let result = tokio::time::timeout(std::time::Duration::from_secs(15), call)
        .await
        .ok()?
        .ok()?;
    let thumb_record: Option<Record> = rmp_serde::from_slice(result.as_bytes()).ok()?;
    let record = thumb_record?;
    if let Some(Entry::App(thumb_entry)) = record.entry().as_option() {
        #[derive(serde::Deserialize)]
        struct ThumbEntry { thumbnail: String }
        if let Ok(te) = rmp_serde::from_slice::<ThumbEntry>(thumb_entry.bytes()) {
            return Some(te.thumbnail);
        }
    }
    None
}

/// Authorise + connect an AppWebsocket for the given signing app version.
/// Returns `(app_ws, role_name)` on success, or None (with a logged warning)
/// if any step fails — caller should skip this version.
async fn connect_signing_app_ws(
    admin_ws: &holochain_client::AdminWebsocket,
    app_port: u16,
    signing_app: &holochain_client::AppInfo,
    ws_origin: &str,
) -> Option<(holochain_client::AppWebsocket, String)> {
    use holochain_client::{AppWebsocket, AuthorizeSigningCredentialsPayload,
        ClientAgentSigner, CellInfo, IssueAppAuthenticationTokenPayload};

    let role_name = signing_app.cell_info.keys()
        .find(|k| k.starts_with("flowsta_signing"))?
        .clone();
    let cell_id = signing_app.cell_info[&role_name].iter()
        .find_map(|c| match c {
            CellInfo::Provisioned(p) => Some(p.cell_id.clone()),
            _ => None,
        })?;
    let creds = match admin_ws.authorize_signing_credentials(AuthorizeSigningCredentialsPayload {
        cell_id: cell_id.clone(), functions: None,
    }).await {
        Ok(c) => c,
        Err(e) => {
            log::warn!("auth creds for {}: {}", signing_app.installed_app_id, e);
            return None;
        }
    };
    let issued = match admin_ws.issue_app_auth_token(
        IssueAppAuthenticationTokenPayload::for_installed_app_id(
            signing_app.installed_app_id.clone(),
        ),
    ).await {
        Ok(t) => t,
        Err(e) => {
            log::warn!("token for {}: {}", signing_app.installed_app_id, e);
            return None;
        }
    };
    let signer = ClientAgentSigner::default();
    signer.add_credentials(cell_id, creds);
    let app_ws = match AppWebsocket::connect_with_config(
        format!("localhost:{}", app_port),
        long_request_ws_config(),
        issued.token, signer.into(),
        Some(ws_origin.into()),
    ).await {
        Ok(ws) => ws,
        Err(e) => {
            log::warn!("app WS for {}: {}", signing_app.installed_app_id, e);
            return None;
        }
    };
    Some((app_ws, role_name))
}

/// Build the JSON for one own signature. Revocation + thumbnail fetches run
/// in parallel.
async fn build_own_signature_json(
    app_ws: &holochain_client::AppWebsocket,
    role_name: &str,
    record: &holochain_types::prelude::Record,
    entry: SignatureEntry,
    signing_app_id: &str,
) -> serde_json::Value {
    let action_hash = record.action_hashed().hash.clone();
    let (revocation, thumbnail) = tokio::join!(
        fetch_revocation_for_action(app_ws, role_name, &action_hash),
        fetch_thumbnail_for_action(app_ws, role_name, &action_hash),
    );
    let (revoked, revoked_at, revocation_reason) = revocation;
    let action_hash_hex = hex::encode(action_hash.get_raw_39());
    let raw_32 = entry.signer.get_raw_32();
    let pub_key_arr: [u8; 32] = raw_32.try_into().unwrap_or([0u8; 32]);
    let signer_str = crate::key_derivation::construct_agent_pub_key_string(&pub_key_arr);

    serde_json::json!({
        "file_hash": hex::encode(&entry.file_hash),
        "signature": crate::key_derivation::base64_standard_encode(&entry.signature),
        "agent_pub_key": signer_str,
        "signed_at": entry.signed_at,
        "action_hash": action_hash_hex,
        "signing_app_id": signing_app_id,
        "intent": entry.intent,
        "ai_generation": entry.ai_generation,
        "content_rights": entry.content_rights,
        "integrity_report": entry.integrity_report,
        "perceptual_hash": entry.perceptual_hash,
        "supersedes": entry.supersedes.as_ref().map(|b| hex::encode(b)),
        "expires_at": entry.expires_at,
        "tags": entry.tags,
        "comment": entry.comment,
        "revoked": revoked,
        "revoked_at": revoked_at,
        "revocation_reason": revocation_reason,
        "thumbnail": thumbnail,
    })
}

/// Build the JSON for one linked-agent signature. Matches existing behavior:
/// linked sigs assume not-revoked (only thumbnail is fetched).
async fn build_linked_signature_json(
    app_ws: &holochain_client::AppWebsocket,
    role_name: &str,
    record: &holochain_types::prelude::Record,
    entry: SignatureEntry,
    signing_app_id: &str,
) -> serde_json::Value {
    let action_hash = record.action_hashed().hash.clone();
    let thumbnail = fetch_thumbnail_for_action(app_ws, role_name, &action_hash).await;
    let action_hash_hex = hex::encode(action_hash.get_raw_39());
    let raw_32 = entry.signer.get_raw_32();
    let pub_key_arr: [u8; 32] = raw_32.try_into().unwrap_or([0u8; 32]);
    let signer_str = crate::key_derivation::construct_agent_pub_key_string(&pub_key_arr);

    serde_json::json!({
        "file_hash": hex::encode(&entry.file_hash),
        "signature": crate::key_derivation::base64_standard_encode(&entry.signature),
        "agent_pub_key": signer_str,
        "signed_at": entry.signed_at,
        "action_hash": action_hash_hex,
        "signing_app_id": signing_app_id,
        "intent": entry.intent,
        "ai_generation": entry.ai_generation,
        "content_rights": entry.content_rights,
        "integrity_report": entry.integrity_report,
        "perceptual_hash": entry.perceptual_hash,
        "supersedes": entry.supersedes.as_ref().map(|b| hex::encode(b)),
        "expires_at": entry.expires_at,
        "tags": entry.tags,
        "comment": entry.comment,
        "revoked": false,
        "revoked_at": serde_json::Value::Null,
        "revocation_reason": serde_json::Value::Null,
        "thumbnail": thumbnail,
    })
}

/// Query own signatures for one signing DNA version. Per-signature
/// enrichment runs in parallel. Returns `Err` on a transient failure
/// (zome call timeout, decode failure) so the caller can distinguish
/// "no sigs" from "couldn't reach the cell" — that distinction matters
/// for the frontend's "don't show a partial count" rule.
async fn query_own_sigs_for_version(
    admin_ws: &holochain_client::AdminWebsocket,
    app_port: u16,
    signing_app: &holochain_client::AppInfo,
) -> Result<Vec<serde_json::Value>, String> {
    use holochain_client::ZomeCallTarget;
    use holochain_types::prelude::{Entry, ExternIO, Record};

    let (app_ws, role_name) = connect_signing_app_ws(
        admin_ws, app_port, signing_app, "flowsta-vault-read",
    ).await.ok_or_else(|| format!("connect_signing_app_ws failed for {}",
        signing_app.installed_app_id))?;

    let payload_mp = rmp_serde::to_vec_named(&())
        .map_err(|e| format!("msgpack ({}): {}", signing_app.installed_app_id, e))?;

    let result = app_ws.call_zome(
        ZomeCallTarget::RoleName(role_name.clone().into()),
        "signing".into(),
        "get_my_signatures".into(),
        ExternIO::from(payload_mp),
    ).await.map_err(|e| format!(
        "get_my_signatures failed for {}: {}", signing_app.installed_app_id, e
    ))?;

    let records: Vec<Record> = rmp_serde::from_slice(result.as_bytes())
        .map_err(|e| format!("decode records ({}): {}", signing_app.installed_app_id, e))?;
    log::info!("Got {} signatures from {}", records.len(), signing_app.installed_app_id);

    let entries: Vec<(&Record, SignatureEntry)> = records.iter().filter_map(|record| {
        let entry_bytes = match record.entry().as_option() {
            Some(Entry::App(b)) => b,
            _ => return None,
        };
        rmp_serde::from_slice::<SignatureEntry>(entry_bytes.bytes())
            .ok()
            .map(|e| (record, e))
    }).collect();

    let futures = entries.into_iter().map(|(record, entry)| {
        build_own_signature_json(&app_ws, &role_name, record, entry,
            &signing_app.installed_app_id)
    });
    Ok(futures::future::join_all(futures).await)
}

/// Resolve the set of linked agents to query for cross-agent signatures.
/// Tries the identity DNA's `get_linked_agents` first, falls back to the
/// cached web agent key set during auto-link on unlock.
async fn fetch_linked_agent_keys(
    admin_ws: &holochain_client::AdminWebsocket,
    app_port: u16,
    apps: &[holochain_client::AppInfo],
    cached_web_agent_key: Option<String>,
) -> Vec<holochain_types::prelude::AgentPubKey> {
    use holochain_client::{AppWebsocket, AuthorizeSigningCredentialsPayload,
        ClientAgentSigner, CellInfo, IssueAppAuthenticationTokenPayload, ZomeCallTarget};
    use holochain_types::prelude::{AgentPubKey, ExternIO};

    let mut identity_apps: Vec<_> = apps.iter()
        .filter(|a| a.installed_app_id.starts_with("flowsta_identity_v"))
        .collect();
    identity_apps.sort_by(|a, b| b.installed_app_id.cmp(&a.installed_app_id));
    let identity_app = match identity_apps.into_iter().next() {
        Some(a) => a,
        None => {
            log::info!("No identity DNA with agent_linking found — skipping cross-agent lookup");
            return Vec::new();
        }
    };

    let identity_role = match identity_app.cell_info.keys()
        .find(|k| k.starts_with("flowsta_identity")) {
        Some(r) => r.clone(),
        None => return Vec::new(),
    };
    let identity_cell_id = match identity_app.cell_info[&identity_role].iter()
        .find_map(|c| match c {
            CellInfo::Provisioned(p) => Some(p.cell_id.clone()),
            _ => None,
        }) {
        Some(c) => c,
        None => return Vec::new(),
    };

    let my_agent_key = identity_cell_id.agent_pubkey().clone();

    let creds = match admin_ws.authorize_signing_credentials(AuthorizeSigningCredentialsPayload {
        cell_id: identity_cell_id.clone(), functions: None,
    }).await {
        Ok(c) => c,
        Err(e) => { log::warn!("identity auth creds: {}", e); return Vec::new(); }
    };
    let issued = match admin_ws.issue_app_auth_token(
        IssueAppAuthenticationTokenPayload::for_installed_app_id(
            identity_app.installed_app_id.clone(),
        ),
    ).await {
        Ok(t) => t,
        Err(e) => { log::warn!("identity token: {}", e); return Vec::new(); }
    };
    let signer = ClientAgentSigner::default();
    signer.add_credentials(identity_cell_id, creds);
    let identity_ws = match AppWebsocket::connect_with_config(
        format!("localhost:{}", app_port),
        long_request_ws_config(),
        issued.token, signer.into(),
        Some("flowsta-vault-linked".into()),
    ).await {
        Ok(ws) => ws,
        Err(e) => { log::warn!("identity app WS: {}", e); return Vec::new(); }
    };

    let payload_mp = match rmp_serde::to_vec_named(&my_agent_key) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    // Seed with the cached web agent key immediately. The Vault(14) log
    // showed `get_linked_agents` waiting the full 240 s kitsune2 timeout
    // before falling back to this same cache — wasted minutes when the
    // answer was already in memory. We still try the DHT below to catch
    // any additional linked agents (rare today; non-web links would only
    // come from future features), but with a short opportunistic budget.
    let mut linked_keys: Vec<AgentPubKey> = Vec::new();
    if let Some(ref cached) = cached_web_agent_key {
        match base64_standard_decode(cached) {
            Ok(key_bytes) if key_bytes.len() == 39 => {
                linked_keys.push(AgentPubKey::from_raw_39(key_bytes));
                log::info!("Seeded linked agents from cached web agent key");
            }
            Ok(key_bytes) => {
                log::warn!("Cached web agent key is {} bytes, expected 39", key_bytes.len());
            }
            Err(_) => log::warn!("Failed to decode cached web agent key"),
        }
    }

    // Opportunistic DHT pass — 10 s budget. If gossip has already
    // landed the link record, we pick up any extras; otherwise we
    // skip the wait and rely on the cached seed.
    let dht_call = identity_ws.call_zome(
        ZomeCallTarget::RoleName(identity_role.into()),
        "agent_linking".into(),
        "get_linked_agents".into(),
        ExternIO::from(payload_mp),
    );
    match tokio::time::timeout(std::time::Duration::from_secs(10), dht_call).await {
        Ok(Ok(result)) => {
            let extras: Vec<AgentPubKey> = rmp_serde::from_slice(result.as_bytes())
                .unwrap_or_default();
            for key in extras {
                if !linked_keys.contains(&key) {
                    linked_keys.push(key);
                }
            }
        }
        Ok(Err(e)) => log::info!("get_linked_agents zome error (using cached only): {}", e),
        Err(_) => log::info!("get_linked_agents timed out at 10s (using cached only)"),
    }

    if linked_keys.is_empty() {
        log::info!("No linked agents found (no cache, no DHT result)");
    }
    linked_keys
}

/// Query linked agents' signatures for one signing DNA version.
/// Per-agent calls run serially (typically 1-2 linked agents); per-signature
/// enrichment within a returned batch runs in parallel.
///
/// Returns `Err` if any linked-agent query fails (DHT timeout, WS error)
/// — the caller needs to distinguish "linked agent has no sigs" from
/// "we couldn't fetch them yet". A silent `Vec::new()` here was the
/// root cause of beta7 showing 4/6 on cold-start Windows: when the
/// cold-DHT `get_signatures_for_agent` timed out, the call returned []
/// and the frontend treated it as authoritative.
async fn query_linked_sigs_for_version(
    admin_ws: &holochain_client::AdminWebsocket,
    app_port: u16,
    signing_app: &holochain_client::AppInfo,
    linked_keys: &[holochain_types::prelude::AgentPubKey],
) -> Result<Vec<serde_json::Value>, String> {
    use holochain_client::ZomeCallTarget;
    use holochain_types::prelude::{Entry, ExternIO, Record};

    let (app_ws, role_name) = connect_signing_app_ws(
        admin_ws, app_port, signing_app, "flowsta-vault-linked-sign",
    ).await.ok_or_else(|| format!("connect_signing_app_ws failed for {}",
        signing_app.installed_app_id))?;

    let mut all = Vec::new();
    for linked_key in linked_keys {
        let payload = rmp_serde::to_vec_named(linked_key)
            .map_err(|e| format!("encode linked key: {}", e))?;
        let result = app_ws.call_zome(
            ZomeCallTarget::RoleName(role_name.clone().into()),
            "signing".into(),
            "get_signatures_for_agent".into(),
            ExternIO::from(payload),
        ).await.map_err(|e| format!(
            "get_signatures_for_agent failed on {}: {}", signing_app.installed_app_id, e
        ))?;
        let records: Vec<Record> = rmp_serde::from_slice(result.as_bytes())
            .map_err(|e| format!("decode linked records ({}): {}",
                signing_app.installed_app_id, e))?;
        if !records.is_empty() {
            log::info!("Got {} signatures for linked agent from {}",
                records.len(), signing_app.installed_app_id);
        }

        let entries: Vec<(&Record, SignatureEntry)> = records.iter().filter_map(|record| {
            let entry_bytes = match record.entry().as_option() {
                Some(Entry::App(b)) => b,
                _ => return None,
            };
            rmp_serde::from_slice::<SignatureEntry>(entry_bytes.bytes())
                .ok()
                .map(|e| (record, e))
        }).collect();

        let futures = entries.into_iter().map(|(record, entry)| {
            build_linked_signature_json(&app_ws, &role_name, record, entry,
                &signing_app.installed_app_id)
        });
        let mut sigs: Vec<serde_json::Value> = futures::future::join_all(futures).await;
        all.append(&mut sigs);
    }
    Ok(all)
}

/// True if `err` is one of the messages we see when the conductor's
/// admin WebSocket can't be reached — either the conductor closed the
/// connection (10054) or the process is gone entirely (10061).
fn is_conductor_unreachable_error(err: &str) -> bool {
    err.contains("Websocket")
        || err.contains("ConnectionReset")
        || err.contains("ConnectionClosed")
        || err.contains("ConnectionRefused")
        || err.contains("os error 10054")
        || err.contains("os error 10061")
}

/// Shared setup: open admin WS, ensure all apps enabled, list apps and
/// filter to the bundled signing-DNA version. Returns the admin WS, the
/// app port, the full app list (linked-agent discovery needs identity
/// app entries), and the filtered signing apps.
async fn open_signing_conductor(
    state: &Arc<AppState>,
) -> Result<(holochain_client::AdminWebsocket, u16,
            Vec<holochain_client::AppInfo>,
            Vec<holochain_client::AppInfo>), String> {
    use holochain_client::AdminWebsocket;

    let conductor_ports = {
        let conductor = state.conductor_handle.lock().unwrap();
        conductor.as_ref().map(|h| (h.admin_port, h.app_port))
    };
    let (admin_port, app_port) = conductor_ports.ok_or("Conductor not running")?;

    let admin_ws = AdminWebsocket::connect(
        format!("localhost:{}", admin_port),
        Some("flowsta-vault-read".to_string()),
    ).await.map_err(|e| format!("Admin WS: {}", e))?;

    crate::dna::ensure_apps_enabled(&admin_ws).await;

    let apps = admin_ws.list_apps(None).await.map_err(|e| format!("list_apps: {}", e))?;
    let signing_apps: Vec<_> = apps.iter()
        .filter(|a| a.installed_app_id ==
            crate::dna::make_app_id("signing", crate::dna::BUNDLED_SIGNING_VERSION))
        .cloned()
        .collect();
    Ok((admin_ws, app_port, apps, signing_apps))
}

/// Apply the reverse `superseded_by` pointer in place. The chain only
/// records the forward `supersedes` link; the frontend needs the reverse
/// so amended records drop out of the active list. Scoped within whatever
/// batch is passed in.
fn apply_superseded_by(signatures: &mut [serde_json::Value]) {
    let map: std::collections::HashMap<String, String> = signatures.iter()
        .filter_map(|s| {
            let action_hash = s.get("action_hash")?.as_str()?.to_string();
            let supersedes = s.get("supersedes")?.as_str()?.to_string();
            Some((supersedes, action_hash))
        })
        .collect();
    if map.is_empty() { return; }
    for sig in signatures.iter_mut() {
        let action_hash = match sig.get("action_hash").and_then(|h| h.as_str()) {
            Some(h) => h.to_string(),
            None => continue,
        };
        if let Some(superseded_by) = map.get(&action_hash) {
            if let Some(obj) = sig.as_object_mut() {
                obj.insert(
                    "superseded_by".to_string(),
                    serde_json::Value::String(superseded_by.clone()),
                );
            }
        }
    }
}

/// Returns own signatures only. Split from the linked-agent fetch so the
/// frontend can run both in parallel with independent retry loops; the
/// linked path is the cold-start bottleneck and shouldn't gate the local
/// query that resolves in milliseconds. Returns `Err` on any version
/// failure so the frontend can retry — silently masking failures as `[]`
/// is what caused beta7 to display a 4/6 partial count on cold start.
#[tauri::command]
pub async fn get_my_own_signatures(
    state: State<'_, Arc<AppState>>,
    app_handle: tauri::AppHandle,
) -> Result<Vec<serde_json::Value>, String> {
    match get_my_own_signatures_inner(state.inner()).await {
        Ok(sigs) => Ok(sigs),
        Err(e) => {
            if !is_conductor_unreachable_error(&e) { return Err(e); }
            log::warn!(
                "[get_my_own_signatures] conductor unreachable ({}) — running watchdog",
                e,
            );
            if let Err(re) = ensure_conductor_alive(state.inner(), &app_handle).await {
                log::warn!(
                    "[get_my_own_signatures] watchdog could not restart conductor: {}",
                    re,
                );
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            get_my_own_signatures_inner(state.inner()).await
        }
    }
}

async fn get_my_own_signatures_inner(
    state: &Arc<AppState>,
) -> Result<Vec<serde_json::Value>, String> {
    let (admin_ws, app_port, _apps, signing_apps) = open_signing_conductor(state).await?;
    if signing_apps.is_empty() { return Ok(Vec::new()); }

    let results = futures::future::join_all(
        signing_apps.iter()
            .map(|app| query_own_sigs_for_version(&admin_ws, app_port, app)),
    ).await;
    // Any single-version failure surfaces as Err so the frontend retries.
    let mut signatures: Vec<serde_json::Value> = Vec::new();
    for r in results {
        signatures.extend(r?);
    }
    log::info!(
        "[get_my_own_signatures] {} sig(s) from {} version(s)",
        signatures.len(), signing_apps.len(),
    );
    apply_superseded_by(&mut signatures);
    Ok(signatures)
}

/// Wire-format result for `get_my_linked_signatures`. The `has_linked_agents`
/// flag lets the frontend distinguish two zero-signature cases:
///   - `has_linked_agents=false`: the agent has no linked accounts — the
///     empty result is authoritative, frontend can promote to loaded.
///   - `has_linked_agents=true`: linked accounts exist but returned no
///     sigs — could be legitimate, or cold-DHT-not-yet-gossiped, so the
///     frontend should keep retrying.
#[derive(serde::Serialize)]
pub struct LinkedSignaturesResult {
    pub signatures: Vec<serde_json::Value>,
    pub has_linked_agents: bool,
}

/// Returns signatures from linked agents only. Split from the own-sigs
/// fetch — the cold-DHT `get_links` here can take minutes, so it must
/// not gate the local own-sigs result. Returns `Err` on any sig query
/// failure (per-version) so the frontend can retry without confusing
/// "timed out" with "no sigs".
#[tauri::command]
pub async fn get_my_linked_signatures(
    state: State<'_, Arc<AppState>>,
    app_handle: tauri::AppHandle,
) -> Result<LinkedSignaturesResult, String> {
    match get_my_linked_signatures_inner(state.inner()).await {
        Ok(r) => Ok(r),
        Err(e) => {
            if !is_conductor_unreachable_error(&e) { return Err(e); }
            log::warn!(
                "[get_my_linked_signatures] conductor unreachable ({}) — running watchdog",
                e,
            );
            if let Err(re) = ensure_conductor_alive(state.inner(), &app_handle).await {
                log::warn!(
                    "[get_my_linked_signatures] watchdog could not restart conductor: {}",
                    re,
                );
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            get_my_linked_signatures_inner(state.inner()).await
        }
    }
}

async fn get_my_linked_signatures_inner(
    state: &Arc<AppState>,
) -> Result<LinkedSignaturesResult, String> {
    let (admin_ws, app_port, apps, signing_apps) = open_signing_conductor(state).await?;
    if signing_apps.is_empty() {
        return Ok(LinkedSignaturesResult {
            signatures: Vec::new(),
            has_linked_agents: false,
        });
    }

    let cached_web_key = state.linked_web_agent_key.lock().unwrap().clone();
    // Auto-link races with the conductor-ready event that drives the
    // first refresh — if conductor reports ready before auto-link
    // finishes populating `linked_web_agent_key`, an empty linked_keys
    // result is a false negative ("not yet ready" misread as
    // "no linked agents") and the frontend would promote to a 4/6
    // partial display. Return Err so the frontend retries; the
    // `profile-synced` event fires the next refresh once auto-link
    // is done.
    if cached_web_key.is_none() {
        return Err("auto-link not yet complete (cached web agent key unset)".to_string());
    }
    let linked_keys = fetch_linked_agent_keys(&admin_ws, app_port, &apps, cached_web_key).await;
    if linked_keys.is_empty() {
        log::info!("[get_my_linked_signatures] no linked agents — authoritative empty");
        return Ok(LinkedSignaturesResult {
            signatures: Vec::new(),
            has_linked_agents: false,
        });
    }
    log::info!("[get_my_linked_signatures] querying {} linked agent(s)", linked_keys.len());

    let results = futures::future::join_all(
        signing_apps.iter()
            .map(|app| query_linked_sigs_for_version(&admin_ws, app_port, app, &linked_keys)),
    ).await;
    let mut signatures: Vec<serde_json::Value> = Vec::new();
    for r in results {
        signatures.extend(r?);
    }
    log::info!("[get_my_linked_signatures] {} sig(s)", signatures.len());
    apply_superseded_by(&mut signatures);
    Ok(LinkedSignaturesResult {
        signatures,
        has_linked_agents: true,
    })
}

/// Combined own + linked fetch, used by `export_all_data` where the
/// caller wants a single blocking result and is happy to wait. The
/// interactive UI uses `get_my_own_signatures` + `get_my_linked_signatures`
/// in parallel instead.
#[tauri::command]
pub async fn get_my_signatures(
    state: State<'_, Arc<AppState>>,
    app_handle: tauri::AppHandle,
) -> Result<Vec<serde_json::Value>, String> {
    match get_my_signatures_inner(state.inner()).await {
        Ok(sigs) => Ok(sigs),
        Err(e) => {
            if !is_conductor_unreachable_error(&e) { return Err(e); }
            log::warn!(
                "[get_my_signatures] conductor unreachable ({}) — running watchdog",
                e,
            );
            if let Err(re) = ensure_conductor_alive(state.inner(), &app_handle).await {
                log::warn!(
                    "[get_my_signatures] watchdog could not restart conductor: {}",
                    re,
                );
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            get_my_signatures_inner(state.inner()).await
        }
    }
}

async fn get_my_signatures_inner(
    state: &Arc<AppState>,
) -> Result<Vec<serde_json::Value>, String> {
    let (admin_ws, app_port, apps, signing_apps) = open_signing_conductor(state).await?;
    if signing_apps.is_empty() { return Ok(Vec::new()); }

    let cached_web_key = state.linked_web_agent_key.lock().unwrap().clone();
    let own_future = futures::future::join_all(
        signing_apps.iter()
            .map(|app| query_own_sigs_for_version(&admin_ws, app_port, app)),
    );
    let keys_future = fetch_linked_agent_keys(&admin_ws, app_port, &apps, cached_web_key);
    let (own_results, linked_keys) = tokio::join!(own_future, keys_future);

    // Best-effort: this combined call is for `export_all_data` where a
    // missing per-version result shouldn't fail the whole export.
    let mut signatures: Vec<serde_json::Value> = own_results.into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect();
    log::info!(
        "Loaded {} own signatures from {} signing DNA version(s)",
        signatures.len(), signing_apps.len(),
    );

    if !linked_keys.is_empty() {
        log::info!("Found {} linked agent(s), querying their signatures", linked_keys.len());
        let linked_results = futures::future::join_all(
            signing_apps.iter()
                .map(|app| query_linked_sigs_for_version(&admin_ws, app_port, app, &linked_keys)),
        ).await;
        let linked_sigs: Vec<serde_json::Value> = linked_results.into_iter()
            .filter_map(|r| r.ok())
            .flatten()
            .collect();
        if !linked_sigs.is_empty() {
            log::info!("Found {} signatures from linked agents", linked_sigs.len());
            let existing: std::collections::HashSet<String> = signatures.iter()
                .filter_map(|s| s.get("action_hash").and_then(|h| h.as_str()).map(String::from))
                .collect();
            for sig in linked_sigs {
                let hash = sig.get("action_hash").and_then(|h| h.as_str()).unwrap_or("").to_string();
                if !hash.is_empty() && !existing.contains(&hash) {
                    signatures.push(sig);
                }
            }
        }
    }

    apply_superseded_by(&mut signatures);
    log::info!("Total signatures (own + linked): {}", signatures.len());
    Ok(signatures)
}

/// Revoke a signature by action hash. Creates a RevocationEntry on the DHT.
#[tauri::command]
pub async fn revoke_signature(
    action_hash_hex: String,
    reason: Option<String>,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    use holochain_client::{AdminWebsocket, AppWebsocket, AuthorizeSigningCredentialsPayload,
        ClientAgentSigner, CellInfo, IssueAppAuthenticationTokenPayload, ZomeCallTarget};
    use holochain_types::prelude::ExternIO;

    let conductor_ports = {
        let conductor = state.conductor_handle.lock().unwrap();
        conductor.as_ref().map(|h| (h.admin_port, h.app_port))
    };

    let (admin_port, app_port) = conductor_ports.ok_or("Conductor not running")?;
    let signing_app_id = crate::dna::make_app_id("signing", crate::dna::BUNDLED_SIGNING_VERSION);

    let admin_ws = AdminWebsocket::connect(
        format!("localhost:{}", admin_port),
        Some("flowsta-vault-revoke".to_string()),
    ).await.map_err(|e| format!("Admin WS: {}", e))?;

    crate::dna::ensure_apps_enabled(&admin_ws).await;

    let apps = admin_ws.list_apps(None).await.map_err(|e| format!("list_apps: {}", e))?;
    let signing_app = apps.iter().find(|a| a.installed_app_id == signing_app_id)
        .ok_or("Signing DNA not installed")?;

    let role_name = signing_app.cell_info.keys()
        .find(|k| k.starts_with("flowsta_signing"))
        .ok_or("No signing role")?.clone();

    let cell_id = signing_app.cell_info[&role_name].iter()
        .find_map(|c| match c {
            CellInfo::Provisioned(p) => Some(p.cell_id.clone()),
            _ => None,
        })
        .ok_or("No provisioned signing cell")?;

    let credentials = admin_ws.authorize_signing_credentials(AuthorizeSigningCredentialsPayload {
        cell_id: cell_id.clone(), functions: None,
    }).await.map_err(|e| format!("auth creds: {}", e))?;

    let issued = admin_ws.issue_app_auth_token(
        IssueAppAuthenticationTokenPayload::for_installed_app_id(signing_app_id),
    ).await.map_err(|e| format!("auth token: {}", e))?;

    let signer = ClientAgentSigner::default();
    signer.add_credentials(cell_id, credentials);
    let app_ws = AppWebsocket::connect_with_config(
        format!("localhost:{}", app_port),
        long_request_ws_config(),
        issued.token, signer.into(),
        Some("flowsta-vault-revoke".into()),
    ).await.map_err(|e| format!("App WS: {}", e))?;

    // Build the RevokeInput payload — must use ActionHash type (not raw bytes)
    #[derive(serde::Serialize)]
    struct RevokeInput {
        signature_action: holochain_types::prelude::ActionHash,
        reason: Option<String>,
    }

    let action_bytes = hex::decode(&action_hash_hex)
        .map_err(|_| "Invalid action hash hex".to_string())?;

    let action_hash = holochain_types::prelude::ActionHash::from_raw_39(action_bytes.clone());

    let payload = RevokeInput {
        signature_action: action_hash,
        reason,
    };

    let payload_mp = rmp_serde::to_vec_named(&payload)
        .map_err(|e| format!("MessagePack: {}", e))?;

    let result = app_ws.call_zome(
        ZomeCallTarget::RoleName(role_name.into()),
        "signing".into(),
        "revoke_signature".into(),
        ExternIO::from(payload_mp),
    ).await.map_err(|e| format!("revoke_signature zome call: {}", e))?;

    let revocation_hash = hex::encode(result.as_bytes());
    log::info!("Signature revoked, revocation_hash: {}", revocation_hash);

    Ok(revocation_hash)
}

/// Store a thumbnail for a signature on the local signing DNA.
/// Always targets v1.3 which has the set_thumbnail zome function.
/// The v1.3 coordinator doesn't require the signature to exist locally,
/// so thumbnails can be set for signatures from any DNA version.
#[tauri::command]
pub async fn set_thumbnail(
    action_hash_hex: String,
    thumbnail: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    use holochain_client::{AdminWebsocket, AppWebsocket, AuthorizeSigningCredentialsPayload,
        ClientAgentSigner, CellInfo, IssueAppAuthenticationTokenPayload, ZomeCallTarget};
    use holochain_types::prelude::ExternIO;

    let conductor_ports = {
        let conductor = state.conductor_handle.lock().unwrap();
        conductor.as_ref().map(|h| (h.admin_port, h.app_port))
    };

    let (admin_port, app_port) = conductor_ports.ok_or("Conductor not running")?;
    let signing_app_id = crate::dna::make_app_id("signing", crate::dna::BUNDLED_SIGNING_VERSION);

    let admin_ws = AdminWebsocket::connect(
        format!("localhost:{}", admin_port),
        Some("flowsta-vault-thumb".to_string()),
    ).await.map_err(|e| format!("Admin WS: {}", e))?;

    crate::dna::ensure_apps_enabled(&admin_ws).await;

    let apps = admin_ws.list_apps(None).await.map_err(|e| format!("list_apps: {}", e))?;
    let signing_app = apps.iter().find(|a| a.installed_app_id == signing_app_id)
        .ok_or("Signing DNA not installed")?;

    let role_name = signing_app.cell_info.keys()
        .find(|k| k.starts_with("flowsta_signing"))
        .ok_or("No signing role")?.clone();

    let cell_id = signing_app.cell_info[&role_name].iter()
        .find_map(|c| match c {
            CellInfo::Provisioned(p) => Some(p.cell_id.clone()),
            _ => None,
        })
        .ok_or("No provisioned signing cell")?;

    let credentials = admin_ws.authorize_signing_credentials(AuthorizeSigningCredentialsPayload {
        cell_id: cell_id.clone(), functions: None,
    }).await.map_err(|e| format!("auth creds: {}", e))?;

    let issued = admin_ws.issue_app_auth_token(
        IssueAppAuthenticationTokenPayload::for_installed_app_id(signing_app_id),
    ).await.map_err(|e| format!("auth token: {}", e))?;

    let signer = ClientAgentSigner::default();
    signer.add_credentials(cell_id, credentials);
    let app_ws = AppWebsocket::connect_with_config(
        format!("localhost:{}", app_port),
        long_request_ws_config(),
        issued.token, signer.into(),
        Some("flowsta-vault-thumb".into()),
    ).await.map_err(|e| format!("App WS: {}", e))?;

    let action_hash_bytes = hex::decode(&action_hash_hex)
        .map_err(|e| format!("Invalid action hash hex: {}", e))?;
    let action_hash = holochain_types::prelude::ActionHash::from_raw_39(action_hash_bytes);

    #[derive(serde::Serialize)]
    struct SetThumbnailInput {
        signature_action: holochain_types::prelude::ActionHash,
        thumbnail: String,
    }

    let payload = SetThumbnailInput {
        signature_action: action_hash,
        thumbnail,
    };

    let payload_mp = rmp_serde::to_vec_named(&payload)
        .map_err(|e| format!("MessagePack: {}", e))?;

    let result = app_ws.call_zome(
        ZomeCallTarget::RoleName(role_name.into()),
        "signing".into(),
        "set_thumbnail".into(),
        ExternIO::from(payload_mp),
    ).await.map_err(|e| format!("set_thumbnail zome call: {}", e))?;

    let thumb_hash = hex::encode(result.as_bytes());
    log::info!("Thumbnail set on DHT, hash: {}", thumb_hash);

    Ok(thumb_hash)
}

/// Commit a SignatureRecord to the signing DNA via the local conductor.
/// Returns the ActionHash as a base64-encoded string.
async fn commit_signature_to_dht(
    admin_port: u16,
    app_port: u16,
    file_hash: &[u8],
    signature: &[u8],
    signed_at: i64,
    intent: Option<&str>,
    ai_generation: Option<&str>,
    content_rights: Option<&serde_json::Value>,
    integrity_report: Option<&serde_json::Value>,
    perceptual_hash: Option<&serde_json::Value>,
    // v1.3+ optional fields. supersedes is the raw 39-byte action_hash
    // of the signature this one replaces (chain backpointer). Older DNA
    // versions ignore unknown fields, so passing None on v1.0–v1.2 is safe.
    comment: Option<&str>,
    supersedes: Option<&[u8]>,
) -> Result<String, String> {
    use holochain_client::{AdminWebsocket, AppWebsocket, AuthorizeSigningCredentialsPayload,
        ClientAgentSigner, CellInfo, IssueAppAuthenticationTokenPayload, ZomeCallTarget};
    use holochain_types::prelude::ExternIO;

    let signing_app_id = crate::dna::make_app_id("signing", crate::dna::BUNDLED_SIGNING_VERSION);

    // Connect to admin WS
    let admin_ws = AdminWebsocket::connect(
        format!("localhost:{}", admin_port),
        Some("flowsta-vault-sign".to_string()),
    )
    .await
    .map_err(|e| format!("Admin WS connect failed: {}", e))?;

    // Ensure all apps are enabled — conductor may disable cells on restart
    crate::dna::ensure_apps_enabled(&admin_ws).await;

    // Find the signing app and its provisioned cell
    let apps = admin_ws
        .list_apps(None)
        .await
        .map_err(|e| format!("list_apps failed: {}", e))?;

    let signing_app = apps
        .iter()
        .find(|a| a.installed_app_id == signing_app_id)
        .ok_or_else(|| format!("Signing DNA not installed ({})", signing_app_id))?;

    let role_name = signing_app
        .cell_info
        .keys()
        .find(|k| k.starts_with("flowsta_signing"))
        .ok_or("No flowsta_signing role found")?
        .clone();

    let cell_info_list = &signing_app.cell_info[&role_name];
    let cell_id = cell_info_list
        .iter()
        .find_map(|c| match c {
            CellInfo::Provisioned(p) => Some(p.cell_id.clone()),
            _ => None,
        })
        .ok_or("No provisioned signing cell")?;

    // Authorize signing credentials for this cell
    let credentials = admin_ws
        .authorize_signing_credentials(AuthorizeSigningCredentialsPayload {
            cell_id: cell_id.clone(),
            functions: None,
        })
        .await
        .map_err(|e| format!("authorize_signing_credentials failed: {}", e))?;

    // Issue auth token
    let issued = admin_ws
        .issue_app_auth_token(
            IssueAppAuthenticationTokenPayload::for_installed_app_id(signing_app_id),
        )
        .await
        .map_err(|e| format!("issue_app_auth_token failed: {}", e))?;

    // Connect app WS with a ClientAgentSigner (must have credentials loaded)
    let signer = ClientAgentSigner::default();
    signer.add_credentials(cell_id, credentials);
    let app_ws = AppWebsocket::connect_with_config(
        format!("localhost:{}", app_port),
        long_request_ws_config(),
        issued.token,
        signer.into(),
        Some("flowsta-vault-sign".into()),
    )
    .await
    .map_err(|e| format!("App WS connect failed: {}", e))?;

    // Build the SignatureRecord payload.
    // Must match the DNA's Rust struct exactly for MessagePack deserialization.
    // We use holochain_types::prelude::SerializedBytes to properly encode
    // the AgentPubKey and other Holochain types.
    let agent_key = signing_app.agent_pub_key.clone();

    // Build a struct that mirrors the DNA's SignatureRecord
    // Mirror structs matching the signing DNA's types exactly (PascalCase enum variants)
    #[derive(serde::Serialize)]
    struct SignaturePayload {
        file_hash: Vec<u8>,
        signature: Vec<u8>,
        signer: holochain_types::prelude::AgentPubKey,
        signed_at: i64,
        intent: Option<String>,
        ai_generation: Option<String>,
        content_rights: Option<ContentRightsPayload>,
        integrity_report: Option<IntegrityReportPayload>,
        perceptual_hash: Option<PerceptualHashPayload>,
        // v1.3+ SignatureRecord extensions. Field order doesn't matter
        // for MessagePack named-field encoding (rmp_serde::to_vec_named).
        supersedes: Option<holochain_types::prelude::ActionHash>,
        expires_at: Option<i64>,
        tags: Option<Vec<String>>,
        comment: Option<String>,
    }

    #[derive(serde::Serialize)]
    struct PerceptualHashPayload {
        hash_type: String,
        hash_value: Vec<u8>,
        bands: Vec<Vec<u8>>,
    }

    #[derive(serde::Serialize)]
    struct ContentRightsPayload {
        license: Option<String>,
        commercial_licensing: Option<String>,
        ai_training: Option<String>,
        contact_preference: Option<String>,
    }

    #[derive(serde::Serialize)]
    struct IntegrityReportPayload {
        checks_performed: Vec<String>,
        issues_found: Vec<IntegrityIssuePayload>,
        checked_at: i64,
    }

    #[derive(serde::Serialize)]
    struct IntegrityIssuePayload {
        check_type: String,
        severity: String,
        description: String,
    }

    // Map frontend kebab/snake_case values to DNA PascalCase enum variants
    fn map_license(v: &str) -> String {
        match v {
            "all-rights-reserved" => "AllRightsReserved",
            "cc0" => "CC0",
            "cc-by" => "CCBY",
            "cc-by-sa" => "CCBYSA",
            "cc-by-nc" => "CCBYNC",
            "cc-by-nc-sa" => "CCBYNCSA",
            "mit" => "MIT",
            "apache-2" => "Apache2",
            "gpl-3" => "GPL3",
            other => other,
        }.to_string()
    }

    fn map_commercial(v: &str) -> String {
        match v {
            "not_available" => "NotAvailable",
            "open_to_licensing" => "OpenToLicensing",
            other => other,
        }.to_string()
    }

    fn map_ai_training(v: &str) -> String {
        match v {
            "allowed" => "Allowed",
            "allowed_with_attribution" => "AllowedWithAttribution",
            "requires_license" => "RequiresLicense",
            "not_allowed" => "NotAllowed",
            other => other,
        }.to_string()
    }

    fn map_contact(v: &str) -> String {
        match v {
            "no_contact" => "NoContact",
            "allow_contact_requests" => "AllowContactRequests",
            other => other,
        }.to_string()
    }

    // Parse content_rights from the frontend JSON value
    let cr_payload = content_rights.and_then(|cr| {
        let obj = cr.as_object()?;
        Some(ContentRightsPayload {
            license: obj.get("license").and_then(|v| v.as_str()).map(map_license),
            commercial_licensing: obj.get("commercial_licensing").and_then(|v| v.as_str()).map(map_commercial),
            ai_training: obj.get("ai_training").and_then(|v| v.as_str()).map(map_ai_training),
            contact_preference: obj.get("contact_preference").and_then(|v| v.as_str()).map(map_contact),
        })
    });

    // Parse integrity_report from the frontend JSON value
    let ir_payload = integrity_report.and_then(|ir| {
        let obj = ir.as_object()?;
        Some(IntegrityReportPayload {
            checks_performed: obj.get("checks_performed")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            issues_found: obj.get("issues_found")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| {
                    let o = v.as_object()?;
                    Some(IntegrityIssuePayload {
                        check_type: o.get("check_type")?.as_str()?.to_string(),
                        severity: o.get("severity")?.as_str()?.to_string(),
                        description: o.get("description")?.as_str()?.to_string(),
                    })
                }).collect())
                .unwrap_or_default(),
            checked_at: obj.get("checked_at").and_then(|v| v.as_i64()).unwrap_or(0),
        })
    });

    let payload = SignaturePayload {
        file_hash: file_hash.to_vec(),
        signature: signature.to_vec(),
        signer: agent_key,
        signed_at,
        intent: intent.map(|i| match i {
            "authorship" => "Authorship",
            "approval" => "Approval",
            "witness" => "Witness",
            "receipt" => "Receipt",
            "agreement" => "Agreement",
            other => other,
        }.to_string()),
        ai_generation: ai_generation.map(|a| match a {
            "none" => "None",
            "assisted" => "Assisted",
            "generated" => "Generated",
            other => other,
        }.to_string()),
        content_rights: cr_payload,
        integrity_report: ir_payload,
        perceptual_hash: perceptual_hash.and_then(|ph| {
            let obj = ph.as_object()?;
            Some(PerceptualHashPayload {
                hash_type: obj.get("hash_type")?.as_str()?.to_string(),
                hash_value: obj.get("hash_value")?.as_array()?
                    .iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect(),
                bands: obj.get("bands")?.as_array()?
                    .iter().filter_map(|band| {
                        Some(band.as_array()?.iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect())
                    }).collect(),
            })
        }),
        supersedes: supersedes.map(|b| holochain_types::prelude::ActionHash::from_raw_39(b.to_vec())),
        expires_at: None,
        tags: None,
        comment: comment.map(|s| s.to_string()),
    };

    // Encode with MessagePack using the same encoder Holochain uses
    let payload_mp = rmp_serde::to_vec_named(&payload)
        .map_err(|e| format!("MessagePack serialization failed: {}", e))?;

    let result = app_ws
        .call_zome(
            ZomeCallTarget::RoleName(role_name.into()),
            "signing".into(),
            "create_signature".into(),
            ExternIO::from(payload_mp),
        )
        .await
        .map_err(|e| format!("Zome call create_signature failed: {}", e))?;

    // Result is MessagePack-encoded ActionHash — deserialize to get raw 39 bytes
    let action_hash: holochain_types::prelude::ActionHash =
        rmp_serde::from_slice(result.as_bytes())
            .map_err(|e| format!("Failed to decode ActionHash from zome result: {}", e))?;
    let action_hash_hex = hex::encode(action_hash.get_raw_39());
    log::info!("Signature committed to DHT, action_hash: {}", action_hash_hex);

    Ok(action_hash_hex)
}

// ============================================
// Sign quota cache (HMAC-signed local persistence)
// ============================================

#[tauri::command]
pub fn read_quota_cache(state: State<'_, Arc<AppState>>) -> Result<Option<crate::quota_cache::QuotaCache>, String> {
    crate::quota_cache::read(&state.data_dir)
}

/// POST to the API's /quota/sync-by-agent with an Ed25519 signature.
/// Called after each successful local sign so server-side quota stays accurate.
/// Silently returns Ok(false) if the user hasn't linked a web account yet.
#[tauri::command]
pub async fn sync_quota_to_server(
    state: State<'_, Arc<AppState>>,
    api_url: String,
    count: u32,
) -> Result<bool, String> {
    if count == 0 { return Ok(false); }

    log::info!("[quota-sync] starting, count={}", count);

    // Pull everything we need from the vault config. Uses the same auth shape
    // as /auth/link-desktop-agent: sign with device_seed, identify user via
    // recovery_lookup_hash.
    let (desktop_agent_key, recovery_lookup_hash, device_seed) = {
        let config = state.vault_config.lock().unwrap();
        let config = config.as_ref().ok_or("Vault is locked")?;

        let agent_b64 = config.agent_pub_key_raw_b64.clone()
            .ok_or("No desktop agent pub key in config")?;
        let hash = config.recovery_lookup_hash.clone()
            .ok_or("No recovery lookup hash in config")?;
        let seed_bytes = config.device_seed.as_ref()
            .ok_or("No device seed in config")?;
        if seed_bytes.len() != 32 {
            return Err("Device seed has wrong length".into());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_bytes);
        (agent_b64, hash, seed)
    };

    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    // Canonical payload matches the API's verification string
    let canonical = format!("flowsta-quota-sync:{}:{}:{}", desktop_agent_key, timestamp_ms, count);
    let signature = crate::key_derivation::sign_with_device_seed(&device_seed, canonical.as_bytes());
    let sig_hex = hex::encode(signature);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/sign-it/quota/sync-by-agent", api_url))
        .json(&serde_json::json!({
            "desktop_agent_key": desktop_agent_key,
            "recovery_lookup_hash": recovery_lookup_hash,
            "count": count,
            "timestamp": timestamp_ms,
            "signature": sig_hex,
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        log::error!("[quota-sync] failed ({}): {}", status, body);
        return Err(format!("Sync failed ({}): {}", status, body));
    }

    log::info!("[quota-sync] success: synced {} signatures", count);
    Ok(true)
}

#[tauri::command]
pub fn write_quota_cache(
    state: State<'_, Arc<AppState>>,
    cache: crate::quota_cache::QuotaCache,
) -> Result<crate::quota_cache::QuotaCache, String> {
    crate::quota_cache::write(&state.data_dir, cache)
}

#[tauri::command]
pub fn increment_quota_used(state: State<'_, Arc<AppState>>) -> Result<Option<crate::quota_cache::QuotaCache>, String> {
    crate::quota_cache::increment_used(&state.data_dir)
}

