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
            approved_apps: Mutex::new(Vec::new()),
            linked_third_party_apps: Mutex::new(linked_apps),
            conductor_handle: Mutex::new(None),
            conductor_status: Mutex::new(ConductorStatus::Stopped),
            mau_state: crate::mau::MauState::new(),
            verified_apps: Mutex::new(verified_apps),
            linked_app_scopes: Mutex::new(linked_app_scopes),
            backup_key: Mutex::new(None),
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
        let apps = self.linked_third_party_apps.lock().unwrap();
        let path = self.data_dir.join("linked-apps.json");
        if let Ok(json) = serde_json::to_string_pretty(&*apps) {
            let _ = std::fs::write(path, json);
        }
    }

    /// Persist the granted scopes store to disk.
    pub fn save_linked_app_scopes(&self) {
        let scopes = self.linked_app_scopes.lock().unwrap();
        let path = self.data_dir.join("linked-app-scopes.json");
        if let Ok(json) = serde_json::to_string_pretty(&*scopes) {
            let _ = std::fs::write(path, json);
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

    // Spawn conductor startup in background (if device seed is available)
    spawn_conductor_startup(device_seed, data_dir, passphrase, app_handle, state.inner().clone());

    Ok(result)
}

/// Lock the vault (clear in-memory config and stop conductor).
#[tauri::command]
pub fn lock_vault(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    // Clear MAU state before clearing vault config (needs device_seed)
    crate::mau::clear_mau_state(&state);

    let mut config = state.vault_config.lock().unwrap();
    *config = None;

    // Shutdown conductor + lair if running
    if let Some(handle) = state.conductor_handle.lock().unwrap().take() {
        handle.shutdown();
    }
    *state.conductor_status.lock().unwrap() = ConductorStatus::Stopped;

    log::info!("Vault locked.");
    Ok(())
}

/// Get the current conductor status (for frontend polling).
#[tauri::command]
pub fn get_conductor_status(state: State<'_, Arc<AppState>>) -> ConductorStatus {
    state.conductor_status.lock().unwrap().clone()
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
                        *state.conductor_status.lock().unwrap() = ConductorStatus::Ready {
                            admin_port: port,
                        };

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
                                cfg.recovery_lookup_hash.is_some()
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
                                    } else {
                                        log::warn!("Auto-link returned failure: {}", result.message);
                                    }
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

    // Reconstruct AgentPubKey from the stored raw base64.
    let agent_key = match agent_key_raw_b64 {
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
    };

    // Emit update check status.
    let _ = app_handle.emit(
        "dna-update-status",
        serde_json::json!({"status": "checking"}),
    );

    let result = crate::dna_updater::check_and_update_dnas(
        admin_port,
        download_dir,
        &recovery_lookup_hash,
        &current_private_ver,
        &current_identity_ver,
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
    // Clear in-memory config
    let mut config = state.vault_config.lock().unwrap();
    *config = None;

    // Delete vault file from disk
    let vault_path = state.vault_path.lock().unwrap();
    if vault_path.exists() {
        std::fs::remove_file(&*vault_path)
            .map_err(|e| format!("Failed to delete vault file: {}", e))?;
    }

    log::info!("Vault reset — file deleted.");
    Ok(())
}

/// Get the identity info (only when unlocked).
#[tauri::command]
pub fn get_identity(state: State<'_, Arc<AppState>>) -> Result<VaultIdentity, String> {
    let config = state.vault_config.lock().unwrap();
    let config = config.as_ref().ok_or("Vault is locked")?;

    Ok(VaultIdentity {
        agent_pub_key: config.agent_pub_key.clone(),
        did: config.did.clone(),
        installed_app_ids: config.installed_app_ids.clone(),
        created_at: config.created_at,
        display_name: config.display_name.clone(),
        profile_picture: config.profile_picture.clone(),
        web_email: config.web_email.clone(),
        web_username: config.web_username.clone(),
        web_agent_pub_key: config.web_agent_pub_key.clone(),
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

    let status = resp.status();
    if !status.is_success() {
        // 404 = phrase doesn't match any account
        return Ok(false);
    }

    // Verify the returned agent key matches the signed-in user's key
    let body: AgentKeyLookupResponse = resp
        .json()
        .await
        .map_err(|e| format!("Invalid API response: {}", e))?;

    match body.agent_pub_key {
        Some(ref key) => Ok(key == &expected_web_agent_key),
        None => Ok(false),
    }
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

    Ok(LinkResult {
        success: link_resp.success.unwrap_or(false),
        web_agent_key: link_resp.web_agent_key,
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

/// Export all vault data (identity + backups) as JSON.
#[tauri::command]
pub fn export_all_data(
    state: State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    crate::backup::export_all_data(&state)
}

/// List individual backup metadata for a specific app.
#[tauri::command]
pub fn list_app_backup_details(
    client_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<crate::backup::BackupMeta>, String> {
    crate::backup::list_app_backups(&state.data_dir, &client_id)
}

/// Export (decrypt) a single backup by client_id + label.
#[tauri::command]
pub fn export_single_backup(
    client_id: String,
    label: Option<String>,
    state: State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let label_ref = label.as_deref();
    let (data, meta) = crate::backup::retrieve_backup(&state, &client_id, label_ref)?;

    let data_value = if meta.content_type.contains("json") {
        serde_json::from_slice(&data)
            .unwrap_or_else(|_| serde_json::Value::String(hex::encode(&data)))
    } else {
        serde_json::Value::String(hex::encode(&data))
    };

    Ok(serde_json::json!({
        "label": meta.label,
        "app_name": meta.app_name,
        "created_at": meta.created_at,
        "data_size": meta.data_size,
        "content_type": meta.content_type,
        "data": data_value,
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
