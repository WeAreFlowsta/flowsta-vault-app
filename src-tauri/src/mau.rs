//! Active-connections reporting for third-party Holochain apps
//! (formerly "MAU tracking" - the billing metric is active connections).
//!
//! Records first IPC interaction per client_id per calendar month.
//! Events are HMAC-signed and stored encrypted locally, then synced
//! to the Flowsta API when connectivity is available.
//!
//! Privacy: the sync payload is client_id + month_year ONLY - which app,
//! which month, nothing else. The server derives its own counting pseudonym;
//! no analytics id, activity count, or timestamps leave the device. The
//! richer local record (analytics_id/counts/timestamps in MauEvent) is
//! retained purely for on-disk format stability and stays on-device.
//! Developers see aggregate counts only.

use crate::commands::AppState;
use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::path::PathBuf;

/// HMAC constant for deriving the MAU integrity key from device_seed.
const MAU_INTEGRITY_CONSTANT: &str = "flowsta-mau-integrity";

/// HMAC constant for deriving the MAU storage encryption key from device_seed.
const MAU_STORAGE_CONSTANT: &str = "flowsta-mau-storage";

/// A single MAU event for one client_id in one calendar month.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MauEvent {
    pub client_id: String,
    pub analytics_id: String,
    pub month_year: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub activity_count: u32,
    pub synced: bool,
    /// HMAC-SHA256 hex signature for tamper detection.
    pub hmac: String,
}

/// Encrypted MAU store persisted to disk.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct MauStore {
    pub events: Vec<MauEvent>,
    /// Maps client_id -> analytics_id (random UUID, generated once per app).
    pub analytics_ids: HashMap<String, String>,
}

// ── In-memory MAU state ────────────────────────────────────────────

/// Thread-safe in-memory MAU store. Loaded on unlock, saved after changes.
pub struct MauState {
    pub store: std::sync::Mutex<Option<MauStore>>,
}

impl MauState {
    pub fn new() -> Self {
        Self {
            store: std::sync::Mutex::new(None),
        }
    }
}

// ── Key derivation ─────────────────────────────────────────────────

/// Derive the HMAC integrity key from device_seed.
fn derive_mau_integrity_key(device_seed: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(MAU_INTEGRITY_CONSTANT.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(device_seed);
    let result = mac.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes());
    key
}

/// Derive the AES-256-GCM encryption key from device_seed.
fn derive_mau_storage_key(device_seed: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(MAU_STORAGE_CONSTANT.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(device_seed);
    let result = mac.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes());
    key
}

/// Compute HMAC-SHA256 over the canonical event fields.
fn compute_event_hmac(integrity_key: &[u8; 32], event: &MauEvent) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(integrity_key)
        .expect("HMAC can take key of any size");
    mac.update(event.client_id.as_bytes());
    mac.update(b"|");
    mac.update(event.analytics_id.as_bytes());
    mac.update(b"|");
    mac.update(event.month_year.as_bytes());
    mac.update(b"|");
    mac.update(&event.first_seen_at.to_le_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Verify an event's HMAC is valid.
fn verify_event_hmac(integrity_key: &[u8; 32], event: &MauEvent) -> bool {
    let expected = compute_event_hmac(integrity_key, event);
    expected == event.hmac
}

// ── Encrypted persistence ──────────────────────────────────────────

fn mau_store_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("mau-events.enc")
}

/// Encrypt and save the MAU store to disk.
fn save_mau_store(
    data_dir: &std::path::Path,
    store: &MauStore,
    device_seed: &[u8; 32],
) -> Result<(), String> {
    let key = derive_mau_storage_key(device_seed);
    let plaintext =
        serde_json::to_vec(store).map_err(|e| format!("MAU serialize failed: {}", e))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(&key)
        .map_err(|e| format!("MAU cipher init failed: {}", e))?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| "MAU encryption failed".to_string())?;

    // Store as JSON: { nonce: hex, ciphertext: hex }
    let encrypted = serde_json::json!({
        "nonce": hex::encode(nonce_bytes),
        "ciphertext": hex::encode(ciphertext),
    });

    let path = mau_store_path(data_dir);
    let json = serde_json::to_string(&encrypted)
        .map_err(|e| format!("MAU envelope serialize failed: {}", e))?;
    std::fs::write(&path, json).map_err(|e| format!("MAU write failed: {}", e))?;
    Ok(())
}

/// Load and decrypt the MAU store from disk.
fn load_mau_store(
    data_dir: &std::path::Path,
    device_seed: &[u8; 32],
) -> Result<MauStore, String> {
    let path = mau_store_path(data_dir);
    if !path.exists() {
        return Ok(MauStore::default());
    }

    let json = std::fs::read_to_string(&path).map_err(|e| format!("MAU read failed: {}", e))?;
    let envelope: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| format!("MAU envelope parse failed: {}", e))?;

    let nonce_hex = envelope["nonce"]
        .as_str()
        .ok_or("MAU missing nonce")?;
    let ct_hex = envelope["ciphertext"]
        .as_str()
        .ok_or("MAU missing ciphertext")?;

    let nonce_bytes = hex::decode(nonce_hex).map_err(|_| "MAU bad nonce hex")?;
    let ciphertext = hex::decode(ct_hex).map_err(|_| "MAU bad ciphertext hex")?;

    let key = derive_mau_storage_key(device_seed);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(&key)
        .map_err(|e| format!("MAU cipher init failed: {}", e))?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "MAU decryption failed (corrupted or tampered)".to_string())?;

    let store: MauStore = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("MAU store parse failed: {}", e))?;
    Ok(store)
}

// ── Public API ─────────────────────────────────────────────────────

/// Load the MAU store into memory. Called on vault unlock.
pub fn load_mau_state(app_state: &AppState) {
    let device_seed = {
        let config = app_state.vault_config.lock().unwrap();
        match config.as_ref().and_then(|c| c.device_seed.as_ref()) {
            Some(seed) if seed.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(seed);
                arr
            }
            _ => return,
        }
    };

    match load_mau_store(&app_state.data_dir, &device_seed) {
        Ok(store) => {
            let event_count = store.events.len();
            *app_state.mau_state.store.lock().unwrap() = Some(store);
            log::info!("MAU store loaded ({} events)", event_count);
        }
        Err(e) => {
            log::warn!("Failed to load MAU store (starting fresh): {}", e);
            *app_state.mau_state.store.lock().unwrap() = Some(MauStore::default());
        }
    }
}

/// Clear MAU state from memory. Called on vault lock.
pub fn clear_mau_state(app_state: &AppState) {
    *app_state.mau_state.store.lock().unwrap() = None;
}

/// Get current month as "YYYY-MM".
fn current_month_year() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Simple epoch to YYYY-MM conversion
    let days = secs / 86400;
    let mut y = 1970i64;
    let mut remaining = days as i64;

    loop {
        let year_days = if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
            366
        } else {
            365
        };
        if remaining < year_days {
            break;
        }
        remaining -= year_days;
        y += 1;
    }

    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days: [i64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    let mut m = 0usize;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining < md {
            m = i;
            break;
        }
        remaining -= md;
    }

    format!("{:04}-{:02}", y, m + 1)
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Generate a random UUID v4 (without pulling in the uuid crate).
fn random_uuid() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    // Set version 4 and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        // Last 6 bytes as a single hex number
        ((bytes[10] as u64) << 40)
            | ((bytes[11] as u64) << 32)
            | ((bytes[12] as u64) << 24)
            | ((bytes[13] as u64) << 16)
            | ((bytes[14] as u64) << 8)
            | (bytes[15] as u64),
    )
}

/// Record an MAU event for a client_id if this is the first interaction this month.
/// Called from IPC handlers (link-identity, sign, etc).
pub fn record_mau_event_if_needed(app_state: &AppState, client_id: &str) {
    let device_seed = {
        let config = app_state.vault_config.lock().unwrap();
        match config.as_ref().and_then(|c| c.device_seed.as_ref()) {
            Some(seed) if seed.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(seed);
                arr
            }
            _ => return, // Vault locked or no seed - skip silently
        }
    };

    let month_year = current_month_year();
    let now = unix_now();

    let mut store_guard = app_state.mau_state.store.lock().unwrap();
    let store = match store_guard.as_mut() {
        Some(s) => s,
        None => return, // MAU state not loaded
    };

    // Check if we already have an event for this client_id + month
    if let Some(event) = store
        .events
        .iter_mut()
        .find(|e| e.client_id == client_id && e.month_year == month_year)
    {
        // Already tracked this month - just update last_seen and activity count
        event.last_seen_at = now;
        event.activity_count += 1;
        // Don't re-sign; the HMAC covers immutable fields (first_seen_at)
    } else {
        // First interaction this month - create new event
        let analytics_id = store
            .analytics_ids
            .entry(client_id.to_string())
            .or_insert_with(random_uuid)
            .clone();

        let integrity_key = derive_mau_integrity_key(&device_seed);

        let mut event = MauEvent {
            client_id: client_id.to_string(),
            analytics_id,
            month_year,
            first_seen_at: now,
            last_seen_at: now,
            activity_count: 1,
            synced: false,
            hmac: String::new(),
        };
        event.hmac = compute_event_hmac(&integrity_key, &event);

        store.events.push(event);
        log::info!("MAU event recorded for client_id: {}", client_id);
    }

    // Persist to disk (fire-and-forget - non-critical if it fails)
    if let Err(e) = save_mau_store(&app_state.data_dir, store, &device_seed) {
        log::warn!("Failed to persist MAU store: {}", e);
    }
}

/// Look up client_id for a linked app by origin, then record MAU.
/// Used by sign/authenticate handlers where we know the origin but not client_id.
pub fn record_mau_for_origin(app_state: &AppState, origin: Option<&str>) {
    // We can't directly map origin to client_id since origins are browser URLs
    // and client_ids are developer identifiers. Instead, check all linked apps.
    // For now, the MAU recording only happens on explicit /link-identity calls
    // where client_id is provided, and on subsequent IPC calls we check by
    // looking up the app_agent_pub_key. But since sign requests don't include
    // app_agent_pub_key, we skip origin-based tracking for now.
    //
    // The primary MAU trigger is the /link-identity call (once per link).
    // For ongoing activity tracking, third-party apps should include
    // client_id in their IPC calls (future enhancement).
    let _ = (app_state, origin);
}

/// Get pending (unsynced) MAU events, verifying HMAC integrity.
/// Returns events that pass HMAC check, drops tampered ones.
pub fn get_pending_mau_events(app_state: &AppState) -> Vec<MauEvent> {
    let device_seed = {
        let config = app_state.vault_config.lock().unwrap();
        match config.as_ref().and_then(|c| c.device_seed.as_ref()) {
            Some(seed) if seed.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(seed);
                arr
            }
            _ => return Vec::new(),
        }
    };

    let integrity_key = derive_mau_integrity_key(&device_seed);

    let store_guard = app_state.mau_state.store.lock().unwrap();
    let store = match store_guard.as_ref() {
        Some(s) => s,
        None => return Vec::new(),
    };

    store
        .events
        .iter()
        .filter(|e| !e.synced && verify_event_hmac(&integrity_key, e))
        .cloned()
        .collect()
}

/// Mark events as synced after successful API call.
pub fn mark_events_synced(app_state: &AppState, client_id_months: &[(String, String)]) {
    let device_seed = {
        let config = app_state.vault_config.lock().unwrap();
        match config.as_ref().and_then(|c| c.device_seed.as_ref()) {
            Some(seed) if seed.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(seed);
                arr
            }
            _ => return,
        }
    };

    let mut store_guard = app_state.mau_state.store.lock().unwrap();
    let store = match store_guard.as_mut() {
        Some(s) => s,
        None => return,
    };

    for event in store.events.iter_mut() {
        if client_id_months
            .iter()
            .any(|(cid, my)| cid == &event.client_id && my == &event.month_year)
        {
            event.synced = true;
        }
    }

    if let Err(e) = save_mau_store(&app_state.data_dir, store, &device_seed) {
        log::warn!("Failed to persist MAU store after marking synced: {}", e);
    }
}

/// Sync pending MAU events to the Flowsta API.
/// Returns the number of events synced, or an error.
pub async fn sync_mau_to_api(app_state: &AppState) -> Result<usize, String> {
    let pending = get_pending_mau_events(app_state);
    if pending.is_empty() {
        return Ok(0);
    }

    let recovery_lookup_hash = {
        let config = app_state.vault_config.lock().unwrap();
        config
            .as_ref()
            .and_then(|c| c.recovery_lookup_hash.clone())
            .ok_or("No recovery lookup hash")?
    };

    let api_url = option_env!("FLOWSTA_API_URL")
        .unwrap_or("https://auth-api.flowsta.com");

    // Build request payload. Active-connections metric: the server derives
    // the counted key itself, so the Vault reports only WHICH app and WHICH
    // month - no analytics id, no activity counts, no timestamps leave the
    // device. (The local store keeps its richer record purely on-device;
    // its on-disk format and HMAC are unchanged.)
    let events_json: Vec<serde_json::Value> = pending
        .iter()
        .map(|e| {
            serde_json::json!({
                "client_id": e.client_id,
                "month_year": e.month_year,
            })
        })
        .collect();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let resp = client
        .post(format!("{}/api/v1/mau/vault-sync", api_url))
        .json(&serde_json::json!({
            "recovery_lookup_hash": recovery_lookup_hash,
            "events": events_json,
        }))
        .send()
        .await
        .map_err(|e| format!("MAU sync request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("MAU sync failed ({}): {}", status, body));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("MAU sync response parse failed: {}", e))?;

    let synced_count = body["synced"].as_u64().unwrap_or(0) as usize;

    // Mark synced events
    let synced_pairs: Vec<(String, String)> = pending
        .iter()
        .map(|e| (e.client_id.clone(), e.month_year.clone()))
        .collect();
    mark_events_synced(app_state, &synced_pairs);

    log::info!("MAU sync complete: {} events synced", synced_count);
    Ok(synced_count)
}

/// Spawn periodic MAU sync task. Called after vault unlock + conductor ready.
pub fn spawn_mau_sync_task(app_state: std::sync::Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        // Initial sync attempt after 10 seconds (let conductor start first)
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        loop {
            // Check if vault is still unlocked
            {
                let config = app_state.vault_config.lock().unwrap();
                if config.is_none() {
                    log::info!("MAU sync: vault locked, stopping sync task");
                    break;
                }
            }

            match sync_mau_to_api(&app_state).await {
                Ok(count) if count > 0 => {
                    log::info!("MAU sync: {} events synced", count);
                }
                Ok(_) => {} // No pending events - silent
                Err(e) => {
                    log::debug!("MAU sync failed (will retry): {}", e);
                }
            }

            // Retry every 30 minutes
            tokio::time::sleep(std::time::Duration::from_secs(30 * 60)).await;
        }
    });
}
