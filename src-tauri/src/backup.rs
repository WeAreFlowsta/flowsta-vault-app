//! App data backup storage for third-party Holochain apps.
//!
//! Apps can store encrypted data blobs in the vault via the IPC `/backup` endpoint.
//! Each app's data is encrypted with a key derived from the vault's device seed,
//! stored in `data_dir/backups/<sanitized_client_id>/`. Apps can store multiple
//! versioned snapshots or overwrite a single latest backup.
//!
//! Users own their data — they can view, export, or delete any app's backup
//! from the Your Data page in the vault UI.

use crate::commands::AppState;
use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const BACKUP_STORAGE_CONSTANT: &str = "flowsta-backup-storage";

/// Maximum backup size per app: 50 MB.
const MAX_BACKUP_SIZE: usize = 50 * 1024 * 1024;

/// Maximum number of backups per app.
const MAX_BACKUPS_PER_APP: usize = 10;

// ── Helpers ─────────────────────────────────────────────────────────

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn iso_now() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Simple UTC ISO-8601 timestamp
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;
    // Approximate date calculation (good enough for export timestamps)
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds,
    )
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Days since 1970-01-01
    let mut year = 1970;
    loop {
        let year_days = if is_leap(year) { 366 } else { 365 };
        if days < year_days {
            break;
        }
        days -= year_days;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut month = 1;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ── Types ──────────────────────────────────────────────────────────

/// Metadata for a single backup snapshot.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BackupMeta {
    /// Developer client_id.
    pub client_id: String,
    /// Human-readable app name.
    pub app_name: String,
    /// Optional label for this backup (e.g. "v2", "before-migration").
    pub label: Option<String>,
    /// Unix timestamp when backup was created.
    pub created_at: i64,
    /// Size of the unencrypted data in bytes.
    pub data_size: usize,
    /// MIME type hint for the data (default: application/json).
    pub content_type: String,
}

/// Summary of all backups for one app.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AppBackupSummary {
    pub client_id: String,
    pub app_name: String,
    pub backup_count: usize,
    pub total_size: usize,
    pub last_backup_at: i64,
}

/// Overall backup stats for the vault.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BackupStats {
    pub app_count: usize,
    pub total_backups: usize,
    pub total_size: usize,
    pub apps: Vec<AppBackupSummary>,
}

/// Encrypted backup file on disk.
#[derive(Serialize, Deserialize)]
struct EncryptedBackup {
    nonce: String,
    ciphertext: String,
    meta: BackupMeta,
}

// ── Key derivation ─────────────────────────────────────────────────

fn derive_backup_key(device_seed: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(BACKUP_STORAGE_CONSTANT.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(device_seed);
    let result = mac.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes());
    key
}

// ── Path helpers ───────────────────────────────────────────────────

/// Sanitize client_id for use as a directory name.
fn sanitize_id(client_id: &str) -> String {
    client_id
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn backups_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("backups")
}

fn app_backup_dir(data_dir: &Path, client_id: &str) -> PathBuf {
    backups_dir(data_dir).join(sanitize_id(client_id))
}

fn backup_file_path(data_dir: &Path, client_id: &str, label: &str) -> PathBuf {
    let filename = format!("{}.enc", sanitize_id(label));
    app_backup_dir(data_dir, client_id).join(filename)
}

// ── Encrypt / Decrypt ──────────────────────────────────────────────

fn encrypt_data(data: &[u8], device_seed: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12]), String> {
    let key = derive_backup_key(device_seed);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(&key)
        .map_err(|e| format!("Backup cipher init failed: {}", e))?;
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|_| "Backup encryption failed".to_string())?;

    Ok((ciphertext, nonce_bytes))
}

fn decrypt_data(ciphertext: &[u8], nonce_bytes: &[u8], device_seed: &[u8; 32]) -> Result<Vec<u8>, String> {
    let key = derive_backup_key(device_seed);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(&key)
        .map_err(|e| format!("Backup cipher init failed: {}", e))?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Backup decryption failed (corrupted or tampered)".to_string())
}

// ── Public API ─────────────────────────────────────────────────────

/// Save a backup for an app. Encrypts the data and writes to disk.
pub fn save_backup(
    app_state: &AppState,
    client_id: &str,
    app_name: &str,
    label: Option<&str>,
    data: &[u8],
    content_type: Option<&str>,
) -> Result<BackupMeta, String> {
    if data.len() > MAX_BACKUP_SIZE {
        return Err(format!(
            "Backup too large: {} bytes (max {} bytes)",
            data.len(),
            MAX_BACKUP_SIZE
        ));
    }

    let device_seed = {
        let config = app_state.vault_config.lock().unwrap();
        let config = config.as_ref().ok_or("Vault is locked")?;
        let seed = config.device_seed.as_ref().ok_or("No device seed")?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(seed);
        arr
    };

    // Auto-rotate: if at the limit, delete the oldest backup to make room
    let label_str = label.unwrap_or("latest");
    let app_dir = app_backup_dir(&app_state.data_dir, client_id);
    if app_dir.exists() {
        let target_path = backup_file_path(&app_state.data_dir, client_id, label_str);
        let is_overwrite = target_path.exists();

        if !is_overwrite {
            let mut existing: Vec<_> = std::fs::read_dir(&app_dir)
                .map_err(|e| format!("Failed to read backup dir: {}", e))?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("enc"))
                .collect();

            while existing.len() >= MAX_BACKUPS_PER_APP {
                // Find the oldest backup by reading metadata
                let oldest = existing
                    .iter()
                    .filter_map(|entry| {
                        let json = std::fs::read_to_string(entry.path()).ok()?;
                        let enc: EncryptedBackup = serde_json::from_str(&json).ok()?;
                        Some((entry.path(), enc.meta.created_at))
                    })
                    .min_by_key(|(_, ts)| *ts);

                if let Some((oldest_path, _)) = oldest {
                    log::info!("Auto-rotating: deleting oldest backup {:?}", oldest_path);
                    let _ = std::fs::remove_file(&oldest_path);
                    existing.retain(|e| e.path() != oldest_path);
                } else {
                    break;
                }
            }
        }
    }

    // Encrypt
    let (ciphertext, nonce_bytes) = encrypt_data(data, &device_seed)?;

    let meta = BackupMeta {
        client_id: client_id.to_string(),
        app_name: app_name.to_string(),
        label: Some(label_str.to_string()),
        created_at: unix_now(),
        data_size: data.len(),
        content_type: content_type.unwrap_or("application/json").to_string(),
    };

    let encrypted = EncryptedBackup {
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
        meta: meta.clone(),
    };

    // Write to disk
    std::fs::create_dir_all(app_backup_dir(&app_state.data_dir, client_id))
        .map_err(|e| format!("Failed to create backup dir: {}", e))?;

    let path = backup_file_path(&app_state.data_dir, client_id, label_str);
    let json = serde_json::to_string(&encrypted)
        .map_err(|e| format!("Backup serialize failed: {}", e))?;
    std::fs::write(&path, json).map_err(|e| format!("Backup write failed: {}", e))?;

    log::info!(
        "Saved backup for {} ({}) — {} bytes, label: {}",
        app_name,
        client_id,
        data.len(),
        label_str,
    );

    Ok(meta)
}

/// Retrieve and decrypt a backup for an app.
pub fn retrieve_backup(
    app_state: &AppState,
    client_id: &str,
    label: Option<&str>,
) -> Result<(Vec<u8>, BackupMeta), String> {
    let device_seed = {
        let config = app_state.vault_config.lock().unwrap();
        let config = config.as_ref().ok_or("Vault is locked")?;
        let seed = config.device_seed.as_ref().ok_or("No device seed")?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(seed);
        arr
    };

    let label_str = label.unwrap_or("latest");
    let path = backup_file_path(&app_state.data_dir, client_id, label_str);

    if !path.exists() {
        return Err(format!("No backup found for label '{}'", label_str));
    }

    let json = std::fs::read_to_string(&path)
        .map_err(|e| format!("Backup read failed: {}", e))?;
    let encrypted: EncryptedBackup = serde_json::from_str(&json)
        .map_err(|e| format!("Backup parse failed: {}", e))?;

    let nonce_bytes = hex::decode(&encrypted.nonce)
        .map_err(|_| "Backup bad nonce hex".to_string())?;
    let ciphertext = hex::decode(&encrypted.ciphertext)
        .map_err(|_| "Backup bad ciphertext hex".to_string())?;

    let plaintext = decrypt_data(&ciphertext, &nonce_bytes, &device_seed)?;

    Ok((plaintext, encrypted.meta))
}

/// List all backups for a specific app.
pub fn list_app_backups(data_dir: &Path, client_id: &str) -> Result<Vec<BackupMeta>, String> {
    let app_dir = app_backup_dir(data_dir, client_id);
    if !app_dir.exists() {
        return Ok(Vec::new());
    }

    let mut metas = Vec::new();
    let entries = std::fs::read_dir(&app_dir)
        .map_err(|e| format!("Failed to read backup dir: {}", e))?;

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().and_then(|x| x.to_str()) != Some("enc") {
            continue;
        }
        if let Ok(json) = std::fs::read_to_string(&path) {
            if let Ok(encrypted) = serde_json::from_str::<EncryptedBackup>(&json) {
                metas.push(encrypted.meta);
            }
        }
    }

    metas.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(metas)
}

/// Get backup stats for all apps.
pub fn get_backup_stats(data_dir: &Path) -> BackupStats {
    let base = backups_dir(data_dir);
    if !base.exists() {
        return BackupStats {
            app_count: 0,
            total_backups: 0,
            total_size: 0,
            apps: Vec::new(),
        };
    }

    let mut apps = Vec::new();
    let mut total_backups = 0;
    let mut total_size = 0;

    if let Ok(entries) = std::fs::read_dir(&base) {
        for entry in entries.filter_map(|e| e.ok()) {
            if !entry.path().is_dir() {
                continue;
            }

            let dir_name = entry.file_name().to_string_lossy().to_string();

            let mut app_backups = 0;
            let mut app_size = 0;
            let mut last_at = 0i64;
            let mut app_name = dir_name.clone();
            let mut client_id = dir_name.clone();

            if let Ok(files) = std::fs::read_dir(entry.path()) {
                for file in files.filter_map(|f| f.ok()) {
                    let path = file.path();
                    if path.extension().and_then(|x| x.to_str()) != Some("enc") {
                        continue;
                    }
                    if let Ok(json) = std::fs::read_to_string(&path) {
                        if let Ok(enc) = serde_json::from_str::<EncryptedBackup>(&json) {
                            app_backups += 1;
                            app_size += enc.meta.data_size;
                            if enc.meta.created_at > last_at {
                                last_at = enc.meta.created_at;
                                app_name = enc.meta.app_name.clone();
                                client_id = enc.meta.client_id.clone();
                            }
                        }
                    }
                }
            }

            if app_backups > 0 {
                total_backups += app_backups;
                total_size += app_size;
                apps.push(AppBackupSummary {
                    client_id,
                    app_name,
                    backup_count: app_backups,
                    total_size: app_size,
                    last_backup_at: last_at,
                });
            }
        }
    }

    apps.sort_by(|a, b| b.last_backup_at.cmp(&a.last_backup_at));

    BackupStats {
        app_count: apps.len(),
        total_backups,
        total_size,
        apps,
    }
}

/// Delete all backups for a specific app.
pub fn delete_app_backups(data_dir: &Path, client_id: &str) -> Result<usize, String> {
    let app_dir = app_backup_dir(data_dir, client_id);
    if !app_dir.exists() {
        return Ok(0);
    }

    let mut deleted = 0;
    if let Ok(entries) = std::fs::read_dir(&app_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            if entry.path().extension().and_then(|x| x.to_str()) == Some("enc") {
                if std::fs::remove_file(entry.path()).is_ok() {
                    deleted += 1;
                }
            }
        }
    }

    // Remove the directory if empty
    let _ = std::fs::remove_dir(&app_dir);

    log::info!("Deleted {} backups for {}", deleted, client_id);
    Ok(deleted)
}

/// Delete a specific backup by label.
pub fn delete_backup(data_dir: &Path, client_id: &str, label: Option<&str>) -> Result<(), String> {
    let label_str = label.unwrap_or("latest");
    let path = backup_file_path(data_dir, client_id, label_str);
    if !path.exists() {
        return Err(format!("No backup found for label '{}'", label_str));
    }
    std::fs::remove_file(&path).map_err(|e| format!("Failed to delete backup: {}", e))?;

    // Remove the app dir if now empty
    let app_dir = app_backup_dir(data_dir, client_id);
    if let Ok(entries) = std::fs::read_dir(&app_dir) {
        if entries.into_iter().next().is_none() {
            let _ = std::fs::remove_dir(&app_dir);
        }
    }

    Ok(())
}

/// Export all vault data (identity + keys + backups) as a single JSON blob.
/// Includes cryptographic key material for CAL (Cryptographic Autonomy License)
/// compliance — users must be able to independently recreate their identity
/// and use their data without depending on Flowsta.
pub fn export_all_data(app_state: &AppState) -> Result<serde_json::Value, String> {
    let config = {
        let config = app_state.vault_config.lock().unwrap();
        config.as_ref().ok_or("Vault is locked")?.clone()
    };

    let stats = get_backup_stats(&app_state.data_dir);

    // Collect decrypted backup data for each app
    let mut app_data = Vec::new();
    for app_summary in &stats.apps {
        let metas = list_app_backups(&app_state.data_dir, &app_summary.client_id)?;
        let mut snapshots = Vec::new();

        for meta in &metas {
            let label = meta.label.as_deref().unwrap_or("latest");
            match retrieve_backup(app_state, &app_summary.client_id, Some(label)) {
                Ok((data, backup_meta)) => {
                    // Try to parse as JSON for nice formatting, fall back to hex
                    let data_value = if backup_meta.content_type.contains("json") {
                        serde_json::from_slice(&data).unwrap_or_else(|_| {
                            serde_json::Value::String(hex::encode(&data))
                        })
                    } else {
                        serde_json::Value::String(hex::encode(&data))
                    };

                    snapshots.push(serde_json::json!({
                        "label": meta.label,
                        "saved_at": meta.created_at,
                        "size_bytes": meta.data_size,
                        "content_type": meta.content_type,
                        "data": data_value,
                    }));
                }
                Err(e) => {
                    log::warn!("Failed to decrypt backup {} for {}: {}", label, app_summary.client_id, e);
                }
            }
        }

        app_data.push(serde_json::json!({
            "app_name": app_summary.app_name,
            "client_id": app_summary.client_id,
            "snapshot_count": snapshots.len(),
            "snapshots": snapshots,
        }));
    }

    // Build the linked apps list
    let linked_apps = app_state.linked_third_party_apps.lock().unwrap().clone();

    // Format the device seed as hex (if present)
    let device_seed_hex = config.device_seed.as_ref().map(|s| hex::encode(s));

    let export = serde_json::json!({
        "_readme": concat!(
            "This file contains your complete Flowsta Vault export. ",
            "It includes your cryptographic keys and all app data — ",
            "everything you need to recreate your identity independently. ",
            "KEEP THIS FILE SAFE. Anyone with your device_seed can sign ",
            "as you on the Holochain network.",
        ),

        "format": {
            "version": "2.0",
            "exported_at": iso_now(),
            "license": "Cryptographic Autonomy License v1.0 (CAL-1.0)",
        },

        // ── Who you are ───────────────────────────────────────────
        "you": {
            "_readme": concat!(
                "Your Flowsta identity. The DID is your decentralised ",
                "identifier. The agent_pub_key is your Holochain network ",
                "address.",
            ),
            "display_name": config.display_name,
            "email": config.web_email,
            "did": config.did,
            "agent_pub_key": config.agent_pub_key,
            "vault_created_at": config.created_at,
        },

        // ── Your cryptographic keys ───────────────────────────────
        "keys": {
            "_readme": concat!(
                "These are the private cryptographic keys that prove you ",
                "are you on the Holochain network. Your device_seed is used ",
                "to derive your Ed25519 signing keypair. With this seed you ",
                "can recreate your identity on any Holochain conductor. ",
                "NEVER share these with anyone.",
            ),
            "device_seed_hex": device_seed_hex,
            "agent_pub_key_full_b64": config.agent_pub_key_raw_b64,
            "recovery_lookup_hash": config.recovery_lookup_hash,
        },

        // ── Web account link ──────────────────────────────────────
        "web_account": {
            "_readme": "Your linked Flowsta web account, if any.",
            "linked": config.web_agent_pub_key.is_some(),
            "web_agent_pub_key": config.web_agent_pub_key,
            "username": config.web_username,
        },

        // ── Holochain setup ──────────────────────────────────────
        "holochain": {
            "_readme": concat!(
                "The DNA versions and app IDs installed on your local ",
                "Holochain conductor. You need these to recreate your ",
                "conductor setup.",
            ),
            "conductor_version": config.conductor_version,
            "installed_app_ids": config.installed_app_ids,
            "private_dna_version": config.private_dna_version,
            "identity_dna_version": config.identity_dna_version,
        },

        // ── Connected third-party apps ────────────────────────────
        "connected_apps": {
            "_readme": concat!(
                "Apps that have linked their Holochain identity to your ",
                "vault. Each app has its own agent key on the network.",
            ),
            "count": linked_apps.len(),
            "apps": linked_apps.iter().map(|app| {
                serde_json::json!({
                    "app_name": app.app_name,
                    "client_id": app.client_id,
                    "app_agent_pub_key": app.app_agent_pub_key,
                    "linked_at": app.linked_at,
                })
            }).collect::<Vec<_>>(),
        },

        // ── App data backups ──────────────────────────────────────
        "app_data": {
            "_readme": concat!(
                "Decrypted data backups stored by connected Holochain apps. ",
                "Each app can store multiple snapshots. The data is yours — ",
                "you can import it into any compatible app.",
            ),
            "total_apps": stats.app_count,
            "total_snapshots": stats.total_backups,
            "total_size_bytes": stats.total_size,
            "apps": app_data,
        },
    });

    Ok(export)
}
