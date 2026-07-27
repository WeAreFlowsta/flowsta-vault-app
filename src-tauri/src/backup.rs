//! App data backup storage for third-party Holochain apps.
//!
//! Apps can store encrypted data blobs in the vault via the IPC `/backup` endpoint.
//! Each app's data is encrypted with a key derived from the vault's device seed,
//! stored in `data_dir/backups/<sanitized_client_id>/`. Apps can store multiple
//! versioned snapshots or overwrite a single latest backup.
//!
//! Users own their data - they can view, export, or delete any app's backup
//! from the Your Data page in the vault UI.

use crate::commands::AppState;
use crate::key_derivation::base64_standard_encode;
use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const BACKUP_STORAGE_CONSTANT: &str = "flowsta-backup-storage";

/// Maximum size of ONE backup object (transfer/memory guard, not a storage
/// ceiling - apps store as many named objects as they need and split
/// oversized payloads into parts). Advertised to apps via GET /backup/limits
/// so they never hardcode a twin of this number.
pub const MAX_BACKUP_SIZE: usize = 50 * 1024 * 1024;

/// Maximum number of AUTO-TIMESTAMPED snapshots per app ("backup-<ts>"
/// labels only). Named labels are app-managed state and are never rotated.
pub const MAX_BACKUPS_PER_APP: usize = 10;

/// Decompression guard for gzipped backups: readable-export/summary
/// decompression refuses to inflate past this (zip-bomb hygiene). The raw
/// bytes themselves always round-trip verbatim regardless.
const MAX_GUNZIP_BYTES: usize = 512 * 1024 * 1024;

/// Gunzip a gzipped backup payload (for the readable export view and the
/// Your Data summary). Fails soft - callers fall back to the raw bytes.
pub fn gunzip_backup(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| format!("gunzip failed: {}", e))?;
        if n == 0 {
            break;
        }
        if out.len() + n > MAX_GUNZIP_BYTES {
            return Err("gunzip refused: decompressed size over guard".into());
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// The decompressed-if-gzipped view of a payload, by content type.
pub(crate) fn plain_view<'a>(data: &'a [u8], content_type: &str) -> std::borrow::Cow<'a, [u8]> {
    if content_type.contains("gzip") {
        match gunzip_backup(data) {
            Ok(v) => std::borrow::Cow::Owned(v),
            Err(e) => {
                log::warn!("Backup marked gzip but did not decompress: {}", e);
                std::borrow::Cow::Borrowed(data)
            }
        }
    } else {
        std::borrow::Cow::Borrowed(data)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn iso_now() -> String {
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
    /// Per-entry-type counts extracted from canonical-shape payloads at save
    /// time. None for legacy / non-canonical backups. Lets the Your Data UI
    /// show "12 polls, 38 votes" without decrypting the payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<BackupRecordSummary>,
}

/// Per-entry-type record counts. Pulled from a canonical-shape payload's
/// top-level `_summary` field at save time and persisted with the backup
/// metadata so the Your Data UI can render counts without decryption.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BackupRecordSummary {
    /// Counts keyed by entry type name (e.g. "Poll": 12, "Vote": 38).
    pub counts_by_entry_type: std::collections::BTreeMap<String, usize>,
    /// Total record count across all entry types.
    pub total_records: usize,
}

/// Summary of all backups for one app.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AppBackupSummary {
    pub client_id: String,
    pub app_name: String,
    pub backup_count: usize,
    pub total_size: usize,
    pub last_backup_at: i64,
    /// Per-entry-type counts from the most recent canonical-shape backup,
    /// or None for legacy backups / when no backup metadata has a summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_summary: Option<BackupRecordSummary>,
    /// True when the app stores per-object backups indexed by a "manifest"
    /// label - the UI presents these as one summarized backup, not a pile
    /// of snapshots.
    #[serde(default)]
    pub has_manifest: bool,
    /// Distinct conversations among per-object backups ("conv-*" labels,
    /// multi-part ".pN" objects counted once).
    #[serde(default)]
    pub conversation_count: usize,
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

/// Derive the backup encryption key from a device seed.
/// Exposed so AppState can cache it across lock/unlock.
pub fn derive_backup_key_from_seed(device_seed: &[u8; 32]) -> [u8; 32] {
    derive_backup_key(device_seed)
}

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

fn encrypt_with_key(data: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12]), String> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(key)
        .map_err(|e| format!("Backup cipher init failed: {}", e))?;
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|_| "Backup encryption failed".to_string())?;

    Ok((ciphertext, nonce_bytes))
}

fn decrypt_with_key(ciphertext: &[u8], nonce_bytes: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(key)
        .map_err(|e| format!("Backup cipher init failed: {}", e))?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Backup decryption failed (corrupted or tampered)".to_string())
}

// ── Public API ─────────────────────────────────────────────────────

/// Save a backup for an app. Encrypts the data and writes to disk.
/// When no label is provided, auto-generates a timestamped label so each
/// backup is a separate snapshot. Apps can pass an explicit label to
/// overwrite a specific named backup (e.g. "latest" or "pre-migration").
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

    // Use device seed if unlocked, otherwise fall back to cached backup key
    let backup_key = {
        let config = app_state.vault_config.lock().unwrap();
        if let Some(ref cfg) = *config {
            if let Some(ref seed) = cfg.device_seed {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(seed);
                derive_backup_key(&arr)
            } else {
                *app_state.backup_key.lock().unwrap()
                    .as_ref()
                    .ok_or("Vault has never been unlocked")?
            }
        } else {
            *app_state.backup_key.lock().unwrap()
                .as_ref()
                .ok_or("Vault has never been unlocked")?
        }
    };

    // Auto-generate a timestamped label when none is provided, so each
    // backup is a separate snapshot rather than overwriting "latest".
    let auto_label = format!("backup-{}", unix_now());
    let label_str = label.unwrap_or(&auto_label);
    let app_dir = app_backup_dir(&app_state.data_dir, client_id);
    if app_dir.exists() {
        let target_path = backup_file_path(&app_state.data_dir, client_id, label_str);
        let is_overwrite = target_path.exists();

        if !is_overwrite {
            // Rotation applies ONLY to auto-timestamped snapshots
            // ("backup-<ts>") - versioned copies of the same thing, where
            // keeping the newest N is the point. Named labels are
            // app-managed STATE, not snapshots: "recovery" holds an escrowed
            // key, and apps store per-object data (e.g. one backup per
            // conversation) under stable labels. Counting them toward a cap
            // would make saving one object silently delete another - so
            // named labels are never rotated, only overwritten or deleted
            // by their app (or the user, from Your Data).
            let mut auto_snapshots: Vec<(std::path::PathBuf, i64)> =
                std::fs::read_dir(&app_dir)
                    .map_err(|e| format!("Failed to read backup dir: {}", e))?
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("enc"))
                    .filter_map(|entry| {
                        let json = std::fs::read_to_string(entry.path()).ok()?;
                        let enc: EncryptedBackup = serde_json::from_str(&json).ok()?;
                        let auto = enc
                            .meta
                            .label
                            .as_deref()
                            .map(|l| l.starts_with("backup-"))
                            .unwrap_or(true);
                        auto.then(|| (entry.path(), enc.meta.created_at))
                    })
                    .collect();

            let saving_auto = label_str.starts_with("backup-");
            while saving_auto && auto_snapshots.len() >= MAX_BACKUPS_PER_APP {
                if let Some(idx) = auto_snapshots
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, (_, ts))| *ts)
                    .map(|(i, _)| i)
                {
                    let (oldest_path, _) = auto_snapshots.remove(idx);
                    log::info!("Auto-rotating: deleting oldest snapshot {:?}", oldest_path);
                    let _ = std::fs::remove_file(oldest_path);
                } else {
                    break;
                }
            }
        }
    }

    // Encrypt
    let (ciphertext, nonce_bytes) = encrypt_with_key(data, &backup_key)?;

    // Extract the canonical-shape summary if present, so the Your Data UI can
    // render per-entry-type counts without decrypting the backup. Gzipped
    // payloads are inflated just for this read.
    let summary = extract_summary_if_canonical(&plain_view(
        data,
        content_type.unwrap_or("application/json"),
    ));

    let meta = BackupMeta {
        client_id: client_id.to_string(),
        app_name: app_name.to_string(),
        label: Some(label_str.to_string()),
        created_at: unix_now(),
        data_size: data.len(),
        content_type: content_type.unwrap_or("application/json").to_string(),
        summary,
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
        "Saved backup for {} ({}) - {} bytes, label: {}",
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
    // Use device seed if unlocked, otherwise fall back to cached backup key
    let backup_key = {
        let config = app_state.vault_config.lock().unwrap();
        if let Some(ref cfg) = *config {
            if let Some(ref seed) = cfg.device_seed {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(seed);
                derive_backup_key(&arr)
            } else {
                *app_state.backup_key.lock().unwrap()
                    .as_ref()
                    .ok_or("Vault has never been unlocked")?
            }
        } else {
            *app_state.backup_key.lock().unwrap()
                .as_ref()
                .ok_or("Vault has never been unlocked")?
        }
    };

    // If no label given, find the most recent backup for this app
    let path = if let Some(l) = label {
        let p = backup_file_path(&app_state.data_dir, client_id, l);
        if !p.exists() {
            return Err(format!("No backup found for label '{}'", l));
        }
        p
    } else {
        // Try "latest" first for backwards compat, then fall back to newest
        let latest_path = backup_file_path(&app_state.data_dir, client_id, "latest");
        if latest_path.exists() {
            latest_path
        } else {
            let metas = list_app_backups(&app_state.data_dir, client_id)?;
            let newest = metas.first().ok_or("No backups found for this app")?;
            backup_file_path(&app_state.data_dir, client_id, newest.label.as_deref().unwrap_or("latest"))
        }
    };

    let json = std::fs::read_to_string(&path)
        .map_err(|e| format!("Backup read failed: {}", e))?;
    let encrypted: EncryptedBackup = serde_json::from_str(&json)
        .map_err(|e| format!("Backup parse failed: {}", e))?;

    let nonce_bytes = hex::decode(&encrypted.nonce)
        .map_err(|_| "Backup bad nonce hex".to_string())?;
    let ciphertext = hex::decode(&encrypted.ciphertext)
        .map_err(|_| "Backup bad ciphertext hex".to_string())?;

    let plaintext = decrypt_with_key(&ciphertext, &nonce_bytes, &backup_key)?;

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
            let mut latest_summary: Option<BackupRecordSummary> = None;
            let mut has_manifest = false;
            let mut manifest_summary: Option<BackupRecordSummary> = None;
            let mut conv_bases: std::collections::HashSet<String> =
                std::collections::HashSet::new();

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
                            if let Some(label) = enc.meta.label.as_deref() {
                                if label == "manifest" {
                                    has_manifest = true;
                                } else if let Some(rest) = label.strip_prefix("conv-") {
                                    // Multi-part objects ("....pN") are one
                                    // conversation.
                                    let base = rest
                                        .rsplit_once(".p")
                                        .filter(|(_, n)| n.chars().all(|c| c.is_ascii_digit()))
                                        .map(|(b, _)| b)
                                        .unwrap_or(rest);
                                    conv_bases.insert(base.to_string());
                                }
                            }
                            if enc.meta.created_at > last_at {
                                last_at = enc.meta.created_at;
                                app_name = enc.meta.app_name.clone();
                                client_id = enc.meta.client_id.clone();
                                latest_summary = enc.meta.summary.clone();
                            }
                            // The manifest's summary describes the WHOLE
                            // per-object backup - it wins over whichever
                            // object happens to be newest.
                            if enc.meta.label.as_deref() == Some("manifest") {
                                if enc.meta.summary.is_some() {
                                    manifest_summary = enc.meta.summary.clone();
                                }
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
                    latest_summary: manifest_summary.or(latest_summary),
                    has_manifest,
                    conversation_count: conv_bases.len(),
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

/// Extract `_summary.counts_by_entry_type` from a canonical-shape JSON payload.
/// Returns None for non-JSON, non-canonical, or missing-summary cases.
fn extract_summary_if_canonical(data: &[u8]) -> Option<BackupRecordSummary> {
    let payload: serde_json::Value = serde_json::from_slice(data).ok()?;
    // Canonical monoliths (v1 + cells) and per-object manifests (v2 +
    // conversations index) both carry a top-level _summary.
    let is_manifest = payload.get("version").and_then(|v| v.as_u64()) == Some(2)
        && payload.get("conversations").and_then(|c| c.as_array()).is_some();
    if !is_canonical_backup(&payload) && !is_manifest {
        return None;
    }
    let summary_obj = payload.get("_summary")?.as_object()?;
    let total_records = summary_obj.get("totalRecords")?.as_u64()? as usize;
    let counts_obj = summary_obj.get("countsByEntryType")?.as_object()?;
    let mut counts = std::collections::BTreeMap::new();
    for (k, v) in counts_obj {
        if let Some(n) = v.as_u64() {
            counts.insert(k.clone(), n as usize);
        }
    }
    Some(BackupRecordSummary {
        counts_by_entry_type: counts,
        total_records,
    })
}

/// Detect a canonical-shape backup (v1 + `cells[].records[]` per GENERIC_BACKUP_PLAN.md).
pub fn is_canonical_backup(payload: &serde_json::Value) -> bool {
    payload
        .get("version")
        .and_then(|v| v.as_u64())
        == Some(1)
        && payload.get("cells").and_then(|c| c.as_array()).is_some()
}

/// Reshape a canonical-shape backup so the user's CAL §4.2.1 export contains
/// the human_readable view of each record (plain English) rather than the
/// signed raw_record bytes.
///
/// Preserves every top-level field present in the input payload so apps can
/// include extension blocks (e.g. an `app_keys` slot for app-specific seeds
/// the CAL obliges them to expose) and have those blocks survive the export.
pub fn canonicalize_for_export(payload: &serde_json::Value) -> serde_json::Value {
    let mut result = payload.clone();

    // Only rewrite `cells[].records[]` - every other top-level key passes
    // through untouched.
    if let Some(cells) = result.get_mut("cells").and_then(|v| v.as_array_mut()) {
        for cell in cells.iter_mut() {
            if let Some(records) = cell.get_mut("records").and_then(|v| v.as_array_mut()) {
                for record in records.iter_mut() {
                    let entry_type = record.get("entryType").cloned().unwrap_or(serde_json::Value::Null);
                    let action_hash = record.get("actionHash").cloned().unwrap_or(serde_json::Value::Null);
                    let created_at_ms = record.get("createdAtMs").cloned().unwrap_or(serde_json::Value::Null);
                    let human = record.get("human_readable").cloned().unwrap_or(serde_json::Value::Null);
                    *record = serde_json::json!({
                        "entry_type": entry_type,
                        "action_hash": action_hash,
                        "created_at_ms": created_at_ms,
                        "human_readable": human,
                    });
                }
            }
        }
    }

    result
}

/// Export all vault data (identity + keys + backups) as a single JSON blob.
/// Includes cryptographic key material for CAL (Cryptographic Autonomy License)
/// compliance - users must be able to independently recreate their identity
/// and use their data without depending on Flowsta.
pub fn export_all_data(
    app_state: &AppState,
    signatures: Option<Vec<serde_json::Value>>,
    sealed_records: Option<Vec<serde_json::Value>>,
) -> Result<serde_json::Value, String> {
    export_all_data_with_progress(app_state, signatures, sealed_records, |_, _, _| {})
}

/// `export_all_data` with a per-app progress callback `(current, total,
/// app_name)` - decrypting every app's snapshots is the slow part of a
/// large export, and the Your Data page narrates it to the user.
pub fn export_all_data_with_progress(
    app_state: &AppState,
    signatures: Option<Vec<serde_json::Value>>,
    sealed_records: Option<Vec<serde_json::Value>>,
    mut progress: impl FnMut(usize, usize, &str),
) -> Result<serde_json::Value, String> {
    let config = {
        let config = app_state.vault_config.lock().unwrap();
        config.as_ref().ok_or("Vault is locked")?.clone()
    };

    let stats = get_backup_stats(&app_state.data_dir);

    // Collect decrypted backup data for each app
    let total_apps = stats.apps.len();
    let mut app_data = Vec::new();
    for (app_index, app_summary) in stats.apps.iter().enumerate() {
        progress(app_index + 1, total_apps, &app_summary.app_name);
        let metas = list_app_backups(&app_state.data_dir, &app_summary.client_id)?;
        let mut snapshots = Vec::new();

        for meta in &metas {
            let label = meta.label.as_deref().unwrap_or("latest");
            match retrieve_backup(app_state, &app_summary.client_id, Some(label)) {
                Ok((data, backup_meta)) => {
                    // Parse the payload to JSON for the readable view -
                    // gunzipping first when the app stored it compressed.
                    // Hex-fallback for non-JSON content. The verbatim bytes
                    // ride in restore_base64 below either way.
                    let parsed_data = if backup_meta.content_type.contains("json") {
                        serde_json::from_slice::<serde_json::Value>(&plain_view(
                            &data,
                            &backup_meta.content_type,
                        ))
                        .ok()
                    } else {
                        None
                    };

                    // For canonical-shape backups (version: 1 + cells[].records[]),
                    // pull each record's human_readable view into the export. This
                    // is what the CAL §4.2.1 user-data-export users actually read.
                    // For legacy/non-canonical payloads, inline as-is (existing
                    // behaviour) so backwards compat is preserved.
                    let data_value = match parsed_data {
                        Some(json) if is_canonical_backup(&json) => {
                            canonicalize_for_export(&json)
                        }
                        Some(json) => json,
                        None => serde_json::Value::String(hex::encode(&data)),
                    };

                    snapshots.push(serde_json::json!({
                        "label": meta.label,
                        "saved_at": meta.created_at,
                        "size_bytes": meta.data_size,
                        "content_type": meta.content_type,
                        "data": data_value,
                        // Raw bytes (base64) for lossless re-import - the
                        // human-readable `data` above is for the user; this
                        // is what import_vault_export re-stores verbatim.
                        "restore_base64": base64_standard_encode(&data),
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
            "It includes your cryptographic keys and all app data - ",
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
                "Your Flowsta identity. The DID is your decentralized ",
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
                "Each app can store multiple snapshots. The Cryptographic ",
                "Autonomy License (§4.2.1 - \"No Withholding User Data\") ",
                "guarantees you full ownership of this data: you can take ",
                "this export to any compatible Holochain app and use it ",
                "independently of Flowsta or the app's original developer.",
            ),
            "total_apps": stats.app_count,
            "total_snapshots": stats.total_backups,
            "total_size_bytes": stats.total_size,
            "apps": app_data,
        },

        // ── Sign It signatures ──────────────────────────────────────
        "sign_it": {
            "_readme": concat!(
                "Every cryptographic signature you've created with Sign It, ",
                "across every installed signing DNA version. Each signature ",
                "includes the file hash, your Ed25519 signature (base64), the ",
                "signing intent, content rights, AI disclosure, perceptual ",
                "hash bands (for fuzzy matching), any thumbnail, and ",
                "revocation status. Anyone with the file and your agent ",
                "public key can verify these signatures independently.",
            ),
            "count": signatures.as_ref().map(|s| s.len()).unwrap_or(0),
            "signatures": signatures.unwrap_or_default(),
        },

        // ── Sealed private records ──────────────────────────────────
        // The canonical private data post-R2 (profile, activity, app
        // records in the encrypted v2 cell). Body is the DECRYPTED JSON
        // - CAL-readable AND what import_vault_export re-stores.
        "sealed_records": {
            "_readme": concat!(
                "Your private records, decrypted. These live only on your ",
                "device (they do not gossip to Flowsta or anyone else), so ",
                "this export - or a premium encrypted backup - is how they ",
                "survive losing this machine. Import restores them after a ",
                "recovery-phrase reinstall.",
            ),
            "count": sealed_records.as_ref().map(|r| r.len()).unwrap_or(0),
            "records": sealed_records.unwrap_or_default(),
        },
    });

    Ok(export)
}

#[cfg(test)]
mod rotation_tests {
    use super::*;
    use crate::commands::AppState;

    fn state_with_key(dir: &Path) -> AppState {
        let state = AppState::new(dir.to_path_buf());
        *state.backup_key.lock().unwrap() = Some([7u8; 32]);
        state
    }

    #[test]
    fn named_labels_never_rotate() {
        let tmp = tempfile::tempdir().unwrap();
        let state = state_with_key(tmp.path());
        for i in 0..(MAX_BACKUPS_PER_APP + 5) {
            save_backup(
                &state,
                "app.test",
                "Test App",
                Some(&format!("conv-{}", i)),
                b"{\"v\":1}",
                None,
            )
            .unwrap();
        }
        let metas = list_app_backups(tmp.path(), "app.test").unwrap();
        assert_eq!(metas.len(), MAX_BACKUPS_PER_APP + 5);
    }

    #[test]
    fn auto_snapshots_rotate_and_spare_named() {
        let tmp = tempfile::tempdir().unwrap();
        let state = state_with_key(tmp.path());
        for i in 0..3 {
            save_backup(
                &state,
                "app.test",
                "Test App",
                Some(&format!("conv-{}", i)),
                b"{}",
                None,
            )
            .unwrap();
        }
        // Auto labels carry a unix-second timestamp; make them distinct.
        for i in 0..(MAX_BACKUPS_PER_APP + 4) {
            save_backup(
                &state,
                "app.test",
                "Test App",
                Some(&format!("backup-{}", 1000 + i)),
                b"{}",
                None,
            )
            .unwrap();
        }
        let metas = list_app_backups(tmp.path(), "app.test").unwrap();
        let named = metas
            .iter()
            .filter(|m| m.label.as_deref().map(|l| l.starts_with("conv-")).unwrap_or(false))
            .count();
        let autos = metas
            .iter()
            .filter(|m| m.label.as_deref().map(|l| l.starts_with("backup-")).unwrap_or(false))
            .count();
        assert_eq!(named, 3);
        assert_eq!(autos, MAX_BACKUPS_PER_APP);
    }

    #[test]
    fn gzip_summary_and_roundtrip() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let state = state_with_key(tmp.path());
        let canonical = br#"{"version":1,"cells":[{"records":[]}],"_summary":{"countsByEntryType":{"Message":2},"totalRecords":2}}"#;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(canonical).unwrap();
        let gz = enc.finish().unwrap();
        let meta = save_backup(
            &state,
            "app.test",
            "Test App",
            Some("conv-a"),
            &gz,
            Some("application/json+gzip"),
        )
        .unwrap();
        // Summary extracted through the gunzip path.
        assert_eq!(meta.summary.as_ref().unwrap().total_records, 2);
        // Raw bytes round-trip verbatim.
        let (data, _) = retrieve_backup(&state, "app.test", Some("conv-a")).unwrap();
        assert_eq!(data, gz);
        assert_eq!(gunzip_backup(&data).unwrap(), canonical.to_vec());
    }
}
