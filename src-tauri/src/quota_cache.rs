//! Sign quota cache with HMAC-signed local persistence.
//!
//! Vault must enforce sign quotas locally for offline use. We can't
//! trust localStorage (trivially editable), so we persist quota state in
//! `data_dir/quota_cache.json` HMAC-signed with a device-local key.
//!
//! Threat model:
//!   - Defeats casual tampering (clearing localStorage, hand-editing the JSON)
//!   - A determined user with file system access + understanding of the format
//!     can still tamper. That's accepted — they own the device.
//!   - Future hardening: source chain query (signing DNA v1.5+) which is
//!     append-only and cryptographically signed by the agent.
//!
//! HMAC key is generated once on first use and stored in `data_dir/.quota.key`.
//! If the key file is missing, a new one is generated (any old cache becomes
//! invalid, treated as exhausted = safest).

use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

/// Persisted quota cache shape. Mirrors the JSON returned by the API's
/// `/api/v1/sign-it/quota/by-agent` endpoint, plus a write counter for replay
/// resistance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaCache {
    pub tier: String,
    pub used: u32,
    pub limit: u32,
    pub period_end: Option<String>,   // ISO timestamp
    pub last_synced_at: i64,           // ms epoch
    pub write_counter: u64,            // monotonic per-write
}

#[derive(Serialize, Deserialize)]
struct SignedCache {
    payload: QuotaCache,
    hmac_hex: String,
}

fn key_path(data_dir: &PathBuf) -> PathBuf {
    data_dir.join(".quota.key")
}

fn cache_path(data_dir: &PathBuf) -> PathBuf {
    data_dir.join("quota_cache.json")
}

/// Get or create the HMAC key. Stored as 32 random bytes hex-encoded.
fn load_or_create_key(data_dir: &PathBuf) -> Result<[u8; 32], String> {
    let path = key_path(data_dir);

    if path.exists() {
        let hex_str = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read quota key: {}", e))?;
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| format!("Invalid quota key encoding: {}", e))?;
        if bytes.len() != 32 {
            return Err("Quota key has wrong length".into());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    fs::create_dir_all(data_dir).map_err(|e| format!("Failed to create data dir: {}", e))?;
    fs::write(&path, hex::encode(&key))
        .map_err(|e| format!("Failed to write quota key: {}", e))?;
    Ok(key)
}

fn compute_hmac(key: &[u8; 32], payload: &QuotaCache) -> Result<String, String> {
    let json = serde_json::to_string(payload)
        .map_err(|e| format!("Failed to serialize quota payload: {}", e))?;
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| format!("HMAC init failed: {}", e))?;
    mac.update(json.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Read and verify the cached quota state.
/// Returns Ok(None) if no cache exists or the HMAC is invalid (treat as no cache).
pub fn read(data_dir: &PathBuf) -> Result<Option<QuotaCache>, String> {
    let path = cache_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read quota cache: {}", e))?;
    let signed: SignedCache = match serde_json::from_str(&raw) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };

    let key = load_or_create_key(data_dir)?;
    let expected = compute_hmac(&key, &signed.payload)?;
    if expected != signed.hmac_hex {
        // Tampered — treat as no cache. Caller falls back to API or refuses to sign.
        log::warn!("⚠️ Quota cache HMAC mismatch — discarding (possible tampering)");
        return Ok(None);
    }

    Ok(Some(signed.payload))
}

/// Write a new quota cache state, HMAC-signed with the device key.
/// Increments write_counter for replay-detection.
pub fn write(data_dir: &PathBuf, mut payload: QuotaCache) -> Result<QuotaCache, String> {
    // Bump write counter past whatever was last persisted, to thwart simple replay.
    if let Ok(Some(existing)) = read(data_dir) {
        payload.write_counter = existing.write_counter.saturating_add(1);
    } else {
        payload.write_counter = payload.write_counter.max(1);
    }

    let key = load_or_create_key(data_dir)?;
    let hmac_hex = compute_hmac(&key, &payload)?;
    let signed = SignedCache { payload: payload.clone(), hmac_hex };
    let json = serde_json::to_string(&signed)
        .map_err(|e| format!("Failed to serialize signed cache: {}", e))?;

    fs::create_dir_all(data_dir).map_err(|e| format!("Failed to create data dir: {}", e))?;
    fs::write(cache_path(data_dir), json)
        .map_err(|e| format!("Failed to write quota cache: {}", e))?;
    Ok(payload)
}

/// Increment the cached `used` count by 1. Returns the new state.
/// Used after a successful local sign so the cache stays accurate offline.
pub fn increment_used(data_dir: &PathBuf) -> Result<Option<QuotaCache>, String> {
    let Some(mut cache) = read(data_dir)? else { return Ok(None); };
    cache.used = cache.used.saturating_add(1);
    Ok(Some(write(data_dir, cache)?))
}
