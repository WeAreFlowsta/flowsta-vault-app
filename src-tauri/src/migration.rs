//! Custodial-account migration ("Upgrade your account").
//!
//! Moves a flowsta.com web account into this device's Vault:
//! the account's private-cell data is exported losslessly by the API
//! (encrypted fields returned AS STORED), decrypted locally with the web
//! password the user just signed in with, re-encrypted under the
//! phrase-derived data key, and written into the encrypted private cell on
//! this device. After a local encrypted backup exists, the device key
//! signs the flip and the API makes it the account's auth authority
//! (password login dies, Vault-grant lives, the original DID is preserved
//! via the agent link graph).
//!
//! Order is load-bearing:
//!   sign-in → phrase → export → verify → link device → create vault →
//!   import → TOTP vault-local → backup → signed flip
//! The device link MUST be committed while the custodial cell is alive
//! (the identity zome verifies the pair signature through it), and the
//! flip comes last so any earlier failure leaves the account fully
//! custodial and the flow safely retryable.
//!
//! Record mapping into the encrypted private cell (v2 Sealed records):
//! - UserProfile        → "user_profile" with the email DECRYPTED into the
//!                        body (the sealed cipher is the encryption now -
//!                        keeping the password-locked blob would break
//!                        phrase-only recovery once the web password dies)
//! - EmailPermission    → "email_permission" (as stored, plaintext fields)
//! - LoginActivity      → "login_activity"
//! - DashboardActivity  → "dashboard_activity"
//! - OAuthActivity      → "oauth_activity"
//! - PrivacySettings    → "privacy_settings"
//! - AppAnalyticsId     → "app_analytics_id" (app_id now lives inside the
//!                        cipher - the v1.11 link-tag leak is gone by
//!                        construction)
//! - ProfilePicture     → "profile_picture"
//! - TotpConfig         → NOT sealed: decrypted and kept vault-local
//!                        (root secrets are never gossiped)
//! - RecoveryPhrase     → NOT imported (the phrase IS the seed now; used
//!                        only to verify the entered phrase matches)
//! - Session            → dropped by design

use crate::backup;
use crate::commands::{base64_standard_decode, AppState};
use crate::key_derivation::{
    base64_standard_encode, build_sorted_agent_pair_payload, construct_agent_pub_key_bytes,
    construct_agent_pub_key_string, derive_device_keypair, derive_recovery_lookup_hash,
    derive_seed, msgpack_encode_bytes, sign_with_device_seed, validate_mnemonic,
    DEVICE_1_CONSTANT,
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{Emitter, State};

// ── Decryption of API-exported fields ───────────────────────────────────────
//
// Must byte-match api/src/services/encryption.js encryptWithPassword:
// key = scrypt(password, salt, N=16384, r=8, p=1, len=32)
// AES-256-GCM, 12-byte nonce; entry fields carry ciphertext (tag split
// off), nonce, salt, tag - each standard base64.

fn b64(field: &str, value: &str) -> Result<Vec<u8>, String> {
    base64_standard_decode(value).map_err(|_| format!("Invalid base64 in exported {}", field))
}

/// Decrypt one exported AES-GCM field group with the web password.
pub fn decrypt_api_field(
    cipher_b64: &str,
    nonce_b64: &str,
    salt_b64: &str,
    tag_b64: &str,
    password: &str,
) -> Result<String, String> {
    let salt = b64("salt", salt_b64)?;
    let nonce = b64("nonce", nonce_b64)?;
    let mut cipher = b64("ciphertext", cipher_b64)?;
    let tag = b64("tag", tag_b64)?;
    if nonce.len() != 12 {
        return Err(format!("Exported nonce is {} bytes, expected 12", nonce.len()));
    }

    let params = scrypt::Params::new(14, 8, 1, 32)
        .map_err(|e| format!("scrypt params: {}", e))?;
    let mut key = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut key)
        .map_err(|e| format!("scrypt derivation failed: {}", e))?;

    // The aes-gcm crate expects ciphertext||tag.
    cipher.extend_from_slice(&tag);
    let aead = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let plain = aead
        .decrypt(Nonce::from_slice(&nonce), cipher.as_ref())
        .map_err(|_| "decrypt_failed: wrong password or corrupted field".to_string())?;
    String::from_utf8(plain).map_err(|_| "Decrypted field is not valid UTF-8".to_string())
}

// ── Export bundle (mirrors the private zome's ExportedData) ─────────────────

#[derive(Deserialize)]
struct WireEncrypted4 {
    nonce: String,
    salt: String,
    tag: String,
}

#[derive(Deserialize)]
struct WireProfile {
    encrypted_email: String,
    #[serde(flatten)]
    enc: WireEncrypted4,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    created_at: i64,
    #[serde(default)]
    updated_at: i64,
}

#[derive(Deserialize)]
struct WireRecovery {
    encrypted_mnemonic: String,
    #[serde(flatten)]
    enc: WireEncrypted4,
}

#[derive(Deserialize)]
struct WireTotp {
    encrypted_secret: String,
    nonce: String,
    salt: String,
    tag: String,
    encrypted_backup_codes: String,
    backup_nonce: String,
    backup_salt: String,
    backup_tag: String,
    #[serde(default)]
    enabled: bool,
}

#[derive(Deserialize)]
struct WireBundle {
    user_profile: Option<WireProfile>,
    recovery_phrase: Option<WireRecovery>,
    #[serde(default)]
    sessions: Vec<serde_json::Value>,
    #[serde(default)]
    email_permissions: Vec<serde_json::Value>,
    #[serde(default)]
    login_activities: Vec<serde_json::Value>,
    #[serde(default)]
    dashboard_activities: Vec<serde_json::Value>,
    #[serde(default)]
    oauth_activities: Vec<serde_json::Value>,
    privacy_settings: Option<serde_json::Value>,
    #[serde(default)]
    analytics_ids: Vec<serde_json::Value>,
    totp_config: Option<WireTotp>,
    profile_picture: Option<serde_json::Value>,
}

// ── Mapping output ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct MappedRecord {
    pub entry_type: String,
    /// Original creation time normalized to milliseconds (goes inside the
    /// sealed cipher; the DHT action timestamp will be "now" - that's the
    /// only timing a peer can see).
    pub created_at_ms: u64,
    pub body: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct MigratedTotp {
    pub secret: String,
    pub backup_codes: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug)]
pub struct MappedBundle {
    pub records: Vec<MappedRecord>,
    pub email: String,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub totp: Option<MigratedTotp>,
    /// The account had 2FA configured but its secret would not decrypt
    /// with the password in hand - the server's password-change/reset
    /// sweeps never re-encrypted the 2FA record, so long-lived accounts
    /// carry it under an older password. Best-effort by design: Vault
    /// approval replaces 2FA after the upgrade, so this never blocks.
    pub totp_skipped: bool,
    pub sessions_skipped: usize,
}

/// Normalize a v1.11 timestamp to milliseconds. The API writes cell
/// timestamps in microseconds (`Date.now() * 1000`), but a few older
/// records carry plain milliseconds - disambiguate by magnitude.
fn to_millis(ts: i64) -> u64 {
    if ts <= 0 {
        return 0;
    }
    if ts >= 100_000_000_000_000 {
        (ts / 1000) as u64 // microseconds
    } else {
        ts as u64
    }
}

fn record_created_ms(v: &serde_json::Value, fallback_ms: u64) -> u64 {
    v.get("created_at")
        .and_then(|x| x.as_i64())
        .map(to_millis)
        .filter(|&ms| ms > 0)
        .unwrap_or(fallback_ms)
}

pub fn normalize_mnemonic(phrase: &str) -> String {
    phrase
        .trim()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Decrypt and map an exported bundle into sealed-record inputs.
///
/// Verifies the entered phrase against the account's stored (encrypted)
/// recovery phrase - the strong ownership check: by export time every
/// migrating account has a phrase blob, and it must decrypt to exactly the
/// phrase in hand, whether it was the user's existing phrase or one the
/// server just minted for the ceremony.
pub fn map_bundle(
    bundle: &serde_json::Value,
    password: &str,
    expected_mnemonic: &str,
) -> Result<MappedBundle, String> {
    let wire: WireBundle = serde_json::from_value(bundle.clone())
        .map_err(|e| format!("Unexpected export bundle shape: {}", e))?;

    let recovery = wire
        .recovery_phrase
        .as_ref()
        .ok_or("export_missing_phrase: the account has no stored recovery phrase record")?;
    let stored_phrase = decrypt_api_field(
        &recovery.encrypted_mnemonic,
        &recovery.enc.nonce,
        &recovery.enc.salt,
        &recovery.enc.tag,
        password,
    )
    .map_err(|e| format!("Could not decrypt the account's recovery phrase record ({})", e))?;
    if normalize_mnemonic(&stored_phrase) != normalize_mnemonic(expected_mnemonic) {
        return Err(
            "phrase_mismatch: this phrase is not the one on file for this account".to_string(),
        );
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let mut records = Vec::new();
    let mut email = String::new();
    let mut username = None;
    let mut display_name = None;

    if let Some(profile) = &wire.user_profile {
        email = decrypt_api_field(
            &profile.encrypted_email,
            &profile.enc.nonce,
            &profile.enc.salt,
            &profile.enc.tag,
            password,
        )
        .map_err(|e| format!("Could not decrypt the account email ({})", e))?;
        username = profile.username.clone();
        display_name = if profile.display_name.is_empty() {
            None
        } else {
            Some(profile.display_name.clone())
        };
        records.push(MappedRecord {
            entry_type: "user_profile".into(),
            created_at_ms: if profile.created_at > 0 {
                to_millis(profile.created_at)
            } else {
                now_ms
            },
            body: serde_json::json!({
                "email": email,
                "username": profile.username,
                "display_name": profile.display_name,
                "created_at": profile.created_at,
                "updated_at": profile.updated_at,
            }),
        });
    }

    let passthrough: [(&str, &Vec<serde_json::Value>); 5] = [
        ("email_permission", &wire.email_permissions),
        ("login_activity", &wire.login_activities),
        ("dashboard_activity", &wire.dashboard_activities),
        ("oauth_activity", &wire.oauth_activities),
        ("app_analytics_id", &wire.analytics_ids),
    ];
    for (entry_type, items) in passthrough {
        for item in items {
            records.push(MappedRecord {
                entry_type: entry_type.into(),
                created_at_ms: record_created_ms(item, now_ms),
                body: item.clone(),
            });
        }
    }

    if let Some(settings) = &wire.privacy_settings {
        records.push(MappedRecord {
            entry_type: "privacy_settings".into(),
            created_at_ms: record_created_ms(settings, now_ms),
            body: settings.clone(),
        });
    }
    if let Some(picture) = &wire.profile_picture {
        records.push(MappedRecord {
            entry_type: "profile_picture".into(),
            created_at_ms: picture
                .get("updated_at")
                .and_then(|x| x.as_i64())
                .map(to_millis)
                .filter(|&ms| ms > 0)
                .unwrap_or(now_ms),
            body: picture.clone(),
        });
    }

    // 2FA carry-over is BEST-EFFORT. The server's password-change/reset
    // sweeps never re-encrypted the TotpConfig record, so accounts that
    // changed (or phrase-reset) their password after enabling 2FA hold it
    // under an older password. Ownership is already proven by the profile
    // decrypt above + the phrase-blob check - and Vault approval replaces
    // 2FA after the upgrade - so an unreadable secret is skipped, never a
    // reason to abort the account move.
    let mut totp_skipped = false;
    let totp = match &wire.totp_config {
        Some(t) => {
            let decrypted = decrypt_api_field(
                &t.encrypted_secret,
                &t.nonce,
                &t.salt,
                &t.tag,
                password,
            )
            .and_then(|secret| {
                decrypt_api_field(
                    &t.encrypted_backup_codes,
                    &t.backup_nonce,
                    &t.backup_salt,
                    &t.backup_tag,
                    password,
                )
                .map(|codes| (secret, codes))
            });
            match decrypted {
                Ok((secret, codes)) => Some(MigratedTotp {
                    secret,
                    backup_codes: codes
                        .split(',')
                        .map(|c| c.trim().to_string())
                        .filter(|c| !c.is_empty())
                        .collect(),
                    enabled: t.enabled,
                }),
                Err(e) => {
                    log::warn!(
                        "[migration] 2FA settings not carried over (encrypted under an older password): {}",
                        e
                    );
                    totp_skipped = true;
                    None
                }
            }
        }
        None => None,
    };

    Ok(MappedBundle {
        records,
        email,
        username,
        display_name,
        totp,
        totp_skipped,
        sessions_skipped: wire.sessions.len(),
    })
}

// ── API calls ───────────────────────────────────────────────────────────────

fn api_base(api_url: &str) -> String {
    api_url.trim_end_matches('/').to_string()
}

async fn parse_json(resp: reqwest::Response) -> Result<(u16, serde_json::Value), String> {
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Invalid API response: {}", e))?;
    Ok((status, body))
}

fn api_err(context: &str, status: u16, body: &serde_json::Value) -> String {
    format!(
        "{}: {} ({}) [{}]",
        context,
        body.get("error").and_then(|v| v.as_str()).unwrap_or("unknown_error"),
        body.get("message").and_then(|v| v.as_str()).unwrap_or(""),
        status
    )
}

pub struct MeInfo {
    pub user_id: String,
    pub did: String,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub profile_picture: Option<String>,
}

pub(crate) async fn fetch_me(api_url: &str, jwt: &str) -> Result<MeInfo, String> {
    let resp = reqwest::Client::new()
        .get(format!("{}/auth/me", api_base(api_url)))
        .bearer_auth(jwt)
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;
    let (status, body) = parse_json(resp).await?;
    if status >= 300 {
        return Err(api_err("me_failed", status, &body));
    }
    let user = body.get("user").unwrap_or(&body);
    let get = |k: &str| user.get(k).and_then(|v| v.as_str()).map(String::from);
    Ok(MeInfo {
        user_id: get("id").ok_or("Account lookup response missing user id")?,
        did: get("did").unwrap_or_default(),
        username: get("username"),
        display_name: get("displayName").or_else(|| get("display_name")),
        profile_picture: get("profilePicture").or_else(|| get("profile_picture")),
    })
}

pub struct ExportResult {
    pub web_agent_b64: String,
    pub dna_version: String,
    pub data: serde_json::Value,
}

/// Wait until the account is export- and link-ready. Old accounts get a
/// one-time background DNA migration at sign-in (private and/or identity);
/// the wizard's next steps gate on the versions it produces, so poll the
/// cheap status probe instead of burning the rate-limited export as one.
/// Ready accounts pass through on the first call with no delay.
async fn wait_until_account_ready(
    api_url: &str,
    jwt: &str,
    app_handle: &tauri::AppHandle,
) -> Result<(), String> {
    #[derive(Deserialize)]
    struct DnaStatus {
        export_ready: bool,
        link_ready: bool,
        migration_status: Option<String>,
    }
    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8 * 60);
    let mut announced = false;
    loop {
        let resp = client
            .get(format!("{}/auth/migration/dna-status", api_url.trim_end_matches('/')))
            .bearer_auth(jwt)
            .send()
            .await
            .map_err(|e| format!("Account status check failed: {}", e))?;
        let status_code = resp.status();
        if status_code.is_success() {
            let st: DnaStatus = resp
                .json()
                .await
                .map_err(|e| format!("Bad status response: {}", e))?;
            if st.export_ready && st.link_ready {
                return Ok(());
            }
            if st.migration_status.as_deref() == Some("failed") {
                return Err(
                    "account_update_failed: the one-time account update did not complete - \
                     your account is unchanged. Run the upgrade again to retry."
                        .to_string(),
                );
            }
        }
        // Older API without the probe: fall through to the export attempt,
        // which enforces the same gate with a clear error.
        if status_code.as_u16() == 404 {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(
                "account_update_timeout: the one-time account update is taking longer than \
                 expected. Your account is unchanged - try the upgrade again shortly."
                    .to_string(),
            );
        }
        if !announced {
            emit_progress(
                app_handle,
                "updating",
                "Bringing your account up to date - a one-time update is running…",
            );
            announced = true;
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

pub(crate) async fn fetch_export(api_url: &str, jwt: &str) -> Result<ExportResult, String> {
    let resp = reqwest::Client::new()
        .post(format!("{}/auth/migration/export", api_base(api_url)))
        .bearer_auth(jwt)
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;
    let (status, body) = parse_json(resp).await?;
    if status >= 300 {
        return Err(api_err("export_failed", status, &body));
    }
    Ok(ExportResult {
        web_agent_b64: body
            .get("agent_pub_key")
            .and_then(|v| v.as_str())
            .ok_or("Export response missing agent_pub_key")?
            .to_string(),
        dna_version: body
            .get("dna_version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        data: body.get("data").cloned().ok_or("Export response missing data")?,
    })
}

/// Mint (or re-mint, for the lost-phrase escape hatch) the account's
/// recovery phrase server-side and bind its lookup hash. The migrating
/// user then completes the write-down ceremony with THIS phrase, and it
/// becomes the seed of their device identity.
#[tauri::command]
pub async fn migration_new_phrase(
    api_url: String,
    jwt: String,
    password: String,
) -> Result<String, String> {
    let resp = reqwest::Client::new()
        .post(format!("{}/auth/setup-recovery-phrase", api_base(&api_url)))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({ "password": password }))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;
    let (status, body) = parse_json(resp).await?;
    if status >= 300 {
        return Err(api_err("setup_phrase_failed", status, &body));
    }
    body.get("recoveryPhrase")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or("Phrase setup response missing recoveryPhrase".to_string())
}

/// Confirm the phrase's lookup hash resolves to THIS account's web agent
/// key before linking - refuses a phrase that belongs to a different
/// account (the link endpoint identifies the target account by the hash).
pub(crate) async fn verify_lookup_binding(
    api_url: &str,
    lookup_hash: &str,
    web_39: &[u8; 39],
) -> Result<(), String> {
    let resp = reqwest::Client::new()
        .get(format!(
            "{}/auth/agent-key-by-lookup-hash?hash={}",
            api_base(api_url),
            lookup_hash
        ))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;
    let (status, body) = parse_json(resp).await?;
    if status >= 300 {
        return Err(api_err("lookup_hash_not_found", status, &body));
    }
    let key_b64 = body
        .get("agent_pub_key")
        .and_then(|v| v.as_str())
        .ok_or("Lookup response missing agent_pub_key")?;
    // The API returns either the raw 32-byte key or the full 39-byte key.
    let bytes = base64_standard_decode(key_b64).map_err(|_| "Bad key encoding in lookup")?;
    let resolved_39 = match bytes.len() {
        32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            construct_agent_pub_key_bytes(&k)
        }
        39 => {
            let mut k = [0u8; 39];
            k.copy_from_slice(&bytes);
            k
        }
        n => return Err(format!("Lookup key is {} bytes, expected 32 or 39", n)),
    };
    if &resolved_39 != web_39 {
        return Err(
            "phrase_mismatch: this phrase resolves to a different account".to_string(),
        );
    }
    Ok(())
}

/// Commit the device↔web agent link through the identity zome (pair
/// signature over MessagePack of the sorted 78-byte key pair). Must run
/// while the custodial cell is still enabled.
pub(crate) async fn link_device_key(
    api_url: &str,
    device_seed: &[u8; 32],
    device_39: &[u8; 39],
    web_39: &[u8; 39],
    lookup_hash: &str,
) -> Result<(), String> {
    let pair = build_sorted_agent_pair_payload(device_39, web_39);
    let signature = sign_with_device_seed(device_seed, &msgpack_encode_bytes(&pair));

    let resp = reqwest::Client::new()
        .post(format!("{}/auth/link-desktop-agent", api_base(api_url)))
        .json(&serde_json::json!({
            "desktop_agent_key": base64_standard_encode(device_39),
            "recovery_lookup_hash": lookup_hash,
            "signature": base64_standard_encode(&signature),
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;
    let (status, body) = parse_json(resp).await?;
    if status >= 300 {
        // A previous attempt may already have committed this link - that is
        // success for our purposes (the flow is retryable).
        let text = body.to_string().to_lowercase();
        if text.contains("already linked") || text.contains("already_linked") {
            return Ok(());
        }
        return Err(api_err("link_failed", status, &body));
    }
    Ok(())
}

pub(crate) async fn complete_flip(
    api_url: &str,
    jwt: &str,
    user_id: &str,
    device_seed: &[u8; 32],
    device_b64: &str,
) -> Result<Vec<String>, String> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let canonical = format!(
        "flowsta-migration-complete:v1:{}:{}:{}",
        user_id, device_b64, ts
    );
    let signature = hex::encode(sign_with_device_seed(device_seed, canonical.as_bytes()));

    let resp = reqwest::Client::new()
        .post(format!("{}/auth/migration/complete", api_base(api_url)))
        .bearer_auth(jwt)
        .json(&serde_json::json!({
            "device_agent_pub_key": device_b64,
            "timestamp": ts,
            "signature": signature,
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to reach API: {}", e))?;
    let (status, body) = parse_json(resp).await?;
    if status >= 300 {
        return Err(api_err("flip_failed", status, &body));
    }
    Ok(body
        .get("cells_disabled")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default())
}

// ── The orchestrator ────────────────────────────────────────────────────────

#[derive(Serialize, Clone)]
struct MigrationProgress {
    stage: &'static str,
    message: String,
}

/// Restart the conductor stack so a config change (the backfilled private
/// cell material) takes effect - cell installs are decided at conductor
/// start. Waits out an in-flight start first: shutting the stack down
/// mid-start races the startup task (the double-stack hazard), and the
/// restart itself goes through the watchdog's serialized recovery path.
async fn restart_conductor_for_upgrade(
    state: &Arc<AppState>,
    app_handle: &tauri::AppHandle,
) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    loop {
        let starting = matches!(
            *state.conductor_status.lock().unwrap(),
            crate::conductor::ConductorStatus::Starting { .. }
        );
        if !starting {
            break;
        }
        if std::time::Instant::now() > deadline {
            return Err(
                "Your vault is still starting up - wait for it to finish, then retry the upgrade."
                    .to_string(),
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    if let Some(handle) = state.conductor_handle.lock().unwrap().take() {
        handle.shutdown();
    }
    crate::commands::ensure_conductor_alive(state, app_handle).await
}

fn emit_progress(app: &tauri::AppHandle, stage: &'static str, message: &str) {
    let _ = app.emit(
        "migration-progress",
        MigrationProgress {
            stage,
            message: message.to_string(),
        },
    );
}

#[derive(Serialize)]
pub struct PhraseMigrationLogin {
    pub token: String,
    pub email: String,
    /// Throwaway password minted during the phrase proof - feeds the
    /// standard migration continuation, then dies with the custodial
    /// account at the flip.
    pub password: String,
    pub agent_pub_key: String,
}

/// Phrase-first entry to the account upgrade: prove ownership of a
/// flowsta.com account with the recovery phrase alone - no password.
///
/// Mechanics: the recovery-reset endpoint's proof is cryptographic (the
/// phrase-derived key must decrypt the account's recovery-encrypted
/// email), and the reset re-encrypts the account's data under the new
/// password in the same step. We set that password to a random throwaway
/// the user never sees, then hand the wizard the same (jwt, email,
/// password) triple the password sign-in produces - the entire tested
/// migration pipeline runs unchanged from there. 2FA never blocks this
/// path: phrase recovery already outranks it, matching the web's old
/// forgot-password semantics.
#[tauri::command]
pub async fn phrase_migration_login(
    api_url: String,
    phrase: String,
) -> Result<PhraseMigrationLogin, String> {
    let mnemonic = normalize_mnemonic(&phrase);
    if !validate_mnemonic(&mnemonic) {
        return Err("Invalid recovery phrase".into());
    }

    // Strong random throwaway: a fresh 24-word mnemonic is 256 bits of
    // entropy and satisfies every password rule the API applies.
    let throwaway = crate::device_identity::generate_new_mnemonic()?;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{}/auth/reset-password-with-phrase",
            api_url.trim_end_matches('/')
        ))
        .json(&serde_json::json!({
            "recoveryPhrase": mnemonic,
            "newPassword": throwaway,
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
        let code = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("phrase_login_failed");
        if status.as_u16() == 404 {
            return Err("no_account_for_phrase".into());
        }
        return Err(code.to_string());
    }

    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or("Reset succeeded but no token returned")?
        .to_string();
    let user = body.get("user").cloned().unwrap_or_default();
    let email = user
        .get("emailPlain")
        .and_then(|v| v.as_str())
        .ok_or("Reset succeeded but no email returned - is the API up to date?")?
        .to_string();
    let agent_pub_key = user
        .get("agentPubKey")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    log::info!("[migration] phrase-first sign-in proved account ownership");

    Ok(PhraseMigrationLogin {
        token,
        email,
        password: throwaway,
        agent_pub_key,
    })
}

#[derive(Serialize)]
pub struct MigrationSummary {
    pub records_migrated: usize,
    pub sessions_skipped: usize,
    pub totp_moved: bool,
    /// 2FA existed but its secret was encrypted under an older password -
    /// skipped by design (Vault approval replaces 2FA).
    pub totp_skipped: bool,
    pub cells_disabled: Vec<String>,
    pub backup_label: String,
    pub email: String,
    pub did: String,
    pub agent_pub_key: String,
}

/// Run the full account upgrade. Called after the user has signed in
/// (password or phrase-first), holds the verified phrase, and has
/// explicitly consented. Everything before the final flip call is
/// non-destructive and retryable.
///
/// Runs in three vault situations:
/// - no vault yet (wizard): creates one mid-flow;
/// - a vault this flow created on an earlier, interrupted attempt: resumes;
/// - an existing vault from the custodial-linked era, unlocked, upgrading
///   in place: backfills the phrase-derived private-cell material and
///   restarts the conductor so the encrypted cell installs, then proceeds
///   like a resume. The vault file always keeps ITS OWN unlock password.
///
/// `password` is the ACCOUNT password (decrypts the export). The vault
/// file's password is `vault_password` (fresh vaults; defaults to
/// `password`) or the cached unlock passphrase (existing vaults).
#[tauri::command]
pub async fn migrate_custodial_account(
    api_url: String,
    jwt: String,
    password: String,
    mnemonic: String,
    vault_password: Option<String>,
    app_handle: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<MigrationSummary, String> {
    migrate_custodial_account_inner(
        api_url,
        jwt,
        password,
        mnemonic,
        vault_password,
        app_handle,
        state.inner().clone(),
    )
    .await
}

/// Non-command core so the headless test harness can drive the upgrade
/// (the Tauri command isn't reachable over the IPC bridge).
pub(crate) async fn migrate_custodial_account_inner(
    api_url: String,
    jwt: String,
    password: String,
    mnemonic: String,
    vault_password: Option<String>,
    app_handle: tauri::AppHandle,
    state: Arc<AppState>,
) -> Result<MigrationSummary, String> {
    let mnemonic = normalize_mnemonic(&mnemonic);
    if !validate_mnemonic(&mnemonic) {
        return Err("Invalid recovery phrase".into());
    }

    // Device-side derivations (never leave this function).
    let device_seed = derive_seed(&mnemonic, DEVICE_1_CONSTANT).map_err(|e| e.to_string())?;
    let signing_key = derive_device_keypair(&mnemonic).map_err(|e| e.to_string())?;
    let device_pub = signing_key.verifying_key().to_bytes();
    let device_39 = construct_agent_pub_key_bytes(&device_pub);
    let device_b64 = base64_standard_encode(&device_39);
    let lookup_hash = derive_recovery_lookup_hash(&mnemonic)
        .map_err(|e| e.to_string())?
        .to_lowercase();

    // Sort out the vault situation up front, before any server call:
    // which password the vault file uses, and whether this is an existing
    // custodial-era vault that needs its private-cell material backfilled.
    let vault_is_set_up = {
        let path = state.vault_path.lock().unwrap();
        crate::vault::vault_exists(&path)
    };
    let vault_pw: String = if vault_is_set_up {
        let mut guard = state.unlock_passphrase.lock().unwrap();
        let arr = guard
            .as_mut()
            .ok_or("A vault already exists on this device - unlock it first, then retry the upgrade")?;
        let bytes = arr.lock();
        String::from_utf8(bytes.to_vec())
            .map_err(|_| "Cached vault passphrase unavailable - lock and unlock, then retry".to_string())?
    } else {
        vault_password.unwrap_or_else(|| password.clone())
    };
    let legacy_backfill = if vault_is_set_up {
        let config = state.vault_config.lock().unwrap();
        let cfg = config
            .as_ref()
            .ok_or("A vault already exists on this device - unlock it first, then retry the upgrade")?;
        // The phrase must re-derive THIS vault's identity - an upgraded
        // vault and its account are the same keypair by construction.
        if cfg.agent_pub_key != construct_agent_pub_key_string(&device_pub) {
            return Err(
                "vault_phrase_mismatch: this isn't the recovery phrase this Vault was created from"
                    .to_string(),
            );
        }
        cfg.hosting_model.as_deref() != Some("device-hosted")
    } else {
        false
    };

    emit_progress(&app_handle, "account", "Checking your account…");
    let me = fetch_me(&api_url, &jwt).await?;

    wait_until_account_ready(&api_url, &jwt, &app_handle).await?;
    emit_progress(&app_handle, "export", "Fetching your account data…");
    let export = fetch_export(&api_url, &jwt).await?;
    let web_bytes = base64_standard_decode(&export.web_agent_b64)
        .map_err(|_| "Bad web agent key in export")?;
    if web_bytes.len() != 39 {
        return Err(format!(
            "Web agent key is {} bytes, expected 39",
            web_bytes.len()
        ));
    }
    let mut web_39 = [0u8; 39];
    web_39.copy_from_slice(&web_bytes);

    emit_progress(&app_handle, "decrypt", "Decrypting your data on this device…");
    let mapped = map_bundle(&export.data, &password, &mnemonic)?;

    // The phrase must belong to THIS account before we link with it.
    verify_lookup_binding(&api_url, &lookup_hash, &web_39).await?;

    emit_progress(&app_handle, "link", "Linking this device to your identity…");
    link_device_key(&api_url, &device_seed, &device_39, &web_39, &lookup_hash).await?;

    // Create the vault, resume into one this flow created earlier, or
    // upgrade an existing custodial-era vault in place (phrase-vs-vault
    // identity already verified up front).
    if vault_is_set_up {
        if legacy_backfill {
            // This vault predates the encrypted private cell: give it the
            // phrase-derived cell material and the device-hosted marker,
            // then restart the conductor - cell selection is decided at
            // conductor start. Everything here is re-derivable from the
            // phrase; retries land in the resume path below.
            emit_progress(&app_handle, "vault", "Preparing your vault's private cell…");
            let data_key = crate::key_derivation::derive_data_encryption_key(&mnemonic)
                .map_err(|e| format!("Data key derivation failed: {}", e))?;
            let private_network_seed =
                crate::key_derivation::derive_private_network_seed(&mnemonic)
                    .map_err(|e| format!("Network seed derivation failed: {}", e))?;
            {
                let vault_path = state.vault_path.lock().unwrap().clone();
                let mut config = state.vault_config.lock().unwrap();
                let cfg = config.as_mut().ok_or("Vault locked mid-upgrade")?;
                cfg.data_key = Some(data_key.to_vec());
                cfg.private_network_seed = Some(private_network_seed);
                cfg.hosting_model = Some("device-hosted".to_string());
                cfg.web_email = Some(mapped.email.clone());
                if cfg.web_username.is_none() {
                    cfg.web_username = mapped.username.clone().or(me.username.clone());
                }
                if cfg.display_name.is_none() {
                    cfg.display_name = mapped.display_name.clone().or(me.display_name.clone());
                }
                if cfg.profile_picture.is_none() {
                    cfg.profile_picture = me.profile_picture.clone();
                }
                let mut encrypted = crate::vault::encrypt_vault(cfg, &vault_pw)
                    .map_err(|e| format!("Vault save failed: {}", e))?;
                encrypted.display_email = cfg.web_email.clone().or(cfg.web_username.clone());
                crate::vault::save_vault(&vault_path, &encrypted)
                    .map_err(|e| format!("Vault save failed: {}", e))?;
            }
            emit_progress(
                &app_handle,
                "vault",
                "Restarting your vault to add the private cell…",
            );
            restart_conductor_for_upgrade(&state, &app_handle).await?;
            log::info!("[migration] existing vault backfilled for device hosting");
        } else {
            log::info!("[migration] resuming with the existing vault");
        }
    } else {
        emit_progress(&app_handle, "vault", "Creating your vault…");
        let web_agent_str = {
            // Preserve the web identity in uhCAk form for the dashboard.
            let mut key_32 = [0u8; 32];
            key_32.copy_from_slice(&web_39[3..35]);
            construct_agent_pub_key_string(&key_32)
        };
        crate::commands::setup_vault_inner(
            mnemonic.clone(),
            vault_pw.clone(),
            Some(web_agent_str),
            Some(mapped.email.clone()),
            mapped.username.clone().or(me.username.clone()),
            mapped.display_name.clone().or(me.display_name.clone()),
            me.profile_picture.clone(),
            Some("device-hosted".to_string()),
            false, // migration is online by construction - no reconcile needed
            false, // ...and registration long predates it
            app_handle.clone(),
            &state,
        )?;
    }

    // Wait for the conductor + encrypted private cell. First boot on a
    // fresh vault initializes lair and installs DNAs - allow minutes, and
    // probe by actually listing (the conductor can report ready before the
    // cell accepts calls).
    emit_progress(
        &app_handle,
        "cell",
        "Starting your private cell (first start can take a few minutes)…",
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    let existing = loop {
        match crate::sealed::sealed_list_inner(&state).await {
            Ok(list) => break list,
            Err(e) => {
                if std::time::Instant::now() > deadline {
                    return Err(format!(
                        "Your private cell did not come up in time ({}). Your account is unchanged - retry the upgrade.",
                        e
                    ));
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    };

    emit_progress(&app_handle, "import", "Moving your data into your vault…");
    let already: std::collections::HashSet<(String, u64)> = existing
        .iter()
        .map(|r| (r.entry_type.clone(), r.created_at))
        .collect();
    let mut stored = 0usize;
    for record in &mapped.records {
        if already.contains(&(record.entry_type.clone(), record.created_at_ms)) {
            continue; // resume: already imported by a previous attempt
        }
        crate::sealed::sealed_store_inner(
            &state,
            record.entry_type.clone(),
            record.body.clone(),
            Vec::new(),
            record.created_at_ms,
        )
        .await
        .map_err(|e| format!("Import failed on {}: {}", record.entry_type, e))?;
        stored += 1;
    }

    // Verify every mapped record is now readable on-device before anything
    // irreversible happens.
    let on_device = crate::sealed::sealed_list_inner(&state).await?;
    let have: std::collections::HashSet<(String, u64)> = on_device
        .iter()
        .map(|r| (r.entry_type.clone(), r.created_at))
        .collect();
    for record in &mapped.records {
        if !have.contains(&(record.entry_type.clone(), record.created_at_ms)) {
            return Err(format!(
                "Verification failed: {} record not readable on-device - account left unchanged",
                record.entry_type
            ));
        }
    }
    log::info!(
        "[migration] {} records on-device ({} newly stored)",
        mapped.records.len(),
        stored
    );

    // 2FA material stays vault-local (never sealed, never gossiped).
    if let Some(totp) = &mapped.totp {
        let vault_path = state.vault_path.lock().unwrap().clone();
        let mut config = state.vault_config.lock().unwrap();
        if let Some(cfg) = config.as_mut() {
            cfg.totp_secret = Some(totp.secret.clone());
            cfg.totp_backup_codes = Some(totp.backup_codes.clone());
            cfg.totp_enabled = Some(totp.enabled);
            cfg.web_email = Some(mapped.email.clone());
            let mut encrypted = crate::vault::encrypt_vault(cfg, &vault_pw)
                .map_err(|e| format!("Vault save failed: {}", e))?;
            encrypted.display_email = cfg.web_email.clone().or(cfg.web_username.clone());
            crate::vault::save_vault(&vault_path, &encrypted)
                .map_err(|e| format!("Vault save failed: {}", e))?;
        }
    }

    // Backup gate: a local encrypted export of everything that just moved
    // must exist before the account flips.
    emit_progress(&app_handle, "backup", "Writing your local encrypted backup…");
    let backup_label = format!(
        "account-migration-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    let backup_payload = serde_json::json!({
        "version": 1,
        "kind": "flowsta-account-migration",
        "exported_at": backup::iso_now(),
        "user_id": me.user_id,
        "did": me.did,
        "email": mapped.email,
        "dna_version": export.dna_version,
        "records": mapped.records,
        "totp": mapped.totp,
        "sessions_skipped": mapped.sessions_skipped,
    });
    backup::save_backup(
        &state,
        "flowsta",
        "Flowsta Account",
        Some(&backup_label),
        &serde_json::to_vec(&backup_payload).map_err(|e| e.to_string())?,
        Some("application/json"),
    )?;

    // The signed flip - after this, password login is dead and this device
    // key is the account's auth authority. The original DID never changes.
    emit_progress(&app_handle, "flip", "Switching your account to this device…");
    let cells_disabled =
        complete_flip(&api_url, &jwt, &me.user_id, &device_seed, &device_b64).await?;

    emit_progress(&app_handle, "done", "Your account now lives on this device.");
    log::info!(
        "[migration] account {} flipped to device-hosted ({} cells disabled)",
        me.user_id,
        cells_disabled.len()
    );

    // Remember the account's original web agent key. Signature reads use it
    // to show pre-upgrade signatures immediately - the identity-DNA link
    // graph also carries this, but a fresh cell's network walk can exceed
    // the read budget for a long time after setup. Same role the auto-link
    // cache plays for custodial-linked vaults.
    {
        let vault_path = state.vault_path.lock().unwrap().clone();
        let mut config = state.vault_config.lock().unwrap();
        if let Some(cfg) = config.as_mut() {
            cfg.web_agent_pub_key = Some(export.web_agent_b64.clone());
            match crate::vault::encrypt_vault(cfg, &vault_pw) {
                Ok(mut encrypted) => {
                    encrypted.display_email = cfg.web_email.clone().or(cfg.web_username.clone());
                    if let Err(e) = crate::vault::save_vault(&vault_path, &encrypted) {
                        log::warn!("[migration] web agent key persist failed (non-fatal): {}", e);
                    }
                }
                Err(e) => log::warn!("[migration] config encrypt failed (non-fatal): {}", e),
            }
        }
    }
    *state.linked_web_agent_key.lock().unwrap() = Some(export.web_agent_b64.clone());

    // Views branch on the hosting model (quota key, signature reads,
    // account cards) - tell them the world changed.
    let _ = app_handle.emit("profile-updated", serde_json::json!({}));

    Ok(MigrationSummary {
        records_migrated: mapped.records.len(),
        sessions_skipped: mapped.sessions_skipped,
        totp_moved: mapped.totp.is_some(),
        totp_skipped: mapped.totp_skipped,
        cells_disabled,
        backup_label,
        email: mapped.email,
        did: me.did,
        agent_pub_key: construct_agent_pub_key_string(&device_pub),
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASSWORD: &str = "Migration-Test-Pass-1!";
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    // Golden fixtures produced by api/src/services/encryption.js
    // encryptWithPassword on 2026-07-04 - the cross-language contract.
    const EMAIL_FIXTURE: (&str, &str, &str, &str, &str) = (
        "QJpjqn/5LtgBjCfuaE1iK1kbkQ==",
        "XBkz84I+J8VgYpB8",
        "dWVh3E9hvzgcvzNogzDJnmqrCljbf7GE5s/fKTVZTUI=",
        "VDkZKXNox/6DRQ/LXHOfVg==",
        "migtest@example.com",
    );
    const PHRASE_FIXTURE: (&str, &str, &str, &str) = (
        "t5ObN8+82hmSFycKFVB49/fF7Mx0izSkvIloiyXup6/M/Q4gJ7xY1G8fMl6/HxVI2ooW6oLlIggUq571Of3sUm8IdIJJkogJTCKTdgam239ZZYBwhsxC3ZIisHNRzOge3UvuAVwM95VEJLdwKhqvAqXEAtnkjkTge9PJSF8bSJFg2D7c9USOoNa/FVBkutweRFYITK4fVIarS/LQr/4GptHBpLbJ1Tqdv2CcfwIGukA+ETDUB1kRRUvwvw==",
        "+RSvTkgQ9z+Rl8E8",
        "37iA+RlISmDLqvc2gvA/FuzDWNXYxj7WJB2+sO/RMkA=",
        "1PoConrNDz5jE1OUNrgN0A==",
    );
    const TOTP_FIXTURE: (&str, &str, &str, &str, &str) = (
        "ywYk/pkjFhp9K/Ksbjhwag==",
        "qZPWT/2ZMjtvV4oI",
        "RqpcK55JnBAXhaIV7LDfFb4T27t3PUQkPBAvFyLEEwo=",
        "7EvTWnLg6VBjZ3/lS1OzEg==",
        "JBSWY3DPEHPK3PXP",
    );
    const BACKUP_CODES_FIXTURE: (&str, &str, &str, &str) = (
        "cptLhLFyIewH+dL23Qz548kNig5g+eVOG20UM+reREBm",
        "P2nYOYNPlEE6VA3U",
        "klQCd+pBNbKi/12/MypYvDL/mF7r7WKlA4+Z4d5bQrQ=",
        "3Ey0TEQVsY+qOrthVRcuxw==",
    );

    #[test]
    fn test_decrypt_api_field_golden() {
        let (cipher, nonce, salt, tag, plain) = EMAIL_FIXTURE;
        let out = decrypt_api_field(cipher, nonce, salt, tag, TEST_PASSWORD).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn test_decrypt_api_field_wrong_password() {
        let (cipher, nonce, salt, tag, _) = EMAIL_FIXTURE;
        let out = decrypt_api_field(cipher, nonce, salt, tag, "wrong-password");
        assert!(out.unwrap_err().contains("decrypt_failed"));
    }

    fn fixture_bundle() -> serde_json::Value {
        serde_json::json!({
            "user_profile": {
                "encrypted_email": EMAIL_FIXTURE.0,
                "nonce": EMAIL_FIXTURE.1,
                "salt": EMAIL_FIXTURE.2,
                "tag": EMAIL_FIXTURE.3,
                "username": "migtester",
                "display_name": "Mig Tester",
                "created_at": 1751500000000000_i64, // microseconds
                "updated_at": 1751500000000000_i64,
            },
            "recovery_phrase": {
                "encrypted_mnemonic": PHRASE_FIXTURE.0,
                "nonce": PHRASE_FIXTURE.1,
                "salt": PHRASE_FIXTURE.2,
                "tag": PHRASE_FIXTURE.3,
                "verified": true,
                "created_at": 1751500000000000_i64,
            },
            "sessions": [{"user_agent": "x", "ip_address": "y"}],
            "email_permissions": [
                {"service_name": "billing", "purpose": "invoices", "granted": true,
                 "created_at": 1751500000000000_i64, "updated_at": 1751500000000000_i64}
            ],
            "login_activities": [
                {"timestamp": 1751500000000_i64, "login_method": "password",
                 "session_id": "s1", "created_at": 1751500000000000_i64}
            ],
            "dashboard_activities": [],
            "oauth_activities": [
                {"timestamp": 1751500000000_i64, "app_id": "app-uuid-1",
                 "app_name": "Website", "event_type": "login",
                 "created_at": 1751500000000000_i64}
            ],
            "privacy_settings": {"track_ip_address": false, "track_user_agent": false,
                "activity_log_retention_days": 90,
                "created_at": 1751500000000000_i64, "updated_at": 1751500000000000_i64},
            "analytics_ids": [
                {"app_id": "app-uuid-1", "analytics_id": "anon-uuid",
                 "created_at": 1751500000000000_i64}
            ],
            "totp_config": {
                "encrypted_secret": TOTP_FIXTURE.0,
                "nonce": TOTP_FIXTURE.1,
                "salt": TOTP_FIXTURE.2,
                "tag": TOTP_FIXTURE.3,
                "encrypted_backup_codes": BACKUP_CODES_FIXTURE.0,
                "backup_nonce": BACKUP_CODES_FIXTURE.1,
                "backup_salt": BACKUP_CODES_FIXTURE.2,
                "backup_tag": BACKUP_CODES_FIXTURE.3,
                "enabled": true,
                "created_at": 1751500000000000_i64,
                "updated_at": 1751500000000000_i64,
            },
            "profile_picture": {"profile_picture": "data:image/png;base64,AAA",
                "has_custom_picture": false, "updated_at": 1751500000000000_i64},
            "export_timestamp": 1751600000000000_i64,
            "dna_version": "1.11",
        })
    }

    #[test]
    fn test_map_bundle_full() {
        let mapped = map_bundle(&fixture_bundle(), TEST_PASSWORD, TEST_MNEMONIC).unwrap();

        assert_eq!(mapped.email, "migtest@example.com");
        assert_eq!(mapped.username.as_deref(), Some("migtester"));
        assert_eq!(mapped.display_name.as_deref(), Some("Mig Tester"));
        assert_eq!(mapped.sessions_skipped, 1);

        // profile + permission + login + oauth + privacy + analytics + picture
        assert_eq!(mapped.records.len(), 7);
        let types: Vec<&str> = mapped.records.iter().map(|r| r.entry_type.as_str()).collect();
        assert!(types.contains(&"user_profile"));
        assert!(types.contains(&"email_permission"));
        assert!(types.contains(&"login_activity"));
        assert!(types.contains(&"oauth_activity"));
        assert!(types.contains(&"privacy_settings"));
        assert!(types.contains(&"app_analytics_id"));
        assert!(types.contains(&"profile_picture"));
        // Never sealed: root secrets and dropped types.
        assert!(!types.contains(&"recovery_phrase"));
        assert!(!types.contains(&"totp_config"));
        assert!(!types.contains(&"session"));

        // The profile body carries the DECRYPTED email - the password-locked
        // blob must not survive migration.
        let profile = mapped.records.iter().find(|r| r.entry_type == "user_profile").unwrap();
        assert_eq!(profile.body["email"], "migtest@example.com");
        assert!(profile.body.get("encrypted_email").is_none());

        // Microsecond cell timestamps normalize to milliseconds.
        assert_eq!(profile.created_at_ms, 1751500000000);

        // TOTP decrypts to vault-local material.
        assert!(!mapped.totp_skipped);
        let totp = mapped.totp.unwrap();
        assert_eq!(totp.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(totp.backup_codes, vec!["a1b2c3d4e5f60718", "90aabbccddeeff00"]);
        assert!(totp.enabled);
    }

    #[test]
    fn test_map_bundle_totp_under_stale_password_is_skipped() {
        // The server's password-change/reset sweeps never re-encrypted the
        // 2FA record, so real accounts hold it under an older password.
        // The move must complete anyway (Vault approval replaces 2FA) -
        // TOTP is skipped and flagged, never fatal.
        let mut bundle = fixture_bundle();
        // Corrupt the auth tag → AES-GCM open fails, same as a stale password.
        bundle["totp_config"]["tag"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAA==");
        let mapped = map_bundle(&bundle, TEST_PASSWORD, TEST_MNEMONIC).unwrap();
        assert!(mapped.totp.is_none());
        assert!(mapped.totp_skipped);
        // Everything else still mapped in full.
        assert_eq!(mapped.records.len(), 7);
        assert_eq!(mapped.email, "migtest@example.com");
    }

    #[test]
    fn test_map_bundle_rejects_wrong_phrase() {
        // A valid BIP39 phrase that is NOT the one stored on the account.
        let other = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";
        let err = map_bundle(&fixture_bundle(), TEST_PASSWORD, other).unwrap_err();
        assert!(err.contains("phrase_mismatch"), "{}", err);
    }

    #[test]
    fn test_map_bundle_requires_phrase_record() {
        let mut bundle = fixture_bundle();
        bundle["recovery_phrase"] = serde_json::Value::Null;
        let err = map_bundle(&bundle, TEST_PASSWORD, TEST_MNEMONIC).unwrap_err();
        assert!(err.contains("export_missing_phrase"), "{}", err);
    }

    #[test]
    fn test_to_millis_units() {
        assert_eq!(to_millis(1751500000000000), 1751500000000); // µs → ms
        assert_eq!(to_millis(1751500000000), 1751500000000); // already ms
        assert_eq!(to_millis(0), 0);
        assert_eq!(to_millis(-5), 0);
    }

    #[test]
    fn test_normalize_mnemonic() {
        assert_eq!(
            normalize_mnemonic("  Abandon   ABANDON\nart "),
            "abandon abandon art"
        );
    }

    // ── Staging integration: the full migration contract with real signing ──
    //
    // Mirrors the API-side migration e2e (register → server phrase → device
    // key from THE SAME phrase → pair-sig link → lossless export → local
    // decrypt → flip → password dies / vault-grant lives / DID preserved →
    // revert) through THIS module's functions, plus the account-variant
    // matrix (two-factor, lost phrase, username sign-in, existing
    // signatures). The on-device conductor import is exercised in the GUI
    // walkthrough instead.
    //
    // Run explicitly: cargo test --lib migration -- --ignored
    const STAGING: &str = "https://auth-api-staging.flowsta.com";

    fn unique_suffix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// Register a synthetic custodial user (creates real API cells) → JWT.
    async fn register_staging(
        client: &reqwest::Client,
        email: &str,
        password: &str,
        display_name: &str,
    ) -> String {
        let resp = client
            .post(format!("{}/auth/register", STAGING))
            .json(&serde_json::json!({
                "email": email,
                "password": password,
                "confirmPassword": password,
                "displayName": display_name,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 201, "register");
        let body: serde_json::Value = resp.json().await.unwrap();
        body["token"].as_str().unwrap().to_string()
    }

    struct DeviceIdentity {
        seed: [u8; 32],
        key_39: [u8; 39],
        key_b64: String,
        lookup_hash: String,
    }

    fn derive_device(mnemonic: &str) -> DeviceIdentity {
        let seed = derive_seed(mnemonic, DEVICE_1_CONSTANT).unwrap();
        let pub_key = derive_device_keypair(mnemonic)
            .unwrap()
            .verifying_key()
            .to_bytes();
        let key_39 = construct_agent_pub_key_bytes(&pub_key);
        DeviceIdentity {
            seed,
            key_b64: base64_standard_encode(&key_39),
            key_39,
            lookup_hash: derive_recovery_lookup_hash(mnemonic).unwrap().to_lowercase(),
        }
    }

    /// Link + flip using an already-fetched export as ground truth.
    /// (The export/flip/revert endpoints share one tight rate limiter on
    /// staging - each test must spend exactly one export.)
    async fn link_and_flip(
        jwt: &str,
        user_id: &str,
        export: &ExportResult,
        device: &DeviceIdentity,
    ) {
        let web_bytes = base64_standard_decode(&export.web_agent_b64).unwrap();
        let mut web_39 = [0u8; 39];
        web_39.copy_from_slice(&web_bytes);

        verify_lookup_binding(STAGING, &device.lookup_hash, &web_39)
            .await
            .expect("lookup binding");
        link_device_key(STAGING, &device.seed, &device.key_39, &web_39, &device.lookup_hash)
            .await
            .expect("link");
        let cells = complete_flip(STAGING, jwt, user_id, &device.seed, &device.key_b64)
            .await
            .expect("flip");
        assert!(!cells.is_empty(), "cells disabled: {:?}", cells);
    }

    /// RFC 4648 base32 decode (uppercase, padding ignored) - for the TOTP
    /// secret the two-factor setup endpoint returns.
    fn b32_decode(input: &str) -> Vec<u8> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut bits = 0u32;
        let mut nbits = 0u8;
        let mut out = Vec::new();
        for c in input.trim_end_matches('=').bytes() {
            let v = ALPHABET
                .iter()
                .position(|&a| a == c.to_ascii_uppercase())
                .expect("invalid base32") as u32;
            bits = (bits << 5) | v;
            nbits += 5;
            if nbits >= 8 {
                nbits -= 8;
                out.push((bits >> nbits) as u8);
            }
        }
        out
    }

    /// otplib-compatible TOTP: HMAC-SHA1, 30-second step, 6 digits.
    /// Sleeps past the step boundary when close, so a code computed here is
    /// still valid when the server checks it.
    async fn totp_now(secret_b32: &str) -> String {
        use hmac::{Hmac, Mac};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now % 30 >= 27 {
            tokio::time::sleep(std::time::Duration::from_secs(4)).await;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let counter = (now / 30).to_be_bytes();
        let mut mac =
            <Hmac<sha1::Sha1> as Mac>::new_from_slice(&b32_decode(secret_b32)).unwrap();
        mac.update(&counter);
        let digest = mac.finalize().into_bytes();
        let offset = (digest[19] & 0x0f) as usize;
        let code = ((u32::from(digest[offset]) & 0x7f) << 24
            | u32::from(digest[offset + 1]) << 16
            | u32::from(digest[offset + 2]) << 8
            | u32::from(digest[offset + 3]))
            % 1_000_000;
        format!("{:06}", code)
    }

    #[tokio::test]
    #[ignore]
    async fn migration_flow_against_staging() {
        let client = reqwest::Client::new();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let email = format!("migvault-{}@example.com", suffix);
        let password = format!("Migration-Vault-{}!x", suffix);

        // 1. Register a synthetic custodial user (creates real API cells).
        let resp = client
            .post(format!("{}/auth/register", STAGING))
            .json(&serde_json::json!({
                "email": email,
                "password": password,
                "confirmPassword": password,
                "displayName": format!("Mig Vault {}", suffix),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 201, "register");
        let body: serde_json::Value = resp.json().await.unwrap();
        let jwt = body["token"].as_str().unwrap().to_string();

        // 2. Server mints the phrase (the no-existing-phrase path - the same
        //    endpoint the wizard's lost-phrase escape hatch uses).
        let phrase = migration_new_phrase(STAGING.into(), jwt.clone(), password.clone())
            .await
            .expect("setup-recovery-phrase");
        assert_eq!(phrase.split(' ').count(), 24, "24-word phrase");

        // 3. Device derivations from THE SAME phrase.
        let mnemonic = normalize_mnemonic(&phrase);
        assert!(validate_mnemonic(&mnemonic), "server phrase is valid BIP39");
        let device_seed = derive_seed(&mnemonic, DEVICE_1_CONSTANT).unwrap();
        let device_pub = derive_device_keypair(&mnemonic)
            .unwrap()
            .verifying_key()
            .to_bytes();
        let device_39 = construct_agent_pub_key_bytes(&device_pub);
        let device_b64 = base64_standard_encode(&device_39);
        let lookup_hash = derive_recovery_lookup_hash(&mnemonic).unwrap().to_lowercase();

        // 4. Account info + lossless export.
        let me = fetch_me(STAGING, &jwt).await.expect("me");
        assert!(!me.user_id.is_empty(), "user id");
        let did_before = me.did.clone();
        assert!(did_before.starts_with("did:flowsta:"), "did: {}", did_before);

        let export = fetch_export(STAGING, &jwt).await.expect("export");
        let web_bytes = base64_standard_decode(&export.web_agent_b64).unwrap();
        assert_eq!(web_bytes.len(), 39, "web key 39 bytes");
        let mut web_39 = [0u8; 39];
        web_39.copy_from_slice(&web_bytes);

        // 5. Local decrypt + mapping: the email round-trips through the
        //    server-side scrypt/AES-GCM and our Rust port; the stored phrase
        //    blob decrypts to exactly the phrase in hand.
        let mapped = map_bundle(&export.data, &password, &mnemonic).expect("map_bundle");
        assert_eq!(mapped.email, email, "decrypted email matches");
        assert!(
            mapped.records.iter().any(|r| r.entry_type == "user_profile"),
            "profile mapped"
        );
        assert!(mapped.totp.is_none(), "no 2FA on this account");

        // A wrong (valid) phrase must be rejected by the blob comparison.
        let wrong = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";
        assert!(
            map_bundle(&export.data, &password, wrong)
                .unwrap_err()
                .contains("phrase_mismatch"),
            "wrong phrase rejected"
        );

        // 6. Lookup binding + zome-verified pair link.
        verify_lookup_binding(STAGING, &lookup_hash, &web_39)
            .await
            .expect("lookup binding");
        link_device_key(STAGING, &device_seed, &device_39, &web_39, &lookup_hash)
            .await
            .expect("link");

        // 7. Pre-flip, vault-grant must refuse: the device key is only in
        //    the link table, not yet the account's auth key.
        let pre = crate::device_identity::vault_grant_with_seed(STAGING, &device_seed, &device_b64).await;
        assert!(
            pre.as_ref()
                .err()
                .map(|e| e.contains("unknown_agent_key") || e.contains("not_device_hosted"))
                .unwrap_or(false),
            "pre-flip vault-grant must be refused: {:?}",
            pre.as_ref().err()
        );

        // 8. The signed flip.
        let cells = complete_flip(STAGING, &jwt, &me.user_id, &device_seed, &device_b64)
            .await
            .expect("flip");
        assert!(!cells.is_empty(), "cells disabled: {:?}", cells);

        // 9. Password login dies; vault-grant lives; DID preserved.
        let resp = client
            .post(format!("{}/auth/login", STAGING))
            .json(&serde_json::json!({ "emailOrUsername": email, "password": password }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 403, "password login 403 post-flip");

        let grant = crate::device_identity::vault_grant_with_seed(STAGING, &device_seed, &device_b64)
            .await
            .expect("post-flip vault-grant");
        assert_eq!(grant.did, did_before, "DID preserved");
        assert!(!grant.token.is_empty(), "device session token");

        // 10. Revert lever restores custodial password login.
        let resp = client
            .post(format!("{}/auth/migration/revert", STAGING))
            .bearer_auth(&grant.token)
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "revert 200");

        let resp = client
            .post(format!("{}/auth/login", STAGING))
            .json(&serde_json::json!({ "emailOrUsername": email, "password": password }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "password login restored after revert");
    }

    /// Two-factor account variant: enable real TOTP on the account, sign in
    /// the way the wizard does (temp token + code), migrate, and confirm the
    /// 2FA material decrypts into vault-local form. Post-flip, the device
    /// key is the auth factor - no TOTP challenge on Vault-grant.
    #[tokio::test]
    #[ignore]
    async fn migration_2fa_user_against_staging() {
        let client = reqwest::Client::new();
        let suffix = unique_suffix();
        let email = format!("migvault2fa-{}@example.com", suffix);
        let password = format!("Migration-2FA-{}!x", suffix);
        let jwt = register_staging(&client, &email, &password, "Mig 2FA").await;

        let phrase = migration_new_phrase(STAGING.into(), jwt.clone(), password.clone())
            .await
            .expect("phrase");
        let mnemonic = normalize_mnemonic(&phrase);
        let device = derive_device(&mnemonic);

        // Enable 2FA with a real TOTP round-trip.
        let resp = client
            .post(format!("{}/api/v1/2fa/setup", STAGING))
            .bearer_auth(&jwt)
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "2fa setup");
        let body: serde_json::Value = resp.json().await.unwrap();
        let secret = body["secret"].as_str().expect("totp secret").to_string();

        let code = totp_now(&secret).await;
        let resp = client
            .post(format!("{}/api/v1/2fa/verify-setup", STAGING))
            .bearer_auth(&jwt)
            .json(&serde_json::json!({ "code": code, "password": password }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "2fa verify-setup: {:?}",
            resp.text().await
        );

        // Sign in exactly as the wizard does: password → temp token → code.
        let auth = crate::commands::authenticate_web_account(
            STAGING.into(),
            email.clone(),
            password.clone(),
        )
        .await
        .expect("password step");
        assert!(auth.requires_2fa, "2FA challenge expected");
        let temp = auth.temp_token.expect("temp token");
        let code = totp_now(&secret).await;
        let auth = crate::commands::authenticate_2fa(STAGING.into(), temp, code)
            .await
            .expect("2fa step");
        let jwt2 = auth.token.expect("2fa session token");

        // Export with the 2FA session; the TOTP material must decrypt into
        // vault-local form (never sealed).
        let export = fetch_export(STAGING, &jwt2).await.expect("export");
        let mapped = map_bundle(&export.data, &password, &mnemonic).expect("map");
        let totp = mapped.totp.as_ref().expect("totp present in export");
        assert_eq!(totp.secret, secret, "TOTP secret survives the round trip");
        assert_eq!(totp.backup_codes.len(), 8, "backup codes");
        assert!(totp.enabled);
        assert!(
            !mapped.records.iter().any(|r| r.entry_type == "totp_config"),
            "TOTP must not become a sealed record"
        );

        let me = fetch_me(STAGING, &jwt2).await.unwrap();
        let did_before = me.did.clone();
        link_and_flip(&jwt2, &me.user_id, &export, &device).await;

        // Password login dies BEFORE the 2FA challenge.
        let resp = client
            .post(format!("{}/auth/login", STAGING))
            .json(&serde_json::json!({ "emailOrUsername": email, "password": password }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 403, "password+2FA login 403 post-flip");

        let grant =
            crate::device_identity::vault_grant_with_seed(STAGING, &device.seed, &device.key_b64)
                .await
                .expect("vault-grant post-flip");
        assert_eq!(grant.did, did_before, "DID preserved");

        // Revert restores the custodial 2FA flow intact.
        let resp = client
            .post(format!("{}/auth/migration/revert", STAGING))
            .bearer_auth(&grant.token)
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "revert");
        let auth = crate::commands::authenticate_web_account(STAGING.into(), email, password)
            .await
            .expect("post-revert password step");
        assert!(auth.requires_2fa, "2FA challenge restored after revert");
    }

    /// Lost-phrase variant: re-minting the phrase re-binds the account's
    /// lookup hash - the old phrase stops resolving and is rejected by the
    /// stored-blob comparison; the new phrase migrates cleanly.
    #[tokio::test]
    #[ignore]
    async fn migration_lost_phrase_rebind_against_staging() {
        let client = reqwest::Client::new();
        let suffix = unique_suffix();
        let email = format!("migvaultlost-{}@example.com", suffix);
        let password = format!("Migration-Lost-{}!x", suffix);
        let jwt = register_staging(&client, &email, &password, "Mig Lost").await;

        let phrase1 = migration_new_phrase(STAGING.into(), jwt.clone(), password.clone())
            .await
            .expect("first phrase");
        let phrase2 = migration_new_phrase(STAGING.into(), jwt.clone(), password.clone())
            .await
            .expect("re-minted phrase");
        let old = normalize_mnemonic(&phrase1);
        let new = normalize_mnemonic(&phrase2);
        assert_ne!(old, new, "re-mint must produce a fresh phrase");

        let export = fetch_export(STAGING, &jwt).await.expect("export");
        let web_bytes = base64_standard_decode(&export.web_agent_b64).unwrap();
        let mut web_39 = [0u8; 39];
        web_39.copy_from_slice(&web_bytes);

        // The lost phrase is dead on both checks…
        assert!(
            map_bundle(&export.data, &password, &old)
                .unwrap_err()
                .contains("phrase_mismatch"),
            "old phrase rejected by blob comparison"
        );
        let old_device = derive_device(&old);
        assert!(
            verify_lookup_binding(STAGING, &old_device.lookup_hash, &web_39)
                .await
                .is_err(),
            "old lookup hash no longer resolves to the account"
        );

        // …and the new phrase migrates.
        let mapped = map_bundle(&export.data, &password, &new).expect("new phrase maps");
        assert_eq!(mapped.email, email, "email decrypts");
        let device = derive_device(&new);
        let me = fetch_me(STAGING, &jwt).await.unwrap();
        let did_before = me.did.clone();
        link_and_flip(&jwt, &me.user_id, &export, &device).await;

        let grant =
            crate::device_identity::vault_grant_with_seed(STAGING, &device.seed, &device.key_b64)
                .await
                .expect("vault-grant post-flip");
        assert_eq!(grant.did, did_before, "DID preserved");
    }

    /// Username sign-in entry: the wizard's sign-in accepts a username, the
    /// username survives migration, and username+password login dies with
    /// the flip too.
    /// Username-entry variant. Claiming a username requires a VERIFIED
    /// email (server gate), which a synthetic registration can't satisfy -
    /// so this test uses a durable pre-verified staging fixture account
    /// (username already claimed) provided via env, and REVERTS the flip at
    /// the end so the fixture stays custodial and reusable:
    ///   MIG_TEST_USERNAME_EMAIL / MIG_TEST_USERNAME_PASSWORD /
    ///   MIG_TEST_USERNAME
    /// Without the env, the test instead asserts the verified-email gate
    /// itself and stops (register fresh → claim refused with
    /// email_not_verified).
    #[tokio::test]
    #[ignore]
    async fn migration_username_entry_against_staging() {
        let client = reqwest::Client::new();

        let fixture = (
            std::env::var("MIG_TEST_USERNAME_EMAIL"),
            std::env::var("MIG_TEST_USERNAME_PASSWORD"),
            std::env::var("MIG_TEST_USERNAME"),
        );
        let (password, username) = match fixture {
            (Ok(_email), Ok(pw), Ok(un)) => (pw, un),
            _ => {
                // No fixture - prove the gate: fresh (unverified) accounts
                // must be refused a username.
                let suffix = unique_suffix();
                let email = format!("migvaultuser-{}@example.com", suffix);
                let password = format!("Migration-User-{}!x", suffix);
                let jwt = register_staging(&client, &email, &password, "Mig User").await;
                let resp = client
                    .put(format!("{}/auth/username", STAGING))
                    .bearer_auth(&jwt)
                    .json(&serde_json::json!({ "username": format!("migvault{}", suffix) }))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(resp.status().as_u16(), 403, "unverified email must be refused a username");
                let body = resp.text().await.unwrap_or_default();
                assert!(body.contains("email_not_verified"), "gate code present: {}", body);
                eprintln!("(fixture env not set - verified-email gate asserted; full username flow skipped)");
                return;
            }
        };

        // Sign in BY USERNAME through the wizard's own command.
        let auth = crate::commands::authenticate_web_account(
            STAGING.into(),
            username.clone(),
            password.clone(),
        )
        .await
        .expect("username login");
        assert!(!auth.requires_2fa);
        let jwt = auth.token.expect("session token");

        let phrase = migration_new_phrase(STAGING.into(), jwt.clone(), password.clone())
            .await
            .expect("phrase");
        let mnemonic = normalize_mnemonic(&phrase);
        let device = derive_device(&mnemonic);

        let export = fetch_export(STAGING, &jwt).await.expect("export");
        let mapped = map_bundle(&export.data, &password, &mnemonic).expect("map");
        assert_eq!(
            mapped.username.as_deref(),
            Some(username.as_str()),
            "username present in the exported profile"
        );

        let me = fetch_me(STAGING, &jwt).await.unwrap();
        let did_before = me.did.clone();
        link_and_flip(&jwt, &me.user_id, &export, &device).await;

        // Username+password login dies with the flip…
        let dead = crate::commands::authenticate_web_account(
            STAGING.into(),
            username.clone(),
            password.clone(),
        )
        .await;
        assert!(dead.is_err(), "username login must be refused post-flip");

        // …and the username survives on the device-hosted account.
        let grant =
            crate::device_identity::vault_grant_with_seed(STAGING, &device.seed, &device.key_b64)
                .await
                .expect("vault-grant post-flip");
        assert_eq!(grant.did, did_before, "DID preserved");
        assert_eq!(
            grant.username.as_deref(),
            Some(username.as_str()),
            "username preserved post-flip"
        );

        // Revert so the fixture account returns to custodial and stays
        // reusable for the next run.
        let resp = client
            .post(format!("{}/auth/migration/revert", STAGING))
            .bearer_auth(&grant.token)
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "fixture revert");
        let restored = crate::commands::authenticate_web_account(
            STAGING.into(),
            username.clone(),
            password.clone(),
        )
        .await;
        assert!(restored.is_ok(), "fixture password login restored after revert");
    }

    /// Existing-signatures variant: a signature made while custodial must
    /// still verify - with the signer identity resolved - after the account
    /// flips to device-hosting (signatures live on the shared DHT and the
    /// old key stays attributable through the agent link graph).
    #[tokio::test]
    #[ignore]
    async fn migration_signatures_continuity_against_staging() {
        use sha2::{Digest, Sha256};
        let client = reqwest::Client::new();
        let suffix = unique_suffix();
        let email = format!("migvaultsig-{}@example.com", suffix);
        let password = format!("Migration-Sig-{}!x", suffix);
        let jwt = register_staging(&client, &email, &password, "Mig Signer").await;

        let phrase = migration_new_phrase(STAGING.into(), jwt.clone(), password.clone())
            .await
            .expect("phrase");
        let mnemonic = normalize_mnemonic(&phrase);
        let device = derive_device(&mnemonic);
        let me = fetch_me(STAGING, &jwt).await.unwrap();
        let did_before = me.did.clone();

        // Sign a document while custodial (the API signs through the
        // account's hosted cell - exactly what existing users have done).
        // No `intent` field: the route's default maps to a valid zome enum
        // variant; arbitrary strings are rejected by the zome.
        let file_hash = hex::encode(Sha256::digest(format!("migration-sig-test-{}", suffix)));
        let resp = client
            .post(format!("{}/api/v1/sign-it/sign", STAGING))
            .bearer_auth(&jwt)
            .json(&serde_json::json!({ "file_hash": file_hash }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "custodial sign: {:?}",
            resp.text().await
        );

        // Signer-identity resolution walks the identity DNA - a freshly
        // registered account's records need DHT warmup, so poll rather than
        // assert on the first read.
        let verify_resolved = |hash: String, deadline_secs: u64| {
            let client = client.clone();
            async move {
                let deadline =
                    std::time::Instant::now() + std::time::Duration::from_secs(deadline_secs);
                loop {
                    let resp = client
                        .get(format!("{}/api/v1/sign-it/verify?hash={}", STAGING, hash))
                        .send()
                        .await
                        .unwrap();
                    assert_eq!(resp.status().as_u16(), 200, "verify");
                    let body: serde_json::Value = resp.json().await.unwrap();
                    if body["count"].as_i64() == Some(1)
                        && body["signatures"][0]["signer_did"].as_str().is_some()
                    {
                        return body;
                    }
                    if std::time::Instant::now() > deadline {
                        return body; // let the caller's asserts report what's missing
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
            }
        };

        let before = verify_resolved(file_hash.clone(), 60).await;
        assert_eq!(before["count"].as_i64(), Some(1), "one signature pre-flip");
        assert_eq!(
            before["signatures"][0]["signer_did"].as_str(),
            Some(did_before.as_str()),
            "signer DID resolves pre-flip"
        );

        let export = fetch_export(STAGING, &jwt).await.expect("export");
        map_bundle(&export.data, &password, &mnemonic).expect("map");
        link_and_flip(&jwt, &me.user_id, &export, &device).await;

        // The signature must still verify AND still attribute to the same
        // identity after the flip.
        let after = verify_resolved(file_hash.clone(), 60).await;
        assert_eq!(after["count"].as_i64(), Some(1), "signature survives the flip");
        assert_eq!(
            after["signatures"][0]["signer_did"].as_str(),
            Some(did_before.as_str()),
            "signer DID still resolves post-flip"
        );

        let grant =
            crate::device_identity::vault_grant_with_seed(STAGING, &device.seed, &device.key_b64)
                .await
                .expect("vault-grant post-flip");
        assert_eq!(grant.did, did_before, "DID preserved");
    }
}
