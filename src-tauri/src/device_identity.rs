//! Device-hosted identity: create a sovereign identity in Vault,
//! register it with the Flowsta API, and authenticate via Vault-grant
//! challenge-response. No web password, no API-hosted cells.
//!
//! Signature contracts (must match `api/src/routes/deviceIdentity.js`):
//! - Registration: raw Ed25519 over the canonical UTF-8 string
//!   `flowsta-register-identity:v1:{agentPubKeyB64}:{recoveryLookupHash}:{emailHashHex}:{unixSeconds}`
//!   where emailHash = sha256(lowercase(trim(email))) hex.
//! - Login: raw Ed25519 over the server-issued challenge string
//!   `flowsta-auth-challenge:v1:{nonce}:{client_id}` — signed exactly as
//!   received; the server rejects unprefixed challenges.

use crate::commands::AppState;
use crate::key_derivation::{
    base64_standard_encode, construct_agent_pub_key_bytes, construct_agent_pub_key_string,
    decode_agent_pub_key_flexible, derive_device_keypair, derive_recovery_lookup_hash, derive_seed,
    sign_with_device_seed, validate_mnemonic, DEVICE_1_CONSTANT,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tauri::State;

const VAULT_CLIENT_ID: &str = "flowsta-vault";

/// Generate a fresh 24-word BIP39 mnemonic from OS entropy.
/// Vault was restore-only before this — creation is net-new.
#[tauri::command]
pub fn generate_new_mnemonic() -> Result<String, String> {
    use rand::RngCore;
    let mut entropy = [0u8; 32]; // 256 bits -> 24 words
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
        .map_err(|e| format!("Mnemonic generation failed: {}", e))?;
    Ok(mnemonic.to_string())
}

#[derive(Serialize)]
pub struct RegisterResult {
    pub user_id: String,
    pub did: String,
    pub agent_pub_key: String,
    /// Server-generated identicon (from the DID) — the account's default
    /// picture until the user uploads one. The wizard stores it in the
    /// vault config so the identity has a face from the first unlock.
    pub profile_picture: Option<String>,
}

#[derive(Deserialize)]
struct ApiUser {
    id: Option<String>,
    did: Option<String>,
    #[serde(rename = "agentPubKey")]
    agent_pub_key: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    username: Option<String>,
    #[serde(rename = "profilePicture")]
    profile_picture: Option<String>,
}

#[derive(Deserialize)]
struct ApiEnvelope {
    success: Option<bool>,
    user: Option<ApiUser>,
    token: Option<String>,
    error: Option<String>,
    message: Option<String>,
}

fn api_error(status: reqwest::StatusCode, body: &ApiEnvelope, context: &str) -> String {
    let code = body.error.as_deref().unwrap_or("unknown_error");
    let msg = body.message.as_deref().unwrap_or("");
    format!("{}: {} ({}) [{}]", context, code, msg, status.as_u16())
}

/// Register a Vault-created identity as a new Flowsta account.
/// Creates NO cells anywhere — the API stores only the pubkey + credential.
#[tauri::command]
pub async fn register_device_identity(
    api_url: String,
    mnemonic: String,
    email: String,
    display_name: Option<String>,
) -> Result<RegisterResult, String> {
    if !validate_mnemonic(&mnemonic) {
        return Err("Invalid recovery phrase".into());
    }
    let email = email.trim().to_string();
    if !email.contains('@') {
        return Err("A valid email address is required".into());
    }

    let signing_key =
        derive_device_keypair(&mnemonic).map_err(|e| format!("Key derivation failed: {}", e))?;
    let pub_key_bytes = signing_key.verifying_key().to_bytes();
    let agent_pub_key_39 = construct_agent_pub_key_bytes(&pub_key_bytes);
    let agent_b64 = base64_standard_encode(&agent_pub_key_39);
    let lookup_hash = derive_recovery_lookup_hash(&mnemonic)
        .map_err(|e| format!("Lookup hash derivation failed: {}", e))?
        .to_lowercase();
    let device_seed = derive_seed(&mnemonic, DEVICE_1_CONSTANT)
        .map_err(|e| format!("Device seed derivation failed: {}", e))?;

    let email_hash = hex::encode(Sha256::digest(email.to_lowercase().as_bytes()));
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    // Canonical registration message — signed raw (no MessagePack).
    let canonical = format!(
        "flowsta-register-identity:v1:{}:{}:{}:{}",
        agent_b64, lookup_hash, email_hash, ts
    );
    let signature = hex::encode(sign_with_device_seed(&device_seed, canonical.as_bytes()));

    let client = reqwest::Client::new();
    let url = format!(
        "{}/auth/register-device-identity",
        api_url.trim_end_matches('/')
    );
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "agent_pub_key": agent_b64,
            "email": email,
            "display_name": display_name,
            "recovery_lookup_hash": lookup_hash,
            "timestamp": ts,
            "signature": signature,
        }))
        .send()
        .await
        .map_err(|e| format!("Registration request failed: {}", e))?;

    let status = resp.status();
    let body: ApiEnvelope = resp
        .json()
        .await
        .map_err(|e| format!("Registration response parse failed: {}", e))?;

    if !status.is_success() {
        return Err(api_error(status, &body, "registration_failed"));
    }

    let user = body.user.ok_or("Registration response missing user")?;
    log::info!(
        "Device identity registered with Flowsta (zero cells): {}",
        user.did.as_deref().unwrap_or("?")
    );
    Ok(RegisterResult {
        user_id: user.id.unwrap_or_default(),
        did: user.did.unwrap_or_default(),
        agent_pub_key: user.agent_pub_key.unwrap_or_else(|| {
            construct_agent_pub_key_string(&pub_key_bytes)
        }),
        profile_picture: user.profile_picture,
    })
}

#[derive(Serialize)]
pub struct VaultGrantResult {
    pub token: String,
    pub did: String,
    pub agent_pub_key: String,
    pub display_name: Option<String>,
    pub username: Option<String>,
    pub profile_picture: Option<String>,
    /// For migrated accounts only: the original (pre-upgrade) web agent
    /// key, recovered from the DID, standard-base64 of the 39-byte form —
    /// the same shape migration stores in `VaultConfig.web_agent_pub_key`.
    /// None for born-device-hosted accounts. Only `restore_device_identity`
    /// fills this in.
    pub web_agent_pub_key: Option<String>,
}

/// Shared vault-grant flow: fetch a challenge, sign it raw with the device seed,
/// trade the signature for a JWT.
async fn vault_grant(
    api_url: &str,
    device_seed: &[u8; 32],
    agent_b64: &str,
) -> Result<VaultGrantResult, String> {
    // 10s timeout: without one, a HUNG (not refused) API held the restore
    // wizard's spinner forever. Send errors carry the `api_unreachable:`
    // marker — the documented offline signal alongside `unknown_agent_key`
    // and `not_device_hosted` in the error contract.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client build failed: {}", e))?;
    let base = api_url.trim_end_matches('/');

    let resp = client
        .post(format!("{}/auth/vault/challenge", base))
        .json(&serde_json::json!({ "client_id": VAULT_CLIENT_ID }))
        .send()
        .await
        .map_err(|e| format!("api_unreachable: challenge request failed: {}", e))?;
    let status = resp.status();
    #[derive(Deserialize)]
    struct ChallengeResp {
        challenge: Option<String>,
        error: Option<String>,
    }
    let ch: ChallengeResp = resp
        .json()
        .await
        .map_err(|e| format!("Challenge parse failed: {}", e))?;
    if !status.is_success() {
        return Err(format!(
            "challenge_failed: {} [{}]",
            ch.error.unwrap_or_default(),
            status.as_u16()
        ));
    }
    let challenge = ch.challenge.ok_or("Challenge response missing challenge")?;

    // Domain separation: the challenge string is signed exactly as received.
    let signature = base64_standard_encode(&sign_with_device_seed(
        device_seed,
        challenge.as_bytes(),
    ));

    let resp = client
        .post(format!("{}/auth/vault/token", base))
        .json(&serde_json::json!({
            "challenge": challenge,
            "agent_pub_key": agent_b64,
            "signature": signature,
        }))
        .send()
        .await
        .map_err(|e| format!("api_unreachable: token request failed: {}", e))?;
    let status = resp.status();
    let body: ApiEnvelope = resp
        .json()
        .await
        .map_err(|e| format!("Token response parse failed: {}", e))?;
    if !status.is_success() {
        // Preserve the machine-readable code — the restore path branches on it.
        return Err(api_error(status, &body, "vault_grant_failed"));
    }

    let user = body.user.ok_or("Token response missing user")?;
    Ok(VaultGrantResult {
        token: body.token.ok_or("Token response missing token")?,
        did: user.did.unwrap_or_default(),
        agent_pub_key: user.agent_pub_key.unwrap_or_default(),
        display_name: user.display_name,
        username: user.username,
        profile_picture: user.profile_picture,
        web_agent_pub_key: None,
    })
}

/// Vault-grant with explicit key material — used by the account-migration
/// flow (and its staging test) where the seed is derived from the phrase
/// in hand rather than read from an unlocked vault.
pub(crate) async fn vault_grant_with_seed(
    api_url: &str,
    device_seed: &[u8; 32],
    agent_b64: &str,
) -> Result<VaultGrantResult, String> {
    vault_grant(api_url, device_seed, agent_b64).await
}

/// Authenticate the unlocked vault's device identity with the API.
/// Usable any time post-unlock (e.g. to refresh a session for API calls).
#[tauri::command]
pub async fn vault_grant_login(
    api_url: String,
    state: State<'_, Arc<AppState>>,
) -> Result<VaultGrantResult, String> {
    let (seed_vec, agent_b64) = {
        let config = state.vault_config.lock().unwrap();
        let cfg = config.as_ref().ok_or("Vault is locked")?;
        (
            cfg.device_seed.clone().ok_or("No device seed in vault")?,
            cfg.agent_pub_key_raw_b64
                .clone()
                .ok_or("No raw agent key in vault")?,
        )
    };
    let mut seed = [0u8; 32];
    if seed_vec.len() != 32 {
        return Err("Invalid device seed length".into());
    }
    seed.copy_from_slice(&seed_vec);

    let result = vault_grant(&api_url, &seed, &agent_b64).await?;

    // Self-heal for migrated vaults whose config lacks the original web
    // agent key — the account DID still embeds it.
    let needs_web_key = {
        let config = state.vault_config.lock().unwrap();
        config
            .as_ref()
            .map(|c| {
                c.hosting_model.as_deref() == Some("device-hosted")
                    && c.web_agent_pub_key.is_none()
            })
            .unwrap_or(false)
    };
    if needs_web_key {
        if let Some(key_b64) = derive_legacy_web_key(&result.did, &agent_b64) {
            log::info!("Recovered legacy web agent key from account DID — persisting");
            crate::commands::persist_web_agent_pub_key(state.inner(), &key_b64);
        }
    }

    Ok(result)
}

/// Reconcile the account layer after an OFFLINE restore: one A4 grant
/// fills the fields the offline path couldn't fetch (username, display
/// name, picture, legacy web key), then clears `pending_reconcile`.
///
/// Cadence contract (API-audit): the challenge endpoint allows 20/15min
/// per IP and every SUCCESSFUL grant writes an auth_events row — so this
/// is attempted once per conductor start plus once when the frontend
/// sees the API come back online. Never a poll loop.
///
/// Fill rule: only-None fields — offline in-app edits are never
/// clobbered.
pub(crate) async fn reconcile_account_layer(
    state: &Arc<AppState>,
    api_url: &str,
    app_handle: &tauri::AppHandle,
) {
    use tauri::Emitter;

    let (pending, seed_vec, agent_b64) = {
        let config = state.vault_config.lock().unwrap();
        match config.as_ref() {
            Some(c) => (
                c.pending_reconcile,
                c.device_seed.clone(),
                c.agent_pub_key_raw_b64.clone(),
            ),
            None => (false, None, None),
        }
    };
    if !pending {
        return;
    }
    let (Some(seed_vec), Some(agent_b64)) = (seed_vec, agent_b64) else {
        return;
    };
    if seed_vec.len() != 32 {
        return;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_vec);

    match vault_grant(api_url, &seed, &agent_b64).await {
        Ok(grant) => {
            let legacy_web_key = derive_legacy_web_key(&grant.did, &agent_b64);

            // Persist under the cached passphrase (set_web_email pattern).
            let passphrase = {
                let mut guard = state.unlock_passphrase.lock().unwrap();
                guard
                    .as_mut()
                    .and_then(|arr| String::from_utf8(arr.lock().to_vec()).ok())
            };
            let Some(pw) = passphrase else {
                log::warn!("[reconcile] skipped: no cached passphrase");
                return;
            };
            let vault_path = state.vault_path.lock().unwrap().clone();
            {
                let mut config = state.vault_config.lock().unwrap();
                if let Some(cfg) = config.as_mut() {
                    if cfg.display_name.is_none() {
                        cfg.display_name = grant.display_name.clone();
                    }
                    if cfg.web_username.is_none() {
                        cfg.web_username = grant.username.clone();
                    }
                    if cfg.profile_picture.is_none() {
                        cfg.profile_picture = grant.profile_picture.clone();
                    }
                    if cfg.web_agent_pub_key.is_none() {
                        cfg.web_agent_pub_key = legacy_web_key.clone();
                    }
                    cfg.pending_reconcile = false;
                    match crate::vault::encrypt_vault(cfg, &pw) {
                        Ok(mut encrypted) => {
                            encrypted.display_email =
                                cfg.web_email.clone().or(cfg.web_username.clone());
                            if let Err(e) = crate::vault::save_vault(&vault_path, &encrypted) {
                                log::warn!("[reconcile] persist failed (non-fatal): {}", e);
                            }
                        }
                        Err(e) => log::warn!("[reconcile] encrypt failed (non-fatal): {}", e),
                    }
                }
            }
            if let Some(ref key) = legacy_web_key {
                *state.linked_web_agent_key.lock().unwrap() = Some(key.clone());
            }
            // The frontend refetches profile + signatures on this event.
            let _ = app_handle.emit("profile-synced", ());
            log::info!("[reconcile] account layer reattached — pending_reconcile cleared");
        }
        Err(e) if e.contains("api_unreachable") => {
            log::info!("[reconcile] API still unreachable — retrying on next unlock/online");
        }
        Err(e) if e.contains("unknown_agent_key") => {
            // Offline-restored phrase with no registered account. Leave the
            // flag set: Build 2's deferred registration is the eventual
            // answer; retries are cheap (failed grants write nothing).
            log::info!("[reconcile] no Flowsta account for this identity yet — leaving pending");
        }
        Err(e) if e.contains("not_device_hosted") => {
            log::warn!(
                "[reconcile] this phrase belongs to a custodial flowsta.com account — \
                 restore online (or sign in with the Flowsta account) to upgrade it"
            );
        }
        Err(e) => log::warn!("[reconcile] grant failed: {}", e),
    }
}

/// Frontend-triggered reconcile attempt — invoked when the connectivity
/// poll observes the API coming back online (and harmless any other
/// time: no-ops instantly unless `pending_reconcile` is set).
#[tauri::command]
pub async fn attempt_account_reconcile(
    api_url: String,
    app_handle: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    reconcile_account_layer(state.inner(), &api_url, &app_handle).await;
    Ok(())
}

/// If `did` embeds an agent key DIFFERENT from ours, return it in the
/// vault-config shape (standard base64 of the 39-byte key). A migrated
/// account's DID carries its original (pre-upgrade) web agent key; a
/// born-device-hosted account's DID embeds the device key itself.
pub(crate) fn derive_legacy_web_key(did: &str, device_agent_b64: &str) -> Option<String> {
    let did_key = did.strip_prefix("did:flowsta:")?;
    let did_39 = decode_agent_pub_key_flexible(did_key)?;
    let device = crate::commands::base64_standard_decode(device_agent_b64).ok()?;
    if device.len() != 39 || did_39[3..35] == device[3..35] {
        return None;
    }
    Some(base64_standard_encode(&did_39))
}

/// Startup self-heal: recover a migrated account's original web agent key
/// from its DID when the vault config lacks it (phrase restores that
/// predate the wizard-side recovery). Runs after conductor startup; cheap
/// no-op when nothing is missing, silent no-op offline.
pub(crate) async fn heal_web_agent_key_from_did(
    state: &std::sync::Arc<crate::AppState>,
    api_url: &str,
) {
    let (needs, seed_vec, agent_b64) = {
        let config = state.vault_config.lock().unwrap();
        match config.as_ref() {
            Some(c) => (
                c.hosting_model.as_deref() == Some("device-hosted")
                    && c.web_agent_pub_key.is_none(),
                c.device_seed.clone(),
                c.agent_pub_key_raw_b64.clone(),
            ),
            None => (false, None, None),
        }
    };
    if !needs {
        return;
    }
    let (Some(seed_vec), Some(agent_b64)) = (seed_vec, agent_b64) else {
        return;
    };
    if seed_vec.len() != 32 {
        return;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_vec);

    match vault_grant(api_url, &seed, &agent_b64).await {
        Ok(grant) => {
            if let Some(key_b64) = derive_legacy_web_key(&grant.did, &agent_b64) {
                log::info!("Recovered legacy web agent key from account DID — persisting");
                crate::commands::persist_web_agent_pub_key(state, &key_b64);
            } else {
                log::info!("Web-key heal: DID matches device key (born device-hosted) — nothing to recover");
            }
        }
        Err(e) => log::info!("Web-key heal grant skipped (offline?): {}", e),
    }
}

/// Restore a device-hosted identity from the recovery phrase alone.
/// Derives the key, proves it via challenge-response, and returns the account's
/// public profile so the wizard can rebuild local state. Never re-registers.
///
/// Error contract for the wizard:
/// - contains `unknown_agent_key` -> no device-hosted account for this phrase
/// - contains `not_device_hosted` -> phrase belongs to a custodial web account
///   (use the restore-from-web sign-in path instead)
/// - contains `api_unreachable` -> Flowsta's API can't be reached — offer the
///   OFFLINE restore (identity rebuilds locally; account layer reconciles
///   when the API returns)
#[tauri::command]
pub async fn restore_device_identity(
    api_url: String,
    mnemonic: String,
) -> Result<VaultGrantResult, String> {
    if !validate_mnemonic(&mnemonic) {
        return Err("Invalid recovery phrase".into());
    }
    let signing_key =
        derive_device_keypair(&mnemonic).map_err(|e| format!("Key derivation failed: {}", e))?;
    let pub_key_bytes = signing_key.verifying_key().to_bytes();
    let device_39 = construct_agent_pub_key_bytes(&pub_key_bytes);
    let agent_b64 = base64_standard_encode(&device_39);
    let device_seed = derive_seed(&mnemonic, DEVICE_1_CONSTANT)
        .map_err(|e| format!("Device seed derivation failed: {}", e))?;

    let mut result = vault_grant(&api_url, &device_seed, &agent_b64).await?;

    // A migrated account keeps the DID minted for its ORIGINAL web agent
    // key; a born-device-hosted account's DID embeds the device key. When
    // the DID's key differs from ours, it is the legacy web agent — the
    // handle to the account's pre-upgrade signatures. Migration persists
    // it in the vault config; a phrase restore must recover it here or
    // linked-signature reads start from a cold DHT walk instead.
    result.web_agent_pub_key = derive_legacy_web_key(&result.did, &agent_b64);
    if result.web_agent_pub_key.is_some() {
        log::info!("Restore: DID carries a legacy web agent key (migrated account)");
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAGING: &str = "https://auth-api-staging.flowsta.com";

    /// Full register + restore contract test against the live STAGING API using the real
    /// derivation + signing code. Ignored by default — run explicitly:
    /// `cargo test --lib device_identity -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn test_register_and_restore_against_staging() {
        // Fresh phrase
        let mnemonic = generate_new_mnemonic().unwrap();
        assert_eq!(mnemonic.split(' ').count(), 24);

        let email = format!(
            "btest-{}@example.com",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );

        // Register
        let reg = register_device_identity(
            STAGING.into(),
            mnemonic.clone(),
            email.clone(),
            Some("Device Test".into()),
        )
        .await
        .expect("registration should succeed");
        assert!(reg.did.starts_with("did:flowsta:uhCAk"), "did: {}", reg.did);
        assert!(!reg.user_id.is_empty());

        // Duplicate registration must be rejected (409 — restore is the re-entry path)
        let dup = register_device_identity(
            STAGING.into(),
            mnemonic.clone(),
            email.clone(),
            None,
        )
        .await;
        assert!(
            dup.as_ref().err().map(|e| e.contains("agent_key_already_registered")).unwrap_or(false),
            "duplicate registration must 409: {:?}",
            dup.as_ref().err()
        );

        // Restore from phrase alone (challenge-response)
        let restored = restore_device_identity(STAGING.into(), mnemonic.clone())
            .await
            .expect("restore should succeed");
        assert_eq!(restored.did, reg.did, "restore must recover the SAME identity");
        assert_eq!(restored.display_name.as_deref(), Some("Device Test"));
        assert!(!restored.token.is_empty(), "restore must yield a session token");

        // A wrong phrase must NOT find an account
        let other = generate_new_mnemonic().unwrap();
        let miss = restore_device_identity(STAGING.into(), other).await;
        assert!(
            miss.as_ref().err().map(|e| e.contains("unknown_agent_key")).unwrap_or(false),
            "unknown phrase must be rejected: {:?}",
            miss.as_ref().err()
        );

        // C3: the web phrase-reset path must refuse this device-hosted account.
        // The server recomputes the lookup hash from the phrase, so this uses
        // the real cross-language derivation — a faithful end-to-end check.
        let reset = reqwest::Client::new()
            .post(format!("{}/auth/reset-password-with-phrase", STAGING))
            .json(&serde_json::json!({
                "recoveryPhrase": mnemonic,
                "newPassword": "irrelevant-should-be-refused-1",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            reset.status().as_u16(),
            403,
            "device-hosted phrase-reset must be refused"
        );
        let reset_body: serde_json::Value = reset.json().await.unwrap();
        assert_eq!(
            reset_body["error"], "device_hosted_account",
            "reset refusal reason: {:?}",
            reset_body
        );
    }
}
