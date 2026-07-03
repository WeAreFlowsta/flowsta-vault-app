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
    derive_device_keypair, derive_recovery_lookup_hash, derive_seed, sign_with_device_seed,
    validate_mnemonic, DEVICE_1_CONSTANT,
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
}

/// Shared vault-grant flow: fetch a challenge, sign it raw with the device seed,
/// trade the signature for a JWT.
async fn vault_grant(
    api_url: &str,
    device_seed: &[u8; 32],
    agent_b64: &str,
) -> Result<VaultGrantResult, String> {
    let client = reqwest::Client::new();
    let base = api_url.trim_end_matches('/');

    let resp = client
        .post(format!("{}/auth/vault/challenge", base))
        .json(&serde_json::json!({ "client_id": VAULT_CLIENT_ID }))
        .send()
        .await
        .map_err(|e| format!("Challenge request failed: {}", e))?;
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
        .map_err(|e| format!("Token request failed: {}", e))?;
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

    vault_grant(&api_url, &seed, &agent_b64).await
}

/// Restore a device-hosted identity from the recovery phrase alone.
/// Derives the key, proves it via challenge-response, and returns the account's
/// public profile so the wizard can rebuild local state. Never re-registers.
///
/// Error contract for the wizard:
/// - contains `unknown_agent_key` -> no device-hosted account for this phrase
/// - contains `not_device_hosted` -> phrase belongs to a custodial web account
///   (use the restore-from-web sign-in path instead)
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
    let agent_b64 = base64_standard_encode(&construct_agent_pub_key_bytes(&pub_key_bytes));
    let device_seed = derive_seed(&mnemonic, DEVICE_1_CONSTANT)
        .map_err(|e| format!("Device seed derivation failed: {}", e))?;

    vault_grant(&api_url, &device_seed, &agent_b64).await
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
