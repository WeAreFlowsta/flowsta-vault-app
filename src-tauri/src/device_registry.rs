//! This device, as Flowsta's servers know it.
//!
//! An identity can live on several devices. Each device registers the key
//! its conductor runs, signs beside the identity key when it signs in, and
//! can be removed by another of the identity's devices. That is all the
//! server is told: keys, a random install id, what the device may do, a
//! time and signatures. A device's name, its operating system, its Vault
//! version and when it was last used are never sent - they stay in the
//! identity's own encrypted records (`devices.rs`). The tests at the foot
//! of this file pin the exact fields of every request.

use crate::commands::AppState;
use crate::key_derivation::{
    base64_standard_encode, holo_agent_pub_key_bytes, public_key_of_seed, sign_with_device_seed,
};
use std::sync::{Arc, Mutex};

pub const REGISTER_PREFIX: &str = "flowsta-device-register:v1:";
pub const REMOVE_PREFIX: &str = "flowsta-device-remove:v1:";
pub const COSIGN_PREFIX: &str = "flowsta-device-cosign:v1:";
pub const ENROLLMENT_PREFIX: &str = "flowsta-enrollment-register:v1:";

/// What a Vault device may do, in the order the server expects.
const VAULT_CAPABILITIES: [&str; 4] = ["approve", "login", "read", "sign"];

/// The seed this device co-signs sign-ins with (the seed its conductor
/// runs) while a vault is unlocked. Cleared on lock.
static DEVICE_SIGNER: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// How this device stands with the identity's account, as the last
/// registration answered.
#[derive(serde::Serialize, Clone, Debug, PartialEq, Default)]
pub struct Standing {
    /// "unknown" (not asked yet, or offline), "registered", or
    /// "needs_confirming" (the account wants the recovery phrase or another
    /// device's approval before it counts this device).
    pub device: &'static str,
    /// The account's enrollment key: "none", "waiting" (registered, not in
    /// force yet) or "in_force". `None` until the account has answered.
    pub enrollment: Option<&'static str>,
}

static STANDING: Mutex<Standing> = Mutex::new(Standing { device: "unknown", enrollment: None });

/// What a registration answer says about this device.
pub(crate) fn standing_from(http_status: u16, body: &serde_json::Value) -> Option<Standing> {
    if (200..300).contains(&http_status) {
        let enrollment = match body.get("enrollment") {
            Some(e) if e.is_object() => {
                if e.get("in_force").and_then(|v| v.as_bool()) == Some(true) { "in_force" } else { "waiting" }
            }
            _ => "none",
        };
        return Some(Standing { device: "registered", enrollment: Some(enrollment) });
    }
    (body.get("error").and_then(|e| e.as_str()) == Some("approval_required"))
        .then_some(Standing { device: "needs_confirming", enrollment: Some("in_force") })
}

/// For Settings → Devices.
#[tauri::command]
pub fn device_standing() -> Standing {
    STANDING.lock().unwrap().clone()
}

pub(crate) fn set_device_signer(seed: Option<[u8; 32]>) {
    if seed.is_none() {
        *STANDING.lock().unwrap() = Standing { device: "unknown", enrollment: None };
    }
    let mut slot = DEVICE_SIGNER.lock().unwrap();
    if let Some(old) = slot.as_mut() {
        old.fill(0);
    }
    *slot = seed;
}

/// The enrollment seed, held in memory from the moment the recovery phrase
/// is typed until this device has registered with it (or the vault locks).
/// Never written to disk.
static ENROLLMENT_SEED: Mutex<Option<[u8; 32]>> = Mutex::new(None);

fn set_enrollment_seed(seed: Option<[u8; 32]>) {
    let mut slot = ENROLLMENT_SEED.lock().unwrap();
    if let Some(old) = slot.as_mut() {
        old.fill(0);
    }
    *slot = seed;
}

/// The phrase was just typed: keep its enrollment seed until this device
/// has registered.
pub(crate) fn hold_enrollment_from_phrase(mnemonic: &str) {
    if let Ok(seed) = crate::key_derivation::derive_seed(mnemonic, crate::key_derivation::ENROLLMENT_CONSTANT) {
        set_enrollment_seed(Some(seed));
    }
}

/// The approval of the device that added this one with a code, held until
/// this device has registered with it. It is good for a few minutes.
static APPROVAL: Mutex<Option<Approval>> = Mutex::new(None);

pub(crate) fn hold_approval(approval: Option<Approval>) {
    *APPROVAL.lock().unwrap() = approval;
}

pub(crate) fn forget_enrollment_seed() {
    set_enrollment_seed(None);
}

/// The enrollment key (standard base64 of its 32 bytes) and its signature
/// over the enrollment message for this identity key and time.
pub(crate) fn enrollment_fields(identity_public: &[u8; 32], enrollment_seed: &[u8; 32], timestamp: u64) -> (String, String) {
    let enrollment_key = key32(&public_key_of_seed(enrollment_seed));
    let message = format!("{}{}:{}:{}", ENROLLMENT_PREFIX, key32(identity_public), enrollment_key, timestamp);
    (
        enrollment_key,
        base64_standard_encode(&sign_with_device_seed(enrollment_seed, message.as_bytes())),
    )
}

/// The body of `POST /auth/devices/enrollment`.
pub(crate) fn enrollment_body(
    identity_agent_b64: &str,
    identity_seed: &[u8; 32],
    enrollment_seed: &[u8; 32],
    now_ms: u64,
) -> serde_json::Value {
    let identity_public = public_key_of_seed(identity_seed);
    let (enrollment_key, enrollment_signature) = enrollment_fields(&identity_public, enrollment_seed, now_ms);
    let message = format!("{}{}:{}:{}", ENROLLMENT_PREFIX, key32(&identity_public), enrollment_key, now_ms);
    serde_json::json!({
        "identity_key": identity_agent_b64,
        "enrollment_key": enrollment_key,
        "timestamp": now_ms.to_string(),
        "identity_signature": base64_standard_encode(&sign_with_device_seed(identity_seed, message.as_bytes())),
        "enrollment_signature": enrollment_signature,
    })
}

/// Standard base64 of a key's 32 bytes.
fn key32(public: &[u8; 32]) -> String {
    base64_standard_encode(public)
}

/// Standard base64 of the 39-byte agent key (network form) of a seed.
fn agent_key_b64(seed: &[u8; 32]) -> String {
    base64_standard_encode(&holo_agent_pub_key_bytes(&public_key_of_seed(seed)))
}

/// The two fields a sign-in carries for this device: its key and its
/// signature over the challenge under the device prefix.
pub(crate) fn cosign_with(seed: &[u8; 32], challenge: &str) -> (String, String) {
    let message = format!("{}{}", COSIGN_PREFIX, challenge);
    (
        agent_key_b64(seed),
        base64_standard_encode(&sign_with_device_seed(seed, message.as_bytes())),
    )
}

/// The same, with the device signer of the unlocked vault. `None` while
/// locked or before a vault exists (a sign-in then names no device).
pub(crate) fn cosign(challenge: &str) -> Option<(String, String)> {
    let seed = (*DEVICE_SIGNER.lock().unwrap())?;
    Some(cosign_with(&seed, challenge))
}

/// The message every signature of a registration is over.
fn registration_message(identity_public: &[u8; 32], device_public: &[u8; 32], install_id: &str, now_ms: u64) -> String {
    format!(
        "{}{}:{}:{}:{}:{}",
        REGISTER_PREFIX,
        key32(identity_public),
        key32(device_public),
        install_id,
        VAULT_CAPABILITIES.join(","),
        now_ms
    )
}

/// A device of the identity vouching for a new one: its key, its signature
/// over the new device's registration message, and the time in it.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct Approval {
    pub approver_key: String,
    pub approver_signature: String,
    pub timestamp: u64,
}

/// This device approves a new device of the same identity.
pub(crate) fn approve_device(
    identity_public: &[u8; 32],
    approver_seed: &[u8; 32],
    new_device_public: &[u8; 32],
    install_id: &str,
    now_ms: u64,
) -> Approval {
    let message = registration_message(identity_public, new_device_public, install_id, now_ms);
    Approval {
        approver_key: agent_key_b64(approver_seed),
        approver_signature: base64_standard_encode(&sign_with_device_seed(approver_seed, message.as_bytes())),
        timestamp: now_ms,
    }
}

/// The body of `POST /auth/devices/register`. With the enrollment seed in
/// hand (the phrase was typed on this device) its signature goes with it.
pub(crate) fn registration_body(
    identity_agent_b64: &str,
    identity_seed: &[u8; 32],
    device_seed: &[u8; 32],
    install_id: &str,
    now_ms: u64,
    enrollment_seed: Option<&[u8; 32]>,
) -> serde_json::Value {
    let message = registration_message(
        &public_key_of_seed(identity_seed),
        &public_key_of_seed(device_seed),
        install_id,
        now_ms,
    );
    let mut body = serde_json::json!({
        "identity_key": identity_agent_b64,
        "device_key": agent_key_b64(device_seed),
        "install_id": install_id,
        "capabilities": VAULT_CAPABILITIES,
        "timestamp": now_ms.to_string(),
        "identity_signature": base64_standard_encode(&sign_with_device_seed(identity_seed, message.as_bytes())),
        "device_signature": base64_standard_encode(&sign_with_device_seed(device_seed, message.as_bytes())),
    });
    if let Some(seed) = enrollment_seed {
        body["enrollment_signature"] =
            serde_json::json!(base64_standard_encode(&sign_with_device_seed(seed, message.as_bytes())));
    }
    body
}

/// The same request, backed by a device that approved this one (adding a
/// device with a code). The time is the one the approver signed.
pub(crate) fn approved_registration_body(
    identity_agent_b64: &str,
    identity_seed: &[u8; 32],
    device_seed: &[u8; 32],
    install_id: &str,
    approval: &Approval,
) -> serde_json::Value {
    let mut body = registration_body(identity_agent_b64, identity_seed, device_seed, install_id, approval.timestamp, None);
    body["approver_key"] = serde_json::json!(approval.approver_key);
    body["approver_signature"] = serde_json::json!(approval.approver_signature);
    body
}

/// The body of `POST /auth/devices/remove`. `target_key` is the 32-byte key
/// of the device to remove, standard base64 (as the server lists it).
pub(crate) fn removal_body(
    identity_agent_b64: &str,
    identity_seed: &[u8; 32],
    device_seed: &[u8; 32],
    target_key: &str,
    now_ms: u64,
) -> Result<serde_json::Value, String> {
    let target = crate::commands::base64_standard_decode(target_key).map_err(|_| "bad device key")?;
    let target: [u8; 32] = target.as_slice().try_into().map_err(|_| "bad device key")?;
    let message = format!(
        "{}{}:{}:{}",
        REMOVE_PREFIX,
        key32(&public_key_of_seed(identity_seed)),
        key32(&target),
        now_ms
    );
    Ok(serde_json::json!({
        "identity_key": identity_agent_b64,
        "device_key": base64_standard_encode(&holo_agent_pub_key_bytes(&target)),
        "actor_key": agent_key_b64(device_seed),
        "timestamp": now_ms.to_string(),
        "identity_signature": base64_standard_encode(&sign_with_device_seed(identity_seed, message.as_bytes())),
        "actor_signature": base64_standard_encode(&sign_with_device_seed(device_seed, message.as_bytes())),
    }))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct Keys {
    identity_agent_b64: String,
    identity_seed: [u8; 32],
    device_seed: [u8; 32],
}

/// The keys of the unlocked, device-hosted vault; `None` otherwise.
fn keys(state: &AppState) -> Option<Keys> {
    let config = state.vault_config.lock().unwrap();
    let cfg = config.as_ref()?;
    if cfg.hosting_model.as_deref() != Some("device-hosted") {
        return None;
    }
    Some(Keys {
        identity_agent_b64: cfg.agent_pub_key_raw_b64.clone()?,
        identity_seed: <[u8; 32]>::try_from(cfg.device_seed.as_deref()?).ok()?,
        device_seed: cfg.conductor_seed_bytes()?,
    })
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client build failed: {}", e))
}

/// The conductor seed made for a device that is being set up for an
/// identity that already exists (the phrase door registers the device
/// before its vault is written). Taken by setup.
static JOINING_SEED: Mutex<Option<[u8; 32]>> = Mutex::new(None);

pub(crate) fn hold_joining_seed(seed: [u8; 32]) {
    *JOINING_SEED.lock().unwrap() = Some(seed);
}

pub(crate) fn take_joining_seed() -> Option<[u8; 32]> {
    JOINING_SEED.lock().unwrap().take()
}

/// Register a device whose vault does not exist yet: the phrase door, where
/// the recovery phrase is in hand. Registers the enrollment key as well.
/// Errors carry the server's word (`unknown_agent_key`, `not_device_hosted`,
/// `api_unreachable`, ...) for the wizard to act on.
pub(crate) async fn register_new_device(
    api_url: &str,
    identity_agent_b64: &str,
    identity_seed: &[u8; 32],
    device_seed: &[u8; 32],
    install_id: &str,
    enrollment_seed: &[u8; 32],
) -> Result<(), String> {
    let base = api_url.trim_end_matches('/');
    let body = enrollment_body(identity_agent_b64, identity_seed, enrollment_seed, now_ms());
    let _ = client()?.post(format!("{}/auth/devices/enrollment", base)).json(&body).send().await;
    let body = registration_body(identity_agent_b64, identity_seed, device_seed, install_id, now_ms(), Some(enrollment_seed));
    send_registration(base, &body).await.map(|_| ())
}

/// Post a registration and read the answer. Ok(true) = the server knows the
/// device now.
async fn send_registration(base: &str, body: &serde_json::Value) -> Result<bool, String> {
    let resp = client()?
        .post(format!("{}/auth/devices/register", base))
        .json(body)
        .send()
        .await
        .map_err(|e| format!("api_unreachable: {}", e))?;
    let status = resp.status();
    let answer = resp.json::<serde_json::Value>().await.unwrap_or_default();
    if let Some(standing) = standing_from(status.as_u16(), &answer) {
        *STANDING.lock().unwrap() = standing;
    }
    if status.is_success() {
        return Ok(true);
    }
    let error = answer.get("error").and_then(|e| e.as_str()).unwrap_or_default();
    Err(format!("{} [{}]", error, status.as_u16()))
}

/// Register this device with the identity's account. Safe to repeat: the
/// server answers the same for a device it already knows. Returns whether
/// the server knows this device now.
pub async fn register_this_device(state: &Arc<AppState>, api_url: &str) -> Result<bool, String> {
    let Some(keys) = keys(state) else {
        return Ok(false);
    };
    let install_id = crate::paths::install_id(&state.data_dir).ok_or("no install id")?;
    let base = api_url.trim_end_matches('/');
    let enrollment_seed = *ENROLLMENT_SEED.lock().unwrap();
    if let Some(seed) = enrollment_seed.as_ref() {
        // The identity's enrollment key, when the account does not have it
        // yet. Whatever the answer, the registration below decides.
        let body = enrollment_body(&keys.identity_agent_b64, &keys.identity_seed, seed, now_ms());
        let _ = client()?.post(format!("{}/auth/devices/enrollment", base)).json(&body).send().await;
    }
    let approval = APPROVAL.lock().unwrap().clone();
    let body = match approval.as_ref() {
        Some(approval) => approved_registration_body(
            &keys.identity_agent_b64,
            &keys.identity_seed,
            &keys.device_seed,
            &install_id,
            approval,
        ),
        None => registration_body(
            &keys.identity_agent_b64,
            &keys.identity_seed,
            &keys.device_seed,
            &install_id,
            now_ms(),
            enrollment_seed.as_ref(),
        ),
    };
    let sent = send_registration(base, &body).await;
    match sent {
        Ok(known) => {
            forget_enrollment_seed();
            hold_approval(None);
            Ok(known)
        }
        Err(e) => {
            if approval.is_some() {
                // An approval that was not accepted is not tried again.
                hold_approval(None);
            }
            Err(e)
        }
    }
}

/// What typing the recovery phrase once did.
#[derive(serde::Serialize, Debug, PartialEq)]
pub struct PhraseOnce {
    /// This device now holds keys it was missing (an older setup).
    pub keys_added: bool,
    pub standing: Standing,
}

/// The recovery phrase, typed once on a device that already holds the
/// identity: registers the identity's enrollment key (so only the phrase or
/// one of its devices can add a device), confirms this device with it, and
/// fills in keys an older setup did not keep. The phrase is not stored.
#[tauri::command]
pub async fn use_recovery_phrase_once(
    api_url: String,
    mnemonic: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<PhraseOnce, String> {
    use_recovery_phrase_once_inner(api_url, mnemonic, state.inner()).await
}

pub(crate) async fn use_recovery_phrase_once_inner(api_url: String, mnemonic: String, state: &Arc<AppState>) -> Result<PhraseOnce, String> {
    let mnemonic = crate::migration::normalize_mnemonic(&mnemonic);
    let keys = crate::commands::IdentityKeys::from_phrase(&mnemonic).map_err(|_| "Invalid recovery phrase. Please check your words.".to_string())?;
    let keys_added = {
        let mut config = state.vault_config.lock().unwrap();
        let cfg = config.as_mut().ok_or("Vault is locked")?;
        if cfg.device_seed.as_deref() != Some(keys.identity_seed.as_slice()) {
            return Err("That recovery phrase belongs to a different identity.".into());
        }
        let mut added = false;
        if cfg.hosting_model.as_deref() == Some("device-hosted") {
            if cfg.backup_key.is_none() {
                cfg.backup_key = Some(keys.backup_key.to_vec());
                added = true;
            }
            if cfg.data_key.is_none() {
                cfg.data_key = Some(keys.data_key.to_vec());
                added = true;
            }
            if cfg.private_network_seed.is_none() {
                cfg.private_network_seed = Some(keys.private_network_seed.clone());
                added = true;
            }
            if cfg.recovery_lookup_hash.is_none() {
                cfg.recovery_lookup_hash = keys.recovery_lookup_hash.clone();
                added = true;
            }
        }
        added
    };
    if keys_added {
        crate::commands::persist_config_now(state)?;
        *state.backup_key_identity.lock().unwrap() = Some(keys.backup_key);
    }
    hold_enrollment_from_phrase(&mnemonic);
    let registered = register_this_device(state, &api_url).await;
    forget_enrollment_seed();
    match registered {
        Ok(_) => Ok(PhraseOnce { keys_added, standing: device_standing() }),
        Err(e) if e.starts_with("api_unreachable") => Err("Couldn't reach Flowsta. Check your connection and try again.".into()),
        Err(e) => Err(format!("That did not work ({}). Try again.", e)),
    }
}

/// Remove a device of this identity. `target_key` as the server lists it.
pub async fn remove_device(state: &Arc<AppState>, api_url: &str, target_key: &str) -> Result<(), String> {
    let keys = keys(state).ok_or("Vault is locked")?;
    let body = removal_body(&keys.identity_agent_b64, &keys.identity_seed, &keys.device_seed, target_key, now_ms())?;
    let resp = client()?
        .post(format!("{}/auth/devices/remove", api_url.trim_end_matches('/')))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("api_unreachable: {}", e))?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let error = resp
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
        .unwrap_or_default();
    Err(format!("{} [{}]", error, status.as_u16()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    const IDENTITY: [u8; 32] = [1u8; 32];
    const DEVICE: [u8; 32] = [2u8; 32];
    const ENROLLMENT: [u8; 32] = [4u8; 32];
    const INSTALL: &str = "0123456789abcdef0123456789abcdef";

    fn keys_of(value: &serde_json::Value) -> Vec<String> {
        let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        keys
    }

    fn verifies(seed: &[u8; 32], message: &str, signature_b64: &str) -> bool {
        let key = VerifyingKey::from_bytes(&public_key_of_seed(seed)).unwrap();
        let bytes = crate::commands::base64_standard_decode(signature_b64).unwrap();
        let signature = Signature::from_slice(&bytes).unwrap();
        key.verify(message.as_bytes(), &signature).is_ok()
    }

    /// What registering a device tells the server, and nothing else. A
    /// field added here (a name, a platform, a version, a last-used time)
    /// must fail this test.
    #[test]
    fn a_registration_sends_only_keys_an_install_id_capabilities_a_time_and_signatures() {
        let body = registration_body("IDENTITY39", &IDENTITY, &DEVICE, INSTALL, 1_790_000_000_000, None);
        assert_eq!(
            keys_of(&body),
            ["capabilities", "device_key", "device_signature", "identity_key", "identity_signature", "install_id", "timestamp"]
        );
        assert_eq!(body["capabilities"], serde_json::json!(["approve", "login", "read", "sign"]));
        assert_eq!(body["install_id"], INSTALL);
        assert_eq!(body["identity_key"], "IDENTITY39");
        let message = format!(
            "flowsta-device-register:v1:{}:{}:{}:approve,login,read,sign:1790000000000",
            key32(&public_key_of_seed(&IDENTITY)),
            key32(&public_key_of_seed(&DEVICE)),
            INSTALL
        );
        assert!(verifies(&IDENTITY, &message, body["identity_signature"].as_str().unwrap()));
        assert!(verifies(&DEVICE, &message, body["device_signature"].as_str().unwrap()));

        // After the phrase was typed, one more signature and nothing else.
        let with_phrase = registration_body("IDENTITY39", &IDENTITY, &DEVICE, INSTALL, 1_790_000_000_000, Some(&ENROLLMENT));
        assert_eq!(
            keys_of(&with_phrase),
            ["capabilities", "device_key", "device_signature", "enrollment_signature", "identity_key", "identity_signature", "install_id", "timestamp"]
        );
        assert!(verifies(&ENROLLMENT, &message, with_phrase["enrollment_signature"].as_str().unwrap()));
    }

    #[test]
    fn a_device_added_with_a_code_registers_with_the_approving_devices_signature() {
        let approver = [5u8; 32];
        let approval = approve_device(&public_key_of_seed(&IDENTITY), &approver, &public_key_of_seed(&DEVICE), INSTALL, 1_790_000_000_000);
        let body = approved_registration_body("IDENTITY39", &IDENTITY, &DEVICE, INSTALL, &approval);
        assert_eq!(
            keys_of(&body),
            ["approver_key", "approver_signature", "capabilities", "device_key", "device_signature", "identity_key", "identity_signature", "install_id", "timestamp"]
        );
        assert_eq!(body["timestamp"], "1790000000000");
        assert_eq!(body["approver_key"], agent_key_b64(&approver));
        let message = registration_message(&public_key_of_seed(&IDENTITY), &public_key_of_seed(&DEVICE), INSTALL, 1_790_000_000_000);
        assert!(verifies(&approver, &message, body["approver_signature"].as_str().unwrap()));
        assert!(verifies(&DEVICE, &message, body["device_signature"].as_str().unwrap()));
    }

    #[test]
    fn a_registration_answer_says_how_this_device_stands() {
        let registered = |enrollment: serde_json::Value| standing_from(200, &serde_json::json!({ "device": {}, "enrollment": enrollment }));
        assert_eq!(registered(serde_json::Value::Null), Some(Standing { device: "registered", enrollment: Some("none") }));
        assert_eq!(registered(serde_json::json!({ "in_force": false })), Some(Standing { device: "registered", enrollment: Some("waiting") }));
        assert_eq!(registered(serde_json::json!({ "in_force": true })), Some(Standing { device: "registered", enrollment: Some("in_force") }));
        assert_eq!(
            standing_from(403, &serde_json::json!({ "error": "approval_required" })),
            Some(Standing { device: "needs_confirming", enrollment: Some("in_force") })
        );
        // Anything else (a limit, an outage, an older server) changes nothing.
        assert_eq!(standing_from(429, &serde_json::json!({ "error": "Too many requests" })), None);
        assert_eq!(standing_from(404, &serde_json::Value::Null), None);
    }

    #[test]
    fn registering_the_enrollment_key_sends_two_keys_a_time_and_two_signatures() {
        let body = enrollment_body("IDENTITY39", &IDENTITY, &ENROLLMENT, 1_790_000_000_000);
        assert_eq!(
            keys_of(&body),
            ["enrollment_key", "enrollment_signature", "identity_key", "identity_signature", "timestamp"]
        );
        assert_eq!(body["enrollment_key"], key32(&public_key_of_seed(&ENROLLMENT)));
        let message = format!(
            "flowsta-enrollment-register:v1:{}:{}:1790000000000",
            key32(&public_key_of_seed(&IDENTITY)),
            key32(&public_key_of_seed(&ENROLLMENT))
        );
        assert!(verifies(&IDENTITY, &message, body["identity_signature"].as_str().unwrap()));
        assert!(verifies(&ENROLLMENT, &message, body["enrollment_signature"].as_str().unwrap()));
    }

    #[test]
    fn the_enrollment_key_is_its_own_derivation_from_the_phrase() {
        use crate::key_derivation::{derive_seed, DEVICE_1_CONSTANT, ENROLLMENT_CONSTANT};
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let enrollment = derive_seed(phrase, ENROLLMENT_CONSTANT).unwrap();
        assert_ne!(enrollment, derive_seed(phrase, DEVICE_1_CONSTANT).unwrap());
        assert_eq!(enrollment, derive_seed(phrase, ENROLLMENT_CONSTANT).unwrap());
        hold_enrollment_from_phrase(phrase);
        assert_eq!(*ENROLLMENT_SEED.lock().unwrap(), Some(enrollment));
        forget_enrollment_seed();
        assert!(ENROLLMENT_SEED.lock().unwrap().is_none());
    }

    #[test]
    fn a_removal_sends_only_keys_a_time_and_signatures() {
        let target = key32(&public_key_of_seed(&[3u8; 32]));
        let body = removal_body("IDENTITY39", &IDENTITY, &DEVICE, &target, 1_790_000_000_000).unwrap();
        assert_eq!(
            keys_of(&body),
            ["actor_key", "actor_signature", "device_key", "identity_key", "identity_signature", "timestamp"]
        );
        let message = format!(
            "flowsta-device-remove:v1:{}:{}:1790000000000",
            key32(&public_key_of_seed(&IDENTITY)),
            target
        );
        assert!(verifies(&IDENTITY, &message, body["identity_signature"].as_str().unwrap()));
        assert!(verifies(&DEVICE, &message, body["actor_signature"].as_str().unwrap()));
        assert!(removal_body("IDENTITY39", &IDENTITY, &DEVICE, "not a key", 1).is_err());
    }

    #[test]
    fn a_sign_in_names_this_device_by_its_key_and_a_signature_under_its_own_prefix() {
        let challenge = "flowsta-auth-challenge:v1:nonce:flowsta";
        let (device_key, signature) = cosign_with(&DEVICE, challenge);
        assert_eq!(device_key, agent_key_b64(&DEVICE));
        assert!(verifies(&DEVICE, &format!("flowsta-device-cosign:v1:{}", challenge), &signature));
        // It is not a signature over the challenge itself.
        assert!(!verifies(&DEVICE, challenge, &signature));
    }

    #[test]
    fn the_device_key_is_sent_in_the_form_the_network_uses() {
        let sent = crate::commands::base64_standard_decode(&agent_key_b64(&DEVICE)).unwrap();
        assert_eq!(sent, holo_agent_pub_key_bytes(&public_key_of_seed(&DEVICE)).to_vec());
    }

    /// The Vault's own requests against a running API (never production):
    /// a new account, both devices registered, a sign-in naming the second
    /// device, its removal, and the sign-in refused afterwards.
    ///   FLOWSTA_TEST_API=https://... cargo test --lib device_registry::tests::live -- --ignored
    #[tokio::test]
    #[ignore]
    async fn live_register_sign_in_remove() {
        use sha2::{Digest, Sha256};
        let api = std::env::var("FLOWSTA_TEST_API").expect("FLOWSTA_TEST_API");
        assert!(!api.contains("//auth-api.flowsta.com"), "not against production");
        let identity = crate::key_derivation::new_conductor_seed();
        let second = crate::key_derivation::new_conductor_seed();
        let identity_agent = agent_key_b64(&identity);
        let http = client().unwrap();
        let post = |path: &str, body: serde_json::Value| {
            let request = http.post(format!("{}{}", api, path)).header("user-agent", "flowsta-vault-test").json(&body);
            async move {
                let resp = request.send().await.unwrap();
                (resp.status().as_u16(), resp.json::<serde_json::Value>().await.unwrap_or_default())
            }
        };

        let email = format!("btest-{}@example.com", now_ms());
        let lookup = hex::encode(Sha256::digest(identity));
        let ts = now_ms() / 1000;
        let message = format!(
            "flowsta-register-identity:v1:{}:{}:{}:{}",
            identity_agent,
            lookup,
            hex::encode(Sha256::digest(email.as_bytes())),
            ts
        );
        let enrollment = crate::key_derivation::new_conductor_seed();
        let (enrollment_key, enrollment_signature) = enrollment_fields(&public_key_of_seed(&identity), &enrollment, ts);
        let (status, body) = post(
            "/auth/register-device-identity",
            serde_json::json!({
                "agent_pub_key": identity_agent, "email": email, "display_name": "Vault devices check",
                "recovery_lookup_hash": lookup, "timestamp": ts,
                "signature": base64_standard_encode(&sign_with_device_seed(&identity, message.as_bytes())),
                "enrollment_key": enrollment_key, "enrollment_signature": enrollment_signature,
            }),
        )
        .await;
        assert!(status == 200 || status == 201, "account: {} {}", status, body);

        let install_a = hex::encode(&crate::key_derivation::new_conductor_seed()[..16]);
        let install_b = hex::encode(&crate::key_derivation::new_conductor_seed()[..16]);
        let (status, body) = post("/auth/devices/register", registration_body(&identity_agent, &identity, &identity, &install_a, now_ms(), None)).await;
        assert_eq!(status, 403, "without the enrollment key: {}", body);
        let (status, body) = post("/auth/devices/register", registration_body(&identity_agent, &identity, &identity, &install_a, now_ms(), Some(&enrollment))).await;
        assert_eq!(status, 200, "first device: {}", body);
        let (status, body) = post("/auth/devices/register", registration_body(&identity_agent, &identity, &second, &install_b, now_ms(), Some(&enrollment))).await;
        assert_eq!(status, 200, "second device: {}", body);

        // The Vault's sign-in, as the second device.
        set_device_signer(Some(second));
        crate::device_identity::vault_grant_with_seed(&api, &identity, &identity_agent)
            .await
            .expect("the second device signs in");

        let target = key32(&public_key_of_seed(&second));
        let (status, body) = post("/auth/devices/remove", removal_body(&identity_agent, &identity, &identity, &target, now_ms()).unwrap()).await;
        assert_eq!(status, 200, "removal: {}", body);

        let refused = crate::device_identity::vault_grant_with_seed(&api, &identity, &identity_agent).await;
        assert!(refused.is_err(), "a removed device no longer signs in");
        println!("refused with: {}", refused.err().unwrap());

        set_device_signer(Some(identity));
        crate::device_identity::vault_grant_with_seed(&api, &identity, &identity_agent)
            .await
            .expect("the remaining device signs in");
        set_device_signer(None);
    }

    #[test]
    fn no_device_is_named_while_locked() {
        set_device_signer(None);
        assert!(cosign("c").is_none());
        set_device_signer(Some(DEVICE));
        assert!(cosign("c").is_some());
        set_device_signer(None);
        assert!(cosign("c").is_none());
    }
}
