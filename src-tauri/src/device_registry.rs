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

/// What a Vault device may do, in the order the server expects.
const VAULT_CAPABILITIES: [&str; 4] = ["approve", "login", "read", "sign"];

/// The seed this device co-signs sign-ins with (the seed its conductor
/// runs) while a vault is unlocked. Cleared on lock.
static DEVICE_SIGNER: Mutex<Option<[u8; 32]>> = Mutex::new(None);

pub(crate) fn set_device_signer(seed: Option<[u8; 32]>) {
    let mut slot = DEVICE_SIGNER.lock().unwrap();
    if let Some(old) = slot.as_mut() {
        old.fill(0);
    }
    *slot = seed;
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

/// The body of `POST /auth/devices/register`.
pub(crate) fn registration_body(
    identity_agent_b64: &str,
    identity_seed: &[u8; 32],
    device_seed: &[u8; 32],
    install_id: &str,
    now_ms: u64,
) -> serde_json::Value {
    let message = format!(
        "{}{}:{}:{}:{}:{}",
        REGISTER_PREFIX,
        key32(&public_key_of_seed(identity_seed)),
        key32(&public_key_of_seed(device_seed)),
        install_id,
        VAULT_CAPABILITIES.join(","),
        now_ms
    );
    serde_json::json!({
        "identity_key": identity_agent_b64,
        "device_key": agent_key_b64(device_seed),
        "install_id": install_id,
        "capabilities": VAULT_CAPABILITIES,
        "timestamp": now_ms.to_string(),
        "identity_signature": base64_standard_encode(&sign_with_device_seed(identity_seed, message.as_bytes())),
        "device_signature": base64_standard_encode(&sign_with_device_seed(device_seed, message.as_bytes())),
    })
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

/// Register this device with the identity's account. Safe to repeat: the
/// server answers the same for a device it already knows. Returns whether
/// the server knows this device now.
pub async fn register_this_device(state: &Arc<AppState>, api_url: &str) -> Result<bool, String> {
    let Some(keys) = keys(state) else {
        return Ok(false);
    };
    let install_id = crate::paths::install_id(&state.data_dir).ok_or("no install id")?;
    let body = registration_body(&keys.identity_agent_b64, &keys.identity_seed, &keys.device_seed, &install_id, now_ms());
    let resp = client()?
        .post(format!("{}/auth/devices/register", api_url.trim_end_matches('/')))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("api_unreachable: {}", e))?;
    let status = resp.status();
    if status.is_success() {
        return Ok(true);
    }
    let error = resp
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
        .unwrap_or_default();
    Err(format!("{} [{}]", error, status.as_u16()))
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
        let body = registration_body("IDENTITY39", &IDENTITY, &DEVICE, INSTALL, 1_790_000_000_000);
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
        let (status, body) = post(
            "/auth/register-device-identity",
            serde_json::json!({
                "agent_pub_key": identity_agent, "email": email, "display_name": "Vault devices check",
                "recovery_lookup_hash": lookup, "timestamp": ts,
                "signature": base64_standard_encode(&sign_with_device_seed(&identity, message.as_bytes())),
            }),
        )
        .await;
        assert!(status == 200 || status == 201, "account: {} {}", status, body);

        let install_a = hex::encode(&crate::key_derivation::new_conductor_seed()[..16]);
        let install_b = hex::encode(&crate::key_derivation::new_conductor_seed()[..16]);
        let (status, body) = post("/auth/devices/register", registration_body(&identity_agent, &identity, &identity, &install_a, now_ms())).await;
        assert_eq!(status, 200, "first device: {}", body);
        let (status, body) = post("/auth/devices/register", registration_body(&identity_agent, &identity, &second, &install_b, now_ms())).await;
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
