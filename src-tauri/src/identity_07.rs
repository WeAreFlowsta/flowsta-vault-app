//! The identity's device statements on the 0.7 line: identity 1.5's
//! `devices` zome (`planning/DEVICE_CERTIFICATES_0_7.md` § 4).
//!
//! The same statements the Vault sends to Flowsta's device registry, signed
//! by the identity key, published where any reader can check them without
//! the API: that the identity has an enrollment key (so only the phrase or
//! one of its devices can add a device), and that it removed a device,
//! named by the hash of its key. Nothing here names a device's key in the
//! clear or counts devices. Best effort everywhere: the registry stays the
//! enforcement for sign-in in 1.7.0; these records are what the next
//! readers build on.

use crate::commands::AppState;
use crate::hc::{AppClient, Line};
use crate::key_derivation::{base64_standard_encode, construct_agent_pub_key_bytes, public_key_of_seed, sign_with_device_seed};
use holochain_types::prelude::{ActionHash, AgentPubKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const APP_ID: &str = "flowsta_identity_v1_5";
const ENROLLMENT_PREFIX: &str = "flowsta-enrollment-register:v1:";
const REMOVED_PREFIX: &str = "flowsta-device-removed:v1:";
const WAIT: std::time::Duration = std::time::Duration::from_secs(15);

async fn identity_client(state: &Arc<AppState>) -> Result<(AppClient, String), String> {
    let (admin_port, app_port) = crate::hc::line_ports(state, Line::V07)?;
    let (ws, role) = crate::hc::connect_app_07(state, admin_port, app_port, APP_ID, "flowsta_identity").await?;
    Ok((AppClient::V07(ws), role))
}

fn identity_agent(identity_seed: &[u8; 32]) -> AgentPubKey {
    AgentPubKey::from_raw_39(construct_agent_pub_key_bytes(&public_key_of_seed(identity_seed)).to_vec())
}

/// The statement the enrollment record carries, as the DNA checks it.
pub(crate) fn enrollment_statement(identity_public: &[u8; 32], enrollment_public: &[u8; 32], created_at_ms: i64) -> String {
    format!("{}{}:{}:{}", ENROLLMENT_PREFIX, base64_standard_encode(identity_public), base64_standard_encode(enrollment_public), created_at_ms)
}

/// The statement a removal carries: the device by the hash of its key.
pub(crate) fn removal_statement(identity_public: &[u8; 32], device_key_32: &[u8; 32], at_ms: i64) -> String {
    format!("{}{}:{}:{}", REMOVED_PREFIX, base64_standard_encode(identity_public), hex::encode(Sha256::digest(device_key_32)), at_ms)
}

/// Publish the identity's enrollment key on identity 1.5, once per device
/// (a marker beside the identity's files; the first publish also looks on
/// the network so a second device of the identity does not add a second
/// first key). Only the key's public half is needed: the statement is
/// signed by the identity key. The 0.7 line must be up; otherwise the
/// registration keeps a pending note and the devices round tries again
/// (`device_registry::publish_pending_enrollment`).
pub(crate) async fn publish_enrollment_key(state: &Arc<AppState>, identity_seed: &[u8; 32], enrollment_public: &[u8; 32], created_at_ms: i64) -> Result<bool, String> {
    let marker = state.identity_root().join("enrollment-published-07");
    if marker.exists() {
        return Ok(false);
    }
    let identity = identity_agent(identity_seed);
    let enrollment_public = *enrollment_public;
    let (client, role) = identity_client(state).await?;
    // Already there (this identity's other device published it)?
    #[derive(serde::Deserialize)]
    struct EnrollmentKeyEntry {
        enrollment_key: Vec<u8>,
    }
    let listed = tokio::time::timeout(WAIT, client.call_zome(&role, "devices", "get_enrollment_keys", rmp_serde::to_vec_named(&identity).map_err(|e| e.to_string())?)).await;
    if let Ok(Ok(bytes)) = listed {
        let known = crate::hc::records(Line::V07, &bytes)?
            .iter()
            .filter_map(|r| r.entry_as::<EnrollmentKeyEntry>().ok())
            .any(|e| e.enrollment_key == enrollment_public.to_vec());
        if known {
            let _ = std::fs::write(&marker, b"");
            return Ok(false);
        }
    }
    #[derive(Serialize)]
    struct RegisterEnrollmentKeyInput {
        identity: AgentPubKey,
        enrollment_key: Vec<u8>,
        created_at: i64,
        previous: Option<ActionHash>,
        identity_signature: Vec<u8>,
    }
    let statement = enrollment_statement(&public_key_of_seed(identity_seed), &enrollment_public, created_at_ms);
    let input = RegisterEnrollmentKeyInput {
        identity,
        enrollment_key: enrollment_public.to_vec(),
        created_at: created_at_ms,
        previous: None,
        identity_signature: sign_with_device_seed(identity_seed, statement.as_bytes()).to_vec(),
    };
    client.call_zome(&role, "devices", "register_enrollment_key", rmp_serde::to_vec_named(&input).map_err(|e| e.to_string())?).await?;
    let _ = std::fs::write(&marker, b"");
    log::info!("[identity 1.5] this identity's enrollment key is published");
    Ok(true)
}

/// Publish that the identity removed a device (signed by the identity key).
pub(crate) async fn publish_removal(state: &Arc<AppState>, identity_seed: &[u8; 32], device_key_32: &[u8; 32], at_ms: i64) -> Result<(), String> {
    #[derive(Serialize)]
    enum RemovalSigner {
        Identity,
    }
    #[derive(Serialize)]
    struct RemoveDeviceInput {
        identity: AgentPubKey,
        device_key: Vec<u8>,
        at: i64,
        signer: RemovalSigner,
        signature: Vec<u8>,
    }
    let statement = removal_statement(&public_key_of_seed(identity_seed), device_key_32, at_ms);
    let input = RemoveDeviceInput {
        identity: identity_agent(identity_seed),
        device_key: device_key_32.to_vec(),
        at: at_ms,
        signer: RemovalSigner::Identity,
        signature: sign_with_device_seed(identity_seed, statement.as_bytes()).to_vec(),
    };
    let (client, role) = identity_client(state).await?;
    client.call_zome(&role, "devices", "remove_device", rmp_serde::to_vec_named(&input).map_err(|e| e.to_string())?).await?;
    log::info!("[identity 1.5] a device removal is published");
    Ok(())
}

/// Whether identity 1.5 holds a removal for this device's key. `None` when
/// the question could not be answered (no 0.7 line, cold network).
pub(crate) async fn removed_on_07(state: &Arc<AppState>, device_key_32: &[u8; 32]) -> Option<bool> {
    let (client, role) = identity_client(state).await.ok()?;
    let payload = rmp_serde::to_vec_named(&device_key_32.to_vec()).ok()?;
    let bytes = tokio::time::timeout(WAIT, client.call_zome(&role, "devices", "get_removal_for_device", payload)).await.ok()?.ok()?;
    crate::hc::record_opt(Line::V07, &bytes).ok().map(|r| r.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_statements_are_the_registry_statements_the_dna_checks() {
        let identity = [1u8; 32];
        let enrollment = [2u8; 32];
        let device = [3u8; 32];
        assert_eq!(
            enrollment_statement(&identity, &enrollment, 1790000000000),
            format!("flowsta-enrollment-register:v1:{}:{}:1790000000000", base64_standard_encode(&identity), base64_standard_encode(&enrollment))
        );
        assert_eq!(
            removal_statement(&identity, &device, 1790000000000),
            format!("flowsta-device-removed:v1:{}:{}:1790000000000", base64_standard_encode(&identity), hex::encode(Sha256::digest(device)))
        );
        // A unit variant serializes as its name: the DNA's `RemovalSigner::Identity`.
        #[derive(Serialize)]
        enum RemovalSigner {
            Identity,
        }
        assert_eq!(rmp_serde::to_vec_named(&RemovalSigner::Identity).unwrap(), rmp_serde::to_vec_named(&"Identity").unwrap());
    }
}
