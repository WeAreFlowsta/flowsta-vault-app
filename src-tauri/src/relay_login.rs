//! Relay login — approve a sign-in happening on another
//! device (a phone, or a Firefox/Safari desktop that can't reach the
//! loopback IPC). The browser and this Vault meet at the auth-api:
//!
//!   other device: POST /auth/relay/start  -> shows a XXXX-XXXX code
//!   here:         user types the code (or a flowsta://relay/v1?code= link
//!                 arrives) -> claim -> approval screen -> sign -> approve
//!   other device: poll returns the session.
//!
//! Server side: the auth API's /auth/relay/* routes.
//!
//! Security invariants (do not relax):
//! - The approval screen is ALWAYS shown — no remember/auto-approve for
//!   relay logins. Cross-device approval is the phishing surface ("read me
//!   your code"); the screen is the defense.
//! - The challenge is signed exactly as the server returned it (raw UTF-8
//!   bytes) and is held Rust-side between claim and approve — the webview
//!   never supplies it back, so a compromised frontend can't substitute one.

use crate::commands::AppState;
use crate::key_derivation::sign_with_device_seed;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{Emitter, Manager, State};

/// A claimed relay session held between claim and approve/deny.
#[derive(Debug, Clone, Serialize)]
pub struct RelayClaim {
    pub claim_token: String,
    pub challenge: String,
    pub app_name: String,
    pub ua_family: Option<String>,
    pub ip_prefix: Option<String>,
    pub expires_in: u64,
}

#[derive(Deserialize)]
struct ClaimResponse {
    claim_token: Option<String>,
    challenge: Option<String>,
    app_name: Option<String>,
    origin_hint: Option<OriginHint>,
    expires_in: Option<u64>,
    error: Option<String>,
    message: Option<String>,
}

#[derive(Deserialize)]
struct OriginHint {
    #[serde(rename = "ipPrefix")]
    ip_prefix: Option<String>,
    #[serde(rename = "uaFamily")]
    ua_family: Option<String>,
}

#[derive(Deserialize)]
struct SimpleResponse {
    error: Option<String>,
    message: Option<String>,
}

fn api_err(status: reqwest::StatusCode, error: Option<String>, message: Option<String>, fallback: &str) -> String {
    let code = error.unwrap_or_else(|| fallback.to_string());
    match message {
        Some(m) => format!("{} [{}]: {}", code, status.as_u16(), m),
        None => format!("{} [{}]", code, status.as_u16()),
    }
}

/// Claim a relay code with the API. Plain function so the integration test
/// can drive it without Tauri state.
pub async fn relay_claim_core(api_url: &str, user_code: &str) -> Result<RelayClaim, String> {
    let base = api_url.trim_end_matches('/');
    let resp = reqwest::Client::new()
        .post(format!("{}/auth/relay/claim", base))
        .json(&serde_json::json!({ "user_code": user_code }))
        .send()
        .await
        .map_err(|e| format!("Claim request failed: {}", e))?;
    let status = resp.status();
    let body: ClaimResponse = resp
        .json()
        .await
        .map_err(|e| format!("Claim response parse failed: {}", e))?;
    if !status.is_success() {
        // Machine-readable codes the UI branches on:
        // code_not_found | already_claimed | invalid_code | rate_limited
        return Err(api_err(status, body.error, body.message, "relay_claim_failed"));
    }
    Ok(RelayClaim {
        claim_token: body.claim_token.ok_or("Claim response missing claim_token")?,
        challenge: body.challenge.ok_or("Claim response missing challenge")?,
        app_name: body.app_name.unwrap_or_else(|| "Flowsta".to_string()),
        ua_family: body.origin_hint.as_ref().and_then(|o| o.ua_family.clone()),
        ip_prefix: body.origin_hint.as_ref().and_then(|o| o.ip_prefix.clone()),
        expires_in: body.expires_in.unwrap_or(0),
    })
}

/// Sign the claimed challenge and approve the relay session.
pub async fn relay_approve_core(
    api_url: &str,
    claim: &RelayClaim,
    device_seed: &[u8; 32],
    agent_b64: &str,
) -> Result<(), String> {
    // Domain separation: sign the challenge string exactly as received, raw
    // UTF-8 bytes (same contract as the vault-grant in device_identity.rs).
    let signature = crate::key_derivation::base64_standard_encode(&sign_with_device_seed(
        device_seed,
        claim.challenge.as_bytes(),
    ));

    let base = api_url.trim_end_matches('/');
    let resp = reqwest::Client::new()
        .post(format!("{}/auth/relay/approve", base))
        .json(&serde_json::json!({
            "claim_token": claim.claim_token,
            "agent_pub_key": agent_b64,
            "signature": signature,
        }))
        .send()
        .await
        .map_err(|e| format!("Approve request failed: {}", e))?;
    let status = resp.status();
    let body: SimpleResponse = resp
        .json()
        .await
        .map_err(|e| format!("Approve response parse failed: {}", e))?;
    if !status.is_success() {
        return Err(api_err(status, body.error, body.message, "relay_approve_failed"));
    }
    Ok(())
}

/// Tell the API the user declined (or the approval timed out). Best-effort.
pub async fn relay_deny_core(api_url: &str, claim_token: &str) -> Result<(), String> {
    let base = api_url.trim_end_matches('/');
    let _ = reqwest::Client::new()
        .post(format!("{}/auth/relay/deny", base))
        .json(&serde_json::json!({ "claim_token": claim_token }))
        .send()
        .await
        .map_err(|e| format!("Deny request failed: {}", e))?;
    Ok(())
}

// ── Tauri commands (thin wrappers holding the claim Rust-side) ──────────────

/// Claim a typed/deep-linked code. Requires the vault unlocked (approval
/// needs the device seed anyway — surface locked state before claiming so
/// the code isn't burned on a vault that can't sign).
#[tauri::command]
pub async fn relay_claim(
    api_url: String,
    user_code: String,
    state: State<'_, Arc<AppState>>,
) -> Result<RelayClaim, String> {
    {
        let config = state.vault_config.lock().unwrap();
        if config.is_none() {
            return Err("vault_locked".into());
        }
    }
    let claim = relay_claim_core(&api_url, &user_code).await?;
    {
        let mut pending = state.pending_relay_claim.lock().unwrap();
        *pending = Some(claim.clone());
    }
    Ok(claim)
}

/// Approve the pending claim. Signs the RUST-HELD challenge — the frontend
/// never passes it back.
#[tauri::command]
pub async fn relay_approve(
    api_url: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let claim = {
        let mut pending = state.pending_relay_claim.lock().unwrap();
        pending.take().ok_or("no_pending_relay_claim")?
    };
    let (seed_vec, agent_b64) = {
        let config = state.vault_config.lock().unwrap();
        let cfg = config.as_ref().ok_or("vault_locked")?;
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

    relay_approve_core(&api_url, &claim, &seed, &agent_b64).await
}

/// Deny the pending claim (user clicked Deny, or the approval screen timed out).
#[tauri::command]
pub async fn relay_deny(api_url: String, state: State<'_, Arc<AppState>>) -> Result<(), String> {
    let claim = {
        let mut pending = state.pending_relay_claim.lock().unwrap();
        pending.take()
    };
    if let Some(claim) = claim {
        relay_deny_core(&api_url, &claim.claim_token).await?;
    }
    Ok(())
}

/// Drain a relay code queued while the vault was locked (deep link arrived
/// pre-unlock). The unlock flow calls this and, if present, opens the
/// approval flow with it.
#[tauri::command]
pub fn take_pending_relay_code(state: State<'_, Arc<AppState>>) -> Option<String> {
    state.pending_relay_code.lock().unwrap().take()
}

// ── F3: flowsta:// deep-link routing ────────────────────────────────────────

/// True if a launch/single-instance arg is a flowsta:// URL (vs a file path
/// to sign). MUST be checked BEFORE sign-file path extraction — an auth link
/// misread as a file path would silently do nothing (round-5 catch 7).
pub fn is_flowsta_url(arg: &str) -> bool {
    arg.starts_with("flowsta://")
}

/// Extract the relay code from a flowsta://relay/v1?code=XXXX-XXXX URL.
/// Returns None for any other action/version (forward-compatible: unknown
/// links just focus the window).
pub fn parse_relay_code(url_str: &str) -> Option<String> {
    let url = url::Url::parse(url_str).ok()?;
    if url.scheme() != "flowsta" {
        return None;
    }
    // flowsta://relay/v1?code=... -> host = "relay", path = "/v1"
    if url.host_str() != Some("relay") || url.path() != "/v1" {
        return None;
    }
    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())?;
    // Normalize like the server: uppercase, letters only, exactly 8.
    let normalized: String = code
        .to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect();
    if normalized.len() == 8 {
        Some(normalized)
    } else {
        None
    }
}

/// Handle an incoming flowsta:// URL: queue the relay code, surface the
/// window, and notify the frontend. Works locked or unlocked — the frontend
/// (or the unlock flow via take_pending_relay_code) picks it up.
pub fn handle_flowsta_url(app: &tauri::AppHandle, url_str: &str) {
    let state = app.state::<Arc<AppState>>();
    match parse_relay_code(url_str) {
        Some(code) => {
            log::info!("flowsta:// relay code received via deep link");
            {
                let mut pending = state.pending_relay_code.lock().unwrap();
                *pending = Some(code.clone());
            }
            let _ = app.emit("relay-code-received", code);
        }
        None => {
            log::warn!("Unrecognized flowsta:// URL (action/version) — focusing window only");
        }
    }
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_always_on_top(true);
        let _ = window.set_focus();
        let _ = window.set_always_on_top(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_relay_code() {
        assert_eq!(
            parse_relay_code("flowsta://relay/v1?code=BCDF-GHJK"),
            Some("BCDFGHJK".to_string())
        );
        assert_eq!(
            parse_relay_code("flowsta://relay/v1?code=bcdfghjk"),
            Some("BCDFGHJK".to_string())
        );
        // Wrong action / version / scheme / shape
        assert_eq!(parse_relay_code("flowsta://relay/v2?code=BCDF-GHJK"), None);
        assert_eq!(parse_relay_code("flowsta://other/v1?code=BCDF-GHJK"), None);
        assert_eq!(parse_relay_code("https://relay/v1?code=BCDF-GHJK"), None);
        assert_eq!(parse_relay_code("flowsta://relay/v1?code=SHORT"), None);
        assert_eq!(parse_relay_code("flowsta://relay/v1"), None);
        assert_eq!(parse_relay_code("/home/user/file.pdf"), None);
    }

    #[test]
    fn test_is_flowsta_url() {
        assert!(is_flowsta_url("flowsta://relay/v1?code=X"));
        assert!(!is_flowsta_url("/home/user/flowsta.pdf"));
        assert!(!is_flowsta_url("https://flowsta.com"));
    }

    /// Full relay contract test against STAGING with the real signing code.
    /// Simulates the phone with reqwest; this Vault side uses the same core
    /// functions the commands wrap. Run explicitly:
    /// `cargo test --lib relay_login -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn test_relay_e2e_against_staging() {
        const STAGING: &str = "https://auth-api-staging.flowsta.com";
        use crate::device_identity;
        use crate::key_derivation::{
            base64_standard_encode, construct_agent_pub_key_bytes, derive_device_keypair,
            derive_seed, DEVICE_1_CONSTANT,
        };

        // Fresh identity (register like the device_identity test).
        let mnemonic = device_identity::generate_new_mnemonic().expect("mnemonic");
        let email = format!(
            "relayvault-{}@example.com",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        device_identity::register_device_identity(
            STAGING.into(),
            mnemonic.clone(),
            email,
            Some("Relay Vault Test".into()),
        )
        .await
        .expect("register");

        let signing_key = derive_device_keypair(&mnemonic).expect("keypair");
        let agent_b64 =
            base64_standard_encode(&construct_agent_pub_key_bytes(&signing_key.verifying_key().to_bytes()));
        let device_seed = derive_seed(&mnemonic, DEVICE_1_CONSTANT).expect("seed");

        // Phone side: start.
        let client = reqwest::Client::new();
        let start: serde_json::Value = client
            .post(format!("{}/auth/relay/start", STAGING))
            .json(&serde_json::json!({ "client_id": "flowsta" }))
            .send()
            .await
            .expect("start")
            .json()
            .await
            .expect("start json");
        let relay_id = start["relay_id"].as_str().expect("relay_id").to_string();
        let user_code = start["user_code"].as_str().expect("user_code").to_string();

        // Vault side: claim + approve with the real core functions.
        let claim = relay_claim_core(STAGING, &user_code).await.expect("claim");
        assert!(claim.challenge.starts_with("flowsta-relay-login:v1:"));
        assert_eq!(claim.app_name, "Flowsta");
        relay_approve_core(STAGING, &claim, &device_seed, &agent_b64)
            .await
            .expect("approve");

        // Phone side: poll -> approved with a device-hosted session.
        let poll: serde_json::Value = client
            .post(format!("{}/auth/relay/poll", STAGING))
            .json(&serde_json::json!({ "relay_id": relay_id }))
            .send()
            .await
            .expect("poll")
            .json()
            .await
            .expect("poll json");
        assert_eq!(poll["status"], "approved");
        assert!(poll["token"].as_str().is_some());
        assert_eq!(poll["user"]["hostingModel"], "device-hosted");
    }
}
