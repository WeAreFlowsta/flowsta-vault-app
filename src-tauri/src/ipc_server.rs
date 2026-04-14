//! IPC server on localhost:27777 for SDK bridge.
//!
//! This server allows the @flowsta/holochain SDK (running in a browser)
//! to detect whether Flowsta Vault is running and request signing operations.
//!
//! Endpoints:
//! - GET  /status           → { unlocked, agent_pub_key, did, version }
//! - POST /sign             → signs bytes or actions with the device Ed25519 key
//! - POST /authenticate     → identity proof via challenge-response with user approval
//! - POST /link-identity    → agent-linking signature for third-party Holochain apps (with approval)
//! - POST /sign-document    → Sign It: sign a file hash and commit to signing DNA (with approval)
//! - POST /revoke-identity  → notification from third-party app that identity link was revoked
//! - GET  /link-status      → check if a third-party app is still linked
//! - POST /backup           → store encrypted app data backup
//! - GET  /backup/list      → list all app backups
//! - POST /backup/retrieve  → retrieve a specific app's backup
//! - POST /backup/delete    → delete a specific app's backup

use crate::commands::{
    AppState, AuthRequestInfo, ConnectedSite, PendingAuthRequest, PendingDocumentSignRequest,
    PendingLinkIdentityRequest,
};
use crate::key_derivation::{
    base64_standard_encode, build_sorted_agent_pair_payload, construct_agent_pub_key_bytes,
    construct_agent_pub_key_string, decode_agent_pub_key_string, sign_with_device_seed,
};
use axum::{
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::Emitter;
use tower_http::cors::CorsLayer;

/// Shared state for the IPC server (references the main AppState).
pub struct IpcState {
    pub app_state: Arc<AppState>,
    pub app_handle: tauri::AppHandle,
}

// ── Origin tracking helper ──────────────────────────────────────────

fn extract_origin(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::ORIGIN)
        .and_then(|h| h.to_str().ok())
        .map(String::from)
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn track_request(state: &AppState, origin: Option<&str>, action: &str) {
    let origin = match origin {
        Some(o) if !o.is_empty() => o,
        _ => return, // No origin header — e.g. curl without -H Origin
    };

    let is_auth = action == "authenticate";
    let now = unix_now();
    let mut sites = state.connected_sites.lock().unwrap();
    sites
        .entry(origin.to_string())
        .and_modify(|s| {
            s.last_request = now;
            s.request_count += 1;
            s.last_action = action.to_string();
            if is_auth {
                s.has_authenticated = true;
            }
        })
        .or_insert(ConnectedSite {
            origin: origin.to_string(),
            first_seen: now,
            last_request: now,
            request_count: 1,
            last_action: action.to_string(),
            has_authenticated: is_auth,
            trusted: false, // populated at query time by get_connected_sites
        });
}

// ── GET /status ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct StatusResponse {
    unlocked: bool,
    agent_pub_key: Option<String>,
    did: Option<String>,
    version: String,
    /// Only populated when the requesting app has the "display_name" scope.
    display_name: Option<String>,
    /// Only populated when the requesting app has the "profile_picture" scope.
    profile_picture: Option<String>,
    /// Only populated when the requesting app has the "username" scope.
    web_username: Option<String>,
}

/// Resolve the caller's origin to the `client_id` of a linked third-party app.
/// Returns `None` if the origin is missing, empty, or hasn't been linked.
///
/// Use this to gate sensitive operations (signing, backup retrieve/delete) so
/// that an unlinked / hostile local process can't impersonate a linked app.
fn origin_to_client_id(state: &AppState, origin: Option<&str>) -> Option<String> {
    let orig = match origin {
        Some(o) if !o.is_empty() => o,
        _ => return None,
    };
    let linked = state.linked_third_party_apps.lock().unwrap();
    linked
        .iter()
        .find(|a| a.origin.as_deref() == Some(orig))
        .and_then(|a| a.client_id.clone())
}

/// Look up the scopes granted to the app at the given origin.
///
/// Finds the origin in `linked_third_party_apps`, retrieves its `client_id`,
/// then looks up the scopes stored in `linked_app_scopes`. Returns an empty
/// vec if the origin has not been linked or has no stored scopes.
fn get_scopes_for_origin(state: &AppState, origin: Option<&str>) -> Vec<String> {
    let orig = match origin {
        Some(o) if !o.is_empty() => o,
        _ => return vec![],
    };
    let client_id = {
        let linked = state.linked_third_party_apps.lock().unwrap();
        linked
            .iter()
            .find(|a| a.origin.as_deref() == Some(orig))
            .and_then(|a| a.client_id.clone())
    };
    match client_id {
        Some(cid) => state
            .linked_app_scopes
            .lock()
            .unwrap()
            .get(&cid)
            .cloned()
            .unwrap_or_default(),
        None => vec![],
    }
}

async fn status_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
) -> Json<StatusResponse> {
    // Phase 1: extract vault fields, then drop the lock before any other locks.
    let (unlocked, agent_pub_key, did, display_name_raw, profile_picture_raw, web_username_raw) = {
        let config = state.app_state.vault_config.lock().unwrap();
        (
            config.is_some(),
            config.as_ref().map(|c| c.agent_pub_key.clone()),
            config.as_ref().map(|c| c.did.clone()),
            config.as_ref().and_then(|c| c.display_name.clone()),
            config.as_ref().and_then(|c| c.profile_picture.clone()),
            config.as_ref().and_then(|c| c.web_username.clone()),
        )
    };

    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "status");

    // Phase 2: look up granted scopes for this origin (vault_config lock released).
    let scopes = get_scopes_for_origin(&state.app_state, origin.as_deref());

    // Phase 3: return only fields the app was granted at link time.
    Json(StatusResponse {
        unlocked,
        agent_pub_key,
        did,
        version: env!("CARGO_PKG_VERSION").to_string(),
        display_name: scopes.contains(&"display_name".to_string()).then_some(display_name_raw).flatten(),
        profile_picture: scopes.contains(&"profile_picture".to_string()).then_some(profile_picture_raw).flatten(),
        web_username: scopes.contains(&"username".to_string()).then_some(web_username_raw).flatten(),
    })
}

// ── POST /sign ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SignRequest {
    /// "bytes" or "action"
    #[serde(rename = "type")]
    sign_type: String,
    /// Base64-encoded bytes to sign (when type = "bytes")
    bytes: Option<String>,
    /// Holochain action object to sign (when type = "action")
    action: Option<serde_json::Value>,
    /// Human-readable reason for the signing request (for audit)
    #[allow(dead_code)]
    reason: Option<String>,
}

#[derive(Serialize)]
struct SignBytesResponse {
    success: bool,
    signature: String,
    agent_pub_key: String,
}

#[derive(Serialize)]
struct SignActionResponse {
    success: bool,
    signed_action: serde_json::Value,
    signature: String,
    agent_pub_key: String,
    did: String,
    signed_at: String,
}

#[derive(Serialize)]
struct IpcError {
    error: String,
    description: Option<String>,
}

async fn sign_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
    Json(req): Json<SignRequest>,
) -> Result<axum::response::Response, (StatusCode, Json<IpcError>)> {
    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "sign");

    // SECURITY: only linked third-party apps may request signatures with the
    // user's device key. Without this check, ANY local process could hit
    // localhost:27777/sign and forge Holochain signatures as the user.
    if origin_to_client_id(&state.app_state, origin.as_deref()).is_none() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "not_linked".into(),
                description: Some(
                    "This origin is not a linked third-party app. Call /link-identity and obtain user approval first.".into(),
                ),
            }),
        ));
    }

    // Record MAU for linked third-party apps making sign requests
    crate::mau::record_mau_for_origin(&state.app_state, origin.as_deref());

    // Get vault config (must be unlocked)
    let config = state.app_state.vault_config.lock().unwrap();
    let config = config.as_ref().ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "vault_locked".into(),
                description: Some("Vault is locked. Unlock it first.".into()),
            }),
        )
    })?;

    // Get device seed for signing
    let device_seed = config.device_seed.as_ref().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(IpcError {
                error: "no_device_seed".into(),
                description: Some(
                    "Vault was created before signing support. Please re-create it.".into(),
                ),
            }),
        )
    })?;

    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(device_seed);

    let agent_pub_key = config.agent_pub_key.clone();
    let did = config.did.clone();

    match req.sign_type.as_str() {
        "bytes" => {
            let b64 = req.bytes.ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(IpcError {
                        error: "missing_bytes".into(),
                        description: Some(
                            "Request type is 'bytes' but no 'bytes' field provided.".into(),
                        ),
                    }),
                )
            })?;

            // Decode base64 payload
            let payload = base64_standard_decode(&b64).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(IpcError {
                        error: "invalid_base64".into(),
                        description: Some("Could not decode 'bytes' as base64.".into()),
                    }),
                )
            })?;

            // Sign
            let signature = sign_with_device_seed(&seed_arr, &payload);

            let resp = SignBytesResponse {
                success: true,
                signature: base64_standard_encode(&signature),
                agent_pub_key,
            };

            Ok(axum::response::IntoResponse::into_response(Json(resp)))
        }
        "action" => {
            let action = req.action.ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(IpcError {
                        error: "missing_action".into(),
                        description: Some(
                            "Request type is 'action' but no 'action' field provided.".into(),
                        ),
                    }),
                )
            })?;

            // Serialize the action to canonical JSON bytes for signing
            let action_bytes = serde_json::to_vec(&action).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(IpcError {
                        error: "invalid_action".into(),
                        description: Some(format!("Could not serialize action: {}", e)),
                    }),
                )
            })?;

            // Sign the serialized action
            let signature = sign_with_device_seed(&seed_arr, &action_bytes);

            let resp = SignActionResponse {
                success: true,
                signed_action: action,
                signature: base64_standard_encode(&signature),
                agent_pub_key,
                did,
                signed_at: chrono_now_iso(),
            };

            Ok(axum::response::IntoResponse::into_response(Json(resp)))
        }
        other => Err((
            StatusCode::BAD_REQUEST,
            Json(IpcError {
                error: "unknown_type".into(),
                description: Some(format!(
                    "Unknown sign type '{}'. Expected 'bytes' or 'action'.",
                    other
                )),
            }),
        )),
    }
}

// ── POST /authenticate ──────────────────────────────────────────────

#[derive(Deserialize)]
struct AuthenticateRequest {
    /// Human-readable app name shown in the approval dialog.
    app_name: String,
    /// Base64-encoded challenge nonce to sign (optional).
    challenge: Option<String>,
    /// Human-readable reason shown in the approval dialog.
    reason: Option<String>,
    /// Developer client_id for MAU tracking (optional).
    client_id: Option<String>,
}

#[derive(Serialize)]
struct AuthenticateResponse {
    success: bool,
    did: String,
    agent_pub_key: String,
    /// Ed25519 signature of the challenge (only if challenge was provided).
    signature: Option<String>,
    signed_at: String,
}

async fn authenticate_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
    Json(req): Json<AuthenticateRequest>,
) -> Result<axum::response::Response, (StatusCode, Json<IpcError>)> {
    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "authenticate");

    // Vault must be unlocked
    {
        let config = state.app_state.vault_config.lock().unwrap();
        if config.is_none() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "vault_locked".into(),
                    description: Some("Vault is locked. Unlock it first.".into()),
                }),
            ));
        }
    }

    // Check if this origin is already auto-approved
    let auto_approved = if let Some(ref orig) = origin {
        let approved = state.app_state.approved_apps.lock().unwrap();
        approved.contains(orig)
    } else {
        false
    };

    let approved = if auto_approved {
        true
    } else {
        // Create oneshot channel for approval dialog
        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();

        let request_id = format!("auth-{}", unix_now());

        let pending = PendingAuthRequest {
            info: AuthRequestInfo {
                id: request_id.clone(),
                app_name: req.app_name.clone(),
                origin: origin.clone(),
                reason: req.reason.clone(),
            },
            challenge: req.challenge.clone(),
            responder: tx,
        };

        // Store the pending request
        {
            let mut pending_auth = state.app_state.pending_auth.lock().unwrap();
            *pending_auth = Some(pending);
        }

        // Emit Tauri event to show the approval dialog
        let event_payload = serde_json::json!({
            "id": request_id,
            "app_name": req.app_name,
            "origin": origin,
            "reason": req.reason,
        });

        let _ = state.app_handle.emit("auth-request", event_payload);

        // Wait for user response with 60s timeout
        match tokio::time::timeout(std::time::Duration::from_secs(60), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                // Channel closed (sender dropped)
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(IpcError {
                        error: "internal_error".into(),
                        description: Some("Approval channel closed unexpectedly.".into()),
                    }),
                ));
            }
            Err(_) => {
                // Timeout — clean up pending request
                let mut pending_auth = state.app_state.pending_auth.lock().unwrap();
                *pending_auth = None;
                return Err((
                    StatusCode::REQUEST_TIMEOUT,
                    Json(IpcError {
                        error: "timeout".into(),
                        description: Some(
                            "No response in Flowsta Vault — request timed out. Please try again.".into(),
                        ),
                    }),
                ));
            }
        }
    };

    if !approved {
        return Err((
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "user_denied".into(),
                description: Some("User rejected the authentication request.".into()),
            }),
        ));
    }

    // User approved — build response
    let config = state.app_state.vault_config.lock().unwrap();
    let config = config.as_ref().ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "vault_locked".into(),
                description: Some("Vault was locked during approval.".into()),
            }),
        )
    })?;

    let agent_pub_key = config.agent_pub_key.clone();
    let did = config.did.clone();

    // Sign the challenge if provided
    let signature = if let Some(ref challenge_b64) = req.challenge {
        let device_seed = config.device_seed.as_ref().ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(IpcError {
                    error: "no_device_seed".into(),
                    description: Some(
                        "Vault was created before signing support. Please re-create it.".into(),
                    ),
                }),
            )
        })?;

        let challenge_bytes = base64_standard_decode(challenge_b64).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(IpcError {
                    error: "invalid_challenge".into(),
                    description: Some("Could not decode 'challenge' as base64.".into()),
                }),
            )
        })?;

        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(device_seed);
        let sig = sign_with_device_seed(&seed_arr, &challenge_bytes);
        Some(base64_standard_encode(&sig))
    } else {
        None
    };

    // Record MAU event if client_id was provided
    if let Some(ref client_id) = req.client_id {
        crate::mau::record_mau_event_if_needed(&state.app_state, client_id);
    }

    let resp = AuthenticateResponse {
        success: true,
        did,
        agent_pub_key,
        signature,
        signed_at: chrono_now_iso(),
    };

    Ok(axum::response::IntoResponse::into_response(Json(resp)))
}

// ── POST /link-identity ────────────────────────────────────────────
//
// Purpose-specific endpoint for third-party Holochain apps to request
// an agent-linking signature from the Vault. Unlike /sign, this endpoint:
// 1. Computes the payload itself (the 78-byte sorted key pair)
// 2. Always requires user approval via a dialog
// 3. Returns the Vault's agent public key alongside the signature

#[derive(Deserialize)]
struct LinkIdentityRequest {
    /// Human-readable app name (fallback; API-verified name used when available).
    app_name: String,
    /// Developer client_id from dev.flowsta.com (required).
    client_id: String,
    /// The third-party app's agent public key in uhCAk... format.
    app_agent_pub_key: String,
}

#[derive(Serialize)]
struct LinkIdentityResponse {
    success: bool,
    vault_agent_pub_key: String,
    /// Base64 standard encoded Ed25519 signature (64 bytes).
    vault_signature: String,
}

async fn link_identity_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
    Json(req): Json<LinkIdentityRequest>,
) -> Result<axum::response::Response, (StatusCode, Json<IpcError>)> {
    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "link-identity");

    // Vault must be unlocked
    {
        let config = state.app_state.vault_config.lock().unwrap();
        if config.is_none() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "vault_locked".into(),
                    description: Some("Vault is locked. Unlock it first.".into()),
                }),
            ));
        }
    }

    // Parse the third-party app's agent public key
    let app_agent_39 = decode_agent_pub_key_string(&req.app_agent_pub_key).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(IpcError {
                error: "invalid_agent_pub_key".into(),
                description: Some(
                    "Could not decode app_agent_pub_key. Expected uhCAk... format.".into(),
                ),
            }),
        )
    })?;

    // Validate client_id: check cache first, then API
    if req.client_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(IpcError {
                error: "missing_client_id".into(),
                description: Some(
                    "client_id is required. Register your app at dev.flowsta.com to get one."
                        .into(),
                ),
            }),
        ));
    }

    // Always fetch fresh app info from the API so changes made in Website-dev
    // (scopes, org name, description) are reflected immediately. Fall back to
    // the local cache only if the API is unreachable (offline re-linking).
    let api_url = option_env!("FLOWSTA_API_URL")
        .unwrap_or("https://auth-api.flowsta.com");
    let verify_url = format!(
        "{}/api/v1/apps/verify?client_id={}",
        api_url.trim_end_matches('/'),
        req.client_id
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let api_result = client.get(&verify_url).send().await;

    let app_info = match api_result {
      Ok(api_resp) => {
        let api_resp = api_resp; // keep binding
        // API reachable — parse and use fresh data

        let body: serde_json::Value =
            api_resp.json().await.map_err(|_| {
                (
                    StatusCode::BAD_GATEWAY,
                    Json(IpcError {
                        error: "api_unreachable".into(),
                        description: Some("Invalid response from Flowsta API.".into()),
                    }),
                )
            })?;

        let valid = body.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
        if !valid {
            let error_code = body
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("app_not_found");
            let message = body
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("App not registered. Developers: register at dev.flowsta.com");
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: error_code.into(),
                    description: Some(message.into()),
                }),
            ));
        }

        let app_obj = body.get("app").ok_or_else(|| {
            (
                StatusCode::BAD_GATEWAY,
                Json(IpcError {
                    error: "api_unreachable".into(),
                    description: Some("Invalid response from Flowsta API.".into()),
                }),
            )
        })?;

        let info = crate::commands::VerifiedAppInfo {
            name: app_obj
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(&req.app_name)
                .to_string(),
            description: app_obj
                .get("description")
                .and_then(|v| v.as_str())
                .map(String::from),
            app_type: app_obj
                .get("app_type")
                .and_then(|v| v.as_str())
                .unwrap_or("holochain")
                .to_string(),
            logo_url: app_obj
                .get("logo_url")
                .and_then(|v| v.as_str())
                .map(String::from),
            scopes: app_obj
                .get("scopes")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            organization_name: app_obj
                .get("organization_name")
                .and_then(|v| v.as_str())
                .map(String::from),
        };

        // Update cache with fresh data
        {
            let mut cache = state.app_state.verified_apps.lock().unwrap();
            cache.insert(req.client_id.clone(), info.clone());
        }
        state.app_state.save_verified_apps();

        info
      }
      Err(e) => {
        // API unreachable — fall back to local cache for offline re-linking
        log::debug!("API verification failed for {}: {}", req.client_id, e);
        let cache = state.app_state.verified_apps.lock().unwrap();
        match cache.get(&req.client_id).cloned() {
            Some(cached) => {
                log::debug!("Falling back to cached app info for client_id: {}", req.client_id);
                cached
            }
            None => return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(IpcError {
                    error: "api_unreachable".into(),
                    description: Some(
                        "Could not verify app with Flowsta. Check your internet connection."
                            .into(),
                    ),
                }),
            )),
        }
      }
    };

    // Check for existing link with different client_id (app registration changed)
    let replacing_existing = {
        let linked = state.app_state.linked_third_party_apps.lock().unwrap();
        linked.iter().any(|a| {
            a.app_agent_pub_key == req.app_agent_pub_key
                && a.client_id.as_deref() != Some(&req.client_id)
        })
    };

    // Always require user approval for identity linking
    let (tx, rx) = tokio::sync::oneshot::channel::<bool>();

    let request_id = format!("link-{}", unix_now());

    let pending = PendingLinkIdentityRequest {
        id: request_id.clone(),
        app_name: app_info.name.clone(),
        organization_name: app_info.organization_name.clone(),
        scopes: app_info.scopes.clone(),
        description: app_info.description.clone(),
        logo_url: app_info.logo_url.clone(),
        origin: origin.clone(),
        replacing_existing,
        responder: tx,
    };

    // Store the pending request
    {
        let mut pending_link = state.app_state.pending_link_identity.lock().unwrap();
        *pending_link = Some(pending);
    }

    // Emit Tauri event to show the approval dialog
    let event_payload = serde_json::json!({
        "id": request_id,
        "app_name": app_info.name,
        "organization_name": app_info.organization_name,
        "scopes": app_info.scopes,
        "description": app_info.description,
        "logo_url": app_info.logo_url,
        "origin": origin,
        "replacing_existing": replacing_existing,
    });

    let _ = state.app_handle.emit("link-identity-request", event_payload);

    // Wait for user response with 60s timeout
    let approved = match tokio::time::timeout(std::time::Duration::from_secs(60), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(IpcError {
                    error: "internal_error".into(),
                    description: Some("Approval channel closed unexpectedly.".into()),
                }),
            ));
        }
        Err(_) => {
            // Timeout — clean up pending request
            let mut pending_link = state.app_state.pending_link_identity.lock().unwrap();
            *pending_link = None;
            return Err((
                StatusCode::REQUEST_TIMEOUT,
                Json(IpcError {
                    error: "timeout".into(),
                    description: Some("User did not respond within 60 seconds.".into()),
                }),
            ));
        }
    };

    if !approved {
        return Err((
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "user_denied".into(),
                description: Some("User rejected the identity link request.".into()),
            }),
        ));
    }

    // User approved — extract signing material from vault config (scoped to drop lock)
    let (seed_arr, vault_ed25519_pub, vault_agent_39) = {
        let config = state.app_state.vault_config.lock().unwrap();
        let config = config.as_ref().ok_or_else(|| {
            (
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "vault_locked".into(),
                    description: Some("Vault was locked during approval.".into()),
                }),
            )
        })?;

        let device_seed = config.device_seed.as_ref().ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(IpcError {
                    error: "no_device_seed".into(),
                    description: Some(
                        "Vault was created before signing support. Please re-create it.".into(),
                    ),
                }),
            )
        })?;

        let mut arr = [0u8; 32];
        arr.copy_from_slice(device_seed);

        let pub_key = {
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&arr);
            *signing_key.verifying_key().as_bytes()
        };
        let agent_39 = construct_agent_pub_key_bytes(&pub_key);

        (arr, pub_key, agent_39)
    }; // vault_config lock dropped here — safe to call MAU recording below

    // Build the 78-byte sorted agent pair payload
    // This is the same payload the integrity zome's sorted_agent_pair_bytes() produces
    let payload = build_sorted_agent_pair_payload(&vault_agent_39, &app_agent_39);

    // Sign the raw 78-byte payload (NOT MessagePack-encoded)
    // The reusable crate's integrity zome uses verify_signature_raw to verify this
    let signature = sign_with_device_seed(&seed_arr, &payload);

    let vault_agent_pub_key = construct_agent_pub_key_string(&vault_ed25519_pub);

    // Track this linked app in state for the Vault UI and persist to disk
    {
        let mut linked = state.app_state.linked_third_party_apps.lock().unwrap();
        if let Some(existing) = linked.iter_mut().find(|a| a.app_agent_pub_key == req.app_agent_pub_key) {
            // Update existing link (client_id, app name, or origin may have changed)
            existing.client_id = Some(req.client_id.clone());
            existing.app_name = req.app_name.clone();
            existing.origin = origin.clone();
            existing.linked_at = unix_now();
        } else {
            linked.push(crate::commands::LinkedThirdPartyApp {
                app_name: req.app_name.clone(),
                app_agent_pub_key: req.app_agent_pub_key.clone(),
                linked_at: unix_now(),
                client_id: Some(req.client_id.clone()),
                origin: origin.clone(),
            });
        }
    }
    state.app_state.save_linked_apps();

    // Persist the scopes the user accepted for this app.
    {
        let mut scopes_store = state.app_state.linked_app_scopes.lock().unwrap();
        scopes_store.insert(req.client_id.clone(), app_info.scopes.clone());
    }
    state.app_state.save_linked_app_scopes();

    // Record MAU event for this app (first IPC interaction this month)
    crate::mau::record_mau_event_if_needed(&state.app_state, &req.client_id);

    // Emit event for real-time Vault UI update
    let _ = state.app_handle.emit(
        "linked-app-added",
        serde_json::json!({
            "app_name": req.app_name,
            "app_agent_pub_key": req.app_agent_pub_key,
            "linked_at": unix_now(),
        }),
    );

    let resp = LinkIdentityResponse {
        success: true,
        vault_agent_pub_key,
        vault_signature: base64_standard_encode(&signature),
    };

    Ok(axum::response::IntoResponse::into_response(Json(resp)))
}

// ── POST /revoke-identity ──────────────────────────────────────────
//
// Called by third-party apps to notify Vault that an identity link was revoked.
// No user approval needed — if the app says it revoked, we just clean up locally.

#[derive(Deserialize)]
struct RevokeIdentityRequest {
    #[allow(dead_code)]
    app_name: String,
    app_agent_pub_key: String,
}

#[derive(Serialize)]
struct RevokeIdentityResponse {
    success: bool,
}

async fn revoke_identity_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
    Json(req): Json<RevokeIdentityRequest>,
) -> Result<Json<RevokeIdentityResponse>, (StatusCode, Json<IpcError>)> {
    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "revoke-identity");

    // Capture client_id before removing the entry so we can purge its scopes.
    let client_id_to_remove = {
        let apps = state.app_state.linked_third_party_apps.lock().unwrap();
        apps.iter()
            .find(|a| a.app_agent_pub_key == req.app_agent_pub_key)
            .and_then(|a| a.client_id.clone())
    };

    // Remove the matching linked app
    {
        let mut apps = state.app_state.linked_third_party_apps.lock().unwrap();
        apps.retain(|a| a.app_agent_pub_key != req.app_agent_pub_key);
    }
    state.app_state.save_linked_apps();

    // Purge granted scopes for this app.
    if let Some(cid) = client_id_to_remove {
        state.app_state.linked_app_scopes.lock().unwrap().remove(&cid);
        state.app_state.save_linked_app_scopes();
    }

    // Emit event for real-time Vault UI update
    let _ = state.app_handle.emit(
        "linked-app-revoked",
        serde_json::json!({ "app_agent_pub_key": req.app_agent_pub_key }),
    );

    Ok(Json(RevokeIdentityResponse { success: true }))
}

// ── GET /link-status ──────────────────────────────────────────────
//
// Third-party apps call this to check if Vault still considers the link valid.
// Used to detect vault-side revocation.

#[derive(Serialize)]
struct LinkStatusResponse {
    linked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    app_name: Option<String>,
}

async fn link_status_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
    query: axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<LinkStatusResponse> {
    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "link-status");

    let app_agent_pub_key = query.get("app_agent_pub_key").cloned().unwrap_or_default();

    let apps = state.app_state.linked_third_party_apps.lock().unwrap();
    let found = apps.iter().find(|a| a.app_agent_pub_key == app_agent_pub_key);

    match found {
        Some(app) => Json(LinkStatusResponse {
            linked: true,
            app_name: Some(app.app_name.clone()),
        }),
        None => Json(LinkStatusResponse {
            linked: false,
            app_name: None,
        }),
    }
}

// ── Utility functions ───────────────────────────────────────────────

/// Returns current UTC time as ISO 8601 string (no chrono dependency).
fn chrono_now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();

    // Convert epoch seconds to date-time components
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Days since 1970-01-01 to Y-M-D (simplified calendar arithmetic)
    let mut y = 1970i64;
    let mut remaining_days = days as i64;

    loop {
        let year_days = if is_leap(y) { 366 } else { 365 };
        if remaining_days < year_days {
            break;
        }
        remaining_days -= year_days;
        y += 1;
    }

    let leap = is_leap(y);
    let month_days: [i64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    let mut m = 0usize;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining_days < md {
            m = i;
            break;
        }
        remaining_days -= md;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        remaining_days + 1,
        hours,
        minutes,
        seconds,
    )
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ── Base64 decoding (standard alphabet) ─────────────────────────────

fn base64_standard_decode(input: &str) -> Result<Vec<u8>, ()> {
    fn val(c: u8) -> Result<u32, ()> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(()),
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        out.push(((a << 2) | (b >> 4)) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' {
            let c = val(chunk[2])?;
            out.push((((b & 0xF) << 4) | (c >> 2)) as u8);
            if chunk.len() > 3 && chunk[3] != b'=' {
                let d = val(chunk[3])?;
                out.push((((c & 0x3) << 6) | d) as u8);
            }
        }
    }
    Ok(out)
}

// ── POST /backup ───────────────────────────────────────────────────
//
// Third-party apps can store data in the vault for backup / portability.
// The vault encrypts the data at rest. User approval is required.

#[derive(Deserialize)]
struct BackupRequest {
    client_id: String,
    app_name: String,
    /// Optional label for named backups. If omitted, auto-generates a
    /// timestamped label so each call creates a new snapshot.
    label: Option<String>,
    /// The data to back up (JSON value — will be serialized to bytes).
    data: serde_json::Value,
    /// MIME type hint (default: application/json).
    content_type: Option<String>,
}

#[derive(Serialize)]
struct BackupResponse {
    success: bool,
    label: String,
    data_size: usize,
    created_at: i64,
}

async fn backup_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
    Json(req): Json<BackupRequest>,
) -> Result<axum::response::Response, (StatusCode, Json<IpcError>)> {
    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "backup");

    // SECURITY: caller must be linked AND can only save under its own client_id.
    // Without these checks, a hostile app could overwrite another app's backups
    // with bogus data (data destruction / poisoning).
    let caller_client_id = match origin_to_client_id(&state.app_state, origin.as_deref()) {
        Some(c) => c,
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "not_linked".into(),
                    description: Some("This origin is not a linked third-party app.".into()),
                }),
            ));
        }
    };
    if caller_client_id != req.client_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "client_id_mismatch".into(),
                description: Some("Apps may only save backups under their own client_id.".into()),
            }),
        ));
    }

    // Backup key must be available (set on first unlock, persists through lock)
    {
        let bk = state.app_state.backup_key.lock().unwrap();
        if bk.is_none() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "vault_never_unlocked".into(),
                    description: Some("Vault has never been unlocked in this session. Unlock it first.".into()),
                }),
            ));
        }
    }

    // Serialize data to bytes
    let data_bytes = serde_json::to_vec(&req.data).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(IpcError {
                error: "invalid_data".into(),
                description: Some(format!("Failed to serialize data: {}", e)),
            }),
        )
    })?;

    // Save the backup
    let meta = crate::backup::save_backup(
        &state.app_state,
        &req.client_id,
        &req.app_name,
        req.label.as_deref(),
        &data_bytes,
        req.content_type.as_deref(),
    )
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(IpcError {
                error: "backup_failed".into(),
                description: Some(e),
            }),
        )
    })?;

    Ok(axum::response::IntoResponse::into_response(Json(
        BackupResponse {
            success: true,
            label: meta.label.unwrap_or_else(|| "latest".into()),
            data_size: meta.data_size,
            created_at: meta.created_at,
        },
    )))
}

// ── GET /backup/list ───────────────────────────────────────────────

async fn backup_list_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
) -> Result<axum::response::Response, (StatusCode, Json<IpcError>)> {
    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "backup_list");

    // SECURITY: only return the caller's own backups. Without this scoping,
    // any local process could enumerate which third-party apps the user has
    // linked (revealing sensitive associations: fintech app, dating app, etc).
    let caller_client_id = match origin_to_client_id(&state.app_state, origin.as_deref()) {
        Some(c) => c,
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "not_linked".into(),
                    description: Some(
                        "This origin is not a linked third-party app.".into(),
                    ),
                }),
            ));
        }
    };

    {
        let config = state.app_state.vault_config.lock().unwrap();
        if config.is_none() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "vault_locked".into(),
                    description: Some("Vault is locked.".into()),
                }),
            ));
        }
    }

    // Get all stats then filter to only the caller's app.
    let mut stats = crate::backup::get_backup_stats(&state.app_state.data_dir);
    stats.apps.retain(|a| a.client_id == caller_client_id);
    stats.app_count = stats.apps.len();
    stats.total_backups = stats.apps.iter().map(|a| a.backup_count).sum();
    stats.total_size = stats.apps.iter().map(|a| a.total_size).sum();

    Ok(axum::response::IntoResponse::into_response(Json(stats)))
}

// ── POST /backup/retrieve ──────────────────────────────────────────

#[derive(Deserialize)]
struct BackupRetrieveRequest {
    client_id: String,
    label: Option<String>,
}

async fn backup_retrieve_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
    Json(req): Json<BackupRetrieveRequest>,
) -> Result<axum::response::Response, (StatusCode, Json<IpcError>)> {
    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "backup_retrieve");

    // SECURITY: caller must be a linked app AND can only access its own
    // backups. Without these checks, a hostile app could enumerate and
    // download backups belonging to ANY other linked app the user has.
    let caller_client_id = match origin_to_client_id(&state.app_state, origin.as_deref()) {
        Some(c) => c,
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "not_linked".into(),
                    description: Some(
                        "This origin is not a linked third-party app.".into(),
                    ),
                }),
            ));
        }
    };
    if caller_client_id != req.client_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "client_id_mismatch".into(),
                description: Some(
                    "Apps may only retrieve their own backups.".into(),
                ),
            }),
        ));
    }

    {
        let bk = state.app_state.backup_key.lock().unwrap();
        if bk.is_none() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "vault_never_unlocked".into(),
                    description: Some("Vault has never been unlocked in this session.".into()),
                }),
            ));
        }
    }

    let (data, meta) = crate::backup::retrieve_backup(
        &state.app_state,
        &req.client_id,
        req.label.as_deref(),
    )
    .map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(IpcError {
                error: "backup_not_found".into(),
                description: Some(e),
            }),
        )
    })?;

    // Try to return as JSON, fall back to hex-encoded string
    let data_value: serde_json::Value = if meta.content_type.contains("json") {
        serde_json::from_slice(&data).unwrap_or_else(|_| {
            serde_json::Value::String(hex::encode(&data))
        })
    } else {
        serde_json::Value::String(hex::encode(&data))
    };

    let resp = serde_json::json!({
        "success": true,
        "client_id": meta.client_id,
        "app_name": meta.app_name,
        "label": meta.label,
        "created_at": meta.created_at,
        "data_size": meta.data_size,
        "content_type": meta.content_type,
        "data": data_value,
    });

    Ok(axum::response::IntoResponse::into_response(Json(resp)))
}

// ── POST /backup/delete ────────────────────────────────────────────

#[derive(Deserialize)]
struct BackupDeleteRequest {
    client_id: String,
    /// If omitted, deletes ALL backups for this app.
    label: Option<String>,
    /// If true, delete all backups for this client_id.
    #[serde(default)]
    delete_all: bool,
}

async fn backup_delete_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
    Json(req): Json<BackupDeleteRequest>,
) -> Result<axum::response::Response, (StatusCode, Json<IpcError>)> {
    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "backup_delete");

    // SECURITY: caller must be linked AND can only delete its own backups.
    // Without this, hostile app could destroy data of any other linked app.
    let caller_client_id = match origin_to_client_id(&state.app_state, origin.as_deref()) {
        Some(c) => c,
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "not_linked".into(),
                    description: Some("This origin is not a linked third-party app.".into()),
                }),
            ));
        }
    };
    if caller_client_id != req.client_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "client_id_mismatch".into(),
                description: Some("Apps may only delete their own backups.".into()),
            }),
        ));
    }

    {
        let config = state.app_state.vault_config.lock().unwrap();
        if config.is_none() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "vault_locked".into(),
                    description: Some("Vault is locked.".into()),
                }),
            ));
        }
    }

    if req.delete_all {
        let count =
            crate::backup::delete_app_backups(&state.app_state.data_dir, &req.client_id)
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(IpcError {
                            error: "delete_failed".into(),
                            description: Some(e),
                        }),
                    )
                })?;
        Ok(axum::response::IntoResponse::into_response(Json(
            serde_json::json!({ "success": true, "deleted_count": count }),
        )))
    } else {
        crate::backup::delete_backup(
            &state.app_state.data_dir,
            &req.client_id,
            req.label.as_deref(),
        )
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                Json(IpcError {
                    error: "backup_not_found".into(),
                    description: Some(e),
                }),
            )
        })?;
        Ok(axum::response::IntoResponse::into_response(Json(
            serde_json::json!({ "success": true }),
        )))
    }
}

// ── Server startup ──────────────────────────────────────────────────

// ── POST /sign-document — Sign It document signing ──────────────────

#[derive(Deserialize)]
struct SignDocumentRequest {
    /// SHA-256 hex string of the file
    file_hash: String,
    /// Human-readable label for the approval dialog
    #[serde(default)]
    label: Option<String>,
    /// Why this file is being signed
    #[serde(default)]
    intent: Option<String>,
    /// AI generation disclosure
    #[serde(default)]
    ai_generation: Option<String>,
    /// Content rights manifest
    #[serde(default)]
    content_rights: Option<serde_json::Value>,
    /// App name (shown in approval dialog)
    #[serde(default)]
    app_name: Option<String>,
    /// Developer client_id from dev.flowsta.com
    #[serde(default)]
    client_id: Option<String>,
}

#[derive(Serialize)]
struct SignDocumentResponse {
    success: bool,
    file_hash: String,
    signature: String,
    agent_pub_key: String,
    signed_at: String,
    /// Placeholder for DHT action hash — will be populated once
    /// conductor zome call integration is added in task 1.4
    action_hash: Option<String>,
}

async fn sign_document_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
    Json(req): Json<SignDocumentRequest>,
) -> Result<axum::response::Response, (StatusCode, Json<IpcError>)> {
    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "sign-document");

    // 1. Verify vault is unlocked
    {
        let config = state.app_state.vault_config.lock().unwrap();
        if config.is_none() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "vault_locked".into(),
                    description: Some("Vault is locked. Unlock it first.".into()),
                }),
            ));
        }
    }

    // 2. Validate file_hash is valid hex and 32 bytes
    let hash_bytes = hex::decode(&req.file_hash).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(IpcError {
                error: "invalid_file_hash".into(),
                description: Some("file_hash must be a valid hex string".into()),
            }),
        )
    })?;
    if hash_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(IpcError {
                error: "invalid_file_hash".into(),
                description: Some("file_hash must be exactly 64 hex characters (32 bytes SHA-256)".into()),
            }),
        ));
    }

    // 3. Resolve app name for the approval dialog
    let app_name = req.app_name.clone().unwrap_or_else(|| {
        origin.clone().unwrap_or_else(|| "Unknown app".to_string())
    });

    // 4. Create oneshot channel for user approval
    let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
    let request_id = format!("sign-{}", unix_now());
    let pending = PendingDocumentSignRequest {
        id: request_id.clone(),
        app_name: app_name.clone(),
        file_hash: req.file_hash.clone(),
        label: req.label.clone(),
        origin: origin.clone(),
        responder: tx,
    };

    // 5. Store pending request
    {
        let mut pending_sign = state.app_state.pending_document_sign.lock().unwrap();
        *pending_sign = Some(pending);
    }

    // 6. Emit Tauri event to show approval dialog
    let event_payload = serde_json::json!({
        "id": request_id,
        "app_name": app_name,
        "file_hash": req.file_hash,
        "label": req.label,
        "origin": origin,
    });
    let _ = state.app_handle.emit("document-sign-request", event_payload);

    // 7. Wait for user response with 60s timeout
    let approved = match tokio::time::timeout(std::time::Duration::from_secs(60), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(IpcError {
                    error: "internal_error".into(),
                    description: Some("Approval channel closed unexpectedly.".into()),
                }),
            ));
        }
        Err(_) => {
            // Timeout — clean up
            let mut pending_sign = state.app_state.pending_document_sign.lock().unwrap();
            *pending_sign = None;
            return Err((
                StatusCode::REQUEST_TIMEOUT,
                Json(IpcError {
                    error: "timeout".into(),
                    description: Some("User did not respond within 60 seconds.".into()),
                }),
            ));
        }
    };

    if !approved {
        return Err((
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "user_denied".into(),
                description: Some("User rejected the document signing request.".into()),
            }),
        ));
    }

    // 8. Sign the file hash with the device Ed25519 key
    let (signature_bytes, vault_agent_pub_key) = {
        let config = state.app_state.vault_config.lock().unwrap();
        let config = config.as_ref().ok_or_else(|| {
            (
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "vault_locked".into(),
                    description: Some("Vault was locked during approval.".into()),
                }),
            )
        })?;

        let device_seed = config.device_seed.as_ref().ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(IpcError {
                    error: "no_device_seed".into(),
                    description: Some(
                        "Vault was created before signing support. Please re-create it.".into(),
                    ),
                }),
            )
        })?;

        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(device_seed);

        // Sign the raw file hash bytes (NOT MessagePack-encoded)
        let signature = sign_with_device_seed(&seed_arr, &hash_bytes);

        let pub_key = {
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_arr);
            *signing_key.verifying_key().as_bytes()
        };
        let agent_pub_key = construct_agent_pub_key_string(&pub_key);

        (signature, agent_pub_key)
    }; // vault_config lock dropped

    let now_iso = {
        let secs = unix_now();
        // Simple ISO 8601 without external dep
        format!("{}Z", chrono_lite(secs))
    };

    // 9. Record MAU event if client_id provided
    if let Some(ref client_id) = req.client_id {
        crate::mau::record_mau_event_if_needed(&state.app_state, client_id);
    }

    // 10. Return signature
    // NOTE: DHT commit (action_hash) is added in task 1.4 when conductor
    // zome call integration is built. For now, we return the signature
    // which the calling app can use.
    let resp = SignDocumentResponse {
        success: true,
        file_hash: req.file_hash,
        signature: base64_standard_encode(&signature_bytes),
        agent_pub_key: vault_agent_pub_key,
        signed_at: now_iso,
        action_hash: None,
    };

    Ok(axum::response::IntoResponse::into_response(Json(resp)))
}

/// Simple timestamp to ISO 8601 string (avoids adding chrono dependency).
fn chrono_lite(unix_secs: i64) -> String {
    let secs = unix_secs as u64;
    // Days since epoch
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Simple year/month/day from days since 1970-01-01 (Rata Die algorithm)
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Start the IPC server on localhost.
/// Tries ports 27777, 27778, 27779 in order.
pub async fn start_ipc_server(
    app_state: Arc<AppState>,
    app_handle: tauri::AppHandle,
) -> Result<u16, String> {
    let ipc_state = Arc::new(IpcState {
        app_state,
        app_handle,
    });

    // CORS: allow browser-based SDK to call from any origin on localhost
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
        ])
        .max_age(std::time::Duration::from_secs(3600));

    let app = Router::new()
        .route("/status", get(status_handler))
        .route("/sign", post(sign_handler))
        .route("/authenticate", post(authenticate_handler))
        .route("/link-identity", post(link_identity_handler))
        .route("/sign-document", post(sign_document_handler))
        .route("/revoke-identity", post(revoke_identity_handler))
        .route("/link-status", get(link_status_handler))
        .route("/backup", post(backup_handler))
        .route("/backup/list", get(backup_list_handler))
        .route("/backup/retrieve", post(backup_retrieve_handler))
        .route("/backup/delete", post(backup_delete_handler))
        .layer(cors)
        .with_state(ipc_state);

    // Try ports in sequence
    for port in [27777, 27778, 27779] {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                log::info!("IPC server listening on http://127.0.0.1:{}", port);
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(listener, app).await {
                        log::error!("IPC server error: {}", e);
                    }
                });
                return Ok(port);
            }
            Err(e) => {
                log::warn!("Port {} unavailable: {}", port, e);
            }
        }
    }

    Err("All IPC ports (27777-27779) are unavailable".into())
}
