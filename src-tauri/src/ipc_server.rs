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
use tauri::{Emitter, Manager};

/// What the Vault window looked like before a consent request raised it, so we
/// can put it back afterwards (see `restore_window`).
#[derive(Clone, Copy)]
struct PriorWindowState {
    /// Was Vault the focused/foreground app when the request arrived? If so the
    /// user was actively in Vault and we leave it where it is. Otherwise Vault
    /// only came forward FOR this consent, so we tuck it away afterwards.
    was_focused: bool,
    was_visible: bool,
}

/// Bring the Vault window to the foreground so a freshly-emitted consent dialog
/// isn't hidden behind the third-party app the user just clicked. Returns the
/// window's prior state so the caller can restore it once the user has
/// responded. Best-effort: no-ops if the main window can't be resolved.
///
/// NOTE: on Wayland the compositor will NOT let a background app raise itself
/// in response to a non-user-initiated request — it shows a "<app> is ready"
/// notification instead. There's no API workaround; this is by design.
fn raise_window(app: &tauri::AppHandle) -> Option<PriorWindowState> {
    let win = app.get_webview_window("main")?;
    let prior = PriorWindowState {
        was_focused: win.is_focused().unwrap_or(false),
        was_visible: win.is_visible().unwrap_or(true),
    };
    let _ = win.unminimize();
    let _ = win.show();
    // set_focus() alone does NOT raise the window on Linux/Wayland (and is
    // unreliable on macOS for a background app). Briefly toggling
    // always-on-top forces it forward where the OS allows it — same trick the
    // tray "Open" handler uses.
    let _ = win.set_always_on_top(true);
    let _ = win.set_focus();
    let _ = win.set_always_on_top(false);
    Some(prior)
}

/// Put Vault back the way it was before `raise_window` — so that approving (or
/// denying) a request from another app returns focus to THAT app instead of
/// leaving Vault parked in front. If Vault was already the focused app the user
/// was using, we leave it. Otherwise we minimize (or re-hide) it; minimizing
/// the foreground window hands focus to the app behind it (the caller).
fn restore_window(app: &tauri::AppHandle, prior: Option<PriorWindowState>) {
    let Some(prior) = prior else { return };
    if prior.was_focused {
        return;
    }
    let Some(win) = app.get_webview_window("main") else {
        return;
    };
    if !prior.was_visible {
        let _ = win.hide();
    } else {
        let _ = win.minimize();
    }
}
use tower_http::cors::CorsLayer;

/// Shared state for the IPC server (references the main AppState).
pub struct IpcState {
    pub app_state: Arc<AppState>,
    pub app_handle: tauri::AppHandle,
    pub op_jobs: OpJobs,
}

/// Dev-only: auto-approve all bridge dialogs so the full operation matrix
/// can run headlessly. Compile-gated OUT of release builds; additionally
/// requires the env flag, so a dev build behaves normally by default.
fn auto_approve_enabled() -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::var("FLOWSTA_VAULT_AUTO_APPROVE").as_deref() == Ok("1")
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

/// Report a job's stage (no-op for synchronous callers).
fn set_job_stage(state: &Arc<IpcState>, job_id: &Option<String>, stage: &str) {
    if let Some(id) = job_id {
        state.op_jobs.set_stage(id, stage);
    }
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

    // Get signing material in a scoped block — the config guard must not
    // live across the approval await below (non-Send).
    let (seed_arr, agent_pub_key, did) = {
        let config_guard = state.app_state.vault_config.lock().unwrap();
        let config = config_guard.as_ref().ok_or_else(|| {
            (
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "vault_locked".into(),
                    description: Some("Vault is locked. Unlock it first.".into()),
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
        (seed_arr, config.agent_pub_key.clone(), config.did.clone())
    };

    // Per-action approval: signing with the user's identity key is never
    // silent. Exception: within the post-link ceremony window, the linking
    // flow's agent-pair signature proceeds on the strength of the link
    // approval the user just gave (one dialog for the ceremony, not two).
    let in_ceremony_window = origin
        .as_deref()
        .map(|o| {
            let map = state.app_state.recent_link_approvals.lock().unwrap();
            map.get(o)
                .map(|t| t.elapsed() < std::time::Duration::from_secs(120))
                .unwrap_or(false)
        })
        .unwrap_or(false);

    if !in_ceremony_window {
        let app_name = origin_to_client_id(&state.app_state, origin.as_deref())
            .and_then(|cid| {
                let apps = state.app_state.linked_third_party_apps.lock().unwrap();
                apps.iter().find(|a| a.client_id.as_deref() == Some(cid.as_str())).map(|a| a.app_name.clone())
            })
            .or_else(|| origin.clone())
            .unwrap_or_else(|| "Unknown app".to_string());
        let payload_bytes = req
            .bytes
            .as_ref()
            .map(|b| b.len() * 3 / 4)
            .unwrap_or_default();

        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
        let request_id = format!("rawsign-{}", unix_now());
        {
            let mut pending = state.app_state.pending_raw_sign.lock().unwrap();
            *pending = Some(crate::commands::PendingRawSignRequest {
                id: request_id.clone(),
                app_name: app_name.clone(),
                origin: origin.clone(),
                sign_type: req.sign_type.clone(),
                payload_bytes,
                responder: tx,
            });
        }
        let event_payload = serde_json::json!({
            "id": request_id,
            "app_name": app_name,
            "origin": origin,
            "sign_type": req.sign_type,
            "payload_bytes": payload_bytes,
        });
        raise_window(&state.app_handle);
        let _ = state.app_handle.emit("raw-sign-request", event_payload);

        let approved = match tokio::time::timeout(std::time::Duration::from_secs(60), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => false,
            Err(_) => {
                let mut pending = state.app_state.pending_raw_sign.lock().unwrap();
                *pending = None;
                false
            }
        };
        if !approved {
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "user_denied".into(),
                    description: Some("The user did not approve this signing request.".into()),
                }),
            ));
        }
    }

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

            // Reserved-prefix refusal: Flowsta auth protocols (vault-grant
            // login, relay login, identity registration) verify raw Ed25519
            // signatures over `flowsta-…`-prefixed canonical strings. If this
            // generic surface signed such a payload, a linked app could mint
            // a REAL session as the vault owner. Only the dedicated native
            // flows (which show their own approval UI) may sign these.
            if payload.starts_with(b"flowsta-") {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(IpcError {
                        error: "reserved_prefix".into(),
                        description: Some(
                            "Payloads with the reserved 'flowsta-' prefix cannot be signed via /sign.".into(),
                        ),
                    }),
                ));
            }

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
        // Surface auto-approved authentications so they are visible, not
        // silent — the user chose "remember" (or linked the app), but a
        // sign-in as them should never happen invisibly.
        let _ = state.app_handle.emit(
            "auth-auto-approved",
            serde_json::json!({ "app_name": req.app_name, "origin": origin }),
        );
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

        raise_window(&state.app_handle);
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
    // Extract identity + seed, then RELEASE the vault_config lock before
    // any further work. record_mau_event_if_needed (below) re-locks
    // vault_config, and std::sync::Mutex is non-reentrant — holding the
    // guard across that call self-deadlocks the handler. This bit: an
    // /authenticate carrying a client_id hung forever (handler entered,
    // never returned, the request thread stuck on the second lock).
    let (agent_pub_key, did, device_seed) = {
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
        (
            config.agent_pub_key.clone(),
            config.did.clone(),
            config.device_seed.clone(),
        )
    };

    // Sign the challenge if provided
    let signature = if let Some(ref challenge_b64) = req.challenge {
        let device_seed = device_seed.as_ref().ok_or_else(|| {
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

    // Record MAU event if client_id was provided (vault_config lock released)
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

    let prior = raise_window(&state.app_handle);
    let _ = state.app_handle.emit("link-identity-request", event_payload);

    // Wait for user response with 60s timeout
    let approved = match tokio::time::timeout(std::time::Duration::from_secs(60), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            restore_window(&state.app_handle, prior);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(IpcError {
                    error: "internal_error".into(),
                    description: Some("Approval channel closed unexpectedly.".into()),
                }),
            ));
        }
        Err(_) => {
            // Timeout — clean up pending request and tuck Vault back.
            restore_window(&state.app_handle, prior);
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

    // User has responded (approve or deny) — return Vault to its prior state so
    // focus goes back to the calling app instead of leaving Vault in front.
    restore_window(&state.app_handle, prior);

    if !approved {
        return Err((
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "user_denied".into(),
                description: Some("User rejected the identity link request.".into()),
            }),
        ));
    }

    // Linking is the stronger consent: treat it as an authenticate
    // approval for this session too (same in-memory lifetime as the
    // dialog's "remember" option), so a link immediately followed by an
    // /authenticate — the standard third-party sign-in sequence — shows
    // ONE dialog instead of two.
    if let Some(ref orig) = origin {
        let mut apps = state.app_state.approved_apps.lock().unwrap();
        if !apps.contains(orig) {
            apps.push(orig.clone());
        }
    }
    // Open the linking-ceremony window: the immediate follow-up /sign of the
    // agent-pair payload proceeds without a second dialog. Outside this
    // window, /sign shows per-action approval.
    if let Some(ref orig) = origin {
        state
            .app_state
            .recent_link_approvals
            .lock()
            .unwrap()
            .insert(orig.clone(), std::time::Instant::now());
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
    /// Signer-declared note stored with a published signature (280 max)
    #[serde(default)]
    comment: Option<String>,
    /// Perceptual hash (image/audio/video fingerprint) stored with a
    /// published signature — enables fuzzy matching on the verify page.
    #[serde(default)]
    perceptual_hash: Option<serde_json::Value>,
    /// Small preview image (data:image/... URI) committed alongside a
    /// published signature, like the in-app signing flow does.
    #[serde(default)]
    thumbnail: Option<String>,
    /// Hex action hash of an earlier signature this one amends/replaces.
    #[serde(default)]
    supersedes: Option<String>,
    /// Run as an async job: respond immediately with a job_id and report
    /// progress via /op-status. The page polls; nothing is held open.
    #[serde(default)]
    job: bool,
    /// Publish the signature to the Sign It network from THIS device's
    /// signing cell (web-delegated signing for upgraded accounts).
    /// Restricted to Flowsta origins; the approval dialog says so.
    #[serde(default)]
    commit: bool,
}

/// Wait for the vault to be unlocked, up to `secs`. Used by Flowsta-page
/// requests that arrive while locked: instead of failing immediately, the
/// request rides through the unlock and its approval dialog appears the
/// moment the user is in — no second attempt needed from the web page.
async fn wait_for_unlock(state: &Arc<AppState>, secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        if state.vault_config.lock().unwrap().is_some() {
            return true;
        }
        if std::time::Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Wait for the conductor to come up, up to `secs`. The conductor spawns
/// on unlock and takes a while on a fresh start — a request that rode
/// through the unlock would otherwise approve and then fail to commit.
async fn wait_for_conductor(state: &Arc<AppState>, secs: u64) -> Option<(u16, u16)> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        let ports = {
            let handle = state.conductor_handle.lock().unwrap();
            handle.as_ref().map(|h| (h.admin_port, h.app_port))
        };
        if ports.is_some() {
            return ports;
        }
        if std::time::Instant::now() > deadline {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// Publishing to the user's own signing cell is a Flowsta-surface
/// capability: only pages on flowsta.com (or its subdomains) may request
/// it. Signature-only requests stay available to every app, dialog-gated.
fn is_flowsta_origin(origin: Option<&str>) -> bool {
    let Some(origin) = origin else { return false };
    let Ok(url) = url::Url::parse(origin) else { return false };
    if url.scheme() != "https" {
        return false;
    }
    match url.host_str() {
        Some(host) => host == "flowsta.com" || host.ends_with(".flowsta.com"),
        None => false,
    }
}

#[derive(Serialize)]
struct SignDocumentResponse {
    success: bool,
    file_hash: String,
    signature: String,
    agent_pub_key: String,
    signed_at: String,
    /// Set when the signature was published to the Sign It network
    /// (`commit: true`) — hex of the committed record's action hash.
    action_hash: Option<String>,
}

async fn sign_document_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
    Json(req): Json<SignDocumentRequest>,
) -> Result<axum::response::Response, (StatusCode, Json<IpcError>)> {
    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "sign-document");

    if req.job {
        let job_id = state.op_jobs.create("sign");
        let task_state = state.clone();
        let task_origin = origin.clone();
        let task_job = job_id.clone();
        tokio::spawn(async move {
            match sign_document_core(
                task_state.clone(),
                task_origin,
                req,
                Some(task_job.clone()),
            )
            .await
            {
                Ok(v) => task_state.op_jobs.finish(&task_job, v),
                Err((_, Json(e))) => task_state.op_jobs.fail(
                    &task_job,
                    &e.error,
                    e.description.as_deref().unwrap_or(""),
                ),
            }
        });
        return Ok(axum::response::IntoResponse::into_response(Json(
            serde_json::json!({ "job_id": job_id }),
        )));
    }

    sign_document_core(state, origin, req, None)
        .await
        .map(|v| axum::response::IntoResponse::into_response(Json(v)))
}

async fn sign_document_core(
    state: Arc<IpcState>,
    origin: Option<String>,
    req: SignDocumentRequest,
    job_id: Option<String>,
) -> Result<serde_json::Value, (StatusCode, Json<IpcError>)> {

    // 1. Verify vault is unlocked. For Flowsta pages, surface the locked
    // vault and WAIT through the unlock — the approval dialog then appears
    // immediately and the page's original click completes on its own.
    let locked = state.app_state.vault_config.lock().unwrap().is_none();
    if locked {
        set_job_stage(&state, &job_id, "waiting_unlock");
        let flowsta = is_flowsta_origin(origin.as_deref());
        if flowsta {
            raise_window(&state.app_handle);
            let _ = state.app_handle.emit(
                "unlock-attention",
                serde_json::json!({ "reason": "sign", "origin": origin }),
            );
        }
        // Jobs hold nothing open, so they can politely wait longer.
        let unlock_budget = if job_id.is_some() { 180 } else { 60 };
        if !flowsta || !wait_for_unlock(&state.app_state, unlock_budget).await {
            let _ = state.app_handle.emit("unlock-attention-clear", serde_json::json!({}));
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "vault_locked".into(),
                    description: Some("Vault is locked. Unlock it first.".into()),
                }),
            ));
        }
        let _ = state.app_handle.emit("unlock-attention-clear", serde_json::json!({}));
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
    // Reserved-prefix refusal (same rule as /sign): a crafted 32-byte ASCII
    // "hash" must never yield a signature over a flowsta- auth payload.
    if hash_bytes.starts_with(b"flowsta-") {
        return Err((
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "reserved_prefix".into(),
                description: Some(
                    "Hashes with the reserved 'flowsta-' prefix cannot be signed.".into(),
                ),
            }),
        ));
    }

    if req.commit && !is_flowsta_origin(origin.as_deref()) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "tier_forbidden".into(),
                description: Some(
                    "Publishing a signature through Vault is available to Flowsta pages only."
                        .into(),
                ),
            }),
        ));
    }
    if let Some(ref comment) = req.comment {
        if comment.len() > 280 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(IpcError {
                    error: "invalid_comment".into(),
                    description: Some("comment must be 280 characters or fewer".into()),
                }),
            ));
        }
    }
    let supersedes_bytes = match req.supersedes.as_deref() {
        Some(hex_str) => match hex::decode(hex_str) {
            Ok(b) if b.len() == 39 => Some(b),
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(IpcError {
                        error: "invalid_supersedes".into(),
                        description: Some(
                            "supersedes must be the hex action hash of an earlier signature".into(),
                        ),
                    }),
                ));
            }
        },
        None => None,
    };
    if let Some(ref t) = req.thumbnail {
        if !t.starts_with("data:image/") || t.len() > 300_000 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(IpcError {
                    error: "invalid_thumbnail".into(),
                    description: Some(
                        "thumbnail must be a data:image/... URI under 300 KB".into(),
                    ),
                }),
            ));
        }
    }

    // 3. Resolve app name for the approval dialog
    let app_name = req.app_name.clone().unwrap_or_else(|| {
        origin.clone().unwrap_or_else(|| "Unknown app".to_string())
    });

    // When publishing, make sure the conductor is up BEFORE asking for
    // approval — an approval must always be able to commit. (It spawns on
    // unlock; right after a restart it can need a minute.) The UI shows a
    // visible "preparing" banner for the whole wait.
    if req.commit {
        set_job_stage(&state, &job_id, "preparing");
        let _ = state.app_handle.emit(
            "op-pending",
            serde_json::json!({ "op": "sign", "origin": origin }),
        );
        let ready = wait_for_conductor(&state.app_state, 90).await.is_some();
        let _ = state.app_handle.emit("op-pending-clear", serde_json::json!({}));
        if !ready {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(IpcError {
                    error: "conductor_not_ready".into(),
                    description: Some(
                        "Your Vault is still starting up — try again in a moment.".into(),
                    ),
                }),
            ));
        }
    }

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

    // 6. Emit Tauri event to show approval dialog. `commit` tells the
    // dialog this signature will be PUBLISHED to the Sign It network,
    // not just returned to the calling app.
    let event_payload = serde_json::json!({
        "id": request_id,
        "app_name": app_name,
        "file_hash": req.file_hash,
        "label": req.label,
        "origin": origin,
        "commit": req.commit,
        "amends": supersedes_bytes.is_some(),
    });
    set_job_stage(&state, &job_id, "awaiting_approval");
    raise_window(&state.app_handle);
    let _ = state.app_handle.emit("document-sign-request", event_payload);

    // 7. Wait for user response (jobs can wait longer — nothing is held open)
    let approval_budget = if job_id.is_some() { 120 } else { 60 };
    let approved = if auto_approve_enabled() {
        let _ = state.app_state.pending_document_sign.lock().unwrap().take();
        log::warn!("AUTO-APPROVE (dev): document-sign approved headlessly");
        true
    } else {
        match tokio::time::timeout(std::time::Duration::from_secs(approval_budget), rx).await {
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

    // 10. Publish to the Sign It network when requested — same call the
    // in-app signing flow uses, against this device's signing cell. A
    // requested publish that cannot happen is an ERROR, not a silent
    // signature-only response: the calling page treats the action hash as
    // proof the signature exists on the network.
    set_job_stage(&state, &job_id, "publishing");
    let action_hash = if req.commit {
        let Some((admin_port, app_port)) = wait_for_conductor(&state.app_state, 30).await
        else {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(IpcError {
                    error: "conductor_not_ready".into(),
                    description: Some(
                        "Your Vault is still starting up — try again in a moment.".into(),
                    ),
                }),
            ));
        };
        let now_ms = (unix_now() as i64) * 1000;
        match crate::commands::commit_signature_to_dht(
            admin_port,
            app_port,
            &hash_bytes,
            &signature_bytes,
            now_ms,
            req.intent.as_deref(),
            req.ai_generation.as_deref(),
            req.content_rights.as_ref(),
            None,
            req.perceptual_hash.as_ref(),
            req.comment.as_deref(),
            supersedes_bytes.as_deref(),
        )
        .await
        {
            Ok(hash) => {
                // A published signature counts against the sign quota just
                // like an in-app sign: bump the local cache and push the
                // count to the server so web quota meters update.
                if let Err(e) = crate::quota_cache::increment_used(&state.app_state.data_dir) {
                    log::warn!("Quota cache increment failed (non-fatal): {}", e);
                }
                let sync_state = state.app_state.clone();
                let api_url = option_env!("FLOWSTA_API_URL")
                    .unwrap_or("https://auth-api.flowsta.com")
                    .to_string();
                tokio::spawn(async move {
                    if let Err(e) =
                        crate::commands::sync_quota_to_server_inner(&sync_state, api_url, 1).await
                    {
                        log::warn!("Quota sync after published sign failed (non-fatal): {}", e);
                    }
                });
                // Thumbnail rides on the same source chain — commit it
                // sequentially after the signature (best-effort; the
                // signature stands without it).
                if let Some(ref thumb) = req.thumbnail {
                    if let Err(e) = crate::commands::set_thumbnail_inner(
                        &state.app_state,
                        hash.clone(),
                        thumb.clone(),
                    )
                    .await
                    {
                        log::warn!("Thumbnail commit after publish failed (non-fatal): {}", e);
                    }
                }
                // Tell the Vault UI a signature just landed so the
                // signatures view and quota meter refresh live.
                let _ = state.app_handle.emit(
                    "signature-published",
                    serde_json::json!({ "action_hash": hash, "file_hash": req.file_hash }),
                );
                Some(hash)
            }
            Err(e) => {
                log::error!("Web-delegated signature publish failed: {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(IpcError {
                        error: "commit_failed".into(),
                        description: Some(
                            "The signature was not published — nothing changed. Try again."
                                .into(),
                        ),
                    }),
                ));
            }
        }
    } else {
        None
    };

    let resp = SignDocumentResponse {
        success: true,
        file_hash: req.file_hash,
        signature: base64_standard_encode(&signature_bytes),
        agent_pub_key: vault_agent_pub_key,
        signed_at: now_iso,
        action_hash,
    };

    serde_json::to_value(&resp).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(IpcError {
                error: "internal_error".into(),
                description: Some(format!("Response encoding failed: {}", e)),
            }),
        )
    })
}

// ── POST /profile-update — web dashboard delegating a profile write ─────────
//
// Device-hosted accounts keep their canonical profile in the encrypted
// private cell on THIS device; the dashboard can't write it server-side.
// Flowsta pages only (same capability rule as publishing a signature),
// and every update passes a per-action approval dialog. The dashboard
// separately refreshes the server's public-profile cache so
// flowsta.com/<username> keeps working.

#[derive(Deserialize)]
struct ProfileUpdateRequest {
    #[serde(default)]
    display_name: Option<String>,
    /// Data URI (or https URL) for the profile picture.
    #[serde(default)]
    profile_picture: Option<String>,
    #[serde(default)]
    job: bool,
}

async fn profile_update_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
    Json(req): Json<ProfileUpdateRequest>,
) -> Result<axum::response::Response, (StatusCode, Json<IpcError>)> {
    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "profile-update");

    if req.job {
        let job_id = state.op_jobs.create("profile");
        let task_state = state.clone();
        let task_origin = origin.clone();
        let task_job = job_id.clone();
        tokio::spawn(async move {
            match profile_update_core(task_state.clone(), task_origin, req, Some(task_job.clone())).await {
                Ok(v) => task_state.op_jobs.finish(&task_job, v),
                Err((_, Json(e))) => task_state.op_jobs.fail(
                    &task_job,
                    &e.error,
                    e.description.as_deref().unwrap_or(""),
                ),
            }
        });
        return Ok(axum::response::IntoResponse::into_response(Json(
            serde_json::json!({ "job_id": job_id }),
        )));
    }
    profile_update_core(state, origin, req, None)
        .await
        .map(|v| axum::response::IntoResponse::into_response(Json(v)))
}

async fn profile_update_core(
    state: Arc<IpcState>,
    origin: Option<String>,
    req: ProfileUpdateRequest,
    job_id: Option<String>,
) -> Result<serde_json::Value, (StatusCode, Json<IpcError>)> {

    if !is_flowsta_origin(origin.as_deref()) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "tier_forbidden".into(),
                description: Some(
                    "Updating the Vault-stored profile is available to Flowsta pages only.".into(),
                ),
            }),
        ));
    }
    if state.app_state.vault_config.lock().unwrap().is_none() {
        set_job_stage(&state, &job_id, "waiting_unlock");
        raise_window(&state.app_handle);
        let _ = state.app_handle.emit(
            "unlock-attention",
            serde_json::json!({ "reason": "profile", "origin": origin }),
        );
        let unlock_budget = if job_id.is_some() { 180 } else { 60 };
        let unlocked = wait_for_unlock(&state.app_state, unlock_budget).await;
        let _ = state.app_handle.emit("unlock-attention-clear", serde_json::json!({}));
        if !unlocked {
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "vault_locked".into(),
                    description: Some("Vault is locked. Unlock it first.".into()),
                }),
            ));
        }
    }

    let display_name = req
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    if let Some(ref name) = display_name {
        if name.len() > 80 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(IpcError {
                    error: "invalid_display_name".into(),
                    description: Some("Display name must be 80 characters or fewer.".into()),
                }),
            ));
        }
    }
    let picture = req.profile_picture.filter(|p| !p.is_empty());
    if let Some(ref p) = picture {
        let ok_scheme = p.starts_with("data:image/") || p.starts_with("https://");
        if !ok_scheme || p.len() > 800_000 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(IpcError {
                    error: "invalid_profile_picture".into(),
                    description: Some(
                        "Profile picture must be a data:image/... URI or https URL under 800 KB."
                            .into(),
                    ),
                }),
            ));
        }
    }
    if display_name.is_none() && picture.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(IpcError {
                error: "nothing_to_update".into(),
                description: Some("Provide display_name and/or profile_picture.".into()),
            }),
        ));
    }

    // The write needs the conductor — make sure it's up BEFORE asking for
    // approval so an approval can always land.
    set_job_stage(&state, &job_id, "preparing");
    if wait_for_conductor(&state.app_state, 90).await.is_none() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(IpcError {
                error: "conductor_not_ready".into(),
                description: Some(
                    "Your Vault is still starting up — try again in a moment.".into(),
                ),
            }),
        ));
    }

    // Per-action approval — no silent writes into the user's cell.
    let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
    let request_id = format!("profile-{}", unix_now());
    {
        let mut pending = state.app_state.pending_profile_update.lock().unwrap();
        *pending = Some(crate::commands::PendingProfileUpdateRequest {
            id: request_id.clone(),
            origin: origin.clone(),
            display_name: display_name.clone(),
            picture_changed: picture.is_some(),
            responder: tx,
        });
    }
    set_job_stage(&state, &job_id, "awaiting_approval");
    raise_window(&state.app_handle);
    let _ = state.app_handle.emit(
        "profile-update-request",
        serde_json::json!({
            "id": request_id,
            "origin": origin,
            "display_name": display_name,
            "picture_changed": picture.is_some(),
        }),
    );

    let approved = if auto_approve_enabled() {
        let _ = state.app_state.pending_profile_update.lock().unwrap().take();
        log::warn!("AUTO-APPROVE (dev): profile update approved headlessly");
        true
    } else {
        match tokio::time::timeout(std::time::Duration::from_secs(60), rx).await {
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
                let mut pending = state.app_state.pending_profile_update.lock().unwrap();
                *pending = None;
                return Err((
                    StatusCode::REQUEST_TIMEOUT,
                    Json(IpcError {
                        error: "timeout".into(),
                        description: Some("User did not respond within 60 seconds.".into()),
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
                description: Some("User rejected the profile update.".into()),
            }),
        ));
    }

    set_job_stage(&state, &job_id, "publishing");
    // Write the sealed record(s): display name lives on "user_profile",
    // the picture on "profile_picture" (v1.11 shapes, sealed in v2).
    let now_us = (unix_now() as i64) * 1_000_000;
    let now_ms = (unix_now() as u64) * 1000;
    let existing = crate::sealed::sealed_list_inner(&state.app_state)
        .await
        .map_err(|e| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(IpcError {
                    error: "conductor_not_ready".into(),
                    description: Some(format!(
                        "Your Vault is still starting up ({}) — try again in a moment.",
                        e
                    )),
                }),
            )
        })?;

    let store_err = |e: String| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(IpcError {
                error: "write_failed".into(),
                description: Some(format!("Profile write failed: {}", e)),
            }),
        )
    };

    if let Some(ref name) = display_name {
        // Newest-first ordering from sealed_list — the first match is live.
        let current = existing.iter().find(|r| r.entry_type == "user_profile");
        match current {
            Some(record) => {
                let mut body = record.body.clone();
                body["display_name"] = serde_json::json!(name);
                body["updated_at"] = serde_json::json!(now_us);
                crate::sealed::sealed_replace_inner(
                    &state.app_state,
                    &record.action_hash,
                    "user_profile".into(),
                    body,
                    record.refs.clone(),
                    record.created_at,
                )
                .await
                .map_err(store_err)?;
            }
            None => {
                let email = {
                    let config = state.app_state.vault_config.lock().unwrap();
                    config
                        .as_ref()
                        .and_then(|c| c.web_email.clone())
                        .unwrap_or_default()
                };
                crate::sealed::sealed_store_inner(
                    &state.app_state,
                    "user_profile".into(),
                    serde_json::json!({
                        "email": email,
                        "username": null,
                        "display_name": name,
                        "created_at": now_us,
                        "updated_at": now_us,
                    }),
                    Vec::new(),
                    now_ms,
                )
                .await
                .map_err(store_err)?;
            }
        }
    }

    if let Some(ref pic) = picture {
        let body = serde_json::json!({
            "profile_picture": pic,
            "has_custom_picture": true,
            "updated_at": now_us,
        });
        let current = existing.iter().find(|r| r.entry_type == "profile_picture");
        match current {
            Some(record) => {
                crate::sealed::sealed_replace_inner(
                    &state.app_state,
                    &record.action_hash,
                    "profile_picture".into(),
                    body,
                    record.refs.clone(),
                    record.created_at,
                )
                .await
                .map_err(store_err)?;
            }
            None => {
                crate::sealed::sealed_store_inner(
                    &state.app_state,
                    "profile_picture".into(),
                    body,
                    Vec::new(),
                    now_ms,
                )
                .await
                .map_err(store_err)?;
            }
        }
    }

    // Mirror into the vault config so the app's own UI shows the change
    // immediately; persist with the cached unlock passphrase (best-effort —
    // the sealed records above are the canonical store).
    {
        let passphrase = {
            let mut guard = state.app_state.unlock_passphrase.lock().unwrap();
            guard
                .as_mut()
                .and_then(|locked| String::from_utf8(locked.lock().to_vec()).ok())
        };
        let mut config = state.app_state.vault_config.lock().unwrap();
        if let Some(cfg) = config.as_mut() {
            if let Some(ref name) = display_name {
                cfg.display_name = Some(name.clone());
            }
            if let Some(ref pic) = picture {
                cfg.profile_picture = Some(pic.clone());
            }
            if let Some(pw) = passphrase {
                let vault_path = state.app_state.vault_path.lock().unwrap().clone();
                match crate::vault::encrypt_vault(cfg, &pw) {
                    Ok(mut encrypted) => {
                        encrypted.display_email =
                            cfg.web_email.clone().or(cfg.web_username.clone());
                        if let Err(e) = crate::vault::save_vault(&vault_path, &encrypted) {
                            log::warn!("Profile config persist failed (non-fatal): {}", e);
                        }
                    }
                    Err(e) => log::warn!("Profile config encrypt failed (non-fatal): {}", e),
                }
            }
        }
    }

    let _ = state
        .app_handle
        .emit("profile-updated", serde_json::json!({}));
    Ok(serde_json::json!({ "success": true }))
}

// ── Web-delegated signature management: revoke + thumbnail ─────────────────
//
// Same capability rule as publishing: Flowsta pages only, per-action
// approval in Vault, operations land on THIS device's signing cell.

/// Run the shared approval dialog for a signature-management operation.
/// Returns Ok(()) on approval; an error response otherwise.
async fn cell_op_approval(
    state: &Arc<IpcState>,
    op: &str,
    origin: Option<String>,
    detail: Option<String>,
) -> Result<(), (StatusCode, Json<IpcError>)> {
    let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
    let request_id = format!("{}-{}", op, unix_now());
    {
        let mut pending = state.app_state.pending_cell_op.lock().unwrap();
        *pending = Some(crate::commands::PendingCellOpRequest {
            id: request_id.clone(),
            origin: origin.clone(),
            op: op.to_string(),
            detail: detail.clone(),
            responder: tx,
        });
    }
    raise_window(&state.app_handle);
    let _ = state.app_handle.emit(
        "cell-op-request",
        serde_json::json!({
            "id": request_id,
            "op": op,
            "origin": origin,
            "detail": detail,
        }),
    );

    if auto_approve_enabled() {
        let _ = state.app_state.pending_cell_op.lock().unwrap().take();
        log::warn!("AUTO-APPROVE (dev): {} approved headlessly", op);
        return Ok(());
    }
    match tokio::time::timeout(std::time::Duration::from_secs(60), rx).await {
        Ok(Ok(true)) => Ok(()),
        Ok(Ok(false)) => Err((
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "user_denied".into(),
                description: Some("User rejected the request.".into()),
            }),
        )),
        Ok(Err(_)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(IpcError {
                error: "internal_error".into(),
                description: Some("Approval channel closed unexpectedly.".into()),
            }),
        )),
        Err(_) => {
            let mut pending = state.app_state.pending_cell_op.lock().unwrap();
            *pending = None;
            Err((
                StatusCode::REQUEST_TIMEOUT,
                Json(IpcError {
                    error: "timeout".into(),
                    description: Some("User did not respond within 60 seconds.".into()),
                }),
            ))
        }
    }
}

/// Shared front door for the management endpoints: Flowsta origin,
/// unlocked vault (riding through the unlock like signing does), and a
/// valid 39-byte hex action hash.
async fn cell_op_gate(
    state: &Arc<IpcState>,
    origin: Option<&str>,
    action_hash_hex: &str,
    reason: &str,
) -> Result<(), (StatusCode, Json<IpcError>)> {
    if !is_flowsta_origin(origin) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "tier_forbidden".into(),
                description: Some(
                    "Managing Vault-published signatures is available to Flowsta pages only."
                        .into(),
                ),
            }),
        ));
    }
    if hex::decode(action_hash_hex).map(|b| b.len() != 39).unwrap_or(true) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(IpcError {
                error: "invalid_action_hash".into(),
                description: Some("action_hash must be a hex 39-byte action hash".into()),
            }),
        ));
    }
    if state.app_state.vault_config.lock().unwrap().is_none() {
        raise_window(&state.app_handle);
        let _ = state.app_handle.emit(
            "unlock-attention",
            serde_json::json!({ "reason": reason, "origin": origin }),
        );
        let unlocked = wait_for_unlock(&state.app_state, 60).await;
        let _ = state
            .app_handle
            .emit("unlock-attention-clear", serde_json::json!({}));
        if !unlocked {
            return Err((
                StatusCode::FORBIDDEN,
                Json(IpcError {
                    error: "vault_locked".into(),
                    description: Some("Vault is locked. Unlock it first.".into()),
                }),
            ));
        }
    }
    // The operation commits to the signing cell — wait for the conductor
    // before the approval dialog so an approval can always land.
    if wait_for_conductor(&state.app_state, 90).await.is_none() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(IpcError {
                error: "conductor_not_ready".into(),
                description: Some(
                    "Your Vault is still starting up — try again in a moment.".into(),
                ),
            }),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct RevokeSignatureRequest {
    /// Hex 39-byte action hash of the signature to revoke.
    action_hash: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    job: bool,
}

async fn revoke_signature_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
    Json(req): Json<RevokeSignatureRequest>,
) -> Result<axum::response::Response, (StatusCode, Json<IpcError>)> {
    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "revoke-signature");

    if req.job {
        let job_id = state.op_jobs.create("revoke");
        let task_state = state.clone();
        let task_origin = origin.clone();
        let task_job = job_id.clone();
        tokio::spawn(async move {
            match revoke_signature_core(task_state.clone(), task_origin, req, Some(task_job.clone())).await {
                Ok(v) => task_state.op_jobs.finish(&task_job, v),
                Err((_, Json(e))) => task_state.op_jobs.fail(
                    &task_job,
                    &e.error,
                    e.description.as_deref().unwrap_or(""),
                ),
            }
        });
        return Ok(axum::response::IntoResponse::into_response(Json(
            serde_json::json!({ "job_id": job_id }),
        )));
    }
    revoke_signature_core(state, origin, req, None)
        .await
        .map(|v| axum::response::IntoResponse::into_response(Json(v)))
}

async fn revoke_signature_core(
    state: Arc<IpcState>,
    origin: Option<String>,
    req: RevokeSignatureRequest,
    job_id: Option<String>,
) -> Result<serde_json::Value, (StatusCode, Json<IpcError>)> {
    set_job_stage(&state, &job_id, "preparing");
    cell_op_gate(&state, origin.as_deref(), &req.action_hash, "revoke").await?;

    if let Some(ref r) = req.reason {
        if r.len() > 280 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(IpcError {
                    error: "invalid_reason".into(),
                    description: Some("reason must be 280 characters or fewer".into()),
                }),
            ));
        }
    }

    set_job_stage(&state, &job_id, "awaiting_approval");
    cell_op_approval(&state, "revoke", origin.clone(), req.reason.clone()).await?;

    set_job_stage(&state, &job_id, "publishing");
    let revocation = crate::commands::revoke_signature_inner(
        &state.app_state,
        req.action_hash.clone(),
        req.reason.clone(),
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(IpcError {
                error: "revoke_failed".into(),
                description: Some(format!("Revocation failed: {}", e)),
            }),
        )
    })?;

    let _ = state.app_handle.emit("signature-published", serde_json::json!({}));
    Ok(serde_json::json!({ "success": true, "revocation_hash": revocation }))
}

#[derive(Deserialize)]
struct SetThumbnailRequest {
    /// Hex 39-byte action hash of the signature the preview belongs to.
    action_hash: String,
    /// data:image/... URI.
    thumbnail: String,
    #[serde(default)]
    job: bool,
}

async fn set_thumbnail_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
    Json(req): Json<SetThumbnailRequest>,
) -> Result<axum::response::Response, (StatusCode, Json<IpcError>)> {
    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "set-thumbnail");

    if req.job {
        let job_id = state.op_jobs.create("thumbnail");
        let task_state = state.clone();
        let task_origin = origin.clone();
        let task_job = job_id.clone();
        tokio::spawn(async move {
            match set_thumbnail_core(task_state.clone(), task_origin, req, Some(task_job.clone())).await {
                Ok(v) => task_state.op_jobs.finish(&task_job, v),
                Err((_, Json(e))) => task_state.op_jobs.fail(
                    &task_job,
                    &e.error,
                    e.description.as_deref().unwrap_or(""),
                ),
            }
        });
        return Ok(axum::response::IntoResponse::into_response(Json(
            serde_json::json!({ "job_id": job_id }),
        )));
    }
    set_thumbnail_core(state, origin, req, None)
        .await
        .map(|v| axum::response::IntoResponse::into_response(Json(v)))
}

async fn set_thumbnail_core(
    state: Arc<IpcState>,
    origin: Option<String>,
    req: SetThumbnailRequest,
    job_id: Option<String>,
) -> Result<serde_json::Value, (StatusCode, Json<IpcError>)> {
    set_job_stage(&state, &job_id, "preparing");
    cell_op_gate(&state, origin.as_deref(), &req.action_hash, "thumbnail").await?;

    if !req.thumbnail.starts_with("data:image/") || req.thumbnail.len() > 300_000 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(IpcError {
                error: "invalid_thumbnail".into(),
                description: Some("thumbnail must be a data:image/... URI under 300 KB".into()),
            }),
        ));
    }

    set_job_stage(&state, &job_id, "awaiting_approval");
    cell_op_approval(&state, "thumbnail", origin.clone(), None).await?;

    set_job_stage(&state, &job_id, "publishing");
    let thumb_hash = crate::commands::set_thumbnail_inner(
        &state.app_state,
        req.action_hash.clone(),
        req.thumbnail.clone(),
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(IpcError {
                error: "write_failed".into(),
                description: Some(format!("Thumbnail publish failed: {}", e)),
            }),
        )
    })?;

    let _ = state.app_handle.emit("signature-published", serde_json::json!({}));
    Ok(serde_json::json!({ "success": true, "thumbnail_hash": thumb_hash }))
}

// ── Async operation jobs ────────────────────────────────────────────────────
//
// Committing operations from web pages run as JOBS: the POST validates and
// returns a job id immediately; the page polls /op-status while the request
// rides through unlock, conductor startup, the approval dialog, and the
// commit. Nothing is held open, so there are no client timeout budgets, no
// ghost failures (the client giving up changes nothing), and no duplicate
// risk on retry — the page always learns the real outcome.

use std::collections::HashMap;

#[derive(Clone, Serialize)]
pub struct OpJobSnapshot {
    pub job_id: String,
    /// waiting_unlock | preparing | awaiting_approval | publishing |
    /// done | failed
    pub stage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

struct OpJob {
    snapshot: OpJobSnapshot,
    updated_at: i64,
}

#[derive(Default)]
pub struct OpJobs {
    jobs: std::sync::Mutex<HashMap<String, OpJob>>,
}

const JOB_TTL_SECS: i64 = 10 * 60;

impl OpJobs {
    fn prune(map: &mut HashMap<String, OpJob>) {
        let now = unix_now();
        map.retain(|_, j| now - j.updated_at < JOB_TTL_SECS);
    }

    pub fn create(&self, op: &str) -> String {
        let job_id = format!("{}-{}-{:x}", op, unix_now(), rand::random::<u32>());
        let mut map = self.jobs.lock().unwrap();
        Self::prune(&mut map);
        map.insert(
            job_id.clone(),
            OpJob {
                snapshot: OpJobSnapshot {
                    job_id: job_id.clone(),
                    stage: "preparing".into(),
                    result: None,
                    error: None,
                    description: None,
                },
                updated_at: unix_now(),
            },
        );
        job_id
    }

    pub fn set_stage(&self, job_id: &str, stage: &str) {
        let mut map = self.jobs.lock().unwrap();
        if let Some(job) = map.get_mut(job_id) {
            job.snapshot.stage = stage.into();
            job.updated_at = unix_now();
        }
    }

    pub fn finish(&self, job_id: &str, result: serde_json::Value) {
        let mut map = self.jobs.lock().unwrap();
        if let Some(job) = map.get_mut(job_id) {
            job.snapshot.stage = "done".into();
            job.snapshot.result = Some(result);
            job.updated_at = unix_now();
        }
    }

    pub fn fail(&self, job_id: &str, error: &str, description: &str) {
        let mut map = self.jobs.lock().unwrap();
        if let Some(job) = map.get_mut(job_id) {
            job.snapshot.stage = "failed".into();
            job.snapshot.error = Some(error.into());
            job.snapshot.description = Some(description.into());
            job.updated_at = unix_now();
        }
    }

    pub fn snapshot(&self, job_id: &str) -> Option<OpJobSnapshot> {
        let mut map = self.jobs.lock().unwrap();
        Self::prune(&mut map);
        map.get(job_id).map(|j| j.snapshot.clone())
    }
}

async fn op_status_handler(
    State(state): State<Arc<IpcState>>,
    axum::extract::Path(job_id): axum::extract::Path<String>,
) -> Result<axum::response::Response, (StatusCode, Json<IpcError>)> {
    match state.op_jobs.snapshot(&job_id) {
        Some(snap) => Ok(axum::response::IntoResponse::into_response(Json(snap))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(IpcError {
                error: "unknown_job".into(),
                description: Some("No such job (it may have expired).".into()),
            }),
        )),
    }
}

// ── GET /signatures — the dashboard reads from the Vault, not the network ──
//
// The Vault is the source of truth for the user's own records: this serves
// exactly what the Vault UI shows (own chain, instantly consistent, plus
// linked-agent history as gossip warms). Flowsta pages only; read-only, so
// no approval dialog. The page falls back to the server's shared-network
// lookup only when the Vault isn't reachable.

async fn signatures_handler(
    State(state): State<Arc<IpcState>>,
    headers: HeaderMap,
) -> Result<axum::response::Response, (StatusCode, Json<IpcError>)> {
    let origin = extract_origin(&headers);
    track_request(&state.app_state, origin.as_deref(), "signatures");

    if !is_flowsta_origin(origin.as_deref()) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "tier_forbidden".into(),
                description: Some("Signature reads are available to Flowsta pages only.".into()),
            }),
        ));
    }
    if state.app_state.vault_config.lock().unwrap().is_none() {
        // A background read must not pop the unlock screen — the page
        // just falls back to the network lookup.
        return Err((
            StatusCode::FORBIDDEN,
            Json(IpcError {
                error: "vault_locked".into(),
                description: Some("Vault is locked.".into()),
            }),
        ));
    }
    if wait_for_conductor(&state.app_state, 5).await.is_none() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(IpcError {
                error: "conductor_not_ready".into(),
                description: Some("Vault is still starting up.".into()),
            }),
        ));
    }

    let own = crate::commands::get_my_own_signatures_inner(&state.app_state)
        .await
        .unwrap_or_default();
    // Linked history is best-effort: DHT-bound, additive only.
    let linked = crate::commands::get_my_linked_signatures_inner(&state.app_state)
        .await
        .map(|r| r.signatures)
        .unwrap_or_default();

    let own_hashes: std::collections::HashSet<String> = own
        .iter()
        .filter_map(|s| s.get("action_hash").and_then(|h| h.as_str()).map(String::from))
        .collect();
    let mut signatures = own;
    signatures.extend(linked.into_iter().filter(|s| {
        s.get("action_hash")
            .and_then(|h| h.as_str())
            .map(|h| !own_hashes.contains(h))
            .unwrap_or(true)
    }));

    Ok(axum::response::IntoResponse::into_response(Json(
        serde_json::json!({ "source": "vault", "signatures": signatures }),
    )))
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
        op_jobs: OpJobs::default(),
    });

    // CORS: deliberately permissive. Third-party desktop apps use varied
    // Tauri/Electron custom origins and we can't enumerate them ahead of time.
    // Security relies on the in-handler `origin_to_client_id` check that gates
    // sensitive operations on the caller being a user-approved linked app.
    // CORS here is defense-in-depth, not the primary control.
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
        .route("/profile-update", post(profile_update_handler))
        .route("/revoke-signature", post(revoke_signature_handler))
        .route("/set-thumbnail", post(set_thumbnail_handler))
        .route("/op-status/:job_id", get(op_status_handler))
        .route("/signatures", get(signatures_handler))
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

#[cfg(test)]
mod tests {
    use super::is_flowsta_origin;

    #[test]
    fn test_flowsta_origin_gate() {
        // Flowsta pages over https may request publishing
        assert!(is_flowsta_origin(Some("https://flowsta.com")));
        assert!(is_flowsta_origin(Some("https://www.flowsta.com")));
        assert!(is_flowsta_origin(Some("https://ourtest.flowsta.com")));

        // Everyone else is signature-only
        assert!(!is_flowsta_origin(None));
        assert!(!is_flowsta_origin(Some("https://example.com")));
        assert!(!is_flowsta_origin(Some("https://evilflowsta.com")));
        assert!(!is_flowsta_origin(Some("https://flowsta.com.evil.com")));
        assert!(!is_flowsta_origin(Some("http://flowsta.com"))); // no plaintext
        assert!(!is_flowsta_origin(Some("tauri://localhost")));
        assert!(!is_flowsta_origin(Some("not a url")));
    }
}
