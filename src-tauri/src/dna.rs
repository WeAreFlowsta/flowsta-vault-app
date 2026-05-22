//! DNA installation into the running Holochain conductor.
//!
//! After the conductor is ready, this module installs the Flowsta hApp bundles
//! (identity + private DNAs) via the admin WebSocket. Idempotent — skips
//! installation if the apps are already present.
//!
//! Version constants define what ships with this app build. The DNA updater
//! can override these with newer versions downloaded from the API.

use holochain_client::{AdminWebsocket, AllowedOrigins, AppStatusFilter, InstallAppPayload};
use holochain_types::app::AppBundleSource;
use holochain_types::prelude::AgentPubKey;
use std::path::Path;
use std::process::Child;

/// Default DNA versions bundled with this app build.
/// Used for first-time installs and as fallback when VaultConfig has no version info.
/// MUST match the filenames listed in tauri.conf.json `bundle.resources` and the
/// files actually present in src-tauri/resources/.
pub const BUNDLED_PRIVATE_VERSION: &str = "1.11";
pub const BUNDLED_IDENTITY_VERSION: &str = "1.4";
pub const BUNDLED_SIGNING_VERSION: &str = "1.4";

/// Historical signing DNA versions bundled with this app build, in addition
/// to the current `BUNDLED_SIGNING_VERSION`. Installing these on first launch
/// lets the user see signatures they made on older signing DNA versions
/// (each signature is on whichever DNA was current at sign-time, and the
/// `get_my_signatures` zome only returns entries from the cell it's called
/// against). Without these, a fresh install would only show signatures
/// authored on the current DNA version — historical ones would be invisible.
///
/// Each tuple is `(version, bundled_happ_filename)`. Both must agree with
/// the `BUNDLED_SIGNING_V{X}_{Y}_HAPP_FILE` constants above and the entries
/// in tauri.conf.json `bundle.resources`.
pub const HISTORICAL_SIGNING_VERSIONS: &[(&str, &str)] = &[
    ("1.3", BUNDLED_SIGNING_V1_3_HAPP_FILE),
    ("1.2", BUNDLED_SIGNING_V1_2_HAPP_FILE),
    ("1.1", BUNDLED_SIGNING_V1_1_HAPP_FILE),
    ("1.0", BUNDLED_SIGNING_V1_0_HAPP_FILE),
];

/// hApp bundle filenames bundled with this app build (in src-tauri/resources/).
const BUNDLED_PRIVATE_HAPP_FILE: &str = "flowsta_private_v1_11_happ.happ";
const BUNDLED_IDENTITY_HAPP_FILE: &str = "flowsta_identity_v1_4_happ.happ";
const BUNDLED_SIGNING_HAPP_FILE: &str = "flowsta_signing_v1_4_happ.happ";

// Historical signing-DNA bundles. Installed by `install_historical_signing_dnas`
// at the end of `install_dnas` so users see signatures they made on older
// signing DNA versions. Each constant must have a matching entry in
// tauri.conf.json `bundle.resources` and a file in src-tauri/resources/ —
// scripts/check-bundle-sync.sh enforces this.
const BUNDLED_SIGNING_V1_3_HAPP_FILE: &str = "flowsta_signing_v1_3_happ.happ";
const BUNDLED_SIGNING_V1_2_HAPP_FILE: &str = "flowsta_signing_v1_2_happ.happ";
const BUNDLED_SIGNING_V1_1_HAPP_FILE: &str = "flowsta_signing_v1_1_happ.happ";
const BUNDLED_SIGNING_V1_0_HAPP_FILE: &str = "flowsta_signing_v1_0_happ.happ";

/// Result of DNA installation — app IDs for later use.
pub struct InstalledDnas {
    pub private_app_id: String,
    pub identity_app_id: String,
    pub signing_app_id: String,
}

/// Construct a Holochain installed_app_id from DNA type and version.
/// e.g. ("private", "1.10") → "flowsta_private_v1_10"
pub fn make_app_id(dna_type: &str, version: &str) -> String {
    format!("flowsta_{}_v{}", dna_type, version.replace('.', "_"))
}

/// Construct the .happ filename for a given DNA type and version.
/// e.g. ("private", "1.10") → "flowsta_private_v1_10_happ.happ"
fn make_happ_filename(dna_type: &str, version: &str) -> String {
    format!("flowsta_{}_v{}_happ.happ", dna_type, version.replace('.', "_"))
}

/// Reconnect to the admin WebSocket. Used during recovery from a WS reset.
async fn reconnect_admin(admin_port: u16) -> Result<AdminWebsocket, String> {
    AdminWebsocket::connect(
        format!("localhost:{}", admin_port),
        Some("flowsta-vault".to_string()),
    )
    .await
    .map_err(|e| format!("admin WS reconnect failed: {}", e))
}

/// Install an app, surviving a WebSocket reset mid-call.
///
/// `install_app` for the identity hApp (~3.9 MB) on a clean conductor blocks
/// long enough on first-time WASM compilation that the conductor's WS server
/// resets the long-running admin request before responding (Windows error
/// 10054 / `Websocket closed: ConnectionClosed`). The conductor itself
/// stays alive and the WASM is cached server-side, so a retry on a fresh
/// WebSocket completes quickly.
///
/// `make_payload` is called once per attempt because `InstallAppPayload`
/// isn't `Clone` and we need a fresh value for each retry.
async fn install_app_resilient<F>(
    admin_ws: &mut AdminWebsocket,
    admin_port: u16,
    conductor_child: &mut Child,
    app_id: &str,
    mut make_payload: F,
) -> Result<(), String>
where
    F: FnMut() -> InstallAppPayload,
{
    if admin_ws.install_app(make_payload()).await.is_ok() {
        return Ok(());
    }

    log::warn!(
        "[install] {} initial install_app failed — reconnecting and polling for status",
        app_id,
    );

    let started = std::time::Instant::now();
    // 30 s is plenty for a healthy conductor's slow WASM compile.
    // If the conductor has actually died (its WS server stops accepting
    // connections — Windows error 10061) burning more time here is futile;
    // the outer `start_holochain` retry will restart the conductor entirely.
    let deadline = started + std::time::Duration::from_secs(30);
    let mut attempts: u32 = 0;

    while std::time::Instant::now() < deadline {
        attempts += 1;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // Bail fast if the conductor process exited — no amount of WS
        // reconnecting will recover from that. The outer start_holochain
        // wrapper will spawn a fresh conductor that warm-starts against
        // the on-disk state populated so far.
        if let Ok(Some(status)) = conductor_child.try_wait() {
            return Err(format!(
                "install_app({}) bailing: conductor process exited (status {}) after {}ms",
                app_id,
                status,
                started.elapsed().as_millis(),
            ));
        }

        match reconnect_admin(admin_port).await {
            Ok(ws) => *admin_ws = ws,
            Err(e) => {
                log::warn!("[install] {} reconnect attempt {} failed: {}", app_id, attempts, e);
                continue;
            }
        }

        // Did the install actually complete server-side despite the WS error?
        match admin_ws.list_apps(None).await {
            Ok(apps) if apps.iter().any(|a| a.installed_app_id == app_id) => {
                log::info!(
                    "[install] {} confirmed registered after {}ms ({} attempts)",
                    app_id,
                    started.elapsed().as_millis(),
                    attempts,
                );
                return Ok(());
            }
            Ok(_) => {
                // Not yet registered — try again on the fresh connection.
                // The first attempt's WASM compile is cached server-side
                // even when the response was lost, so this retry is fast.
                match admin_ws.install_app(make_payload()).await {
                    Ok(_) => {
                        log::info!(
                            "[install] {} retry succeeded after {}ms ({} attempts)",
                            app_id,
                            started.elapsed().as_millis(),
                            attempts,
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        log::warn!(
                            "[install] {} retry attempt {} failed: {} — continuing to poll",
                            app_id, attempts, e,
                        );
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "[install] {} list_apps attempt {} failed: {} — continuing to poll",
                    app_id, attempts, e,
                );
            }
        }
    }

    Err(format!(
        "install_app({}) gave up after {}s ({} attempts)",
        app_id,
        started.elapsed().as_secs(),
        attempts,
    ))
}

/// Enable an app, surviving a WebSocket reset mid-call.
///
/// On a fresh install, the conductor's first `enable_app` of a sizeable hApp
/// (identity DNA, ~3.9 MB) blocks long enough on WASM compilation that the
/// conductor's WS server forcibly closes the long-running admin request
/// (Windows error 10054 / `Websocket closed: ConnectionClosed`). The
/// conductor process itself stays alive — only the WebSocket dies — and
/// the work usually does complete server-side.
///
/// This helper:
/// 1. Tries `enable_app` once on the existing connection.
/// 2. On error, reconnects the admin WS, polls `list_apps(Enabled)` until
///    the target app shows Enabled, and retries `enable_app` against the
///    fresh connection on each iteration. Total budget 120 s.
/// 3. Treats already-Enabled (after the first call) as success — the
///    server-side enable completed even though the response was lost.
///
/// `admin_ws` is replaced with a fresh connection on recovery so subsequent
/// calls in the install sequence don't try to use a dead socket.
async fn enable_app_resilient(
    admin_ws: &mut AdminWebsocket,
    admin_port: u16,
    conductor_child: &mut Child,
    app_id: &str,
) -> Result<(), String> {
    if admin_ws.enable_app(app_id.to_string()).await.is_ok() {
        return Ok(());
    }

    log::warn!(
        "[enable] {} initial enable_app failed — reconnecting and polling for status",
        app_id,
    );

    let started = std::time::Instant::now();
    // 30 s is plenty for a healthy conductor's slow WASM compile.
    // If the conductor has actually died (its WS server stops accepting
    // connections — Windows error 10061) burning more time here is futile;
    // the outer `start_holochain` retry will restart the conductor entirely.
    let deadline = started + std::time::Duration::from_secs(30);
    let mut attempts: u32 = 0;

    while std::time::Instant::now() < deadline {
        attempts += 1;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // Bail fast if the conductor process exited — no amount of WS
        // reconnecting will recover from that. The outer start_holochain
        // wrapper will spawn a fresh conductor that warm-starts against
        // the on-disk state populated so far.
        if let Ok(Some(status)) = conductor_child.try_wait() {
            return Err(format!(
                "enable_app({}) bailing: conductor process exited (status {}) after {}ms",
                app_id,
                status,
                started.elapsed().as_millis(),
            ));
        }

        match reconnect_admin(admin_port).await {
            Ok(ws) => *admin_ws = ws,
            Err(e) => {
                log::warn!("[enable] {} reconnect attempt {} failed: {}", app_id, attempts, e);
                continue;
            }
        }

        match admin_ws.list_apps(Some(AppStatusFilter::Enabled)).await {
            Ok(enabled) if enabled.iter().any(|a| a.installed_app_id == app_id) => {
                log::info!(
                    "[enable] {} confirmed Enabled after {}ms ({} attempts)",
                    app_id,
                    started.elapsed().as_millis(),
                    attempts,
                );
                return Ok(());
            }
            Ok(_) => {
                match admin_ws.enable_app(app_id.to_string()).await {
                    Ok(_) => {
                        log::info!(
                            "[enable] {} retry succeeded after {}ms ({} attempts)",
                            app_id,
                            started.elapsed().as_millis(),
                            attempts,
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        log::warn!(
                            "[enable] {} retry attempt {} failed: {} — continuing to poll",
                            app_id, attempts, e,
                        );
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "[enable] {} list_apps attempt {} failed: {} — continuing to poll",
                    app_id, attempts, e,
                );
            }
        }
    }

    Err(format!(
        "enable_app({}) gave up after {}s ({} attempts)",
        app_id,
        started.elapsed().as_secs(),
        attempts,
    ))
}

/// Install Flowsta DNAs into the conductor if not already present.
///
/// Accepts dynamic versions (from VaultConfig or defaults). Checks for existing
/// installs by app ID and verifies agent key matches. If an app with the target
/// app ID already exists with the correct key, installation is skipped.
///
/// Network seeds are baked into the .happ bundles (matching server conductors),
/// so no seed override is needed.
pub async fn install_dnas(
    admin_port: u16,
    resource_dir: &Path,
    agent_key: AgentPubKey,
    private_version: &str,
    identity_version: &str,
    signing_version: &str,
    conductor_child: &mut Child,
) -> Result<InstalledDnas, String> {
    let private_app_id = make_app_id("private", private_version);
    let identity_app_id = make_app_id("identity", identity_version);
    let signing_app_id = make_app_id("signing", signing_version);

    // Determine .happ filenames — use bundled names if version matches bundled,
    // otherwise construct from version (downloaded by dna_updater).
    let private_happ_file = if private_version == BUNDLED_PRIVATE_VERSION {
        BUNDLED_PRIVATE_HAPP_FILE.to_string()
    } else {
        make_happ_filename("private", private_version)
    };
    let identity_happ_file = if identity_version == BUNDLED_IDENTITY_VERSION {
        BUNDLED_IDENTITY_HAPP_FILE.to_string()
    } else {
        make_happ_filename("identity", identity_version)
    };
    let signing_happ_file = if signing_version == BUNDLED_SIGNING_VERSION {
        BUNDLED_SIGNING_HAPP_FILE.to_string()
    } else {
        make_happ_filename("signing", signing_version)
    };

    // 1. Connect to admin WebSocket.
    //    Mutable: enable_app_resilient may swap in a fresh connection if
    //    the conductor's WS server resets a long-running admin call.
    let mut admin_ws = AdminWebsocket::connect(
        format!("localhost:{}", admin_port),
        Some("flowsta-vault".to_string()),
    )
    .await
    .map_err(|e| format!("Failed to connect to admin WebSocket: {}", e))?;

    // 2. Check which apps are already installed and verify agent key matches.
    //    If an app was installed with a different key (e.g. from generate_agent_pub_key),
    //    uninstall it so it gets reinstalled with the correct deterministic key.
    let existing_apps = admin_ws
        .list_apps(None)
        .await
        .map_err(|e| format!("Failed to list apps: {}", e))?;

    // Log all existing apps and their status for debugging CellDisabled issues
    for app in &existing_apps {
        log::info!(
            "Existing app: {} status={:?}",
            app.installed_app_id,
            app.status,
        );
    }

    let mut private_installed = false;
    let mut identity_installed = false;
    let mut signing_installed = false;

    for app in &existing_apps {
        let key_matches = app.agent_pub_key == agent_key;
        if app.installed_app_id == private_app_id {
            if key_matches {
                private_installed = true;
            } else {
                log::warn!("Private app installed with wrong agent key, reinstalling...");
                admin_ws
                    .uninstall_app(private_app_id.clone(), false)
                    .await
                    .map_err(|e| format!("Failed to uninstall private app: {}", e))?;
            }
        }
        if app.installed_app_id == identity_app_id {
            if key_matches {
                identity_installed = true;
            } else {
                log::warn!("Identity app installed with wrong agent key, reinstalling...");
                admin_ws
                    .uninstall_app(identity_app_id.clone(), false)
                    .await
                    .map_err(|e| format!("Failed to uninstall identity app: {}", e))?;
            }
        }
        if app.installed_app_id == signing_app_id {
            if key_matches {
                signing_installed = true;
            } else {
                log::warn!("Signing app installed with wrong agent key, reinstalling...");
                admin_ws
                    .uninstall_app(signing_app_id.clone(), false)
                    .await
                    .map_err(|e| format!("Failed to uninstall signing app: {}", e))?;
            }
        }
    }

    // 2.5. Normalize state: ensure every known-installed-and-keymatched app
    //      is in Enabled state. install_app from a previous run may have
    //      committed the app to the conductor's state DB while enable_app
    //      didn't complete (long WASM compile reset the WS, or the user
    //      locked the vault mid-enable). Without this pass, a partial
    //      install would be detected as "already installed" and skipped on
    //      retry but the cell would never get enabled — DNA verification
    //      then fails with `private=true, identity=false`.
    //
    //      Uses enable_app_resilient so a long compile that resets the WS
    //      again is also handled here.
    for app in &existing_apps {
        let is_target = app.installed_app_id == private_app_id
            || app.installed_app_id == identity_app_id
            || app.installed_app_id == signing_app_id;
        if !is_target {
            continue;
        }
        // Wrong-key apps were just uninstalled in the loop above.
        if app.agent_pub_key != agent_key {
            continue;
        }

        log::info!(
            "[enable] normalizing {} (status was {:?})",
            app.installed_app_id,
            app.status,
        );
        enable_app_resilient(&mut admin_ws, admin_port, conductor_child, &app.installed_app_id)
            .await
            .map_err(|e| format!("Failed to enable existing {}: {}", app.installed_app_id, e))?;
    }

    if private_installed && identity_installed && signing_installed {
        log::info!("All DNAs already installed with correct agent key, skipping");
        return Ok(InstalledDnas {
            private_app_id,
            identity_app_id,
            signing_app_id,
        });
    }

    // 3. Install private DNA if needed.
    if !private_installed {
        let happ_path = resource_dir.join(&private_happ_file);
        if !happ_path.exists() {
            return Err(format!(
                "Private hApp bundle not found at {:?}",
                happ_path
            ));
        }

        let happ_size = std::fs::metadata(&happ_path).map(|m| m.len()).unwrap_or(0);
        log::info!(
            "[dna:private] installing v{} ({} bytes) from {:?}",
            private_version, happ_size, happ_path,
        );
        let install_start = std::time::Instant::now();
        install_app_resilient(
            &mut admin_ws,
            admin_port,
            conductor_child,
            &private_app_id,
            || InstallAppPayload {
                source: AppBundleSource::Path(happ_path.clone()),
                agent_key: Some(agent_key.clone()),
                installed_app_id: Some(private_app_id.clone()),
                network_seed: None,
                roles_settings: None,
                ignore_genesis_failure: false,
            },
        )
        .await
        .map_err(|e| format!("Failed to install private DNA: {}", e))?;
        log::info!(
            "[dna:private] install_app returned in {}ms",
            install_start.elapsed().as_millis()
        );

        let enable_start = std::time::Instant::now();
        enable_app_resilient(&mut admin_ws, admin_port, conductor_child, &private_app_id)
            .await
            .map_err(|e| format!("Failed to enable private DNA: {}", e))?;

        log::info!(
            "[dna:private] enabled in {}ms (total {}ms)",
            enable_start.elapsed().as_millis(),
            install_start.elapsed().as_millis(),
        );
    }

    // 4. Install identity DNA if needed.
    if !identity_installed {
        let happ_path = resource_dir.join(&identity_happ_file);
        if !happ_path.exists() {
            return Err(format!(
                "Identity hApp bundle not found at {:?}",
                happ_path
            ));
        }

        let happ_size = std::fs::metadata(&happ_path).map(|m| m.len()).unwrap_or(0);
        log::info!(
            "[dna:identity] installing v{} ({} bytes) from {:?}",
            identity_version, happ_size, happ_path,
        );
        let install_start = std::time::Instant::now();
        install_app_resilient(
            &mut admin_ws,
            admin_port,
            conductor_child,
            &identity_app_id,
            || InstallAppPayload {
                source: AppBundleSource::Path(happ_path.clone()),
                agent_key: Some(agent_key.clone()),
                installed_app_id: Some(identity_app_id.clone()),
                network_seed: None,
                roles_settings: None,
                ignore_genesis_failure: false,
            },
        )
        .await
        .map_err(|e| format!("Failed to install identity DNA: {}", e))?;
        log::info!(
            "[dna:identity] install_app returned in {}ms",
            install_start.elapsed().as_millis()
        );

        let enable_start = std::time::Instant::now();
        enable_app_resilient(&mut admin_ws, admin_port, conductor_child, &identity_app_id)
            .await
            .map_err(|e| format!("Failed to enable identity DNA: {}", e))?;

        log::info!(
            "[dna:identity] enabled in {}ms (total {}ms)",
            enable_start.elapsed().as_millis(),
            install_start.elapsed().as_millis(),
        );
    }

    // 5. Install signing DNA if needed.
    if !signing_installed {
        let happ_path = resource_dir.join(&signing_happ_file);
        if !happ_path.exists() {
            // Signing DNA is optional for backwards compatibility — log warning but don't fail.
            // Vault can function without it; Sign It features will be unavailable.
            log::warn!(
                "Signing hApp bundle not found at {:?} — Sign It features will be unavailable",
                happ_path
            );
        } else {
            let happ_size = std::fs::metadata(&happ_path).map(|m| m.len()).unwrap_or(0);
            log::info!(
                "[dna:signing] installing v{} ({} bytes) from {:?}",
                signing_version, happ_size, happ_path,
            );
            let install_start = std::time::Instant::now();
            install_app_resilient(
                &mut admin_ws,
                admin_port,
                conductor_child,
                &signing_app_id,
                || InstallAppPayload {
                    source: AppBundleSource::Path(happ_path.clone()),
                    agent_key: Some(agent_key.clone()),
                    installed_app_id: Some(signing_app_id.clone()),
                    network_seed: None,
                    roles_settings: None,
                    ignore_genesis_failure: false,
                },
            )
            .await
            .map_err(|e| format!("Failed to install signing DNA: {}", e))?;
            log::info!(
                "[dna:signing] install_app returned in {}ms",
                install_start.elapsed().as_millis()
            );

            let enable_start = std::time::Instant::now();
            enable_app_resilient(&mut admin_ws, admin_port, conductor_child, &signing_app_id)
                .await
                .map_err(|e| format!("Failed to enable signing DNA: {}", e))?;

            log::info!(
                "[dna:signing] enabled in {}ms (total {}ms)",
                enable_start.elapsed().as_millis(),
                install_start.elapsed().as_millis(),
            );
            signing_installed = true;
        }
    }

    // 6. Verify apps are enabled.
    let enabled_apps = admin_ws
        .list_apps(Some(AppStatusFilter::Enabled))
        .await
        .map_err(|e| format!("Failed to verify installed apps: {}", e))?;

    let private_ok = enabled_apps
        .iter()
        .any(|app| app.installed_app_id == private_app_id);
    let identity_ok = enabled_apps
        .iter()
        .any(|app| app.installed_app_id == identity_app_id);
    let signing_ok = enabled_apps
        .iter()
        .any(|app| app.installed_app_id == signing_app_id);

    if !private_ok || !identity_ok {
        return Err(format!(
            "DNA verification failed: private={}, identity={}",
            private_ok, identity_ok
        ));
    }

    if !signing_ok {
        log::warn!("Signing DNA not enabled — Sign It features will be unavailable");
    }

    log::info!(
        "DNA installation complete: {} enabled apps (signing={})",
        enabled_apps.len(),
        signing_ok,
    );

    // Backfill historical signing DNA versions so the user sees signatures
    // they made before the current DNA. Best-effort — log warnings, don't
    // fail the unlock if any of them error out.
    install_historical_signing_dnas(
        &mut admin_ws,
        admin_port,
        resource_dir,
        &agent_key,
        conductor_child,
    )
    .await;

    Ok(InstalledDnas {
        private_app_id,
        identity_app_id,
        signing_app_id,
    })
}

/// Install older signing DNA versions if they're not already installed.
///
/// The user's signature history lives on whichever signing DNA was current
/// at sign-time. Without these older cells installed, a fresh install would
/// only see signatures authored on `BUNDLED_SIGNING_VERSION`. The historical
/// .happ files ship in `src-tauri/resources/` (see
/// `HISTORICAL_SIGNING_VERSIONS` for the list, and tauri.conf.json
/// `bundle.resources` for the packaging).
///
/// Best-effort: a per-version failure logs a warning and moves on. We
/// intentionally do *not* call `install_app_resilient` here — these
/// installs run after the main install has already been verified, and
/// we don't want a single old-version failure to trigger the auto-restart
/// machinery and block the user from reaching their dashboard.
async fn install_historical_signing_dnas(
    admin_ws: &mut AdminWebsocket,
    _admin_port: u16,
    resource_dir: &Path,
    agent_key: &AgentPubKey,
    _conductor_child: &mut Child,
) {
    let existing_apps = match admin_ws.list_apps(None).await {
        Ok(apps) => apps,
        Err(e) => {
            log::warn!(
                "[historical] could not list apps to check what's already installed: {}",
                e,
            );
            return;
        }
    };

    for (version, happ_filename) in HISTORICAL_SIGNING_VERSIONS {
        let app_id = make_app_id("signing", version);
        if existing_apps
            .iter()
            .any(|a| a.installed_app_id == app_id)
        {
            log::info!("[historical] signing v{} already installed, skipping", version);
            continue;
        }

        let happ_path = resource_dir.join(happ_filename);
        if !happ_path.exists() {
            log::warn!(
                "[historical] signing v{} bundle not found at {:?} — skipping",
                version,
                happ_path,
            );
            continue;
        }

        log::info!("[historical] installing signing v{} from {:?}", version, happ_path);
        let payload = InstallAppPayload {
            source: AppBundleSource::Path(happ_path),
            agent_key: Some(agent_key.clone()),
            installed_app_id: Some(app_id.clone()),
            network_seed: None,
            roles_settings: None,
            ignore_genesis_failure: false,
        };
        match admin_ws.install_app(payload).await {
            Ok(_) => log::info!("[historical] signing v{} installed", version),
            Err(e) => {
                log::warn!(
                    "[historical] signing v{} install failed: {} (skipping)",
                    version, e,
                );
                continue;
            }
        }
        match admin_ws.enable_app(app_id.clone()).await {
            Ok(_) => log::info!("[historical] signing v{} enabled", version),
            Err(e) => {
                log::warn!(
                    "[historical] signing v{} enable failed: {} (left in Disabled state)",
                    version, e,
                );
            }
        }
    }
}

/// Attach an app interface to the conductor so zome calls can be made.
///
/// Uses port 0 (auto-assign) and returns the OS-assigned port.
/// Called once during conductor startup after DNA installation.
pub async fn setup_app_interface(admin_port: u16) -> Result<u16, String> {
    let admin_ws = AdminWebsocket::connect(
        format!("localhost:{}", admin_port),
        Some("flowsta-vault".to_string()),
    )
    .await
    .map_err(|e| format!("Failed to connect to admin WebSocket: {}", e))?;

    let app_port = admin_ws
        .attach_app_interface(0, None, AllowedOrigins::Any, None)
        .await
        .map_err(|e| format!("Failed to attach app interface: {}", e))?;

    log::info!("App interface attached on port {}", app_port);
    Ok(app_port)
}

/// Ensure all installed apps are enabled.
///
/// Holochain conductor can disable cells on restart. This function
/// enables all apps and should be called before making zome calls
/// if there's any chance cells are disabled.
pub async fn ensure_apps_enabled(admin_ws: &AdminWebsocket) {
    use holochain_client::{AuthorizeSigningCredentialsPayload, CellInfo};

    let apps = match admin_ws.list_apps(None).await {
        Ok(a) => a,
        Err(e) => {
            log::warn!("ensure_apps_enabled: list_apps failed: {}", e);
            return;
        }
    };

    for app in &apps {
        match admin_ws.enable_app(app.installed_app_id.clone()).await {
            Ok(_) => {}
            Err(e) => log::warn!(
                "ensure_apps_enabled: failed to enable {}: {}",
                app.installed_app_id,
                e,
            ),
        }
    }

    // Verify cells are actually ready — conductor can report Enabled status
    // while cells are still initializing after a restart.
    // Pick the first signing app to test cell readiness.
    let test_app = apps.iter().find(|a| a.installed_app_id.starts_with("flowsta_signing_v"));
    if let Some(app) = test_app {
        let cell_id = app.cell_info.values()
            .flat_map(|cells| cells.iter())
            .find_map(|c| match c {
                CellInfo::Provisioned(p) => Some(p.cell_id.clone()),
                _ => None,
            });

        if let Some(cell_id) = cell_id {
            // Try to authorize credentials — this will fail with CellDisabled
            // if cells aren't ready. 6 attempts × 3 s sleep gives the
            // conductor up to ~18 s to bring cells online, which matches the
            // pre-0.5.2 behaviour. The shorter budget tried in 0.5.2-beta8
            // caused signatures to come back empty on both Linux and Windows
            // when cells took longer than 3 s to ready —
            // `connect_signing_app_ws` would still see CellDisabled and the
            // per-version sig query returned Vec::new().
            for attempt in 1..=6 {
                match admin_ws.authorize_signing_credentials(AuthorizeSigningCredentialsPayload {
                    cell_id: cell_id.clone(),
                    functions: None,
                }).await {
                    Ok(_) => {
                        if attempt > 1 {
                            log::info!("ensure_apps_enabled: cells ready after {}s wait", (attempt - 1) * 3);
                        } else {
                            log::info!("ensure_apps_enabled: cells ready");
                        }
                        return;
                    }
                    Err(e) => {
                        let err_str = format!("{}", e);
                        if err_str.contains("CellDisabled") && attempt < 6 {
                            log::info!(
                                "ensure_apps_enabled: cells not ready yet (attempt {}), waiting 3s...",
                                attempt,
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            // Re-enable all apps before retrying
                            for app in &apps {
                                let _ = admin_ws.enable_app(app.installed_app_id.clone()).await;
                            }
                        } else {
                            log::warn!("ensure_apps_enabled: cell readiness check failed: {}", e);
                            return;
                        }
                    }
                }
            }
        }
    }
}
