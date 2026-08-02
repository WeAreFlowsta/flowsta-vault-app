//! DNA installation into the running Holochain conductor.
//!
//! After the conductor is ready, this module installs the Flowsta hApp bundles
//! (identity + private DNAs) via the admin WebSocket. Idempotent - skips
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

/// The encrypted private DNA (opaque Sealed records, per-user network).
/// Device-hosted vaults only; installed with a per-user network seed
/// derived from the recovery phrase - never with the manifest's
/// placeholder seed.
pub const BUNDLED_PRIVATE_V2_VERSION: &str = "2.0";

/// Bundle revision of the v2 happ. A rebuilt bundle changes the DNA hash,
/// but the installed app id wouldn't change - the vault would keep serving
/// the stale (possibly broken) cell forever. Bump this whenever the bundled
/// v2 happ file changes; installs of older revisions are replaced on the
/// next unlock. Safe while the cell is single-user-network and re-derivable
/// (its content re-imports from the phrase-derived key or migration).
pub const BUNDLED_PRIVATE_V2_REVISION: u32 = 2;

/// Installed app id for the bundled v2 private cell, including the bundle
/// revision (e.g. "flowsta_private_v2_0_r2"). Revision 1 was the unsuffixed
/// "flowsta_private_v2_0" (hdk 0.6.2 build whose module cannot load on the
/// bundled 0.6.1 conductor).
pub fn private_v2_app_id() -> String {
    format!(
        "{}_r{}",
        make_app_id("private", BUNDLED_PRIVATE_V2_VERSION),
        BUNDLED_PRIVATE_V2_REVISION
    )
}

/// hApp bundle filenames bundled with this app build (in src-tauri/resources/).
const BUNDLED_PRIVATE_HAPP_FILE: &str = "flowsta_private_v1_11_happ.happ";
const BUNDLED_PRIVATE_V2_HAPP_FILE: &str = "flowsta_private_v2_0_happ.happ";
const BUNDLED_IDENTITY_HAPP_FILE: &str = "flowsta_identity_v1_4_happ.happ";
const BUNDLED_SIGNING_HAPP_FILE: &str = "flowsta_signing_v1_4_happ.happ";

// Vault bundles only the current signing DNA. Pre-v1.4 signing DNAs hold no
// real signing data (per-user signing-cell architecture started at v1.4), so
// the 4 older `.happ` files and the historical-install pass have been removed.
// A Vault upgrading from an earlier build keeps any orphaned older cells in
// its conductor; the new code path filters them out (see commands.rs).

/// Result of DNA installation - app IDs for later use.
pub struct InstalledDnas {
    pub private_app_id: String,
    pub identity_app_id: String,
    pub signing_app_id: String,
    /// The encrypted (v2, Sealed-record) private cell - device-hosted vaults
    /// only, installed with the per-user network seed. None when the bundle
    /// is absent or the vault is custodial-linked.
    pub private_v2_app_id: Option<String>,
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

/// Bundled signing-DNA coordinator revision. Coordinator-only changes keep
/// the DNA hash, so an EXISTING cell never picks them up from the happ
/// bundle - it must be hot-swapped via UpdateCoordinators. Bump this
/// together with any coordinator rebuild copied into resources/.
/// Rev 2: self-authored lookups (my signatures, thumbnails) read LOCAL
/// instead of hanging on cold-network get_links.
/// Rev 3: adds get_own_revocations_for_signature (LOCAL) - own-view
/// enrichment stops paying a network round-trip per record.
pub const SIGNING_COORDINATOR_REV: u32 = 3;
const SIGNING_COORDINATOR_WASM: &str = "signing_coordinator_v1_4.wasm";

/// Hot-swap the signing cell's coordinator zome to the bundled revision.
/// Runs on EVERY conductor start: the conductor's coordinator store lives
/// in the conductor dir, and the bundled happ carries the ORIGINAL (rev 1)
/// coordinator (the canonical bundle is never rebuilt), so anything that
/// reinstalls the app from the bundle - reset, restore, a wiped conductor
/// dir - silently reverts the cell to rev 1. A marker file used to gate
/// this call; a reset wiped the store but left the marker behind, and the
/// cell then stayed on rev 1 forever while revocation enrichment quietly
/// reported every record as not revoked (found by the bridge matrix,
/// 2026-08-02). The admin call is cheap and idempotent: apply
/// unconditionally and trust the conductor, never a marker. Failures are
/// non-fatal (retried on the next start).
pub async fn ensure_signing_coordinators(
    admin_port: u16,
    resource_dir: &std::path::Path,
    data_dir: &std::path::Path,
) -> Result<(), String> {
    use holochain_types::prelude::{
        CoordinatorBundle, CoordinatorManifest, CoordinatorSource, UpdateCoordinatorsPayload,
        ZomeDependency, ZomeManifest,
    };

    // Remove the retired gate marker so nothing ever reads it as truth again.
    let _ = std::fs::remove_file(data_dir.join("signing-coordinator-rev"));

    let wasm = std::fs::read(resource_dir.join(SIGNING_COORDINATOR_WASM))
        .map_err(|e| format!("read {}: {}", SIGNING_COORDINATOR_WASM, e))?;

    let admin_ws = AdminWebsocket::connect(
        format!("localhost:{}", admin_port),
        Some("flowsta-vault-coord-update".to_string()),
    )
    .await
    .map_err(|e| format!("Admin WS: {}", e))?;

    let apps = admin_ws
        .list_apps(None)
        .await
        .map_err(|e| format!("list_apps: {}", e))?;
    let signing_app_id = make_app_id("signing", BUNDLED_SIGNING_VERSION);
    let Some(app) = apps.iter().find(|a| a.installed_app_id == signing_app_id) else {
        // No signing cell yet (nothing to swap) - the next start after the
        // install applies it.
        return Ok(());
    };
    let cell_id = app
        .cell_info
        .values()
        .flat_map(|cells| cells.iter())
        .find_map(|c| match c {
            holochain_client::CellInfo::Provisioned(p) => Some(p.cell_id.clone()),
            _ => None,
        })
        .ok_or("No provisioned signing cell")?;

    let zome = ZomeManifest {
        name: "signing".into(),
        hash: None,
        path: "signing_coordinator.wasm".into(),
        dependencies: Some(vec![ZomeDependency {
            name: "signing_integrity".into(),
        }]),
    };
    let resource_id = zome.resource_id();
    let manifest = CoordinatorManifest { zomes: vec![zome] };
    let bundle = mr_bundle::Bundle::new(manifest, [(resource_id, wasm.into())])
        .map_err(|e| format!("coordinator bundle: {}", e))?;

    admin_ws
        .update_coordinators(UpdateCoordinatorsPayload {
            cell_id,
            source: CoordinatorSource::Bundle(Box::new(CoordinatorBundle::from(bundle))),
        })
        .await
        .map_err(|e| format!("update_coordinators: {}", e))?;

    log::info!(
        "Signing coordinator ensured at rev {} on {}",
        SIGNING_COORDINATOR_REV,
        signing_app_id,
    );
    Ok(())
}

#[cfg(test)]
mod coordinator_bundle_tests {
    use super::*;

    /// Emit the bundled signing coordinator as a `.coordinators` file for
    /// UpdateCoordinators rollouts on server conductors (same bundle the
    /// vault hot-swap builds in memory). Run explicitly:
    /// `cargo test --lib write_signing_coordinator_bundle -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn write_signing_coordinator_bundle() {
        use holochain_types::prelude::{CoordinatorManifest, ZomeDependency, ZomeManifest};

        let wasm = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("resources")
                .join(SIGNING_COORDINATOR_WASM),
        )
        .expect("read coordinator wasm from resources/");

        let zome = ZomeManifest {
            name: "signing".into(),
            hash: None,
            path: "signing_coordinator.wasm".into(),
            dependencies: Some(vec![ZomeDependency {
                name: "signing_integrity".into(),
            }]),
        };
        let resource_id = zome.resource_id();
        let manifest = CoordinatorManifest { zomes: vec![zome] };
        let bundle = mr_bundle::Bundle::new(manifest, [(resource_id, wasm.into())])
            .expect("bundle");
        let bytes = bundle.pack().expect("pack");

        let out = std::env::temp_dir().join(format!(
            "signing_coordinator_v1_4_rev{}.coordinators",
            SIGNING_COORDINATOR_REV
        ));
        std::fs::write(&out, &bytes).expect("write bundle file");
        println!("wrote {} ({} bytes)", out.display(), bytes.len());
    }
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
        "[install] {} initial install_app failed - reconnecting and polling for status",
        app_id,
    );

    let started = std::time::Instant::now();
    // 30 s is plenty for a healthy conductor's slow WASM compile.
    // If the conductor has actually died (its WS server stops accepting
    // connections - Windows error 10061) burning more time here is futile;
    // the outer `start_holochain` retry will restart the conductor entirely.
    let deadline = started + std::time::Duration::from_secs(30);
    let mut attempts: u32 = 0;

    while std::time::Instant::now() < deadline {
        attempts += 1;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // Bail fast if the conductor process exited - no amount of WS
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
                // Not yet registered - try again on the fresh connection.
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
                            "[install] {} retry attempt {} failed: {} - continuing to poll",
                            app_id, attempts, e,
                        );
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "[install] {} list_apps attempt {} failed: {} - continuing to poll",
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
/// conductor process itself stays alive - only the WebSocket dies - and
/// the work usually does complete server-side.
///
/// This helper:
/// 1. Tries `enable_app` once on the existing connection.
/// 2. On error, reconnects the admin WS, polls `list_apps(Enabled)` until
///    the target app shows Enabled, and retries `enable_app` against the
///    fresh connection on each iteration. Total budget 120 s.
/// 3. Treats already-Enabled (after the first call) as success - the
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
        "[enable] {} initial enable_app failed - reconnecting and polling for status",
        app_id,
    );

    let started = std::time::Instant::now();
    // 30 s is plenty for a healthy conductor's slow WASM compile.
    // If the conductor has actually died (its WS server stops accepting
    // connections - Windows error 10061) burning more time here is futile;
    // the outer `start_holochain` retry will restart the conductor entirely.
    let deadline = started + std::time::Duration::from_secs(30);
    let mut attempts: u32 = 0;

    while std::time::Instant::now() < deadline {
        attempts += 1;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // Bail fast if the conductor process exited - no amount of WS
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
                            "[enable] {} retry attempt {} failed: {} - continuing to poll",
                            app_id, attempts, e,
                        );
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "[enable] {} list_apps attempt {} failed: {} - continuing to poll",
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
    // Some(per-user seed) = also install the encrypted private DNA v2 with
    // this network-seed override (device-hosted vaults). None = skip v2.
    private_v2_seed: Option<&str>,
    conductor_child: &mut Child,
) -> Result<InstalledDnas, String> {
    let private_app_id = make_app_id("private", private_version);
    let identity_app_id = make_app_id("identity", identity_version);
    let signing_app_id = make_app_id("signing", signing_version);
    let private_v2_app_id = private_v2_app_id();
    let private_v2_stale_prefix = make_app_id("private", BUNDLED_PRIVATE_V2_VERSION);

    // Determine .happ filenames - use bundled names if version matches bundled,
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
    let mut private_v2_installed = false;

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
        if app.installed_app_id == private_v2_app_id {
            if key_matches {
                private_v2_installed = true;
            } else {
                log::warn!("Private v2 app installed with wrong agent key, reinstalling...");
                admin_ws
                    .uninstall_app(private_v2_app_id.clone(), false)
                    .await
                    .map_err(|e| format!("Failed to uninstall private v2 app: {}", e))?;
            }
        } else if app.installed_app_id.starts_with(&private_v2_stale_prefix) {
            // A v2 cell from an older bundle revision (different DNA hash
            // under the same version) - replace it with the current bundle.
            log::warn!(
                "Stale private v2 bundle revision installed ({}), replacing with {}",
                app.installed_app_id,
                private_v2_app_id,
            );
            admin_ws
                .uninstall_app(app.installed_app_id.clone(), false)
                .await
                .map_err(|e| format!("Failed to uninstall stale private v2 app: {}", e))?;
        }
    }

    // 2.5. Normalize state: ensure every known-installed-and-keymatched app
    //      is in Enabled state. install_app from a previous run may have
    //      committed the app to the conductor's state DB while enable_app
    //      didn't complete (long WASM compile reset the WS, or the user
    //      locked the vault mid-enable). Without this pass, a partial
    //      install would be detected as "already installed" and skipped on
    //      retry but the cell would never get enabled - DNA verification
    //      then fails with `private=true, identity=false`.
    //
    //      Uses enable_app_resilient so a long compile that resets the WS
    //      again is also handled here.
    for app in &existing_apps {
        let is_target = app.installed_app_id == private_app_id
            || app.installed_app_id == identity_app_id
            || app.installed_app_id == signing_app_id
            || app.installed_app_id == private_v2_app_id;
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

    let v2_satisfied = private_v2_seed.is_none() || private_v2_installed;
    if private_installed && identity_installed && signing_installed && v2_satisfied {
        log::info!("All DNAs already installed with correct agent key, skipping");
        return Ok(InstalledDnas {
            private_app_id,
            identity_app_id,
            signing_app_id,
            private_v2_app_id: if private_v2_installed { Some(private_v2_app_id) } else { None },
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
            // Signing DNA is optional for backwards compatibility - log warning but don't fail.
            // Vault can function without it; Sign It features will be unavailable.
            log::warn!(
                "Signing hApp bundle not found at {:?} - Sign It features will be unavailable",
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
        log::warn!("Signing DNA not enabled - Sign It features will be unavailable");
    }

    log::info!(
        "DNA installation complete: {} enabled apps (signing={})",
        enabled_apps.len(),
        signing_ok,
    );

    // 6. Install the encrypted private DNA v2 (device-hosted vaults only) -
    //    ALWAYS with the per-user network seed override; the manifest seed is
    //    a placeholder. Non-fatal if the bundle is absent (older resource
    //    sets): sealed-record features are unavailable until it ships.
    let mut private_v2_ok = private_v2_installed;
    if let Some(seed) = private_v2_seed {
        if !private_v2_installed {
            let happ_path = resource_dir.join(BUNDLED_PRIVATE_V2_HAPP_FILE);
            if !happ_path.exists() {
                log::warn!(
                    "Private v2 hApp bundle not found at {:?} - encrypted private data unavailable",
                    happ_path
                );
            } else {
                let happ_size = std::fs::metadata(&happ_path).map(|m| m.len()).unwrap_or(0);
                log::info!(
                    "[dna:private-v2] installing v{} ({} bytes) with per-user network seed",
                    BUNDLED_PRIVATE_V2_VERSION, happ_size,
                );
                let install_start = std::time::Instant::now();
                let seed_owned = seed.to_string();
                install_app_resilient(
                    &mut admin_ws,
                    admin_port,
                    conductor_child,
                    &private_v2_app_id,
                    || InstallAppPayload {
                        source: AppBundleSource::Path(happ_path.clone()),
                        agent_key: Some(agent_key.clone()),
                        installed_app_id: Some(private_v2_app_id.clone()),
                        network_seed: Some(seed_owned.clone()),
                        roles_settings: None,
                        ignore_genesis_failure: false,
                    },
                )
                .await
                .map_err(|e| format!("Failed to install private v2 DNA: {}", e))?;

                enable_app_resilient(&mut admin_ws, admin_port, conductor_child, &private_v2_app_id)
                    .await
                    .map_err(|e| format!("Failed to enable private v2 DNA: {}", e))?;
                log::info!(
                    "[dna:private-v2] installed + enabled in {}ms",
                    install_start.elapsed().as_millis()
                );
                private_v2_ok = true;
            }
        }
    }

    Ok(InstalledDnas {
        private_app_id,
        identity_app_id,
        signing_app_id,
        private_v2_app_id: if private_v2_ok { Some(private_v2_app_id) } else { None },
    })
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
///
/// The readiness probe authorizes signing credentials (the only reliable
/// "cells truly ready" signal - the conductor lies about Enabled status),
/// which COMMITS a cap grant. To keep that to one grant per conductor
/// session the probe result is stored in the credentials cache and the
/// whole probe is skipped while the cache holds an entry for the probe
/// cell.
pub async fn ensure_apps_enabled(
    admin_ws: &AdminWebsocket,
    state: &std::sync::Arc<crate::commands::AppState>,
) {
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

    // Verify cells are actually ready - conductor can report Enabled status
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
            // Single-flight with every other credential fill: concurrent
            // startup probes must not each commit a grant (that races real
            // writes with "chain head has moved").
            let _fill = state.credentials_fill_lock.lock().await;
            // Cache hit = cells were verified ready earlier this conductor
            // session - skip the probe (and its chain write) entirely.
            if state.cell_credentials.lock().unwrap().contains_key(&cell_id) {
                return;
            }
            // Try to authorize credentials - this will fail with CellDisabled
            // if cells aren't ready. Each retry sleeps 3 s; 15 attempts gives
            // the conductor up to ~45 s, headroom for the Windows unlock path
            // where cell readiness has been observed at ~21 s (a beta5 log
            // showed the old 6-attempt / 18 s budget timing out at 18 s with
            // cells ready 3 s later - the next round then proceeded with
            // every signing-DNA auth_creds returning CellDisabled, blanking
            // the result and overwriting the cache with 0 sigs).
            const MAX_ATTEMPTS: u32 = 15;
            for attempt in 1..=MAX_ATTEMPTS {
                match admin_ws.authorize_signing_credentials(AuthorizeSigningCredentialsPayload {
                    cell_id: cell_id.clone(),
                    functions: None,
                }).await {
                    Ok(creds) => {
                        // The probe's grant becomes THE session grant for
                        // this cell - store it so no caller re-authorizes.
                        state.cell_credentials.lock().unwrap().insert(
                            cell_id.clone(),
                            crate::commands::CachedCellCredentials::from_signing(&creds),
                        );
                        if attempt > 1 {
                            log::info!("ensure_apps_enabled: cells ready after {}s wait", (attempt - 1) * 3);
                        } else {
                            log::info!("ensure_apps_enabled: cells ready");
                        }
                        return;
                    }
                    Err(e) => {
                        let err_str = format!("{}", e);
                        if err_str.contains("CellDisabled") && attempt < MAX_ATTEMPTS {
                            log::info!(
                                "ensure_apps_enabled: cells not ready yet (attempt {}/{}), waiting 3s...",
                                attempt, MAX_ATTEMPTS,
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
