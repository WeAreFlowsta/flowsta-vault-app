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

/// Default DNA versions bundled with this app build.
/// Used for first-time installs and as fallback when VaultConfig has no version info.
pub const BUNDLED_PRIVATE_VERSION: &str = "1.10";
pub const BUNDLED_IDENTITY_VERSION: &str = "1.4";
pub const BUNDLED_SIGNING_VERSION: &str = "1.3";

/// hApp bundle filenames bundled with this app build (in src-tauri/resources/).
const BUNDLED_PRIVATE_HAPP_FILE: &str = "flowsta_private_v1_10_happ.happ";
const BUNDLED_IDENTITY_HAPP_FILE: &str = "flowsta_identity_v1_4_happ.happ";
const BUNDLED_SIGNING_HAPP_FILE: &str = "flowsta_signing_v1_3_happ.happ";

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
    let admin_ws = AdminWebsocket::connect(
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

    if private_installed && identity_installed && signing_installed {
        log::info!("All DNAs already installed with correct agent key, skipping");

        // Ensure all apps are enabled — conductor may disable cells on restart
        for app in &existing_apps {
            match admin_ws.enable_app(app.installed_app_id.clone()).await {
                Ok(_) => log::info!("Enabled {}", app.installed_app_id),
                Err(e) => log::warn!("Failed to enable {}: {}", app.installed_app_id, e),
            }
        }

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

        log::info!("Installing private DNA v{} from {:?}...", private_version, happ_path);
        let payload = InstallAppPayload {
            source: AppBundleSource::Path(happ_path),
            agent_key: Some(agent_key.clone()),
            installed_app_id: Some(private_app_id.clone()),
            network_seed: None,
            roles_settings: None,
            ignore_genesis_failure: false,
        };

        admin_ws
            .install_app(payload)
            .await
            .map_err(|e| format!("Failed to install private DNA: {}", e))?;

        admin_ws
            .enable_app(private_app_id.clone())
            .await
            .map_err(|e| format!("Failed to enable private DNA: {}", e))?;

        log::info!("Private DNA v{} installed and enabled", private_version);
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

        log::info!("Installing identity DNA v{} from {:?}...", identity_version, happ_path);
        let payload = InstallAppPayload {
            source: AppBundleSource::Path(happ_path),
            agent_key: Some(agent_key.clone()),
            installed_app_id: Some(identity_app_id.clone()),
            network_seed: None,
            roles_settings: None,
            ignore_genesis_failure: false,
        };

        admin_ws
            .install_app(payload)
            .await
            .map_err(|e| format!("Failed to install identity DNA: {}", e))?;

        admin_ws
            .enable_app(identity_app_id.clone())
            .await
            .map_err(|e| format!("Failed to enable identity DNA: {}", e))?;

        log::info!("Identity DNA v{} installed and enabled", identity_version);
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
            log::info!("Installing signing DNA v{} from {:?}...", signing_version, happ_path);
            let payload = InstallAppPayload {
                source: AppBundleSource::Path(happ_path),
                agent_key: Some(agent_key.clone()),
                installed_app_id: Some(signing_app_id.clone()),
                network_seed: None,
                roles_settings: None,
                ignore_genesis_failure: false,
            };

            admin_ws
                .install_app(payload)
                .await
                .map_err(|e| format!("Failed to install signing DNA: {}", e))?;

            admin_ws
                .enable_app(signing_app_id.clone())
                .await
                .map_err(|e| format!("Failed to enable signing DNA: {}", e))?;

            log::info!("Signing DNA v{} installed and enabled", signing_version);
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

    Ok(InstalledDnas {
        private_app_id,
        identity_app_id,
        signing_app_id,
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
            // Try to authorize credentials — this will fail with CellDisabled if cells aren't ready
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
