//! DNA installation into the running Holochain conductor.
//!
//! After the conductor is ready, this module installs the Flowsta hApp bundles
//! (identity + private DNAs) via the admin WebSocket. Idempotent — skips
//! installation if the apps are already present.

use holochain_client::{AdminWebsocket, AllowedOrigins, AppStatusFilter, InstallAppPayload};
use holochain_types::app::AppBundleSource;
use holochain_types::prelude::AgentPubKey;
use std::path::Path;

/// Installed app IDs — must be stable across restarts so we can detect existing installs.
const PRIVATE_APP_ID: &str = "flowsta_private_v1_10";
const IDENTITY_APP_ID: &str = "flowsta_identity_v1_3";

/// hApp bundle filenames (must match the files in src-tauri/resources/).
const PRIVATE_HAPP_FILE: &str = "flowsta_private_v1_10_happ.happ";
const IDENTITY_HAPP_FILE: &str = "flowsta_identity_v1_3_happ.happ";

/// Result of DNA installation — cell IDs and app IDs for later use.
pub struct InstalledDnas {
    pub private_app_id: String,
    pub identity_app_id: String,
}

/// Install Flowsta DNAs into the conductor if not already present.
///
/// Connects to the admin WebSocket, checks for existing installs, and installs
/// + enables any missing apps. The hApp bundles are read from the resource_dir.
///
/// Network seeds are baked into the .happ bundles (matching server conductors),
/// so no seed override is needed.
pub async fn install_dnas(admin_port: u16, resource_dir: &Path, agent_key: AgentPubKey) -> Result<InstalledDnas, String> {
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

    let mut private_installed = false;
    let mut identity_installed = false;

    for app in &existing_apps {
        let key_matches = app.agent_pub_key == agent_key;
        if app.installed_app_id == PRIVATE_APP_ID {
            if key_matches {
                private_installed = true;
            } else {
                log::warn!("Private app installed with wrong agent key, reinstalling...");
                admin_ws
                    .uninstall_app(PRIVATE_APP_ID.to_string(), false)
                    .await
                    .map_err(|e| format!("Failed to uninstall private app: {}", e))?;
            }
        }
        if app.installed_app_id == IDENTITY_APP_ID {
            if key_matches {
                identity_installed = true;
            } else {
                log::warn!("Identity app installed with wrong agent key, reinstalling...");
                admin_ws
                    .uninstall_app(IDENTITY_APP_ID.to_string(), false)
                    .await
                    .map_err(|e| format!("Failed to uninstall identity app: {}", e))?;
            }
        }
    }

    if private_installed && identity_installed {
        log::info!("Both DNAs already installed with correct agent key, skipping");
        return Ok(InstalledDnas {
            private_app_id: PRIVATE_APP_ID.to_string(),
            identity_app_id: IDENTITY_APP_ID.to_string(),
        });
    }

    // 3. Install private DNA if needed.
    if !private_installed {
        let happ_path = resource_dir.join(PRIVATE_HAPP_FILE);
        if !happ_path.exists() {
            return Err(format!(
                "Private hApp bundle not found at {:?}",
                happ_path
            ));
        }

        log::info!("Installing private DNA from {:?}...", happ_path);
        let payload = InstallAppPayload {
            source: AppBundleSource::Path(happ_path),
            agent_key: Some(agent_key.clone()),
            installed_app_id: Some(PRIVATE_APP_ID.to_string()),
            network_seed: None,
            roles_settings: None,
            ignore_genesis_failure: false,
        };

        admin_ws
            .install_app(payload)
            .await
            .map_err(|e| format!("Failed to install private DNA: {}", e))?;

        admin_ws
            .enable_app(PRIVATE_APP_ID.to_string())
            .await
            .map_err(|e| format!("Failed to enable private DNA: {}", e))?;

        log::info!("Private DNA installed and enabled");
    }

    // 4. Install identity DNA if needed.
    if !identity_installed {
        let happ_path = resource_dir.join(IDENTITY_HAPP_FILE);
        if !happ_path.exists() {
            return Err(format!(
                "Identity hApp bundle not found at {:?}",
                happ_path
            ));
        }

        log::info!("Installing identity DNA from {:?}...", happ_path);
        let payload = InstallAppPayload {
            source: AppBundleSource::Path(happ_path),
            agent_key: Some(agent_key.clone()),
            installed_app_id: Some(IDENTITY_APP_ID.to_string()),
            network_seed: None,
            roles_settings: None,
            ignore_genesis_failure: false,
        };

        admin_ws
            .install_app(payload)
            .await
            .map_err(|e| format!("Failed to install identity DNA: {}", e))?;

        admin_ws
            .enable_app(IDENTITY_APP_ID.to_string())
            .await
            .map_err(|e| format!("Failed to enable identity DNA: {}", e))?;

        log::info!("Identity DNA installed and enabled");
    }

    // 5. Verify both apps are enabled.
    let enabled_apps = admin_ws
        .list_apps(Some(AppStatusFilter::Enabled))
        .await
        .map_err(|e| format!("Failed to verify installed apps: {}", e))?;

    let private_ok = enabled_apps
        .iter()
        .any(|app| app.installed_app_id == PRIVATE_APP_ID);
    let identity_ok = enabled_apps
        .iter()
        .any(|app| app.installed_app_id == IDENTITY_APP_ID);

    if !private_ok || !identity_ok {
        return Err(format!(
            "DNA verification failed: private={}, identity={}",
            private_ok, identity_ok
        ));
    }

    log::info!(
        "DNA installation complete: {} enabled apps",
        enabled_apps.len()
    );

    Ok(InstalledDnas {
        private_app_id: PRIVATE_APP_ID.to_string(),
        identity_app_id: IDENTITY_APP_ID.to_string(),
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
