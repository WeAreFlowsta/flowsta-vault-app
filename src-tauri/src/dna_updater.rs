//! DNA version update checker and installer.
//!
//! On each vault unlock, checks the Flowsta API for newer DNA versions.
//! Handles three cases:
//!   1. Up to date — no action needed.
//!   2. Coordinator-only update — hot-swap via `admin.updateCoordinators()`.
//!   3. Full DNA upgrade (new integrity/seed) — download new .happ, install,
//!      uninstall old, update VaultConfig.
//!
//! Future: when the vault starts writing data to DNAs (cross-device sync),
//! step 3 will also include export → import → verify.

use holochain_client::AdminWebsocket;
use std::path::Path;

/// Response from GET /api/v1/vault/dna-versions
#[derive(serde::Deserialize, Debug)]
pub struct DnaVersionsResponse {
    pub private_dna: DnaVersionInfo,
    pub identity_dna: DnaVersionInfo,
    pub conductor: ConductorInfo,
}

#[derive(serde::Deserialize, Debug)]
pub struct DnaVersionInfo {
    pub version: String,
    pub filename: String,
    pub coordinator_only: bool,
    pub min_vault_version: String,
    pub min_conductor_version: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct ConductorInfo {
    pub latest_version: String,
    pub min_supported: String,
}

/// Result of the update check — tells the caller what happened.
#[derive(Debug, Clone, serde::Serialize)]
pub enum UpdateResult {
    /// Already on latest versions.
    UpToDate,
    /// DNA(s) were updated successfully.
    Updated {
        private_updated: Option<VersionChange>,
        identity_updated: Option<VersionChange>,
    },
    /// Vault app version is too old for the latest DNA — user must update the app.
    AppUpdateRequired {
        min_vault_version: String,
    },
    /// Could not reach the API (offline mode) — continue with current DNAs.
    Offline,
    /// Update failed with an error.
    Failed {
        error: String,
    },
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VersionChange {
    pub from: String,
    pub to: String,
}

/// Check the API for DNA updates and apply them if needed.
///
/// Called after conductor is ready, before emitting the final "Ready" status.
/// Non-fatal: returns `UpdateResult::Offline` or `UpdateResult::Failed` on error
/// so the vault can continue with its current DNAs.
pub async fn check_and_update_dnas(
    admin_port: u16,
    download_dir: &Path,
    recovery_lookup_hash: &str,
    current_private_version: &str,
    current_identity_version: &str,
    agent_key: holochain_types::prelude::AgentPubKey,
) -> UpdateResult {
    let api_url = option_env!("FLOWSTA_API_URL")
        .unwrap_or("https://auth-api.flowsta.com");

    // 1. Fetch latest versions from API.
    let versions = match fetch_dna_versions(api_url).await {
        Ok(v) => v,
        Err(e) => {
            log::warn!("DNA version check failed (offline?): {}", e);
            return UpdateResult::Offline;
        }
    };

    log::info!(
        "Server DNA versions: private={}, identity={} | Local: private={}, identity={}",
        versions.private_dna.version,
        versions.identity_dna.version,
        current_private_version,
        current_identity_version,
    );

    // 2. Check if vault version is sufficient.
    let vault_version = env!("CARGO_PKG_VERSION");
    if version_less_than(vault_version, &versions.private_dna.min_vault_version)
        || version_less_than(vault_version, &versions.identity_dna.min_vault_version)
    {
        let min = if version_less_than(
            &versions.private_dna.min_vault_version,
            &versions.identity_dna.min_vault_version,
        ) {
            versions.identity_dna.min_vault_version.clone()
        } else {
            versions.private_dna.min_vault_version.clone()
        };
        log::warn!(
            "Vault version {} is below minimum {} — app update required",
            vault_version,
            min
        );
        return UpdateResult::AppUpdateRequired {
            min_vault_version: min,
        };
    }

    // 3. Determine what needs updating.
    let private_needs_update = current_private_version != versions.private_dna.version;
    let identity_needs_update = current_identity_version != versions.identity_dna.version;

    if !private_needs_update && !identity_needs_update {
        log::info!("DNAs are up to date");
        return UpdateResult::UpToDate;
    }

    // 4. Apply updates.
    let mut private_updated = None;
    let mut identity_updated = None;

    if private_needs_update {
        log::info!(
            "Updating private DNA: {} → {}",
            current_private_version,
            versions.private_dna.version
        );
        match update_single_dna(
            admin_port,
            download_dir,
            api_url,
            recovery_lookup_hash,
            "private",
            current_private_version,
            &versions.private_dna,
            agent_key.clone(),
        )
        .await
        {
            Ok(true) => {
                private_updated = Some(VersionChange {
                    from: current_private_version.to_string(),
                    to: versions.private_dna.version.clone(),
                });
            }
            Ok(false) => {
                // Same DNA hash — no actual change, don't update VaultConfig version.
                log::info!("Private DNA hash unchanged, keeping version {}", current_private_version);
            }
            Err(e) => {
                log::error!("Private DNA update failed: {}", e);
                return UpdateResult::Failed {
                    error: format!("Private DNA update failed: {}", e),
                };
            }
        }
    }

    if identity_needs_update {
        log::info!(
            "Updating identity DNA: {} → {}",
            current_identity_version,
            versions.identity_dna.version
        );
        match update_single_dna(
            admin_port,
            download_dir,
            api_url,
            recovery_lookup_hash,
            "identity",
            current_identity_version,
            &versions.identity_dna,
            agent_key.clone(),
        )
        .await
        {
            Ok(true) => {
                identity_updated = Some(VersionChange {
                    from: current_identity_version.to_string(),
                    to: versions.identity_dna.version.clone(),
                });
            }
            Ok(false) => {
                log::info!("Identity DNA hash unchanged, keeping version {}", current_identity_version);
            }
            Err(e) => {
                log::error!("Identity DNA update failed: {}", e);
                return UpdateResult::Failed {
                    error: format!("Identity DNA update failed: {}", e),
                };
            }
        }
    }

    // If nothing actually changed (all same-hash), report as up to date.
    if private_updated.is_none() && identity_updated.is_none() {
        return UpdateResult::UpToDate;
    }

    UpdateResult::Updated {
        private_updated,
        identity_updated,
    }
}

/// Fetch DNA version info from the API.
async fn fetch_dna_versions(api_url: &str) -> Result<DnaVersionsResponse, String> {
    let url = format!("{}/api/v1/vault/dna-versions", api_url.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("API returned status {}", resp.status()));
    }

    resp.json::<DnaVersionsResponse>()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))
}

/// Download a .happ bundle from the API and save it to the resource directory.
async fn download_happ_bundle(
    api_url: &str,
    recovery_lookup_hash: &str,
    dna_type: &str,
    version: &str,
    dest_path: &Path,
) -> Result<(), String> {
    let url = format!(
        "{}/api/v1/vault/dna-bundle/{}/{}?recovery_lookup_hash={}",
        api_url.trim_end_matches('/'),
        dna_type,
        version,
        recovery_lookup_hash,
    );

    log::info!("Downloading {} DNA v{} bundle...", dna_type, version);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Download failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Download failed with status {} for {} v{}",
            resp.status(),
            dna_type,
            version
        ));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    if bytes.is_empty() {
        return Err("Downloaded empty bundle".to_string());
    }

    // Write to a temp file first, then rename (atomic on same filesystem)
    let temp_path = dest_path.with_extension("happ.tmp");
    tokio::fs::write(&temp_path, &bytes)
        .await
        .map_err(|e| format!("Failed to write bundle to {:?}: {}", temp_path, e))?;

    tokio::fs::rename(&temp_path, dest_path)
        .await
        .map_err(|e| format!("Failed to rename temp bundle: {}", e))?;

    log::info!(
        "Downloaded {} DNA v{} ({} bytes) to {:?}",
        dna_type,
        version,
        bytes.len(),
        dest_path,
    );

    Ok(())
}

/// Update a single DNA (private or identity).
///
/// Returns Ok(true) if the DNA was actually updated (new cell installed),
/// or Ok(false) if the DNA hash was unchanged (CellAlreadyExists — no-op).
///
/// For now (vault doesn't author data on DNAs), this is a simple swap:
///   1. Download new .happ bundle
///   2. Install new DNA (new app ID)
///   3. Enable new DNA
///   4. Uninstall old DNA
///
/// Future: when vault writes data to DNAs, this will include
/// export → install → import → verify → uninstall old.
async fn update_single_dna(
    admin_port: u16,
    download_dir: &Path,
    api_url: &str,
    recovery_lookup_hash: &str,
    dna_type: &str,
    current_version: &str,
    new_info: &DnaVersionInfo,
    agent_key: holochain_types::prelude::AgentPubKey,
) -> Result<bool, String> {
    let new_version = &new_info.version;

    // 1. Download the new .happ bundle to the app data directory.
    let bundle_path = download_dir.join(&new_info.filename);
    download_happ_bundle(api_url, recovery_lookup_hash, dna_type, new_version, &bundle_path).await?;

    // 2. Connect to admin WebSocket.
    let admin_ws = AdminWebsocket::connect(
        format!("localhost:{}", admin_port),
        Some("flowsta-vault".to_string()),
    )
    .await
    .map_err(|e| format!("Failed to connect to admin WebSocket: {}", e))?;

    // 3. Construct app IDs.
    let old_app_id = make_app_id(dna_type, current_version);
    let new_app_id = make_app_id(dna_type, new_version);

    // 4. Install the new DNA.
    log::info!("Installing {} (from {:?})...", new_app_id, bundle_path);
    let payload = holochain_client::InstallAppPayload {
        source: holochain_types::app::AppBundleSource::Path(bundle_path.clone()),
        agent_key: Some(agent_key.clone()),
        installed_app_id: Some(new_app_id.clone()),
        network_seed: None, // Baked into the .happ bundle
        roles_settings: None,
        ignore_genesis_failure: false,
    };

    match admin_ws.install_app(payload).await {
        Ok(_) => {
            // 5. Enable the new DNA.
            admin_ws
                .enable_app(new_app_id.clone())
                .await
                .map_err(|e| format!("Failed to enable {}: {}", new_app_id, e))?;

            log::info!("{} installed and enabled", new_app_id);

            // 6. Uninstall the old DNA.
            log::info!("Uninstalling old {}...", old_app_id);
            if let Err(e) = admin_ws.uninstall_app(old_app_id.clone(), false).await {
                log::warn!("Failed to uninstall {} (non-fatal): {}", old_app_id, e);
            }

            log::info!(
                "{} DNA updated: {} → {} (old {} uninstalled)",
                dna_type,
                current_version,
                new_version,
                old_app_id
            );
        }
        Err(e) => {
            let err_str = format!("{}", e);
            if err_str.contains("CellAlreadyExists") {
                // Same DNA hash — the new bundle has the same integrity zomes + network seed.
                // The cell is already running correctly under the old app ID.
                // No install/uninstall possible; Holochain won't allow a duplicate cell.
                // Return false so the caller does NOT update VaultConfig version
                // (keeping app ID consistent with what's registered in the conductor).
                log::info!(
                    "CellAlreadyExists — {} DNA hash unchanged between v{} and v{}, skipping",
                    dna_type,
                    current_version,
                    new_version
                );
                return Ok(false);
            } else {
                return Err(format!("Failed to install {}: {}", new_app_id, e));
            }
        }
    }

    Ok(true)
}

/// Construct a Holochain installed_app_id from DNA type and version.
/// e.g. ("private", "1.10") → "flowsta_private_v1_10"
///      ("identity", "1.3") → "flowsta_identity_v1_3"
fn make_app_id(dna_type: &str, version: &str) -> String {
    format!("flowsta_{}_v{}", dna_type, version.replace('.', "_"))
}

/// Compare two semver-like version strings (e.g. "0.1.0" < "0.2.0").
/// Supports 2-part (1.10) and 3-part (0.1.0) versions.
fn version_less_than(a: &str, b: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> {
        v.split('.').filter_map(|s| s.parse::<u32>().ok()).collect()
    };
    let va = parse(a);
    let vb = parse(b);
    for i in 0..va.len().max(vb.len()) {
        let x = va.get(i).copied().unwrap_or(0);
        let y = vb.get(i).copied().unwrap_or(0);
        if x < y {
            return true;
        }
        if x > y {
            return false;
        }
    }
    false // equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_app_id() {
        assert_eq!(make_app_id("private", "1.10"), "flowsta_private_v1_10");
        assert_eq!(make_app_id("identity", "1.3"), "flowsta_identity_v1_3");
        assert_eq!(make_app_id("private", "2.0"), "flowsta_private_v2_0");
    }

    #[test]
    fn test_version_less_than() {
        assert!(version_less_than("0.1.0", "0.2.0"));
        assert!(version_less_than("1.9", "1.10"));
        assert!(!version_less_than("1.10", "1.10"));
        assert!(!version_less_than("1.10", "1.9"));
        assert!(version_less_than("0.1.0", "1.0.0"));
        assert!(!version_less_than("2.0.0", "1.9.9"));
    }
}
