//! DNA installation into the running Holochain conductor.
//!
//! After the conductor is ready, this module installs the Flowsta hApp bundles
//! (identity + private DNAs) via the admin WebSocket. Idempotent - skips
//! installation if the apps are already present.
//!
//! Version constants define what ships with this app build. The DNA updater
//! can override these with newer versions downloaded from the API.

use holochain_client::{AdminWebsocket, AppStatusFilter};
use flowsta_hc_lines::kit::{KitBinary, KitDescriptor, KitFile};
use flowsta_hc_lines::{AdminClient, CoordinatorZome, InstallRequest, Line, ReadyWait, Recovery};
use holochain_types::prelude::AgentPubKey;
use std::path::Path;
use crate::process_ext::SidecarChild;

/// Default DNA versions bundled with this app build.
/// Used for first-time installs and as fallback when VaultConfig has no version info.
/// MUST match the filenames listed in tauri.conf.json `bundle.resources` and the
/// files actually present in src-tauri/resources/.
pub const BUNDLED_PRIVATE_VERSION: &str = "1.11";
pub const BUNDLED_IDENTITY_VERSION: &str = "1.4";
pub const BUNDLED_SIGNING_VERSION: &str = "1.4";

/// The Holochain 0.7 line's DNAs, installed on the 0.7 conductor beside the
/// 0.6 line during the 1.7.0 transition (new DNA hashes, so new networks).
pub const BUNDLED_IDENTITY_VERSION_07: &str = "1.5";
pub const BUNDLED_SIGNING_VERSION_07: &str = "1.5";
const BUNDLED_IDENTITY_V1_5_HAPP_FILE: &str = "flowsta_identity_v1_5_happ.happ";
const BUNDLED_SIGNING_V1_5_HAPP_FILE: &str = "flowsta_signing_v1_5_happ.happ";
/// The 0.7 line's private cell: private v2.1 (the v2.0 shape rebuilt for
/// Holochain 0.7.1; canonical bundle in `reference/DNA_VERSION_HISTORY.md`,
/// copied, never rebuilt). Installed per identity with the same per-user
/// network seed as the 0.6 cell; the DNA hash keeps the two networks apart.
pub const BUNDLED_PRIVATE_V2_VERSION_07: &str = "2.1";
const BUNDLED_PRIVATE_V2_1_HAPP_FILE: &str = "flowsta_private_v2_1_happ.happ";
/// Bundle revision of the v2.1 cell (see `BUNDLED_PRIVATE_V2_REVISION`).
pub const BUNDLED_PRIVATE_V2_1_REVISION: u32 = 1;

/// What a Vault needs to run each line, described once (flowsta-hc-lines
/// `kit`): the two sidecars and the files the line loads. The kit cache
/// keeps a compressed copy of each in `<device root>/kits/` (`kits.rs`), so
/// a later Vault that stops bundling 0.6 runs it from there, checked against
/// the hashes that Vault compiles in. `accepted` stays empty while a release
/// bundles the binaries: their post-signing hashes come out of this
/// release's build and go into the next one.
pub const KIT_06: KitDescriptor = KitDescriptor {
    line: Line::V06,
    conductor: KitBinary { sidecar: "vault-holochain", version: "0.6.1", accepted: &[] },
    lair: KitBinary { sidecar: "vault-lair-keystore", version: "0.6.3", accepted: &[] },
    files: &[
        KitFile { name: BUNDLED_PRIVATE_HAPP_FILE, sha256: "1f28c2e06ec91a7117b7ee2e26b9c93ca940220b4e9d6d696c0ab8712ca39c01" },
        KitFile { name: BUNDLED_PRIVATE_V2_HAPP_FILE, sha256: "1b969f6b96d9bd7bfcde4e1974d56b7a12708838693130358182ad86bcbe0668" },
        KitFile { name: BUNDLED_IDENTITY_HAPP_FILE, sha256: "09d3f3ea3a92c023fc5112734dc540bd7baeba8c069b0686afe3819b3b62fc64" },
        KitFile { name: BUNDLED_SIGNING_HAPP_FILE, sha256: "163b94d071c57b48bb6436e125afb4948cbd4d9cc24ee7ab374b96d77341a0e3" },
        KitFile { name: SIGNING_COORDINATOR_WASM, sha256: "eede2d60bef8348fe5e21a87c30ece23526f47b44650ff310f837680cae5bd30" },
        KitFile { name: PRIVATE_V2_COORDINATOR_WASM, sha256: "125880705a57b14d241b5476e1c1642cfd12acba3857dc4ee15bc9b59cd801b5" },
        KitFile { name: IDENTITY_LINKING_COORDINATOR_WASM, sha256: "7e0ca6c664cfee60b83cc217a5f57ddaa03fc684719873a9d1a14f5f387926e1" },
    ],
};

pub const KIT_07: KitDescriptor = KitDescriptor {
    line: Line::V07,
    conductor: KitBinary { sidecar: "vault-holochain-07", version: "0.7.1", accepted: &[] },
    lair: KitBinary { sidecar: "vault-lair-keystore-07", version: "0.7.1", accepted: &[] },
    files: &[
        KitFile { name: BUNDLED_IDENTITY_V1_5_HAPP_FILE, sha256: "abd9d2c6a7d54705fadfe4d4968b53381b821967d676d8e0a347ae5057f159fa" },
        KitFile { name: BUNDLED_SIGNING_V1_5_HAPP_FILE, sha256: "0703e4dc066f7dee97abcae9e408bbd5dcd4e220ab03a1de58f1bd324abdf61a" },
        KitFile { name: BUNDLED_PRIVATE_V2_1_HAPP_FILE, sha256: "7bf21c2449a2bc6c3770975607d2bed3df889cc2755703f76ebb666063386df8" },
        KitFile { name: SIGNING_COORDINATOR_WASM_07, sha256: "412c3b031d30f3b3e3681c93823c89974ba9e9ee213b326376d01383357facae" },
    ],
};

/// Installed app id of the 0.7 private cell: "flowsta_private_v2_1_r1".
pub fn private_v2_app_id_07() -> String {
    format!("{}_r{}", make_app_id("private", BUNDLED_PRIVATE_V2_VERSION_07), BUNDLED_PRIVATE_V2_1_REVISION)
}

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
///
/// FROZEN at 2: a person's devices now share this network, and a new
/// revision would split devices that have updated from those that have
/// not. Coordinator changes go through `PRIVATE_V2_COORDINATOR_REV`.
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
/// Rev 4: readers count an author's own deletes and link removals, check
/// each lookup's records, and take a signature's revocations from its signer;
/// a record's details are read locally when it is held here.
pub const SIGNING_COORDINATOR_REV: u32 = 4;
const SIGNING_COORDINATOR_WASM: &str = "signing_coordinator_v1_4.wasm";

/// The signing v1.5 cell's coordinator revision (the 0.7 line). Rev 2:
/// `get_carried` reads LOCAL - the carries asked the network whether this
/// agent had carried a record already and waited the full request timeout
/// per record on a cold conductor (the 1.7.0 live test, 2026-10-26).
/// Rev 3: the v1.4 rev 4 readers, revocations from the signer or the copy's
/// witness, and `get_carried` reads only this agent's own index links.
pub const SIGNING_COORDINATOR_REV_07: u32 = 3;
const SIGNING_COORDINATOR_WASM_07: &str = "signing_coordinator_v1_5.wasm";

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
    // Remove the retired gate marker so nothing ever reads it as truth again.
    let _ = std::fs::remove_file(data_dir.join("signing-coordinator-rev"));

    let wasm = std::fs::read(resource_dir.join(SIGNING_COORDINATOR_WASM))
        .map_err(|e| format!("read {}: {}", SIGNING_COORDINATOR_WASM, e))?;
    let admin = AdminClient::connect(Line::V06, admin_port, &crate::conductor::node_origin())
        .await
        .map_err(|e| format!("Admin WS: {}", e))?;
    let apps = admin.list_apps().await.map_err(|e| format!("list_apps: {}", e))?;
    let signing_app_id = make_app_id("signing", BUNDLED_SIGNING_VERSION);
    let Some(app) = apps.iter().find(|a| a.app_id == signing_app_id) else {
        // No signing cell yet (nothing to swap) - the next start after the
        // install applies it.
        return Ok(());
    };
    let cell = app.first_cell().ok_or("No provisioned signing cell")?;
    admin
        .update_coordinators(cell, CoordinatorZome { name: "signing", wasm })
        .await
        .map_err(|e| format!("update_coordinators: {}", e))?;

    log::info!(
        "Signing coordinator ensured at rev {} on {}",
        SIGNING_COORDINATOR_REV,
        signing_app_id,
    );
    Ok(())
}

/// Bundled identity `agent_linking` coordinator, one build for identity v1.3
/// and v1.4 (the same zome). Rev 1 over the bundles' original:
/// `get_linked_agents` takes an entry only when it names the agent, counts a
/// revocation from one of its two agents and a lookup link's removal from
/// its author or one of them.
pub const IDENTITY_LINKING_COORDINATOR_REV: u32 = 1;
const IDENTITY_LINKING_COORDINATOR_WASM: &str = "identity_agent_linking_coordinator_v1_4.wasm";

/// Hot-swap the `agent_linking` coordinator of every identity v1.3 and v1.4
/// cell on the 0.6 conductor to the bundled one. Runs on every start, for
/// the same reason the signing one does; one call per cell (each keeps its
/// own coordinators).
pub async fn ensure_identity_coordinators(admin_port: u16, resource_dir: &std::path::Path) -> Result<(), String> {
    let wasm = std::fs::read(resource_dir.join(IDENTITY_LINKING_COORDINATOR_WASM))
        .map_err(|e| format!("read {}: {}", IDENTITY_LINKING_COORDINATOR_WASM, e))?;
    let admin = AdminClient::connect(Line::V06, admin_port, &crate::conductor::node_origin())
        .await
        .map_err(|e| format!("Admin WS: {}", e))?;
    let apps = admin.list_apps().await.map_err(|e| format!("list_apps: {}", e))?;
    let identity = |id: &str| id.starts_with("flowsta_identity_v1_3") || id.starts_with("flowsta_identity_v1_4");
    let mut swapped = Vec::new();
    for app in apps.iter().filter(|a| identity(&a.app_id)) {
        let Some(cell) = app.first_cell() else { continue };
        admin
            .update_coordinators(cell, CoordinatorZome { name: "agent_linking", wasm: wasm.clone() })
            .await
            .map_err(|e| format!("update_coordinators ({}): {}", app.app_id, e))?;
        swapped.push(app.app_id.clone());
    }
    if !swapped.is_empty() {
        log::info!("Identity agent_linking coordinator ensured at rev {} on {}", IDENTITY_LINKING_COORDINATOR_REV, swapped.join(", "));
    }
    Ok(())
}

/// Bundled private-v2 coordinator revision. The private v2 bundle itself is
/// never rebuilt (its DNA hash names each person's own network), so every
/// coordinator change reaches a cell through UpdateCoordinators.
/// Rev 2: records are linked from one shared base and listed, retired and
/// superseded there, so a person's devices share one set of records; pieces
/// of large objects are sent between those devices as remote signals.
/// Rev 3: a record can carry more links with their own tags (device and
/// removal records get one, so a device can ask for those alone).
/// Rev 4: `list_sealed_at` lists the links with only the records the Vault
/// does not hold yet (its own from the chain, the rest a hundred at a time).
pub const PRIVATE_V2_COORDINATOR_REV: u32 = 4;
const PRIVATE_V2_COORDINATOR_WASM: &str = "private_v2_coordinator.wasm";

/// Hot-swap the private v2 cell's coordinator to the bundled revision.
/// Runs on every conductor start, for the same reason the signing one does.
pub async fn ensure_private_v2_coordinators(
    admin_port: u16,
    resource_dir: &std::path::Path,
) -> Result<(), String> {
    let wasm = std::fs::read(resource_dir.join(PRIVATE_V2_COORDINATOR_WASM))
        .map_err(|e| format!("read {}: {}", PRIVATE_V2_COORDINATOR_WASM, e))?;
    let admin = AdminClient::connect(Line::V06, admin_port, &crate::conductor::node_origin())
        .await
        .map_err(|e| format!("Admin WS: {}", e))?;
    let apps = admin.list_apps().await.map_err(|e| format!("list_apps: {}", e))?;
    let app_id = private_v2_app_id();
    let Some(app) = apps.iter().find(|a| a.app_id == app_id) else {
        // No private v2 cell on this install (nothing to swap).
        return Ok(());
    };
    let cell = app.first_cell().ok_or("No provisioned private v2 cell")?;
    admin
        .update_coordinators(cell, CoordinatorZome { name: "private_data", wasm })
        .await
        .map_err(|e| format!("update_coordinators: {}", e))?;

    log::info!(
        "Private v2 coordinator ensured at rev {} on {}",
        PRIVATE_V2_COORDINATOR_REV,
        app_id,
    );
    Ok(())
}

#[cfg(test)]
mod kit_tests {
    use super::*;

    #[test]
    fn each_kit_names_every_file_its_line_loads_and_their_hashes_match() {
        use sha2::{Digest, Sha256};
        let resources = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("resources");
        let loads_06 = [BUNDLED_PRIVATE_HAPP_FILE, BUNDLED_PRIVATE_V2_HAPP_FILE, BUNDLED_IDENTITY_HAPP_FILE, BUNDLED_SIGNING_HAPP_FILE, SIGNING_COORDINATOR_WASM, PRIVATE_V2_COORDINATOR_WASM, IDENTITY_LINKING_COORDINATOR_WASM];
        let loads_07 = [BUNDLED_IDENTITY_V1_5_HAPP_FILE, BUNDLED_SIGNING_V1_5_HAPP_FILE, BUNDLED_PRIVATE_V2_1_HAPP_FILE, SIGNING_COORDINATOR_WASM_07];
        for (kit, loads) in [(&KIT_06, &loads_06[..]), (&KIT_07, &loads_07[..])] {
            for name in loads {
                assert!(kit.files.iter().any(|f| f.name == *name), "{} is loaded by the {} line but not in its kit", name, kit.line);
            }
            for file in kit.files {
                let bytes = std::fs::read(resources.join(file.name)).unwrap_or_else(|e| panic!("{}: {}", file.name, e));
                assert_eq!(hex::encode(Sha256::digest(&bytes)), file.sha256, "{} changed under the {} kit", file.name, kit.line);
            }
            for bin in [kit.conductor, kit.lair] {
                let dev = format!("{}-{}{}", bin.sidecar, flowsta_hc_lines::TARGET_TRIPLE, if cfg!(windows) { ".exe" } else { "" });
                assert!(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("binaries").join(&dev).exists(), "{} is not a sidecar the Vault bundles", dev);
            }
        }
    }
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

/// The 0.6 admin websocket behind `admin`, for the calls the library's
/// client does not wrap (read again after each resilient call, which may
/// have reconnected).
fn ws06(admin: &AdminClient) -> &AdminWebsocket {
    admin.as_v06().expect("a 0.6 admin client")
}

/// The error for a cell installed under another agent key: the install stops
/// and the cell is left as it is (never uninstalled).
fn wrong_key(app_id: &str, found: &holochain_types::prelude::AgentPubKey) -> String {
    log::warn!("{} is installed under a different agent key ({}); stopping, nothing changed", app_id, found);
    format!("{} on this device belongs to a different conductor key ({}). Nothing was changed.", app_id, found)
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
    conductor_child: &mut SidecarChild,
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
    //    Mutable: the resilient install and enable may swap in a fresh connection if
    //    the conductor's WS server resets a long-running admin call.
    let origin = crate::conductor::node_origin();
    let mut admin = AdminClient::connect(Line::V06, admin_port, &origin)
        .await
        .map_err(|e| format!("Failed to connect to admin WebSocket: {}", e))?;

    // 2. Check which apps are already installed and verify agent key matches.
    //    An app under a different key (e.g. from generate_agent_pub_key) stops
    //    the install with the cell left exactly as it is: never uninstall a
    //    cell that can hold data. No current path installs under another key.
    let existing_apps = ws06(&admin)
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
                return Err(wrong_key(private_app_id.as_str(), &app.agent_pub_key));
            }
        }
        if app.installed_app_id == identity_app_id {
            if key_matches {
                identity_installed = true;
            } else {
                return Err(wrong_key(identity_app_id.as_str(), &app.agent_pub_key));
            }
        }
        if app.installed_app_id == signing_app_id {
            if key_matches {
                signing_installed = true;
            } else {
                return Err(wrong_key(signing_app_id.as_str(), &app.agent_pub_key));
            }
        }
        if app.installed_app_id == private_v2_app_id {
            if key_matches {
                private_v2_installed = true;
            } else {
                // This cell can hold records that exist nowhere else. A
                // different agent key means the conductor was started as the
                // wrong key: stop here and leave the cell exactly as it is.
                return Err(format!(
                    "The private data cell on this device belongs to a different conductor key ({}). Nothing was changed.",
                    app.agent_pub_key
                ));
            }
        } else if app.installed_app_id.starts_with(&private_v2_stale_prefix) {
            // A v2 cell from an older bundle revision (different DNA hash
            // under the same version): install the current bundle beside it
            // and disable this one, kept with whatever it holds (unlock leaves
            // an app disabled this way alone).
            log::warn!(
                "Stale private v2 bundle revision installed ({}), disabling it (kept) beside {}",
                app.installed_app_id,
                private_v2_app_id,
            );
            if let Err(e) = ws06(&admin).disable_app(app.installed_app_id.clone()).await {
                log::warn!("Failed to disable {} (it stays enabled): {}", app.installed_app_id, e);
            }
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
    //      Uses the resilient enable so a long compile that resets the WS
    //      again is also handled here.
    for app in &existing_apps {
        let is_target = app.installed_app_id == private_app_id
            || app.installed_app_id == identity_app_id
            || app.installed_app_id == signing_app_id
            || app.installed_app_id == private_v2_app_id;
        if !is_target {
            continue;
        }
        // A wrong-key app has already stopped the install in the loop above.
        if app.agent_pub_key != agent_key {
            continue;
        }

        log::info!(
            "[enable] normalizing {} (status was {:?})",
            app.installed_app_id,
            app.status,
        );
        admin.enable_resilient(&app.installed_app_id, Recovery { admin_port, origin: &origin, conductor: &mut *conductor_child })
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
        admin.install_resilient(
            &InstallRequest { app_id: &private_app_id, bundle: &happ_path, agent_key: agent_key.get_raw_39(), network_seed: None },
            Recovery { admin_port, origin: &origin, conductor: &mut *conductor_child },
        )
        .await
        .map_err(|e| format!("Failed to install private DNA: {}", e))?;
        log::info!(
            "[dna:private] install_app returned in {}ms",
            install_start.elapsed().as_millis()
        );

        let enable_start = std::time::Instant::now();
        admin.enable_resilient(&private_app_id, Recovery { admin_port, origin: &origin, conductor: &mut *conductor_child })
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
        admin.install_resilient(
            &InstallRequest { app_id: &identity_app_id, bundle: &happ_path, agent_key: agent_key.get_raw_39(), network_seed: None },
            Recovery { admin_port, origin: &origin, conductor: &mut *conductor_child },
        )
        .await
        .map_err(|e| format!("Failed to install identity DNA: {}", e))?;
        log::info!(
            "[dna:identity] install_app returned in {}ms",
            install_start.elapsed().as_millis()
        );

        let enable_start = std::time::Instant::now();
        admin.enable_resilient(&identity_app_id, Recovery { admin_port, origin: &origin, conductor: &mut *conductor_child })
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
            admin.install_resilient(
            &InstallRequest { app_id: &signing_app_id, bundle: &happ_path, agent_key: agent_key.get_raw_39(), network_seed: None },
            Recovery { admin_port, origin: &origin, conductor: &mut *conductor_child },
        )
            .await
            .map_err(|e| format!("Failed to install signing DNA: {}", e))?;
            log::info!(
                "[dna:signing] install_app returned in {}ms",
                install_start.elapsed().as_millis()
            );

            let enable_start = std::time::Instant::now();
            admin.enable_resilient(&signing_app_id, Recovery { admin_port, origin: &origin, conductor: &mut *conductor_child })
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
    let enabled_apps = ws06(&admin)
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
                admin.install_resilient(
            &InstallRequest { app_id: &private_v2_app_id, bundle: &happ_path, agent_key: agent_key.get_raw_39(), network_seed: Some(seed_owned.as_str()) },
            Recovery { admin_port, origin: &origin, conductor: &mut *conductor_child },
        )
                .await
                .map_err(|e| format!("Failed to install private v2 DNA: {}", e))?;

                admin.enable_resilient(&private_v2_app_id, Recovery { admin_port, origin: &origin, conductor: &mut *conductor_child })
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
    let origin = crate::conductor::node_origin();
    let admin = AdminClient::connect(Line::V06, admin_port, &origin)
        .await
        .map_err(|e| format!("Failed to connect to admin WebSocket: {}", e))?;
    let app_port = admin
        .attach_app_interface(&origin)
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
    use holochain_client::CellInfo;

    let apps = match admin_ws.list_apps(None).await {
        Ok(a) => a,
        Err(e) => {
            log::warn!("ensure_apps_enabled: list_apps failed: {}", e);
            return;
        }
    };

    for app in &apps {
        // An app disabled on purpose stays disabled: the DNA updater keeps the
        // version it replaced that way (never uninstalled, still readable).
        if matches!(
            app.status,
            holochain_types::app::AppStatus::Disabled(holochain_types::app::DisabledAppReason::User)
        ) {
            continue;
        }
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
            let reenable: Vec<String> = apps.iter().map(|a| a.installed_app_id.clone()).collect();
            let wait = ReadyWait { attempts: 15, gap: std::time::Duration::from_secs(3), reenable: &reenable, label: "ensure_apps_enabled:" };
            match flowsta_hc_lines::admin::wait_cell_ready_06(admin_ws, &cell_id, &wait).await {
                Ok((creds, attempt)) => {
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
                }
                Err(e) => log::warn!("ensure_apps_enabled: cell readiness check failed: {}", e),
            }
        }
    }
}

// ── The 0.7 conductor (holochain_client 0.9.1) ───────────────────────

/// Install identity 1.5 and signing 1.5 on the 0.7 conductor under the same
/// agent key the 0.6 conductor runs as (the key lives in both lairs; the DNA
/// hashes differ, so one key on two conductors is allowed). Idempotent: an
/// installed app is re-enabled. Nothing is linked or carried here (B4).
/// The 0.7 apps after [`install_dnas_07`]: every app id, and how many were
/// installed this time (not found on the conductor).
pub struct Apps07 {
    pub ids: Vec<String>,
    pub new: usize,
}

pub async fn install_dnas_07(
    admin_port: u16,
    resource_dir: &Path,
    agent_key_raw32: &[u8],
    private_v2_seed: Option<&str>,
) -> Result<Apps07, String> {
    use holochain_types_07::prelude::AgentPubKey;

    let admin = AdminClient::connect(Line::V07, admin_port, &crate::conductor::node_origin())
        .await
        .map_err(|e| format!("Failed to connect to the 0.7 admin WebSocket: {}", e))?;
    let existing = admin.list_apps().await.map_err(|e| format!("Failed to list apps (0.7): {}", e))?;
    let agent_key = AgentPubKey::from_raw_32(agent_key_raw32.to_vec());
    let mut installed = Vec::new();
    let mut new = 0;
    for (app_id, file) in [
        (make_app_id("identity", BUNDLED_IDENTITY_VERSION_07), BUNDLED_IDENTITY_V1_5_HAPP_FILE),
        (make_app_id("signing", BUNDLED_SIGNING_VERSION_07), BUNDLED_SIGNING_V1_5_HAPP_FILE),
    ] {
        if existing.iter().any(|a| a.app_id == app_id) {
            admin
                .enable(&app_id)
                .await
                .map_err(|e| format!("Failed to re-enable {} (0.7): {}", app_id, e))?;
            log::info!("[0.7] {} present and enabled", app_id);
            installed.push(app_id);
            continue;
        }
        let happ_path = resource_dir.join(file);
        if !happ_path.exists() {
            return Err(format!("{} not found at {:?}", file, happ_path));
        }
        log::info!("[0.7] installing {} from {:?}", app_id, happ_path);
        admin
            .install(&InstallRequest { app_id: &app_id, bundle: &happ_path, agent_key: agent_key.get_raw_39(), network_seed: None })
            .await
            .map_err(|e| format!("Failed to install {} (0.7): {}", app_id, e))?;
        admin
            .enable(&app_id)
            .await
            .map_err(|e| format!("Failed to enable {} (0.7): {}", app_id, e))?;
        log::info!("[0.7] {} installed and enabled", app_id);
        new += 1;
        installed.push(app_id);
    }
    // The private cell, with the identity's own network seed (device-hosted
    // vaults only). Nothing is written to it here: the move (move_07) fills
    // it from the 0.6 cell and compares counts before any write goes to it.
    if let Some(seed) = private_v2_seed {
        let app_id = private_v2_app_id_07();
        if let Some(app) = existing.iter().find(|a| a.app_id == app_id) {
            if app.agent_key.as_slice() != agent_key.get_raw_39() {
                return Err(format!(
                    "The 0.7 private data cell on this device belongs to a different conductor key ({}). Nothing was changed.",
                    AgentPubKey::from_raw_39(app.agent_key.clone())
                ));
            }
            admin
                .enable(&app_id)
                .await
                .map_err(|e| format!("Failed to re-enable {} (0.7): {}", app_id, e))?;
            log::info!("[0.7] {} present and enabled", app_id);
            installed.push(app_id);
        } else {
            let happ_path = resource_dir.join(BUNDLED_PRIVATE_V2_1_HAPP_FILE);
            if !happ_path.exists() {
                return Err(format!("{} not found at {:?}", BUNDLED_PRIVATE_V2_1_HAPP_FILE, happ_path));
            }
            log::info!("[0.7] installing {} from {:?} with the identity's network seed", app_id, happ_path);
            admin
                .install(&InstallRequest { app_id: &app_id, bundle: &happ_path, agent_key: agent_key.get_raw_39(), network_seed: Some(seed) })
                .await
                .map_err(|e| format!("Failed to install {} (0.7): {}", app_id, e))?;
            admin
                .enable(&app_id)
                .await
                .map_err(|e| format!("Failed to enable {} (0.7): {}", app_id, e))?;
            log::info!("[0.7] {} installed and enabled", app_id);
            new += 1;
            installed.push(app_id);
        }
    }
    Ok(Apps07 { ids: installed, new })
}

/// Hot-swap the signing v1.5 cell's coordinator to the bundled revision on
/// every 0.7 start (the twin of `ensure_signing_coordinators`: the canonical
/// bundle carries rev 1 and is never rebuilt; the admin call is cheap and
/// idempotent, so it is applied unconditionally and never gated by a marker).
pub async fn ensure_signing_coordinators_07(admin_port: u16, resource_dir: &Path) -> Result<(), String> {
    let wasm = std::fs::read(resource_dir.join(SIGNING_COORDINATOR_WASM_07))
        .map_err(|e| format!("read {}: {}", SIGNING_COORDINATOR_WASM_07, e))?;
    let admin = AdminClient::connect(Line::V07, admin_port, &crate::conductor::node_origin())
        .await
        .map_err(|e| format!("Admin WS (0.7): {}", e))?;
    let apps = admin.list_apps().await.map_err(|e| format!("list_apps (0.7): {}", e))?;
    let signing_app_id = make_app_id("signing", BUNDLED_SIGNING_VERSION_07);
    let Some(app) = apps.iter().find(|a| a.app_id == signing_app_id) else {
        return Ok(());
    };
    let cell = app.first_cell().ok_or("No provisioned signing cell (0.7)")?;
    admin
        .update_coordinators(cell, CoordinatorZome { name: "signing", wasm })
        .await
        .map_err(|e| format!("update_coordinators (0.7): {}", e))?;
    log::info!("[0.7] signing coordinator ensured at rev {} on {}", SIGNING_COORDINATOR_REV_07, signing_app_id);
    Ok(())
}

/// Attach the 0.7 conductor's app interface (the twin of
/// `setup_app_interface`): a free port, this start's origin only.
pub async fn setup_app_interface_07(admin_port: u16) -> Result<u16, String> {
    let origin = crate::conductor::node_origin();
    let admin = AdminClient::connect(Line::V07, admin_port, &origin)
        .await
        .map_err(|e| format!("Failed to connect to the 0.7 admin WebSocket: {}", e))?;
    let app_port = admin
        .attach_app_interface(&origin)
        .await
        .map_err(|e| format!("Failed to attach the 0.7 app interface: {}", e))?;
    log::info!("[0.7] app interface attached on port {}", app_port);
    Ok(app_port)
}

/// How long a start holds the Vault for a line's signing cell before it
/// opens (a sign-in needs that cell first).
const CELLS_START_WAIT: std::time::Duration = std::time::Duration::from_secs(45);
/// How long the probe keeps asking after that. A cold conductor's cells
/// took ~75 s on 11-02 (a staging Vault, past the old 45 s): every
/// sealed read and the first devices round then failed with
/// `CellNotRunning` for half a minute.
const CELLS_COLD_WAIT: std::time::Duration = std::time::Duration::from_secs(300);
const CELLS_PROBE_GAP: std::time::Duration = std::time::Duration::from_secs(3);

fn probes(state: &crate::commands::AppState, line: Line) -> &std::sync::atomic::AtomicUsize {
    match line {
        Line::V06 => &state.cell_probes_06,
        Line::V07 => &state.cell_probes_07,
    }
}

fn probe_gen(state: &crate::commands::AppState, line: Line) -> &std::sync::atomic::AtomicU64 {
    match line {
        Line::V06 => &state.cell_probe_gen_06,
        Line::V07 => &state.cell_probe_gen_07,
    }
}

/// A line's probe still asking, counted in `AppState::cell_probes_06/07`
/// (one per conductor start; two only while a restart's old one ends).
struct CellProbe(std::sync::Arc<crate::commands::AppState>, Line);

impl CellProbe {
    fn begin(state: &std::sync::Arc<crate::commands::AppState>, line: Line) -> Self {
        probes(state, line).fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        CellProbe(state.clone(), line)
    }
}

impl Drop for CellProbe {
    fn drop(&mut self) {
        probes(&self.0, self.1).fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// While `line`'s probe is still asking and the cell a caller needs has not
/// answered this session (`answered`: its grant is cached), wait, checked
/// each second. Returns at once once it has, or when no probe runs (a call
/// then fails or passes on its own, as before).
pub async fn wait_for_cell(state: &crate::commands::AppState, line: Line, answered: impl Fn() -> bool) {
    let started = std::time::Instant::now();
    let mut waited = false;
    while probes(state, line).load(std::sync::atomic::Ordering::SeqCst) > 0
        && !answered()
        && started.elapsed() < CELLS_START_WAIT + CELLS_COLD_WAIT
    {
        waited = true;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    if waited && started.elapsed().as_secs() >= 5 {
        log::info!("[{}] a call waited {} s for its cell", line, started.elapsed().as_secs());
    }
}

/// Start `line`'s probe and wait for its signing cell: a freshly started
/// conductor lists its apps as enabled while the cells are still coming up,
/// and not all at once (a Mac's private cell answered 68 s after its
/// signing cell, 11-04). The probe asks every cell of the line's apps, one
/// cap grant each, cached so no caller authorizes again this session; each
/// call waits for its own cell (`wait_for_cell`). The start waits up to
/// 45 s for the signing cell; past that the Vault opens, and the probe
/// keeps asking for up to 5 minutes.
async fn ensure_cells_ready(line: Line, admin_port: u16, state: &std::sync::Arc<crate::commands::AppState>) {
    let probe = CellProbe::begin(state, line);
    // Not the supervisor's session: a primary's setup runs before its
    // session is numbered.
    let generation = probe_gen(state, line).fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    // A new conductor: what was granted on the last one is asked again.
    match line {
        Line::V06 => state.cell_credentials.lock().unwrap().clear(),
        Line::V07 => state.cell_credentials_07.lock().unwrap().clear(),
    }
    let (signing_ready, signing_answered) = tokio::sync::oneshot::channel();
    let state = state.clone();
    tokio::spawn(async move {
        match line {
            Line::V06 => probe_cells_06(admin_port, &state, generation, signing_ready).await,
            Line::V07 => probe_cells_07(admin_port, &state, generation, signing_ready).await,
        }
        drop(probe);
    });
    // Ends when the signing cell answers, or the probe ends without it.
    if tokio::time::timeout(CELLS_START_WAIT, signing_answered).await.is_err() {
        log::info!(
            "[{}] the signing cell still starting after {} s: the Vault opens, and each call waits for its cell (up to {} min)",
            line,
            CELLS_START_WAIT.as_secs(),
            CELLS_COLD_WAIT.as_secs() / 60
        );
    }
}

pub async fn ensure_cells_ready_06(admin_port: u16, state: &std::sync::Arc<crate::commands::AppState>) {
    ensure_cells_ready(Line::V06, admin_port, state).await
}

pub async fn ensure_cells_ready_07(admin_port: u16, state: &std::sync::Arc<crate::commands::AppState>) {
    ensure_cells_ready(Line::V07, admin_port, state).await
}

/// One probe's bookkeeping: the cells still to answer (the signing cell
/// first), and when each one did.
struct Asking<C> {
    line: Line,
    pending: Vec<(String, C)>,
    answered: Vec<(String, u64)>,
    signing_app_id: String,
    signing_ready: Option<tokio::sync::oneshot::Sender<()>>,
    started: std::time::Instant,
}

impl<C> Asking<C> {
    fn new(line: Line, mut pending: Vec<(String, C)>, signing_app_id: String, signing_ready: tokio::sync::oneshot::Sender<()>) -> Self {
        pending.sort_by_key(|(id, _)| *id != signing_app_id);
        let mut asking = Asking { line, pending, answered: Vec::new(), signing_app_id, signing_ready: Some(signing_ready), started: std::time::Instant::now() };
        // No signing cell on this line: the start does not wait for one.
        if !asking.pending.iter().any(|(id, _)| *id == asking.signing_app_id) {
            asking.signing_ready = None;
        }
        asking
    }

    fn mark_answered(&mut self, i: usize) {
        let (app_id, _) = self.pending.remove(i);
        if app_id == self.signing_app_id {
            if let Some(tx) = self.signing_ready.take() {
                let _ = tx.send(());
            }
        }
        self.answered.push((app_id, self.started.elapsed().as_secs()));
    }

    /// After a round: true when the probe is done (every cell answered, a
    /// newer start asks for its own, or the wait is over), logging why.
    fn done(&self, state: &crate::commands::AppState, generation: u64) -> bool {
        let line = self.line;
        if self.pending.is_empty() {
            log::info!("[{}] cells ready{}", line, ready_summary(&self.answered));
            return true;
        }
        // (A stopped conductor ends the probe at its next try: the socket is gone.)
        if probe_gen(state, line).load(std::sync::atomic::Ordering::SeqCst) != generation {
            return true;
        }
        let waited = self.started.elapsed();
        if waited >= CELLS_START_WAIT + CELLS_COLD_WAIT {
            log::warn!("[{}] {} still not running after {} s; calls try on their own from here", line, self.pending_names(), waited.as_secs());
            return true;
        }
        if waited.as_secs() / 15 != (waited + CELLS_PROBE_GAP).as_secs() / 15 {
            log::info!("[{}] cells not ready yet ({} s): {}", line, waited.as_secs(), self.pending_names());
        }
        false
    }

    fn pending_names(&self) -> String {
        self.pending.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>().join(", ")
    }
}

/// " after 68 s (flowsta_signing_v1_5 3 s, flowsta_private_v2_1_r1 68 s)",
/// or one time when every cell answered together.
fn ready_summary(answered: &[(String, u64)]) -> String {
    let last = answered.iter().map(|(_, s)| *s).max().unwrap_or(0);
    if answered.iter().all(|(_, s)| *s == last) {
        return if last == 0 { String::new() } else { format!(" after {} s", last) };
    }
    let each: Vec<String> = answered.iter().map(|(id, s)| format!("{} {} s", id, s)).collect();
    format!(" after {} s ({})", last, each.join(", "))
}

/// The 0.6 line's probe (`ensure_cells_ready`): every cell of every app it
/// runs except one put aside on purpose, re-enabled between rounds as
/// `ensure_apps_enabled` does.
async fn probe_cells_06(admin_port: u16, state: &std::sync::Arc<crate::commands::AppState>, generation: u64, signing_ready: tokio::sync::oneshot::Sender<()>) {
    use holochain_client::{AdminWebsocket, CellInfo};
    use holochain_types::app::{AppStatus, DisabledAppReason};
    let admin_ws = match AdminWebsocket::connect(format!("localhost:{}", admin_port), Some(crate::conductor::node_origin())).await {
        Ok(a) => a,
        Err(e) => {
            log::warn!("[0.6] readiness check: admin WS: {}", e);
            return;
        }
    };
    let apps = match admin_ws.list_apps(None).await {
        Ok(a) => a,
        Err(e) => {
            log::warn!("[0.6] readiness check: list_apps: {}", e);
            return;
        }
    };
    let mut cells = Vec::new();
    for app in apps.iter().filter(|a| !matches!(a.status, AppStatus::Disabled(DisabledAppReason::User))) {
        for c in app.cell_info.values().flatten() {
            if let CellInfo::Provisioned(p) = c {
                cells.push((app.installed_app_id.clone(), p.cell_id.clone()));
            }
        }
    }
    let mut asking = Asking::new(Line::V06, cells, make_app_id("signing", BUNDLED_SIGNING_VERSION), signing_ready);
    let once = ReadyWait { attempts: 1, gap: CELLS_PROBE_GAP, reenable: &[], label: "[0.6]" };
    loop {
        let mut i = 0;
        while i < asking.pending.len() {
            let (app_id, cell_id) = asking.pending[i].clone();
            // One try at a time, single-flighted with every other credential
            // fill (not held across the gap); a cache hit means a caller's
            // grant got there first.
            let ready = {
                let _fill = state.credentials_fill_lock.lock().await;
                if state.cell_credentials.lock().unwrap().contains_key(&cell_id) {
                    true
                } else {
                    match flowsta_hc_lines::admin::wait_cell_ready_06(&admin_ws, &cell_id, &once).await {
                        Ok((creds, _)) => {
                            state.cell_credentials.lock().unwrap().insert(cell_id.clone(), crate::commands::CachedCellCredentials::from_signing(&creds));
                            true
                        }
                        Err(e) if e.kind == flowsta_hc_lines::ZomeErrorKind::CellNotRunning => false,
                        Err(e) => {
                            log::warn!("[0.6] {}: readiness check failed: {}", app_id, e);
                            return;
                        }
                    }
                }
            };
            if ready {
                asking.mark_answered(i);
            } else {
                i += 1;
            }
        }
        if asking.done(state, generation) {
            return;
        }
        tokio::time::sleep(CELLS_PROBE_GAP).await;
        for (app_id, _) in &asking.pending {
            let _ = admin_ws.enable_app(app_id.clone()).await;
        }
    }
}

/// The 0.7 line's probe (`ensure_cells_ready`): every cell of every app it
/// runs except one put aside on purpose.
async fn probe_cells_07(admin_port: u16, state: &std::sync::Arc<crate::commands::AppState>, generation: u64, signing_ready: tokio::sync::oneshot::Sender<()>) {
    use holochain_client_07::{AdminWebsocket, CellInfo};
    use holochain_types_07::app::{AppStatus, DisabledAppReason};
    let admin_ws = match AdminWebsocket::connect(format!("localhost:{}", admin_port), Some(crate::conductor::node_origin())).await {
        Ok(a) => a,
        Err(e) => {
            log::warn!("[0.7] readiness check: admin WS: {}", e);
            return;
        }
    };
    let apps = match admin_ws.list_apps(None).await {
        Ok(a) => a,
        Err(e) => {
            log::warn!("[0.7] readiness check: list_apps: {}", e);
            return;
        }
    };
    let mut cells = Vec::new();
    for app in apps.iter().filter(|a| !matches!(a.status, AppStatus::Disabled(DisabledAppReason::User))) {
        for c in app.cell_info.values().flatten() {
            if let CellInfo::Provisioned(p) = c {
                cells.push((app.installed_app_id.clone(), p.cell_id.clone()));
            }
        }
    }
    let mut asking = Asking::new(Line::V07, cells, make_app_id("signing", BUNDLED_SIGNING_VERSION_07), signing_ready);
    let once = ReadyWait { attempts: 1, gap: CELLS_PROBE_GAP, reenable: &[], label: "[0.7]" };
    loop {
        let mut i = 0;
        while i < asking.pending.len() {
            let (app_id, cell_id) = asking.pending[i].clone();
            // As on the 0.6 line: one try at a time, single-flighted.
            let ready = {
                let _fill = state.credentials_fill_lock.lock().await;
                if state.cell_credentials_07.lock().unwrap().contains_key(&cell_id) {
                    true
                } else {
                    match flowsta_hc_lines::admin::wait_cell_ready_07(&admin_ws, &cell_id, &once).await {
                        Ok((creds, _)) => {
                            state.cell_credentials_07.lock().unwrap().insert(cell_id.clone(), crate::commands::CachedCellCredentials07::from_signing(&creds));
                            true
                        }
                        Err(e) if e.kind == flowsta_hc_lines::ZomeErrorKind::CellNotRunning => false,
                        Err(e) => {
                            log::warn!("[0.7] {}: readiness check failed: {}", app_id, e);
                            return;
                        }
                    }
                }
            };
            if ready {
                asking.mark_answered(i);
            } else {
                i += 1;
            }
        }
        if asking.done(state, generation) {
            return;
        }
        tokio::time::sleep(CELLS_PROBE_GAP).await;
    }
}

#[cfg(test)]
mod cell_wait_tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn grant(state: &crate::commands::AppState) {
        use holochain_types_07::prelude::{AgentPubKey, CapSecret, CellId, DnaHash};
        let agent = AgentPubKey::from_raw_32([0x5au8, 0x1f, 0x93, 0x04, 0xc7, 0x2e, 0x88, 0x6b].repeat(4));
        let cell = CellId::new(DnaHash::from_raw_32([0x3cu8, 0xd1, 0x07, 0xa9, 0x42, 0xee, 0x15, 0x70].repeat(4)), agent.clone());
        state.cell_credentials_07.lock().unwrap().insert(
            cell,
            crate::commands::CachedCellCredentials07 {
                signing_agent_key: agent,
                keypair: ed25519_dalek::SigningKey::from_bytes(&[0x21u8; 32]),
                cap_secret: CapSecret::from([0x6du8; 64]),
            },
        );
    }

    /// A call waits while its line's probe asks and its own cell has not
    /// answered; no longer.
    #[tokio::test]
    async fn a_call_waits_for_its_own_cell_only_while_the_probe_asks() {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::commands::AppState::new(dir.path().to_path_buf()));
        fn answered(s: &crate::commands::AppState) -> bool {
            !s.cell_credentials_07.lock().unwrap().is_empty()
        }

        // No probe asking: a call goes at once.
        let t = Instant::now();
        wait_for_cell(&state, Line::V07, || answered(&state)).await;
        assert!(t.elapsed() < Duration::from_millis(500));

        // A probe asking: the call waits until its cell has answered.
        let probe = CellProbe::begin(&state, Line::V07);
        let filler = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            grant(&filler);
        });
        let t = Instant::now();
        wait_for_cell(&state, Line::V07, || answered(&state)).await;
        assert!((Duration::from_secs(2)..Duration::from_secs(4)).contains(&t.elapsed()), "{:?}", t.elapsed());

        // Answered this session: no wait, probe or not.
        let t = Instant::now();
        wait_for_cell(&state, Line::V07, || answered(&state)).await;
        assert!(t.elapsed() < Duration::from_millis(500));

        // The other line's probe does not hold a 0.7 call.
        state.cell_credentials_07.lock().unwrap().clear();
        drop(probe);
        let other = CellProbe::begin(&state, Line::V06);
        let t = Instant::now();
        wait_for_cell(&state, Line::V07, || answered(&state)).await;
        assert!(t.elapsed() < Duration::from_millis(500));
        drop(other);

        // A probe that gives up lets its waiters go and try on their own.
        let probe = CellProbe::begin(&state, Line::V07);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            drop(probe);
        });
        let t = Instant::now();
        wait_for_cell(&state, Line::V07, || answered(&state)).await;
        assert!((Duration::from_secs(1)..Duration::from_secs(3)).contains(&t.elapsed()), "{:?}", t.elapsed());
        assert_eq!(state.cell_probes_07.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn the_ready_line_names_the_late_cells() {
        assert_eq!(ready_summary(&[("a".into(), 0), ("b".into(), 0)]), "");
        assert_eq!(ready_summary(&[("a".into(), 6), ("b".into(), 6)]), " after 6 s");
        assert_eq!(
            ready_summary(&[("flowsta_signing_v1_5".into(), 3), ("flowsta_private_v2_1_r1".into(), 68)]),
            " after 68 s (flowsta_signing_v1_5 3 s, flowsta_private_v2_1_r1 68 s)"
        );
    }
}
