//! The move of an identity's records from the 0.6 line to the 0.7 line.
//!
//! Design: `planning/VAULT_0_7_TRANSITION.md` § 3a. The move is a pass that
//! copies what the 0.6 cells hold and the 0.7 cells do not - private
//! records by logical id and version time (R2), the person's own
//! signatures, revocations and thumbnails by `carry_*` (R1, idempotent by
//! the old action hash) - compares, and only then writes the `moved-07`
//! marker that sends this identity's writes to 0.7. Nothing on 0.6 is ever
//! written, disabled or uninstalled by it. The pass keeps running after
//! the flip while the 0.6 line runs, so a record written on 0.6 by a
//! device that has not updated reaches the 0.7 view within a round.
//!
//! Every step is idempotent: a Vault killed anywhere in the pass reopens on
//! the line the marker says and the next pass carries on from what the
//! destination holds.

use crate::commands::AppState;
use crate::hc::Line;
use crate::sealed::{latest_versions, StoreSpec, StoredVersion};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// What `moved-07` holds: when the identity's writes went to 0.7 and what
/// had been carried by then.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Marker {
    pub v: u32,
    pub moved_at_ms: u64,
    pub vault_version: String,
    pub private_records: usize,
    pub signatures: usize,
    pub revocations: usize,
    pub thumbnails: usize,
}

pub fn marker(root: &Path) -> Option<Marker> {
    let bytes = std::fs::read(crate::paths::moved_07_path(root)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Whether this identity's records have moved (its writes go to 0.7).
pub fn moved(root: &Path) -> bool {
    crate::paths::moved_07_path(root).exists()
}

/// What one pass did.
#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct PassOutcome {
    pub reason: String,
    pub started_ms: u64,
    pub took_ms: u64,
    /// Newest versions per logical id on the 0.6 cell.
    pub private_06: usize,
    /// ...that the 0.7 cell already held at that version or newer.
    pub private_present: usize,
    /// ...written to the 0.7 cell this pass.
    pub private_written: usize,
    /// Every 0.6 version is on 0.7 (checked after the writes).
    pub private_complete: bool,
    /// Own signature records on the 0.6 cell.
    pub signatures_06: usize,
    pub signatures_carried: usize,
    pub revocations_carried: usize,
    pub thumbnails_carried: usize,
    pub signing_complete: bool,
    /// This pass wrote the marker.
    pub flipped: bool,
    pub error: Option<String>,
    /// The pass did not run, and why.
    pub skipped: Option<String>,
}

static LAST_PASS: Mutex<Option<(PathBuf, PassOutcome)>> = Mutex::new(None);
static RUNNING: Mutex<Option<PathBuf>> = Mutex::new(None);

/// What the Identity page and `/status` say about the move.
#[derive(Serialize, Clone, Debug)]
pub struct MoveStatus {
    pub moved: bool,
    pub marker: Option<Marker>,
    pub running: bool,
    pub last_pass: Option<PassOutcome>,
    pub line: Line,
}

pub fn status(state: &AppState) -> MoveStatus {
    let root = state.identity_root();
    MoveStatus {
        moved: moved(&root),
        marker: marker(&root),
        running: RUNNING.lock().unwrap().as_deref() == Some(root.as_path()),
        last_pass: LAST_PASS.lock().unwrap().as_ref().filter(|(r, _)| r == &root).map(|(_, o)| o.clone()),
        line: crate::hc::active_line(state),
    }
}

#[tauri::command]
pub fn move_status(state: tauri::State<'_, Arc<AppState>>) -> MoveStatus {
    status(&state)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Run a pass in the background unless one is running for this identity or
/// a line is not up. Called when the 0.7 line comes up and from every
/// devices round.
pub fn schedule_pass(state: Arc<AppState>, reason: &'static str) {
    let root = state.identity_root();
    if crate::hc::line_ports(&state, Line::V06).is_err() || crate::hc::line_ports(&state, Line::V07).is_err() {
        return;
    }
    {
        let mut running = RUNNING.lock().unwrap();
        if running.is_some() {
            return;
        }
        *running = Some(root.clone());
    }
    tauri::async_runtime::spawn(async move {
        struct Done;
        impl Drop for Done {
            fn drop(&mut self) {
                *RUNNING.lock().unwrap() = None;
            }
        }
        let _done = Done;
        let outcome = run_pass(&state, reason).await;
        *LAST_PASS.lock().unwrap() = Some((root, outcome));
    });
}

/// The pass itself; see the module doc. Never fails the caller: the
/// outcome carries the error.
pub async fn run_pass(state: &Arc<AppState>, reason: &str) -> PassOutcome {
    let started = std::time::Instant::now();
    let root = state.identity_root();
    let mut out = PassOutcome { reason: reason.to_string(), started_ms: now_ms(), ..Default::default() };
    let already_moved = moved(&root);

    let (device_hosted, unlocked) = {
        let cfg = state.vault_config.lock().unwrap();
        (
            cfg.as_ref().map(|c| c.hosting_model.as_deref() == Some("device-hosted")).unwrap_or(false),
            cfg.is_some(),
        )
    };
    if !unlocked {
        out.skipped = Some("the Vault is locked".into());
        return out;
    }
    if crate::hc::line_ports(state, Line::V07).is_err() {
        out.skipped = Some("the 0.7 line is not running".into());
        return out;
    }
    if crate::hc::line_ports(state, Line::V06).is_err() {
        out.skipped = Some("the 0.6 line is not running (nothing to carry from)".into());
        return out;
    }

    // ── Private records ──
    if device_hosted {
        match private_pass(state, &mut out).await {
            Ok(()) => {}
            Err(e) => {
                out.error = Some(format!("private records: {}", e));
                finish(&root, started, &mut out);
                return out;
            }
        }
    } else {
        // A custodial-linked vault has no private cell on either line
        // (its records cross with the account, B6).
        out.private_complete = true;
    }

    // ── Signatures (once: nothing new lands on this device's 0.6 cell
    // after the flip, its writes go to 0.7) ──
    if already_moved {
        out.signing_complete = true;
    } else {
        match signing_pass(state, &mut out).await {
            Ok(()) => {}
            Err(e) => {
                out.error = Some(format!("signatures: {}", e));
                finish(&root, started, &mut out);
                return out;
            }
        }
    }

    // ── The flip ──
    if !already_moved && out.private_complete && out.signing_complete {
        let marker = Marker {
            v: 1,
            moved_at_ms: now_ms(),
            vault_version: env!("CARGO_PKG_VERSION").to_string(),
            private_records: out.private_06,
            signatures: out.signatures_06,
            revocations: out.revocations_carried,
            thumbnails: out.thumbnails_carried,
        };
        match serde_json::to_vec_pretty(&marker).map_err(|e| e.to_string()).and_then(|b| crate::vault::write_atomic(&crate::paths::moved_07_path(&root), &b).map_err(|e| e.to_string())) {
            Ok(()) => {
                out.flipped = true;
                crate::sealed::forget_recent_versions();
                crate::devices::announce_again();
                crate::commands::own_record_due();
                state.activity.record(
                    "records_moved",
                    "Your records moved to the new network",
                    Some(format!("{} private records, {} signatures", out.private_06, out.signatures_06)),
                    None,
                    None,
                );
            }
            Err(e) => out.error = Some(format!("the marker was not written: {}", e)),
        }
    }
    finish(&root, started, &mut out);
    out
}

fn finish(root: &Path, started: std::time::Instant, out: &mut PassOutcome) {
    out.took_ms = started.elapsed().as_millis() as u64;
    let id: String = root.file_name().and_then(|n| n.to_str()).unwrap_or("?").chars().take(8).collect();
    match (&out.error, out.flipped) {
        (Some(e), _) => log::warn!(
            "[move] identity {}: pass stopped after {} s ({}): private {}/{} ({} written), signatures {}/{} - {}",
            id, out.took_ms / 1000, out.reason, out.private_present + out.private_written, out.private_06, out.private_written,
            out.signatures_carried, out.signatures_06, e
        ),
        (None, true) => log::info!(
            "[move] identity {}: MOVED to the 0.7 line in {} s - private {}/{} ({} written this pass), signatures {}/{}, revocations {}, thumbnails {}",
            id, out.took_ms / 1000, out.private_present + out.private_written, out.private_06, out.private_written,
            out.signatures_carried, out.signatures_06, out.revocations_carried, out.thumbnails_carried
        ),
        (None, false) if out.private_written > 0 || out.signatures_carried > 0 => log::info!(
            "[move] identity {}: pass ({}) in {} s - private {}/{} ({} written), signatures {}/{}{}",
            id, out.reason, out.took_ms / 1000, out.private_present + out.private_written, out.private_06, out.private_written,
            out.signatures_carried, out.signatures_06,
            if out.private_complete && out.signing_complete { "" } else { " - not complete yet" }
        ),
        _ => log::debug!("[move] identity {}: pass ({}) found nothing to carry", id, out.reason),
    }
}

/// One stored version as a write to the other line: the same logical id,
/// times, body, refs, device and deletion flag.
fn spec_of(v: &StoredVersion) -> StoreSpec {
    let p = &v.payload;
    StoreSpec {
        entry_type: p.entry_type.clone(),
        body: if p.deleted { serde_json::Value::Null } else { rmp_serde::from_slice(&p.body).unwrap_or(serde_json::Value::Null) },
        refs: p.refs.clone(),
        created_at: p.created_at,
        id: Some(p.logical_id()),
        updated_at: Some(p.version_time()),
        deleted: p.deleted,
    }
}

/// Which 0.6 winners the 0.7 cell lacks (no version, or an older one), in
/// creation order, each with the 0.7 version it supersedes.
pub(crate) fn missing_on_07<'a>(
    winners_06: &'a [StoredVersion],
    held_07: &std::collections::HashMap<String, StoredVersion>,
) -> Vec<(&'a StoredVersion, Option<Vec<u8>>)> {
    let mut list: Vec<&StoredVersion> = winners_06
        .iter()
        .filter(|v| held_07.get(&v.payload.logical_id()).map(|c| c.payload.version_time() < v.payload.version_time()).unwrap_or(true))
        .collect();
    list.sort_by(|a, b| a.payload.created_at.cmp(&b.payload.created_at).then_with(|| a.action_hash.cmp(&b.action_hash)));
    list.into_iter().map(|v| (v, held_07.get(&v.payload.logical_id()).map(|c| c.action_hash.clone()))).collect()
}

async fn private_pass(state: &Arc<AppState>, out: &mut PassOutcome) -> Result<(), String> {
    let (winners_06, _) = latest_versions(crate::sealed::sealed_versions_on(state, Line::V06).await?);
    let mut held_07 = crate::sealed::sealed_held_on(state, Line::V07).await?;
    out.private_06 = winners_06.len();
    let missing = missing_on_07(&winners_06, &held_07);
    out.private_present = winners_06.len() - missing.len();
    for (v, supersedes) in missing {
        let id = v.payload.logical_id();
        let stored = {
            let _one_write_at_a_time = state.commit_serial.lock().await;
            crate::sealed::sealed_store_spec_as(
                state,
                Line::V07,
                spec_of(v),
                supersedes.filter(|h| h.len() == 39).map(holochain_types::prelude::ActionHash::from_raw_39),
                v.payload.device.clone(),
            )
            .await?
        };
        held_07.insert(id, StoredVersion { action_hash: hex::decode(&stored).unwrap_or_default(), payload: v.payload.clone() });
        out.private_written += 1;
    }
    // The check reads the 0.7 cell again rather than trusting the writes.
    crate::sealed::forget_recent_versions();
    let held_after = crate::sealed::sealed_held_on(state, Line::V07).await?;
    out.private_complete = missing_on_07(&winners_06, &held_after).is_empty();
    Ok(())
}

async fn signing_pass(state: &Arc<AppState>, out: &mut PassOutcome) -> Result<(), String> {
    let (c06, r06) = match crate::signing_07::signing_client(state, Line::V06).await {
        Ok(c) => c,
        Err(e) if e.contains("not installed") => {
            out.signing_complete = true;
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let (c07, r07) = crate::signing_07::signing_client(state, Line::V07).await?;
    let own = crate::signing_07::own_records_06(&c06, &r06).await?;
    out.signatures_06 = own.len();
    for (record, _entry) in &own {
        let on_07 = crate::signing_07::carry_signature(&c07, &r07, record).await?;
        out.signatures_carried += 1;
        for rev in crate::signing_07::revocations_06(&c06, &r06, &record.action_hash).await? {
            crate::signing_07::carry_revocation(&c07, &r07, &on_07, &rev).await?;
            out.revocations_carried += 1;
        }
        if let Some(thumb) = crate::signing_07::thumbnail_06(&c06, &r06, &record.action_hash).await? {
            crate::signing_07::carry_thumbnail(&c07, &r07, &on_07, &thumb).await?;
            out.thumbnails_carried += 1;
        }
    }
    out.signing_complete = out.signatures_carried == out.signatures_06;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed::{SealedPayload, SEALED_PAYLOAD_V2};

    fn version(id: &str, time: u64, hash: u8) -> StoredVersion {
        StoredVersion {
            action_hash: vec![hash; 39],
            payload: SealedPayload {
                v: SEALED_PAYLOAD_V2,
                entry_type: "login_activity".into(),
                created_at: time,
                body: rmp_serde::to_vec_named(&serde_json::json!({ "n": 1 })).unwrap(),
                refs: vec![],
                id: Some(id.into()),
                updated_at: Some(time),
                device: Some("dev-a".into()),
                deleted: false,
            },
        }
    }

    #[test]
    fn only_what_the_destination_lacks_is_written_oldest_first() {
        let winners_06 = vec![version("c", 3000, 3), version("a", 1000, 1), version("b", 2000, 2)];
        let mut held_07 = std::collections::HashMap::new();
        held_07.insert("b".to_string(), version("b", 2000, 22)); // same version: present
        held_07.insert("c".to_string(), version("c", 2500, 33)); // older: superseded
        let missing = missing_on_07(&winners_06, &held_07);
        let ids: Vec<&str> = missing.iter().map(|(v, _)| v.payload.id.as_deref().unwrap()).collect();
        assert_eq!(ids, vec!["a", "c"]);
        assert_eq!(missing[0].1, None);
        assert_eq!(missing[1].1, Some(vec![33u8; 39]));
        // Nothing missing = complete.
        held_07.insert("a".to_string(), version("a", 1000, 11));
        held_07.insert("c".to_string(), version("c", 3000, 34));
        assert!(missing_on_07(&winners_06, &held_07).is_empty());
    }

    #[test]
    fn a_newer_version_on_the_destination_is_never_overwritten() {
        let winners_06 = vec![version("a", 1000, 1)];
        let mut held_07 = std::collections::HashMap::new();
        held_07.insert("a".to_string(), version("a", 5000, 11));
        assert!(missing_on_07(&winners_06, &held_07).is_empty());
    }

    #[test]
    fn the_spec_keeps_the_record_as_it_was() {
        let mut v = version("a", 1000, 1);
        v.payload.deleted = true;
        let spec = spec_of(&v);
        assert_eq!(spec.id.as_deref(), Some("a"));
        assert_eq!(spec.created_at, 1000);
        assert_eq!(spec.updated_at, Some(1000));
        assert!(spec.deleted);
        assert!(spec.body.is_null());
        let live = spec_of(&version("b", 2000, 2));
        assert_eq!(live.body, serde_json::json!({ "n": 1 }));
    }

    // ── Live: a 0.6 conductor and a 0.7 conductor, the bundled binaries ──
    //
    // cargo test --lib move_07::tests::live -- --ignored --nocapture --test-threads=1

    struct LivePair {
        state: Arc<AppState>,
        children: Vec<std::process::Child>,
        lairs: Vec<crate::process_ext::SidecarChild>,
        dir: PathBuf,
    }
    impl Drop for LivePair {
        fn drop(&mut self) {
            for c in &mut self.children {
                let _ = c.kill();
                let _ = c.wait();
            }
            for l in &mut self.lairs {
                let _ = l.kill();
                let _ = l.wait();
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn manifest_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn start_conductor(dir: &Path, binary: &str, config: &str) -> std::process::Child {
        use std::io::Write;
        let binary = manifest_dir().join("binaries").join(binary);
        assert!(binary.exists(), "the bundled conductor binary {} is needed for this test", binary.display());
        std::fs::create_dir_all(dir.join("data")).unwrap();
        std::fs::create_dir_all(dir.join("ks")).unwrap();
        let config_path = dir.join("conductor-config.yaml");
        std::fs::write(&config_path, config).unwrap();
        let mut child = std::process::Command::new(&binary)
            .arg("--piped")
            .arg("-c")
            .arg(&config_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::fs::File::create(dir.join("holochain.log")).unwrap())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("start the conductor");
        child.stdin.take().unwrap().write_all(b"live-test\n").unwrap();
        child
    }

    /// One identity's two lines on this machine, as the Vault runs them:
    /// the real lair sidecars with ONE seed imported into both (the same
    /// agent key on both lines), the 0.6 conductor with private v2.0 +
    /// signing v1.4, the 0.7 conductor with private v2.1 + signing v1.5.
    async fn live_pair(name: &str, admin_06: u16, admin_07: u16, seed: &str, conductor_seed: &[u8; 32], config: &crate::vault::VaultConfig) -> LivePair {
        let auth = std::fs::read_to_string(manifest_dir().join("../scripts/run-test-instance.sh"))
            .ok()
            .and_then(|t| t.split("FLOWSTA_AUTH_MATERIAL=").nth(1).map(|r| r.split_whitespace().next().unwrap_or("").to_string()))
            .unwrap_or_default();
        // Short paths: the key stores' socket paths have a length limit.
        let dir = PathBuf::from(format!("/tmp/fvmv-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pass = "live-test";
        let origin = crate::conductor::node_origin_for_tests();
        let resources = manifest_dir().join("resources");
        let tag = "live-device-key";

        // The 0.6 key store, the seed imported.
        let lair_06 = dir.join("l6");
        let (mut lair_child_06, url_06) = crate::lair::start_lair_process_with(&lair_06, pass, "vault-lair-keystore").expect("start lair 0.6");
        crate::lair::wait_for_lair_socket(&url_06, 15, &mut lair_child_06, &lair_06).await.expect("lair 0.6 socket");
        let key_06 = {
            let client = crate::lair::connect_to_lair(&url_06, pass).await.expect("connect lair 0.6");
            let info = crate::lair::import_seed_to_lair(&client, conductor_seed, tag).await.expect("import seed 0.6");
            *info.ed25519_pub_key.0
        };
        // The 0.7 key store, the same seed: the same key.
        let lair_07 = dir.join("l7");
        let (mut lair_child_07, url_07) = crate::lair::start_lair_process_with(&lair_07, pass, "vault-lair-keystore-07").expect("start lair 0.7");
        crate::lair::wait_for_lair_socket(&url_07, 15, &mut lair_child_07, &lair_07).await.expect("lair 0.7 socket");
        let key_07 = {
            let client = crate::lair::connect_to_lair_07(&url_07, pass).await.expect("connect lair 0.7");
            crate::lair::import_seed_to_lair_07(&client, conductor_seed, tag).await.expect("import seed 0.7")
        };
        assert_eq!(key_06, key_07, "one seed, one key on both lines");

        let d06 = dir.join("06");
        let d07 = dir.join("07");
        let c06 = start_conductor(
            &d06,
            "vault-holochain-x86_64-unknown-linux-gnu",
            &format!(
                "data_root_path: '{d}/data'\nkeystore:\n  type: lair_server\n  connection_url: '{u}'\nadmin_interfaces:\n- driver:\n    type: websocket\n    port: {p}\n    allowed_origins: '{o}'\nnetwork:\n  bootstrap_url: https://bootstrap-staging.flowsta.com\n  signal_url: wss://bootstrap-staging.flowsta.com\n  relay_url: https://bootstrap-staging.flowsta.com./\n  base64_auth_material_bootstrap: \"{a}\"\n  base64_auth_material_relay: \"{a}\"\n  request_timeout_s: 240\n",
                d = d06.display(), u = url_06.replace('\'', "''"), p = admin_06, o = origin, a = auth,
            ),
        );
        let c07 = start_conductor(
            &d07,
            "vault-holochain-07-x86_64-unknown-linux-gnu",
            &format!(
                "data_root_path: '{d}/data'\nkeystore:\n  type: lair_server\n  connection_url: '{u}'\nadmin_interfaces:\n- driver:\n    type: websocket\n    port: {p}\n    allowed_origins: '{o}'\nnetwork:\n  bootstrap_url: https://bootstrap-staging-7.flowsta.com\n  relay_url: https://bootstrap-staging-7.flowsta.com./\n  base64_auth_material_bootstrap: \"{a}\"\n  base64_auth_material_relay: \"{a}\"\n  request_timeout_s: 240\ndb_sync_level: Normal\n",
                d = d07.display(), u = url_07.replace('\'', "''"), p = admin_07, o = origin, a = auth,
            ),
        );

        // 0.6: private v2.0 + signing v1.4 under the key.
        let app_06 = {
            use holochain_client::{AdminWebsocket, InstallAppPayload};
            let mut admin = None;
            for _ in 0..60 {
                if let Ok(ws) = AdminWebsocket::connect(format!("localhost:{}", admin_06), Some(crate::conductor::node_origin())).await {
                    admin = Some(ws);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            let admin = admin.expect("the 0.6 admin interface");
            let key = holochain_types::prelude::AgentPubKey::from_raw_32(key_06.to_vec());
            for (app_id, file, seed) in [
                (crate::dna::private_v2_app_id(), "flowsta_private_v2_0_happ.happ", Some(seed.to_string())),
                (crate::signing_07::signing_app_id(Line::V06), "flowsta_signing_v1_4_happ.happ", None),
            ] {
                admin
                    .install_app(InstallAppPayload {
                        source: holochain_types::prelude::AppBundleSource::Path(resources.join(file)),
                        agent_key: Some(key.clone()),
                        installed_app_id: Some(app_id.clone()),
                        network_seed: seed,
                        roles_settings: None,
                        ignore_genesis_failure: false,
                    })
                    .await
                    .unwrap_or_else(|e| panic!("install {} on 0.6: {}", app_id, e));
                admin.enable_app(app_id).await.expect("enable (0.6)");
            }
            crate::dna::ensure_private_v2_coordinators(admin_06, &resources).await.expect("private coordinator rev");
            crate::dna::ensure_signing_coordinators(admin_06, &resources, &dir).await.expect("signing coordinator rev");
            crate::dna::setup_app_interface(admin_06).await.expect("0.6 app interface")
        };

        // 0.7: private v2.1 + signing v1.5 under the same key, the way the
        // Vault installs them.
        let app_07 = {
            use holochain_client_07::AdminWebsocket;
            let mut up = false;
            for _ in 0..60 {
                if AdminWebsocket::connect(format!("localhost:{}", admin_07), Some(crate::conductor::node_origin())).await.is_ok() {
                    up = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            assert!(up, "the 0.7 admin interface");
            let apps = crate::dna::install_dnas_07(admin_07, &resources, &key_07[..], Some(seed)).await.expect("install the 0.7 apps");
            assert_eq!(apps.len(), 3, "identity 1.5, signing 1.5, private 2.1");
            crate::dna::ensure_signing_coordinators_07(admin_07, &resources).await.expect("signing 1.5 coordinator rev");
            crate::dna::setup_app_interface_07(admin_07).await.expect("0.7 app interface")
        };

        let state = Arc::new(AppState::new(dir.join("vault")));
        std::fs::create_dir_all(state.identity_root()).unwrap();
        *state.vault_config.lock().unwrap() = Some(config.clone());
        *state.test_conductor_ports.lock().unwrap() = Some((admin_06, app_06));
        *state.test_conductor_ports_07.lock().unwrap() = Some((admin_07, app_07));
        LivePair { state, children: vec![c06, c07], lairs: vec![lair_child_06, lair_child_07], dir }
    }

    #[derive(Serialize)]
    struct SignAndCreate {
        file_hash: Vec<u8>,
        signed_at: i64,
        intent: Option<String>,
        ai_generation: Option<String>,
        content_rights: Option<()>,
        integrity_report: Option<()>,
        perceptual_hash: Option<()>,
        supersedes: Option<holochain_types::prelude::ActionHash>,
        expires_at: Option<i64>,
        tags: Option<Vec<String>>,
        comment: Option<String>,
    }

    async fn sign_on_06(client: &crate::hc::AppClient, role: &str, byte: u8, signed_at: i64, supersedes: Option<Vec<u8>>) -> Vec<u8> {
        let input = rmp_serde::to_vec_named(&SignAndCreate {
            file_hash: vec![byte; 32],
            signed_at,
            intent: Some("Authorship".into()),
            ai_generation: None,
            content_rights: None,
            integrity_report: None,
            perceptual_hash: None,
            supersedes: supersedes.map(holochain_types::prelude::ActionHash::from_raw_39),
            expires_at: None,
            tags: None,
            comment: Some(format!("file {}", byte)),
        })
        .unwrap();
        let out = client.call_zome(role, "signing", "sign_and_create", input).await.expect("sign_and_create");
        let h: holochain_types::prelude::ActionHash = rmp_serde::from_slice(&out).unwrap();
        h.get_raw_39().to_vec()
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "starts a real 0.6 conductor and a real 0.7 conductor"]
    async fn live_the_move_carries_records_and_signatures_and_flips_once() {
        let seed = format!("move-{}", hex::encode(crate::key_derivation::new_conductor_seed())[..16].to_string());
        let identity_public = crate::key_derivation::public_key_of_seed(&[27u8; 32]);
        let mut config: crate::vault::VaultConfig = serde_json::from_str(
            r#"{"agent_pub_key":"uhCAkTest","did":"did:flowsta:uhCAkTest","installed_app_ids":[],"created_at":1}"#,
        )
        .unwrap();
        config.data_key = Some(vec![35u8; 32]);
        config.hosting_model = Some("device-hosted".into());
        config.agent_pub_key_raw_b64 = Some(crate::key_derivation::base64_standard_encode(
            &crate::key_derivation::construct_agent_pub_key_bytes(&identity_public),
        ));
        // This device's conductor key: the seed both key stores hold.
        let conductor_seed = [28u8; 32];
        config.conductor_seed = Some(conductor_seed.to_vec());
        let pair = live_pair("a", 46061, 46062, &seed, &conductor_seed, &config).await;
        let state = &pair.state;
        let root = state.identity_root();
        assert_eq!(crate::hc::active_line(state), Line::V06);

        // ── Before: the identity's life on 0.6 ──
        // Private records: a profile, forty log entries, an edit, a deletion,
        // and a record another device wrote (kept as that device's).
        let profile = crate::sealed::sealed_store_inner(state, "user_profile".into(), serde_json::json!({ "name": "first" }), vec![], 1_000).await.unwrap();
        for i in 0..40u64 {
            crate::sealed::sealed_store_inner(state, "login_activity".into(), serde_json::json!({ "n": i }), vec![], 2_000 + i).await.unwrap();
        }
        crate::sealed::sealed_replace_inner(state, &profile, "user_profile".into(), serde_json::json!({ "name": "edited" }), vec![], 1_000).await.unwrap();
        let gone = crate::sealed::sealed_store_inner(state, "dashboard_activity".into(), serde_json::json!({ "x": 1 }), vec![], 3_000).await.unwrap();
        crate::sealed::sealed_delete_inner(state, &gone).await.unwrap();
        crate::sealed::sealed_store_spec_as(
            state,
            Line::V06,
            StoreSpec { entry_type: "login_activity".into(), body: serde_json::json!({ "from": "b" }), refs: vec![], created_at: 4_000, id: None, updated_at: None, deleted: false },
            None,
            Some("device-b".into()),
        )
        .await
        .unwrap();
        crate::sealed::forget_recent_versions();
        let (winners_06, _) = latest_versions(crate::sealed::sealed_versions_on(state, Line::V06).await.unwrap());
        assert_eq!(winners_06.len(), 43, "profile, 40 logs, the deleted record (one logical id), device b's record");

        // Signatures: three, one superseding another, one revoked, one with a thumbnail.
        let (c06, r06) = crate::signing_07::signing_client(state, Line::V06).await.unwrap();
        let s1 = sign_on_06(&c06, &r06, 1, 10_000, None).await;
        let s2 = sign_on_06(&c06, &r06, 2, 20_000, Some(s1.clone())).await;
        let s3 = sign_on_06(&c06, &r06, 3, 30_000, None).await;
        #[derive(Serialize)]
        struct RevokeInput {
            signature_action: holochain_types::prelude::ActionHash,
            reason: Option<String>,
        }
        c06.call_zome(&r06, "signing", "revoke_signature", rmp_serde::to_vec_named(&RevokeInput { signature_action: holochain_types::prelude::ActionHash::from_raw_39(s3.clone()), reason: Some("wrong file".into()) }).unwrap())
            .await
            .expect("revoke on 0.6");
        #[derive(Serialize)]
        struct SetThumbnailInput {
            signature_action: holochain_types::prelude::ActionHash,
            thumbnail: String,
        }
        c06.call_zome(&r06, "signing", "set_thumbnail", rmp_serde::to_vec_named(&SetThumbnailInput { signature_action: holochain_types::prelude::ActionHash::from_raw_39(s2.clone()), thumbnail: "data:image/png;base64,AAAA".into() }).unwrap())
            .await
            .expect("thumbnail on 0.6");

        // ── The pass ──
        let started = std::time::Instant::now();
        let out = run_pass(state, "test").await;
        println!("first pass in {:?}: {:#?}", started.elapsed(), out);
        assert_eq!(out.error, None);
        assert_eq!(out.private_06, 43);
        assert_eq!(out.private_written, 43);
        assert!(out.private_complete);
        assert_eq!(out.signatures_06, 3);
        assert_eq!(out.signatures_carried, 3);
        assert_eq!(out.revocations_carried, 1);
        assert_eq!(out.thumbnails_carried, 1);
        assert!(out.signing_complete);
        assert!(out.flipped);
        assert!(moved(&root));
        let m = marker(&root).unwrap();
        assert_eq!((m.private_records, m.signatures, m.revocations, m.thumbnails), (43, 3, 1, 1));
        assert_eq!(crate::hc::active_line(state), Line::V07);

        // What 0.7 holds is what 0.6 held: same ids, same versions, same devices.
        let held_07 = crate::sealed::sealed_held_on(state, Line::V07).await.unwrap();
        assert_eq!(held_07.len(), 43);
        for v in &winners_06 {
            let on_07 = held_07.get(&v.payload.logical_id()).expect("every 0.6 record is on 0.7");
            assert_eq!(on_07.payload.version_time(), v.payload.version_time());
            assert_eq!(on_07.payload.deleted, v.payload.deleted);
            assert_eq!(on_07.payload.device, v.payload.device, "the writing device is kept");
            assert_ne!(on_07.action_hash, v.action_hash, "a new action on the new network");
        }
        assert_eq!(held_07.get("user_profile").unwrap().payload.deleted, false);
        let edited: serde_json::Value = rmp_serde::from_slice(&held_07.get("user_profile").unwrap().payload.body).unwrap();
        assert_eq!(edited["name"], "edited");
        let from_b = held_07.values().find(|v| v.payload.device.as_deref() == Some("device-b")).expect("device b's record");
        assert_eq!(from_b.payload.created_at, 4_000);

        // The signatures on 0.7: three carried records, the chain whole, the
        // revocation and the thumbnail with them.
        let own_07 = crate::signing_07::own_signatures(state).await.unwrap();
        assert_eq!(own_07.len(), 3);
        let by_original = |h: &[u8]| own_07.iter().find(|s| s["original_action_hash"] == hex::encode(h)).expect("carried");
        assert_eq!(by_original(&s3)["revoked"], true);
        assert_eq!(by_original(&s3)["revocation_reason"], "wrong file");
        assert_eq!(by_original(&s2)["thumbnail"], "data:image/png;base64,AAAA");
        assert_eq!(by_original(&s1)["thumbnail"], serde_json::Value::Null);
        assert_eq!(by_original(&s2)["supersedes"], hex::encode(&s1), "the record is byte-identical: its supersedes names the 0.6 hash");
        let merged = crate::signing_07::merge_own(Vec::new(), own_07.clone());
        let s2_merged = merged.iter().find(|s| s["original_action_hash"] == hex::encode(&s2)).unwrap();
        assert_eq!(s2_merged["supersedes"], by_original(&s1)["action_hash"], "the view re-points the chain at the carried copy");

        // ── A second pass carries nothing and flips nothing ──
        let again = run_pass(state, "test again").await;
        assert_eq!(again.error, None);
        assert_eq!(again.private_written, 0);
        assert_eq!(again.private_present, 43);
        assert!(again.private_complete && again.signing_complete && !again.flipped);
        assert_eq!(marker(&root), Some(m.clone()), "the marker is written once");
        assert_eq!(crate::signing_07::own_signatures(state).await.unwrap().len(), 3, "carries are idempotent");

        // ── After the flip: writes go to 0.7, 0.6 is untouched ──
        crate::sealed::sealed_store_inner(state, "login_activity".into(), serde_json::json!({ "after": true }), vec![], 5_000).await.unwrap();
        crate::sealed::forget_recent_versions();
        assert_eq!(crate::sealed::sealed_held_on(state, Line::V07).await.unwrap().len(), 44);
        assert_eq!(latest_versions(crate::sealed::sealed_versions_on(state, Line::V06).await.unwrap()).0.len(), 43, "nothing new on 0.6");
        let (admin_06, app_06) = crate::hc::line_ports(state, Line::V06).unwrap();
        let s4 = crate::commands::commit_signature_to_dht(state, admin_06, app_06, &[4u8; 32], 40_000, Some("authorship"), None, None, None, None, Some("after the move"), None)
            .await
            .expect("the Vault's Sign It write after the flip");
        let own_after = crate::signing_07::own_signatures(state).await.unwrap();
        assert_eq!(own_after.len(), 4);
        assert!(own_after.iter().any(|s| s["action_hash"] == s4 && s.get("original_action_hash").is_none()), "a native 0.7 record, written by the Vault's own path");
        let (c06b, r06b) = crate::signing_07::signing_client(state, Line::V06).await.unwrap();
        assert_eq!(crate::signing_07::own_records_06(&c06b, &r06b).await.unwrap().len(), 3, "nothing new on the 0.6 signing cell");

        // ── A device that has not updated writes on 0.6: the next pass carries it ──
        crate::sealed::sealed_store_spec_as(
            state,
            Line::V06,
            StoreSpec { entry_type: "login_activity".into(), body: serde_json::json!({ "late": true }), refs: vec![], created_at: 6_000, id: None, updated_at: None, deleted: false },
            None,
            Some("device-b".into()),
        )
        .await
        .unwrap();
        crate::sealed::forget_recent_versions();
        let late = run_pass(state, "catch-up").await;
        assert_eq!(late.error, None);
        assert_eq!(late.private_written, 1);
        assert!(late.private_complete && !late.flipped);
        let held = crate::sealed::sealed_held_on(state, Line::V07).await.unwrap();
        assert!(held.values().any(|v| v.payload.created_at == 6_000 && v.payload.device.as_deref() == Some("device-b")));
        assert_eq!(held.len(), 45);
        println!("the move: first pass {:?}, {} s total", out.took_ms, started.elapsed().as_secs());
    }

    #[test]
    fn the_marker_round_trips() {
        let dir = std::env::temp_dir().join(format!("fv-move-marker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!moved(&dir));
        let m = Marker { v: 1, moved_at_ms: 5, vault_version: "1.7.0".into(), private_records: 3, signatures: 2, revocations: 1, thumbnails: 0 };
        crate::vault::write_atomic(&crate::paths::moved_07_path(&dir), &serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(moved(&dir));
        assert_eq!(marker(&dir), Some(m));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
