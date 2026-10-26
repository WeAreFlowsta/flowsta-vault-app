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
        let outcome = run_pass(&state, reason).await;
        *LAST_PASS.lock().unwrap() = Some((root, outcome));
        *RUNNING.lock().unwrap() = None;
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
