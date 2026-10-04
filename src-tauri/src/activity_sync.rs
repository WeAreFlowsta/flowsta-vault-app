//! One Activity feed across the identity's devices.
//!
//! Each device keeps its own log (`activity.rs`, local, readable while
//! locked). This module carries the lines across: each new local line is
//! written once as a small sealed record, and the lines the other devices
//! wrote are read back and shown beside the local ones, each marked with
//! the device it happened on.

use crate::activity::ActivityEvent;
use crate::commands::AppState;
use crate::sealed::{SealedListItem, StoreSpec};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

pub const ACTIVITY_ENTRY_TYPE: &str = "activity";
/// At most this many lines go out in one pass (a device from before 1.6.0
/// may hold hundreds; they follow over a few passes).
const PER_PASS: usize = 60;

/// Where this device's own log has been written up to.
#[derive(Serialize, Deserialize, Default, Clone, Copy, PartialEq, Debug)]
pub struct Cursor {
    /// Unix seconds of the newest line written, and how many lines at that
    /// second were written (several can share a second).
    pub at: i64,
    pub n_at: usize,
}

/// The local lines not yet written, oldest first, and the cursor after them.
pub fn pending(events_oldest_first: &[ActivityEvent], cursor: Cursor) -> (Vec<ActivityEvent>, Cursor) {
    let mut seen_at_cursor = 0usize;
    let mut out = Vec::new();
    for e in events_oldest_first {
        if e.at < cursor.at {
            continue;
        }
        if e.at == cursor.at {
            seen_at_cursor += 1;
            if seen_at_cursor <= cursor.n_at {
                continue;
            }
        }
        out.push(e.clone());
        if out.len() >= PER_PASS {
            break;
        }
    }
    let next = match out.last() {
        None => cursor,
        Some(last) => {
            let n_at = out.iter().filter(|e| e.at == last.at).count() + if last.at == cursor.at { cursor.n_at } else { 0 };
            Cursor { at: last.at, n_at }
        }
    };
    (out, next)
}

/// Lines written by the identity's other devices, as this device holds them.
pub fn from_other_devices(records: &[SealedListItem], my_install: &str, device_names: &dyn Fn(&str) -> Option<String>) -> Vec<ActivityEvent> {
    let mut lines: Vec<ActivityEvent> = records
        .iter()
        .filter(|r| r.entry_type == ACTIVITY_ENTRY_TYPE)
        .filter_map(|r| {
            let install = r.body.get("install_id").and_then(|v| v.as_str())?;
            if install == my_install {
                return None;
            }
            let mut event: ActivityEvent = serde_json::from_value(r.body.clone()).ok()?;
            event.install = Some(install.to_string());
            event.device = Some(device_names(install).unwrap_or_else(|| "another device".to_string()));
            Some(event)
        })
        .collect();
    lines.sort_by_key(|e| e.at);
    lines
}

static ELSEWHERE: Mutex<Vec<ActivityEvent>> = Mutex::new(Vec::new());

pub(crate) fn forget_elsewhere() {
    ELSEWHERE.lock().unwrap().clear();
}

/// This device's log and the other devices' lines together, newest first.
pub fn merged(local_newest_first: Vec<ActivityEvent>, limit: usize) -> Vec<ActivityEvent> {
    let mut all = local_newest_first;
    all.extend(ELSEWHERE.lock().unwrap().iter().cloned());
    all.sort_by(|a, b| b.at.cmp(&a.at));
    all.truncate(limit);
    all
}

/// One pass: write the local lines not yet written; read the others'.
pub async fn round(state: &Arc<AppState>) -> Result<bool, String> {
    let my_install = crate::paths::install_id(&state.data_dir).ok_or("no install id")?;
    let path = crate::paths::activity_synced_path(&state.identity_root());
    let cursor: Cursor = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();

    let mut local = state.activity.recent(usize::MAX);
    local.reverse();
    let (to_write, next) = pending(&local, cursor);
    for (i, event) in to_write.iter().enumerate() {
        let mut body = serde_json::to_value(event).map_err(|e| e.to_string())?;
        body["install_id"] = serde_json::json!(my_install);
        let at_ms = event.at as u64 * 1000;
        crate::sealed::sealed_store_spec(
            state,
            StoreSpec {
                entry_type: ACTIVITY_ENTRY_TYPE.to_string(),
                body,
                refs: Vec::new(),
                created_at: at_ms,
                id: Some(format!("{}:{}:{}:{}", ACTIVITY_ENTRY_TYPE, my_install, event.at, cursor_index(&to_write, i, cursor))),
                updated_at: Some(at_ms),
                deleted: false,
            },
            None,
        )
        .await?;
    }
    let wrote = !to_write.is_empty();
    if wrote {
        if let Ok(bytes) = serde_json::to_vec(&next) {
            let _ = std::fs::write(&path, bytes);
        }
    }

    let records = crate::sealed::sealed_list_inner(state).await?;
    let devices = crate::devices::devices_in(&records);
    let names = |install: &str| devices.iter().find(|d| d.install_id == install).map(|d| d.name.clone());
    let theirs = from_other_devices(&records, &my_install, &names);
    let changed = {
        let mut slot = ELSEWHERE.lock().unwrap();
        let changed = slot.len() != theirs.len() || slot.last().map(|e| e.at) != theirs.last().map(|e| e.at);
        *slot = theirs;
        changed
    };
    Ok(wrote || changed)
}

/// The place of line `i` among the lines of the same second (the id must
/// differ for lines that share a second).
fn cursor_index(batch: &[ActivityEvent], i: usize, cursor: Cursor) -> usize {
    let at = batch[i].at;
    let before_in_batch = batch[..i].iter().filter(|e| e.at == at).count();
    before_in_batch + if at == cursor.at { cursor.n_at } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(at: i64, label: &str) -> ActivityEvent {
        ActivityEvent { at, kind: "sign_in".into(), label: label.into(), detail: None, origin: None, app_name: None, device: None, install: None }
    }

    #[test]
    fn each_local_line_goes_out_once_even_when_lines_share_a_second() {
        let log = vec![event(10, "a"), event(11, "b"), event(11, "c"), event(12, "d")];
        let (first, cursor) = pending(&log, Cursor::default());
        assert_eq!(first.len(), 4);
        assert_eq!(cursor, Cursor { at: 12, n_at: 1 });
        assert!(pending(&log, cursor).0.is_empty(), "nothing new, nothing written");
        // Two more lines, one in the cursor's second.
        let mut longer = log.clone();
        longer.push(event(12, "e"));
        longer.push(event(13, "f"));
        let (second, cursor2) = pending(&longer, cursor);
        assert_eq!(second.iter().map(|e| e.label.as_str()).collect::<Vec<_>>(), vec!["e", "f"]);
        assert_eq!(cursor2, Cursor { at: 13, n_at: 1 });
        // Ids differ for the two lines at second 11.
        assert_eq!(cursor_index(&first, 1, Cursor::default()), 0);
        assert_eq!(cursor_index(&first, 2, Cursor::default()), 1);
        assert_eq!(cursor_index(&second, 0, cursor), 1, "after the one already written at second 12");
    }

    #[test]
    fn the_other_devices_lines_are_read_back_with_their_device_named() {
        let item = |install: &str, at: i64| SealedListItem {
            action_hash: String::new(),
            entry_type: ACTIVITY_ENTRY_TYPE.into(),
            created_at: 0,
            body: serde_json::json!({ "at": at, "kind": "sign_in", "label": "Signed in to X", "install_id": install }),
            refs: vec![],
            id: String::new(),
            updated_at: 0,
            device: None,
        };
        let records = vec![item("me", 5), item("other", 7), item("unknown", 6)];
        let names = |install: &str| (install == "other").then(|| "Office PC".to_string());
        let lines = from_other_devices(&records, "me", &names);
        assert_eq!(lines.iter().map(|e| (e.at, e.device.clone().unwrap())).collect::<Vec<_>>(), vec![(6, "another device".to_string()), (7, "Office PC".to_string())]);
        *ELSEWHERE.lock().unwrap() = lines;
        let merged = merged(vec![event(9, "mine"), event(1, "old")], 3);
        assert_eq!(merged.iter().map(|e| e.at).collect::<Vec<_>>(), vec![9, 7, 6]);
        forget_elsewhere();
    }
}
