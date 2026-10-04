//! The Vault's own activity log: what happened here, in the order it
//! happened, for the Overview and the Activity page. Kept as a small local
//! file, readable while locked; `activity_sync.rs` carries the lines to the
//! identity's other devices and shows theirs here.
//!
//! Signatures, backups and app links are NOT logged: the feed already
//! derives them from their own records (the signing network, backup stats,
//! the linked-apps store), which predate this log. Everything that had no
//! record of its own goes here: sign-ins, email grants, remembered sites,
//! unlinks, the email and password changes, identity setup.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[allow(unused_imports)]
pub use crate::paths::ACTIVITY_FILE;
/// Newest entries kept; older ones fall off the end.
const CAP: usize = 500;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ActivityEvent {
    /// Unix seconds.
    pub at: i64,
    /// Machine kind: sign_in, relay_approved, email_shared, email_unshared,
    /// site_remembered, site_forgotten, app_unlinked, email_changed,
    /// password_changed, identity_created, identity_restored.
    pub kind: String,
    /// One line, past tense, as shown to the person.
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    /// The device it happened on, when it was not this one (name and install id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install: Option<String>,
}

pub struct ActivityLog {
    /// Identity root the log persists under; switched by a relocation.
    data_dir: Mutex<std::path::PathBuf>,
    events: Mutex<Vec<ActivityEvent>>,
    /// Set once the Tauri app exists, so a new entry can nudge open pages.
    app_handle: Mutex<Option<tauri::AppHandle>>,
}

impl ActivityLog {
    pub fn load(data_dir: &std::path::Path) -> Self {
        let mut events: Vec<ActivityEvent> =
            crate::vault::load_json_or_quarantine(&crate::paths::activity_path(data_dir));
        events.sort_by_key(|e| e.at);
        if events.len() > CAP {
            let drop_n = events.len() - CAP;
            events.drain(0..drop_n);
        }
        Self { data_dir: Mutex::new(data_dir.to_path_buf()), events: Mutex::new(events), app_handle: Mutex::new(None) }
    }

    /// Forget every entry (full erase); the file is removed by the caller.
    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }

    /// Point the log at a new identity root and take up THAT root's
    /// entries. The activity log is per identity: on a relocation the file
    /// moved with the identity, and on a switch (1.5.0) the other root has
    /// its own file. Keeping the old entries in memory wrote identity A's
    /// activity into identity B's file (seen 2026-09-29: both identities
    /// showed two "identity_created" lines after one switch).
    pub fn set_root(&self, root: &std::path::Path) {
        let mut events: Vec<ActivityEvent> =
            crate::vault::load_json_or_quarantine(&crate::paths::activity_path(root));
        events.sort_by_key(|e| e.at);
        if events.len() > CAP {
            let drop_n = events.len() - CAP;
            events.drain(0..drop_n);
        }
        *self.data_dir.lock().unwrap() = root.to_path_buf();
        *self.events.lock().unwrap() = events;
    }

    pub fn attach(&self, handle: tauri::AppHandle) {
        *self.app_handle.lock().unwrap() = Some(handle);
    }

    /// Append one entry (now), persist, and tell the UI.
    pub fn record(&self, kind: &str, label: impl Into<String>, detail: Option<String>, origin: Option<String>, app_name: Option<String>) {
        let event = ActivityEvent {
            at: crate::ipc_server::unix_now() as i64,
            kind: kind.to_string(),
            label: label.into(),
            detail,
            origin,
            app_name,
            device: None,
            install: None,
        };
        let json = {
            let mut events = self.events.lock().unwrap();
            events.push(event.clone());
            if events.len() > CAP {
                let drop_n = events.len() - CAP;
                events.drain(0..drop_n);
            }
            serde_json::to_string_pretty(&*events)
        };
        if let Ok(json) = json {
            if let Err(e) = crate::vault::write_atomic(&crate::paths::activity_path(&self.data_dir.lock().unwrap()), json.as_bytes()) {
                log::warn!("activity log not saved: {}", e);
            }
        }
        if let Some(h) = self.app_handle.lock().unwrap().as_ref() {
            use tauri::Emitter;
            let _ = h.emit("activity-recorded", serde_json::json!({ "kind": event.kind }));
        }
    }

    /// Newest first.
    pub fn recent(&self, limit: usize) -> Vec<ActivityEvent> {
        let events = self.events.lock().unwrap();
        events.iter().rev().take(limit).cloned().collect()
    }

    pub fn kinds_newest_first(&self, limit: usize) -> Vec<String> {
        self.recent(limit).into_iter().map(|e| e.kind).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switching_root_takes_up_that_roots_entries_and_never_carries_the_old_ones() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let log = ActivityLog::load(&a);
        log.record("identity_created", "A created", None, None, None);
        log.set_root(&b);
        assert!(log.recent(10).is_empty(), "B starts with its own (empty) log");
        log.record("identity_created", "B created", None, None, None);
        log.set_root(&a);
        let kinds_a = log.kinds_newest_first(10);
        assert_eq!(kinds_a, vec!["identity_created".to_string()], "A has exactly its one entry");
        assert_eq!(log.recent(1)[0].label, "A created");
        let on_disk_b: Vec<ActivityEvent> =
            crate::vault::load_json_or_quarantine(&crate::paths::activity_path(&b));
        assert_eq!(on_disk_b.len(), 1);
        assert_eq!(on_disk_b[0].label, "B created", "B's file holds only B's entry");
    }

    #[test]
    fn keeps_newest_within_cap_and_survives_reload() {
        let dir = tempfile::tempdir().unwrap();
        let log = ActivityLog::load(dir.path());
        for i in 0..(CAP + 20) {
            log.record("sign_in", format!("Signed in #{}", i), None, None, None);
        }
        let recent = log.recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].label, format!("Signed in #{}", CAP + 19));
        let reloaded = ActivityLog::load(dir.path());
        assert_eq!(reloaded.recent(1000).len(), CAP);
        assert_eq!(reloaded.recent(1)[0].label, format!("Signed in #{}", CAP + 19));
    }

    #[test]
    fn corrupt_file_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(ACTIVITY_FILE), b"{not json").unwrap();
        let log = ActivityLog::load(dir.path());
        assert!(log.recent(10).is_empty());
    }
}
