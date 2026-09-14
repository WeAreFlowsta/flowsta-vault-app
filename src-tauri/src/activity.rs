//! The Vault's own activity log: what happened here, in the order it
//! happened, for the Overview and the Activity page. Local only - never
//! synced or filed anywhere - and capped so it stays a small file.
//!
//! Signatures, backups and app links are NOT logged: the feed already
//! derives them from their own records (the signing network, backup stats,
//! the linked-apps store), which predate this log. Everything that had no
//! record of its own goes here: sign-ins, email grants, remembered sites,
//! unlinks, the email and password changes, identity setup.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

pub const ACTIVITY_FILE: &str = "activity.json";
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
}

pub struct ActivityLog {
    data_dir: std::path::PathBuf,
    events: Mutex<Vec<ActivityEvent>>,
    /// Set once the Tauri app exists, so a new entry can nudge open pages.
    app_handle: Mutex<Option<tauri::AppHandle>>,
}

impl ActivityLog {
    pub fn load(data_dir: &std::path::Path) -> Self {
        let mut events: Vec<ActivityEvent> =
            crate::vault::load_json_or_quarantine(&data_dir.join(ACTIVITY_FILE));
        events.sort_by_key(|e| e.at);
        if events.len() > CAP {
            let drop_n = events.len() - CAP;
            events.drain(0..drop_n);
        }
        Self { data_dir: data_dir.to_path_buf(), events: Mutex::new(events), app_handle: Mutex::new(None) }
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
            if let Err(e) = crate::vault::write_atomic(&self.data_dir.join(ACTIVITY_FILE), json.as_bytes()) {
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
