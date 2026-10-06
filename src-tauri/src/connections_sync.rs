//! Connections and remembered sites follow the identity.
//!
//! Which apps a person connected, what each may see, and which sites they
//! chose to remember are kept as sealed records in the identity's private
//! network, one per app and one per site. Each device compares three
//! things: what it holds now, what it held when it last looked, and what
//! the records say.
//!
//!   - Changed here since the last look: the record is written (it is the
//!     newest, so it wins).
//!   - Unchanged here, different in the records: this device follows.
//!     A Disconnect made on any device disconnects the app on every one;
//!     a remembered site is remembered everywhere.
//!
//! An app connected on another device is NOT connected here until it links
//! on this device too (it is a different install with its own key); the
//! approval it shows then can say the person already uses it.
//!
//! The local JSON files stay what the Vault reads while locked.

use crate::commands::AppState;
use crate::sealed::{SealedListItem, StoreSpec};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

pub const CONNECTION_ENTRY_TYPE: &str = "connection";
pub const SITE_ENTRY_TYPE: &str = "remembered_site";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Connection {
    pub app_name: String,
    /// Sorted, so two devices holding the same scopes compare equal.
    pub scopes: Vec<String>,
}

/// What follows the identity, as one device holds it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Shared {
    pub connections: BTreeMap<String, Connection>,
    pub sites: BTreeSet<String>,
}

/// What the identity's records say.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Recorded {
    /// client_id -> the connection, or `None` when it was disconnected.
    pub connections: BTreeMap<String, Option<Connection>>,
    /// origin -> remembered or forgotten.
    pub sites: BTreeMap<String, bool>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Step {
    /// Changed on this device: write it to the records.
    RecordConnection { client_id: String, connection: Option<Connection>, app_name: String },
    RecordSite { origin: String, remembered: bool },
    /// Changed on another device: follow.
    Disconnect { client_id: String },
    SetScopes { client_id: String, scopes: Vec<String> },
    RememberSite { origin: String },
    ForgetSite { origin: String },
}

/// The steps that bring this device and the records together, and the
/// apps connected on other devices only.
pub fn merge(base: &Shared, local: &Shared, recorded: &Recorded) -> (Vec<Step>, BTreeMap<String, Connection>) {
    let mut steps = Vec::new();
    let mut elsewhere = BTreeMap::new();

    let clients: BTreeSet<&String> = base
        .connections
        .keys()
        .chain(local.connections.keys())
        .chain(recorded.connections.keys())
        .collect();
    for client_id in clients {
        let was = base.connections.get(client_id);
        let is = local.connections.get(client_id);
        let record = recorded.connections.get(client_id);
        if is != was {
            // Changed here. Nothing to write when the records already say so.
            if record != Some(&is.cloned()) && !(is.is_none() && record.is_none()) {
                let app_name = is.or(was).map(|c| c.app_name.clone()).unwrap_or_default();
                steps.push(Step::RecordConnection { client_id: client_id.clone(), connection: is.cloned(), app_name });
            }
            continue;
        }
        match (is, record) {
            (Some(_), Some(None)) => steps.push(Step::Disconnect { client_id: client_id.clone() }),
            (Some(mine), Some(Some(theirs))) if mine.scopes != theirs.scopes => {
                steps.push(Step::SetScopes { client_id: client_id.clone(), scopes: theirs.scopes.clone() })
            }
            (None, Some(Some(theirs))) => {
                elsewhere.insert(client_id.clone(), theirs.clone());
            }
            // Here and not in the records yet (a device from before this
            // was kept): say so.
            (Some(mine), None) => steps.push(Step::RecordConnection {
                client_id: client_id.clone(),
                connection: Some(mine.clone()),
                app_name: mine.app_name.clone(),
            }),
            _ => {}
        }
    }

    let origins: BTreeSet<&String> = base.sites.iter().chain(local.sites.iter()).chain(recorded.sites.keys()).collect();
    for origin in origins {
        let was = base.sites.contains(origin);
        let is = local.sites.contains(origin);
        let record = recorded.sites.get(origin).copied();
        if is != was {
            if record != Some(is) && (is || record.is_some()) {
                steps.push(Step::RecordSite { origin: origin.clone(), remembered: is });
            }
            continue;
        }
        match (is, record) {
            (true, Some(false)) => steps.push(Step::ForgetSite { origin: origin.clone() }),
            (false, Some(true)) => steps.push(Step::RememberSite { origin: origin.clone() }),
            (true, None) => steps.push(Step::RecordSite { origin: origin.clone(), remembered: true }),
            _ => {}
        }
    }
    (steps, elsewhere)
}

/// What the records say, from a listing.
pub fn recorded_in(records: &[SealedListItem]) -> Recorded {
    let mut recorded = Recorded::default();
    for item in records {
        if item.entry_type == CONNECTION_ENTRY_TYPE {
            let Some(client_id) = item.body.get("client_id").and_then(|v| v.as_str()) else { continue };
            let connected = item.body.get("connected").and_then(|v| v.as_bool()).unwrap_or(false);
            let connection = connected.then(|| Connection {
                app_name: item.body.get("app_name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                scopes: sorted(
                    item.body
                        .get("scopes")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                        .unwrap_or_default(),
                ),
            });
            recorded.connections.insert(client_id.to_string(), connection);
        } else if item.entry_type == SITE_ENTRY_TYPE {
            let Some(origin) = item.body.get("origin").and_then(|v| v.as_str()) else { continue };
            let remembered = item.body.get("remembered").and_then(|v| v.as_bool()).unwrap_or(false);
            recorded.sites.insert(origin.to_string(), remembered);
        }
    }
    recorded
}

fn sorted(mut scopes: Vec<String>) -> Vec<String> {
    scopes.sort();
    scopes.dedup();
    scopes
}

/// What this device holds now.
fn local_shared(state: &AppState) -> Shared {
    let scopes = state.linked_app_scopes.lock().unwrap().clone();
    let mut shared = Shared::default();
    for app in state.linked_third_party_apps.lock().unwrap().iter() {
        if let Some(client_id) = app.client_id.as_ref() {
            shared.connections.insert(
                client_id.clone(),
                Connection { app_name: app.app_name.clone(), scopes: sorted(scopes.get(client_id).cloned().unwrap_or_default()) },
            );
        }
    }
    shared.sites = state.approved_apps.lock().unwrap().iter().cloned().collect();
    shared
}

/// Apps connected on the identity's other devices and not on this one.
static ELSEWHERE: Mutex<BTreeMap<String, Connection>> = Mutex::new(BTreeMap::new());

pub(crate) fn forget_elsewhere() {
    ELSEWHERE.lock().unwrap().clear();
}

/// An app the person already connected on another device, for the approval
/// shown when it first links on this one.
#[tauri::command]
pub fn connection_known_elsewhere(client_id: String) -> Option<Connection> {
    ELSEWHERE.lock().unwrap().get(&client_id).cloned()
}

/// The apps connected on other devices only (their client ids).
pub fn known_elsewhere() -> Vec<String> {
    ELSEWHERE.lock().unwrap().keys().cloned().collect()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn write(state: &Arc<AppState>, entry_type: &str, id: String, body: serde_json::Value) -> Result<(), String> {
    let now = now_ms();
    crate::sealed::sealed_store_spec(
        state,
        StoreSpec { entry_type: entry_type.to_string(), body, refs: Vec::new(), created_at: now, id: Some(id), updated_at: Some(now), deleted: false },
        None,
    )
    .await
    .map(|_| ())
}

/// One pass. Returns whether anything changed on this device.
pub async fn round(state: &Arc<AppState>) -> Result<bool, String> {
    let records = crate::sealed::sealed_list_inner(state).await?;
    let path = crate::paths::shared_connections_path(&state.identity_root());
    let base: Shared = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let local = local_shared(state);
    let (steps, elsewhere) = merge(&base, &local, &recorded_in(&records));
    *ELSEWHERE.lock().unwrap() = elsewhere;

    let mut changed_here = false;
    for step in steps {
        match step {
            Step::RecordConnection { client_id, connection, app_name } => {
                let body = serde_json::json!({
                    "client_id": client_id,
                    "app_name": app_name,
                    "scopes": connection.as_ref().map(|c| c.scopes.clone()).unwrap_or_default(),
                    "connected": connection.is_some(),
                });
                write(state, CONNECTION_ENTRY_TYPE, format!("{}:{}", CONNECTION_ENTRY_TYPE, client_id), body).await?;
            }
            Step::RecordSite { origin, remembered } => {
                let body = serde_json::json!({ "origin": origin, "remembered": remembered });
                write(state, SITE_ENTRY_TYPE, format!("site:{}", origin), body).await?;
            }
            Step::Disconnect { client_id } => {
                let name = {
                    let mut apps = state.linked_third_party_apps.lock().unwrap();
                    let name = apps.iter().find(|a| a.client_id.as_deref() == Some(client_id.as_str())).map(|a| a.app_name.clone());
                    apps.retain(|a| a.client_id.as_deref() != Some(client_id.as_str()));
                    name
                };
                state.save_linked_apps();
                state.linked_app_scopes.lock().unwrap().remove(&client_id);
                state.save_linked_app_scopes();
                crate::commands::revoke_email_grant(state, &client_id);
                let name = name.unwrap_or(client_id);
                state.activity.record("app_unlinked_elsewhere", format!("{} was disconnected on another device", name), None, None, Some(name));
                changed_here = true;
            }
            Step::SetScopes { client_id, scopes } => {
                state.linked_app_scopes.lock().unwrap().insert(client_id, scopes);
                state.save_linked_app_scopes();
                changed_here = true;
            }
            Step::RememberSite { origin } => {
                let mut sites = state.approved_apps.lock().unwrap();
                if !sites.contains(&origin) {
                    sites.push(origin);
                }
                drop(sites);
                state.save_approved_sites();
                changed_here = true;
            }
            Step::ForgetSite { origin } => {
                state.approved_apps.lock().unwrap().retain(|o| o != &origin);
                state.save_approved_sites();
                changed_here = true;
            }
        }
    }

    let now = local_shared(state);
    if now != base {
        if let Ok(bytes) = serde_json::to_vec(&now) {
            let _ = std::fs::write(&path, bytes);
        }
    }
    Ok(changed_here)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection(scopes: &[&str]) -> Connection {
        Connection { app_name: "Poll App".into(), scopes: scopes.iter().map(|s| s.to_string()).collect() }
    }

    fn shared(connections: &[(&str, Connection)], sites: &[&str]) -> Shared {
        Shared {
            connections: connections.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
            sites: sites.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn recorded(connections: &[(&str, Option<Connection>)], sites: &[(&str, bool)]) -> Recorded {
        Recorded {
            connections: connections.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
            sites: sites.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }

    #[test]
    fn an_app_connected_here_is_written_to_the_records_once() {
        let local = shared(&[("app", connection(&["profile"]))], &[]);
        let (steps, _) = merge(&Shared::default(), &local, &Recorded::default());
        assert_eq!(
            steps,
            vec![Step::RecordConnection { client_id: "app".into(), connection: Some(connection(&["profile"])), app_name: "Poll App".into() }]
        );
        // Written and seen again: nothing more to do.
        let (steps, _) = merge(&local, &local, &recorded(&[("app", Some(connection(&["profile"])))], &[]));
        assert!(steps.is_empty());
    }

    #[test]
    fn a_disconnect_on_another_device_disconnects_here() {
        let mine = shared(&[("app", connection(&["profile"]))], &[]);
        let (steps, _) = merge(&mine, &mine, &recorded(&[("app", None)], &[]));
        assert_eq!(steps, vec![Step::Disconnect { client_id: "app".into() }]);
    }

    #[test]
    fn a_disconnect_here_is_written_for_the_other_devices() {
        let before = shared(&[("app", connection(&["profile"]))], &[]);
        let (steps, _) = merge(&before, &Shared::default(), &recorded(&[("app", Some(connection(&["profile"])))], &[]));
        assert_eq!(steps, vec![Step::RecordConnection { client_id: "app".into(), connection: None, app_name: "Poll App".into() }]);
    }

    #[test]
    fn connecting_again_here_after_a_disconnect_elsewhere_wins() {
        // Disconnected everywhere earlier (base: none). The person connects it here again.
        let local = shared(&[("app", connection(&["profile"]))], &[]);
        let (steps, _) = merge(&Shared::default(), &local, &recorded(&[("app", None)], &[]));
        assert_eq!(
            steps,
            vec![Step::RecordConnection { client_id: "app".into(), connection: Some(connection(&["profile"])), app_name: "Poll App".into() }]
        );
    }

    #[test]
    fn an_app_connected_only_on_another_device_is_not_connected_here() {
        let (steps, elsewhere) = merge(&Shared::default(), &Shared::default(), &recorded(&[("app", Some(connection(&["email"])))], &[]));
        assert!(steps.is_empty(), "it links on this device itself, with its own approval");
        assert_eq!(elsewhere.get("app"), Some(&connection(&["email"])));
    }

    #[test]
    fn what_an_app_may_see_follows_the_identity() {
        let mine = shared(&[("app", connection(&["profile"]))], &[]);
        let (steps, _) = merge(&mine, &mine, &recorded(&[("app", Some(connection(&["email", "profile"])))], &[]));
        assert_eq!(steps, vec![Step::SetScopes { client_id: "app".into(), scopes: vec!["email".into(), "profile".into()] }]);
    }

    #[test]
    fn a_device_from_before_says_what_it_holds() {
        // Nothing changed here since the last look, and the records have nothing yet.
        let mine = shared(&[("app", connection(&[]))], &["https://a.example"]);
        let (steps, _) = merge(&mine, &mine, &Recorded::default());
        assert_eq!(steps.len(), 2);
    }

    #[test]
    fn remembered_sites_carry_over_both_ways() {
        let (steps, _) = merge(&Shared::default(), &Shared::default(), &recorded(&[], &[("https://a.example", true)]));
        assert_eq!(steps, vec![Step::RememberSite { origin: "https://a.example".into() }]);

        let mine = shared(&[], &["https://a.example"]);
        let (steps, _) = merge(&mine, &mine, &recorded(&[], &[("https://a.example", false)]));
        assert_eq!(steps, vec![Step::ForgetSite { origin: "https://a.example".into() }]);

        // Remembered here just now: written.
        let (steps, _) = merge(&Shared::default(), &mine, &Recorded::default());
        assert_eq!(steps, vec![Step::RecordSite { origin: "https://a.example".into(), remembered: true }]);
        // Forgotten here just now: written, even though the records still say remembered.
        let (steps, _) = merge(&mine, &Shared::default(), &recorded(&[], &[("https://a.example", true)]));
        assert_eq!(steps, vec![Step::RecordSite { origin: "https://a.example".into(), remembered: false }]);
        // A site forgotten everywhere stays forgotten.
        let (steps, _) = merge(&Shared::default(), &Shared::default(), &recorded(&[], &[("https://a.example", false)]));
        assert!(steps.is_empty());
    }

    #[test]
    fn the_records_read_back_as_written() {
        let item = |entry_type: &str, body: serde_json::Value| SealedListItem {
            action_hash: String::new(),
            entry_type: entry_type.into(),
            created_at: 0,
            body,
            refs: vec![],
            id: String::new(),
            updated_at: 0,
            device: None,
        };
        let recorded = recorded_in(&[
            item(CONNECTION_ENTRY_TYPE, serde_json::json!({ "client_id": "app", "app_name": "Poll App", "scopes": ["profile", "email"], "connected": true })),
            item(CONNECTION_ENTRY_TYPE, serde_json::json!({ "client_id": "gone", "app_name": "Old", "scopes": [], "connected": false })),
            item(SITE_ENTRY_TYPE, serde_json::json!({ "origin": "https://a.example", "remembered": true })),
            item("device", serde_json::json!({})),
        ]);
        assert_eq!(recorded.connections.get("app"), Some(&Some(Connection { app_name: "Poll App".into(), scopes: vec!["email".into(), "profile".into()] })));
        assert_eq!(recorded.connections.get("gone"), Some(&None));
        assert_eq!(recorded.sites.get("https://a.example"), Some(&true));
    }
}
