//! One face over the two Holochain client lines (ProofPoll 0.5.0's shape).
//!
//! While the Vault runs a 0.6.1 conductor beside a 0.7.1 one, a `Record`
//! from one line does not decode with the other line's types (the 0.7
//! action model changed the wire shape). Everything above this module
//! works with [`RecordView`], a line-free view of a record, and sends zome
//! calls through [`AppClient`], which knows which line it speaks.
//!
//! What crosses the boundary unchanged: our own entry structs (msgpack,
//! the same bytes on both lines) and hashes (39 raw bytes; the 0.6 types
//! serialize them as the same bytes the 0.7 types do, so a wire struct
//! typed with the 0.6 `ActionHash` / `AgentPubKey` is good for both lines).

use crate::commands::AppState;
use std::sync::Arc;

/// Which Holochain line a conductor speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Line {
    /// Holochain 0.6.1: private v2.0, identity 1.4, signing 1.4.
    V06,
    /// Holochain 0.7.1: private v2.1, identity 1.5, signing 1.5.
    V07,
}

impl Line {
    /// The generation name device records carry (`DeviceRecord.generation`).
    pub fn generation(self) -> &'static str {
        match self {
            Line::V06 => "holochain-0.6",
            Line::V07 => "holochain-0.7",
        }
    }
    /// The suffix on this line's per-identity files (`sealed-records.bin`
    /// for 0.6, `sealed-records-07.bin` for 0.7).
    pub fn file_suffix(self) -> &'static str {
        match self {
            Line::V06 => "",
            Line::V07 => "-07",
        }
    }
}

impl std::fmt::Display for Line {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Line::V06 => "0.6",
            Line::V07 => "0.7",
        })
    }
}

/// The line an identity's records live on now: 0.7 once the move has
/// written its marker, 0.6 before (and for every Vault that never updated).
/// The marker is the only switch; nothing else decides which line a read
/// or write goes to.
pub fn active_line(state: &AppState) -> Line {
    if crate::paths::moved_07_path(&state.identity_root()).exists() {
        Line::V07
    } else {
        Line::V06
    }
}

/// The admin and app ports of one line of the running conductor pair.
pub fn line_ports(state: &AppState, line: Line) -> Result<(u16, u16), String> {
    #[cfg(test)]
    if let Some(ports) = *state.test_conductor_ports.lock().unwrap() {
        if line == Line::V06 {
            return Ok(ports);
        }
    }
    #[cfg(test)]
    if let Some(ports) = *state.test_conductor_ports_07.lock().unwrap() {
        if line == Line::V07 {
            return Ok(ports);
        }
    }
    let handle = state.conductor_handle.lock().unwrap();
    let h = handle.as_ref().ok_or("Conductor not running")?;
    match line {
        Line::V06 => h.ports_06().ok_or_else(|| "The 0.6 line is not running".to_string()),
        Line::V07 => {
            let l = h.line_07.as_ref().ok_or("The 0.7 line is not running")?;
            Ok((l.admin_port, l.app_port))
        }
    }
}

/// An app websocket on one of the two lines.
pub enum AppClient {
    V06(holochain_client::AppWebsocket),
    V07(holochain_client_07::AppWebsocket),
}

impl AppClient {
    pub fn line(&self) -> Line {
        match self {
            AppClient::V06(_) => Line::V06,
            AppClient::V07(_) => Line::V07,
        }
    }

    /// Call a zome function. `payload` is the msgpack of the input; the
    /// result is the msgpack of the output. Errors are the client's Debug
    /// text, as the callers' substring checks expect ("chain head has
    /// moved", "zome function that doesn't exist", "nauthorized", ...).
    pub async fn call_zome(&self, role: &str, zome: &str, fn_name: &str, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        match self {
            AppClient::V06(c) => {
                use holochain_client::ZomeCallTarget;
                use holochain_types::prelude::ExternIO;
                c.call_zome(ZomeCallTarget::RoleName(role.into()), zome.into(), fn_name.into(), ExternIO::from(payload))
                    .await
                    .map(|io| io.into_vec())
                    .map_err(|e| format!("{} failed: {:?}", fn_name, e))
            }
            AppClient::V07(c) => {
                use holochain_client_07::ZomeCallTarget;
                use holochain_types_07::prelude::ExternIO;
                c.call_zome(ZomeCallTarget::RoleName(role.into()), zome.into(), fn_name.into(), ExternIO::from(payload))
                    .await
                    .map(|io| io.into_vec())
                    .map_err(|e| format!("{} failed: {:?}", fn_name, e))
            }
        }
    }
}

/// What the Vault needs from a record, whichever line produced it. Kept on
/// disk as the held-records file (serde), so the shape is a format.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RecordView {
    /// The action hash, 39 raw bytes.
    #[serde(with = "serde_bytes")]
    pub action_hash: Vec<u8>,
    /// The author's agent key, 39 raw bytes.
    #[serde(with = "serde_bytes")]
    pub author: Vec<u8>,
    /// Action timestamp, microseconds since the epoch.
    pub timestamp_us: i64,
    /// The app entry's msgpack bytes, when the record carries an entry.
    #[serde(default, with = "serde_bytes_opt")]
    pub entry: Option<Vec<u8>>,
    /// The signed action as that line encodes it (msgpack): the proof a
    /// carried record travels with.
    #[serde(with = "serde_bytes")]
    pub signed_action: Vec<u8>,
    pub line: Line,
}

/// `serde_bytes` for an `Option<Vec<u8>>`.
mod serde_bytes_opt {
    pub fn serialize<S: serde::Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&serde_bytes::Bytes::new(b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let v: Option<serde_bytes::ByteBuf> = serde::Deserialize::deserialize(d)?;
        Ok(v.map(|b| b.into_vec()))
    }
}

impl RecordView {
    /// Decode the entry as one of our own entry structs.
    pub fn entry_as<T: serde::de::DeserializeOwned>(&self) -> Result<T, String> {
        let bytes = self.entry.as_ref().ok_or("Record has no entry")?;
        rmp_serde::from_slice(bytes).map_err(|e| format!("Failed to decode entry: {}", e))
    }
}

/// Decode a zome output of `Vec<Record>` from the given line.
pub fn records(line: Line, bytes: &[u8]) -> Result<Vec<RecordView>, String> {
    match line {
        Line::V06 => {
            let recs: Vec<holochain_types::prelude::Record> =
                rmp_serde::from_slice(bytes).map_err(|e| format!("Failed to decode records (0.6): {}", e))?;
            Ok(recs.iter().map(view_06).collect())
        }
        Line::V07 => {
            let recs: Vec<holochain_types_07::prelude::Record> =
                rmp_serde::from_slice(bytes).map_err(|e| format!("Failed to decode records (0.7): {}", e))?;
            Ok(recs.iter().map(view_07).collect())
        }
    }
}

/// Decode a zome output of `Option<Record>` from the given line.
pub fn record_opt(line: Line, bytes: &[u8]) -> Result<Option<RecordView>, String> {
    match line {
        Line::V06 => {
            let rec: Option<holochain_types::prelude::Record> =
                rmp_serde::from_slice(bytes).map_err(|e| format!("Failed to decode record (0.6): {}", e))?;
            Ok(rec.as_ref().map(view_06))
        }
        Line::V07 => {
            let rec: Option<holochain_types_07::prelude::Record> =
                rmp_serde::from_slice(bytes).map_err(|e| format!("Failed to decode record (0.7): {}", e))?;
            Ok(rec.as_ref().map(view_07))
        }
    }
}

/// Decode a zome output of one `Record` from the given line.
pub fn record(line: Line, bytes: &[u8]) -> Result<RecordView, String> {
    match line {
        Line::V06 => {
            let rec: holochain_types::prelude::Record =
                rmp_serde::from_slice(bytes).map_err(|e| format!("Failed to decode record (0.6): {}", e))?;
            Ok(view_06(&rec))
        }
        Line::V07 => {
            let rec: holochain_types_07::prelude::Record =
                rmp_serde::from_slice(bytes).map_err(|e| format!("Failed to decode record (0.7): {}", e))?;
            Ok(view_07(&rec))
        }
    }
}

pub fn view_06(r: &holochain_types::prelude::Record) -> RecordView {
    RecordView {
        action_hash: r.action_address().get_raw_39().to_vec(),
        author: r.action().author().get_raw_39().to_vec(),
        timestamp_us: r.action().timestamp().as_micros(),
        entry: r.entry().as_option().and_then(|e| e.as_app_entry()).map(|a| a.as_ref().bytes().to_vec()),
        signed_action: rmp_serde::to_vec_named(r.signed_action()).unwrap_or_default(),
        line: Line::V06,
    }
}

pub fn view_07(r: &holochain_types_07::prelude::Record) -> RecordView {
    RecordView {
        action_hash: r.action_address().get_raw_39().to_vec(),
        author: r.action().author().get_raw_39().to_vec(),
        timestamp_us: r.action().timestamp().as_micros(),
        entry: r.entry().as_option().and_then(|e| e.as_app_entry()).map(|a| a.as_ref().bytes().to_vec()),
        signed_action: rmp_serde::to_vec_named(r.signed_action()).unwrap_or_default(),
        line: Line::V07,
    }
}

/// Connect to one installed app on the 0.7 line and return the app
/// websocket with the cell's cached signing credentials, plus the role
/// name (the first role whose name starts with `role_prefix`). The 0.7 twin
/// of `sealed::connect_sealed_app_ws` / `commands::connect_signing_app_ws`.
pub async fn connect_app_07(
    state: &Arc<AppState>,
    admin_port: u16,
    app_port: u16,
    app_id: &str,
    role_prefix: &str,
) -> Result<(holochain_client_07::AppWebsocket, String), String> {
    use holochain_client_07::{AdminWebsocket, AppWebsocket, CellInfo, ClientAgentSigner, IssueAppAuthenticationTokenPayload};

    let admin_ws = AdminWebsocket::connect(format!("localhost:{}", admin_port), Some(crate::conductor::node_origin()))
        .await
        .map_err(|e| format!("Admin WS connect failed (0.7): {}", e))?;
    let apps = admin_ws.list_apps(None).await.map_err(|e| format!("list_apps failed (0.7): {}", e))?;
    let app = apps
        .iter()
        .find(|a| a.installed_app_id == app_id)
        .ok_or_else(|| format!("{} is not installed on the 0.7 line", app_id))?;
    let role_name = app
        .cell_info
        .keys()
        .find(|k| k.starts_with(role_prefix))
        .ok_or_else(|| format!("No {} role in {} (0.7)", role_prefix, app_id))?
        .clone();
    let cell_id = app.cell_info[&role_name]
        .iter()
        .find_map(|c| match c {
            CellInfo::Provisioned(p) => Some(p.cell_id.clone()),
            _ => None,
        })
        .ok_or_else(|| format!("No provisioned cell in {} (0.7)", app_id))?;
    let credentials = crate::commands::cell_credentials_cached_07(state, &admin_ws, &cell_id).await?;
    let issued = admin_ws
        .issue_app_auth_token(IssueAppAuthenticationTokenPayload::for_installed_app_id(app_id.to_string()))
        .await
        .map_err(|e| format!("issue_app_auth_token failed (0.7): {}", e))?;
    let signer = ClientAgentSigner::default();
    signer.add_credentials(cell_id, credentials);
    let app_ws = AppWebsocket::connect_with_config(
        format!("localhost:{}", app_port),
        long_request_ws_config_07(),
        issued.token,
        signer.into(),
        Some(crate::conductor::node_origin()),
    )
    .await
    .map_err(|e| format!("App WS connect failed (0.7): {}", e))?;
    Ok((app_ws, role_name))
}

/// The 0.7 twin of `commands::long_request_ws_config`.
pub fn long_request_ws_config_07() -> Arc<holochain_client_07::WebsocketConfig> {
    let mut cfg = holochain_client_07::WebsocketConfig::CLIENT_DEFAULT;
    cfg.default_request_timeout = std::time::Duration::from_secs(300);
    Arc::new(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_the_same_bytes_on_both_lines() {
        let h = holochain_types::prelude::ActionHash::from_raw_32(vec![7u8; 32]);
        let h7 = holochain_types_07::prelude::ActionHash::from_raw_39(h.get_raw_39().to_vec());
        assert_eq!(h.to_string(), h7.to_string());
        // The msgpack of a hash is the same on both lines, so a wire struct
        // typed with the 0.6 hash serves the 0.7 cell too.
        assert_eq!(rmp_serde::to_vec_named(&h).unwrap(), rmp_serde::to_vec_named(&h7).unwrap());
        let k = holochain_types::prelude::AgentPubKey::from_raw_32(vec![9u8; 32]);
        let k7 = holochain_types_07::prelude::AgentPubKey::from_raw_39(k.get_raw_39().to_vec());
        assert_eq!(rmp_serde::to_vec_named(&k).unwrap(), rmp_serde::to_vec_named(&k7).unwrap());
    }

    #[test]
    fn our_structs_encode_identically_for_both_lines() {
        #[derive(serde::Serialize, Debug)]
        struct In {
            title: String,
            n: u32,
        }
        let a = holochain_types::prelude::ExternIO::encode(&In { title: "x".into(), n: 2 }).unwrap().into_vec();
        let b = holochain_types_07::prelude::ExternIO::encode(&In { title: "x".into(), n: 2 }).unwrap().into_vec();
        assert_eq!(a, b);
        assert_eq!(a, rmp_serde::to_vec_named(&In { title: "x".into(), n: 2 }).unwrap());
    }

    #[test]
    fn a_line_names_its_generation_and_files() {
        assert_eq!(Line::V06.generation(), "holochain-0.6");
        assert_eq!(Line::V07.generation(), "holochain-0.7");
        assert_eq!(Line::V06.file_suffix(), "");
        assert_eq!(Line::V07.file_suffix(), "-07");
        assert_eq!(format!("{}", Line::V07), "0.7");
    }
}
