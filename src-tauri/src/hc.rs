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

pub use flowsta_hc_lines::{Line, RecordView};

/// The suffix on this line's per-identity files (`sealed-records.bin` for
/// 0.6, `sealed-records-07.bin` for 0.7): a Vault naming, not the library's.
pub trait LineFiles {
    fn file_suffix(self) -> &'static str;
}

impl LineFiles for Line {
    fn file_suffix(self) -> &'static str {
        match self {
            Line::V06 => "",
            Line::V07 => "-07",
        }
    }
}

/// The line an identity's records live on now: 0.7 once the move has
/// written its marker, 0.6 before (and for every Vault that never updated).
/// The marker is the only switch; nothing else decides which line a read
/// or write goes to.
pub fn active_line(state: &AppState) -> Line {
    if crate::move_07::moved(&state.identity_root()) {
        Line::V07
    } else {
        Line::V06
    }
}

/// The admin and app ports of one line of the running conductor pair.
pub fn line_ports(state: &AppState, line: Line) -> Result<(u16, u16), String> {
    // Only the tests' port overrides read the state; the lines are the supervisor's.
    #[cfg(not(test))]
    let _ = state;
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
    let sup = crate::conductor::supervisor();
    sup.session().ok_or("Conductor not running")?;
    match line {
        Line::V06 => sup.ports(Line::V06).ok_or_else(|| "The 0.6 line is not running".to_string()),
        Line::V07 => sup.ports(Line::V07).ok_or_else(|| "The 0.7 line is not running".to_string()),
    }
}

/// An app websocket on one of the two lines; a failed call is a
/// [`ZomeCallError`] whose kind callers decide on (its text is the text
/// callers searched before).
pub use flowsta_hc_lines::{AppClient, ZomeCallError, ZomeErrorKind};

/// Decode a zome output of `Vec<Record>` from the given line.
pub fn records(line: Line, bytes: &[u8]) -> Result<Vec<RecordView>, String> {
    Ok(flowsta_hc_lines::records(line, bytes)?)
}

/// Decode a zome output of `Option<Record>` from the given line.
pub fn record_opt(line: Line, bytes: &[u8]) -> Result<Option<RecordView>, String> {
    Ok(flowsta_hc_lines::record_opt(line, bytes)?)
}

/// Decode a zome output of one `Record` from the given line.
pub fn record(line: Line, bytes: &[u8]) -> Result<RecordView, String> {
    Ok(flowsta_hc_lines::record(line, bytes)?)
}

pub fn view_06(r: &holochain_types::prelude::Record) -> Result<RecordView, String> {
    Ok(flowsta_hc_lines::view_06(r)?)
}

pub fn view_07(r: &holochain_types_07::prelude::Record) -> Result<RecordView, String> {
    Ok(flowsta_hc_lines::view_07(r)?)
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
    fn a_line_names_its_generation_and_files() {
        assert_eq!(Line::V06.generation(), "holochain-0.6");
        assert_eq!(Line::V07.generation(), "holochain-0.7");
        assert_eq!(Line::V06.file_suffix(), "");
        assert_eq!(Line::V07.file_suffix(), "-07");
        assert_eq!(format!("{}", Line::V07), "0.7");
    }
}
