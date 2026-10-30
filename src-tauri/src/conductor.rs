//! Holochain conductor lifecycle management.
//!
//! Manages the full startup sequence: lair-keystore → conductor → connect → install DNAs.
//! The conductor starts on vault unlock and stops on vault lock.

use crate::{dna, lair};
use lair_keystore_api::prelude::*;
use std::path::{Path, PathBuf};
use crate::process_ext::{SidecarChild, SidecarCommand};
use tauri::{Emitter, Manager};
use crate::commands::AppState;
use crate::hc::Line;
use std::sync::Arc;

/// Candidate admin WebSocket ports for the conductor.
/// Tries each in order - allows staging and production vaults to coexist.
const ADMIN_WS_PORTS: &[u16] = &[4455, 4456, 4457];

/// Candidate admin WebSocket ports for the Holochain 0.7 conductor, the
/// second line of the 1.7.0 transition. Disjoint from the 0.6 list so a
/// staging Vault beside a production one still finds two free pairs.
const ADMIN_WS_PORTS_07: &[u16] = &[4458, 4459, 4460];

/// The 0.7 line of a running Vault: lair 0.7.1 + conductor 0.7.1, holding
/// the same agent key as the 0.6 line and running identity 1.5 + signing 1.5.
/// Absent when the line could not start - the Vault keeps working on 0.6.
pub struct Line07Handle {
    pub lair_child: SidecarChild,
    pub conductor_child: SidecarChild,
    pub admin_port: u16,
    /// The app interface the Vault's zome calls on this line go through.
    pub app_port: u16,
}

impl Line07Handle {
    fn shutdown(mut self) {
        stop_line_children("0.7", &mut self.conductor_child, &mut self.lair_child);
    }
}

/// The 0.6 line: lair 0.6.3 + conductor 0.6.1, as every identity ran before
/// 1.7.0. An identity born on 1.7.0 never has one (`line_06_wanted`).
pub struct Line06Handle {
    pub lair_child: SidecarChild,
    pub conductor_child: SidecarChild,
    pub lair_client: LairClient,
    pub admin_port: u16,
    pub app_port: u16,
}

impl Line06Handle {
    fn shutdown(mut self) {
        stop_line_children("0.6", &mut self.conductor_child, &mut self.lair_child);
    }
}

/// Stop one line's conductor, then its key store: asked first, killed only
/// if still running after the grace (measured 2026-10-30: both lines'
/// conductors exit about 0.1 s after SIGTERM, lair in under 10 ms). A
/// conductor killed in the middle of a write is what a clean stop avoids.
fn stop_line_children(line: &str, conductor: &mut SidecarChild, lair: &mut SidecarChild) {
    use crate::process_ext::{stop_gracefully, StopOutcome};
    for (what, child, grace) in [("conductor", conductor, 5), ("lair-keystore", lair, 2)] {
        match stop_gracefully(child, std::time::Duration::from_secs(grace)) {
            Ok(StopOutcome::Killed) => log::warn!("The {} {} did not stop within {} s and was killed", line, what, grace),
            Ok(_) => log::info!("The {} {} stopped", line, what),
            Err(e) => log::warn!("Stopping the {} {}: {}", line, what, e),
        }
    }
}

/// Handle to the running conductor lines of one identity. Drop this to
/// stop every process. At least one line is present once a start succeeded.
pub struct ConductorHandle {
    /// The 0.6 line: the primary line of an identity that has not moved
    /// yet; attached later, when wanted, to one that has; never present for
    /// one born on 1.7.0.
    pub line_06: Option<Line06Handle>,
    /// The 0.7 line: attached from a task to an identity that has not moved
    /// yet; the primary line of one that has (or was born on 1.7.0);
    /// `None` while it starts or when it could not.
    pub line_07: Option<Line07Handle>,
    /// The line the Vault is Ready on and the watchdog watches: 0.6 until
    /// the identity's records have moved, 0.7 after (and from birth).
    pub primary: Line,
    /// The key the conductors run as (the same on both lines).
    pub agent_key_32: [u8; 32],
    /// Which start this is (see `CONDUCTOR_SESSION`).
    pub session: u64,
}

impl ConductorHandle {
    /// The 0.6 line's admin and app ports, when it runs.
    pub fn ports_06(&self) -> Option<(u16, u16)> {
        self.line_06.as_ref().map(|l| (l.admin_port, l.app_port))
    }
    pub fn admin_port_06(&self) -> Option<u16> {
        self.line_06.as_ref().map(|l| l.admin_port)
    }
    /// The admin port the Vault reports as "the conductor": the primary line's.
    pub fn primary_admin_port(&self) -> u16 {
        match self.primary {
            Line::V06 => self.line_06.as_ref().map(|l| l.admin_port),
            Line::V07 => self.line_07.as_ref().map(|l| l.admin_port),
        }
        .unwrap_or(0)
    }
    /// Whether the primary line's conductor process still runs.
    pub fn alive(&mut self) -> bool {
        match self.primary {
            Line::V06 => self.line_06.as_mut().map(|l| matches!(l.conductor_child.try_wait(), Ok(None))).unwrap_or(false),
            Line::V07 => self.line_07.as_mut().map(|l| matches!(l.conductor_child.try_wait(), Ok(None))).unwrap_or(false),
        }
    }
    /// Whether the 0.6 conductor process still runs: `None` without a 0.6 line.
    pub fn line_06_alive(&mut self) -> Option<bool> {
        self.line_06.as_mut().map(|l| matches!(l.conductor_child.try_wait(), Ok(None)))
    }
    /// Take a 0.6 line whose conductor has died out of the handle (the next
    /// devices round attaches a fresh one if it is still wanted).
    pub fn drop_dead_line_06(&mut self) {
        if let Some(line) = self.line_06.take() {
            line.shutdown();
        }
    }

    /// Whether the 0.7 conductor process still runs: `None` when there is
    /// no 0.7 line on this handle.
    pub fn line_07_alive(&mut self) -> Option<bool> {
        self.line_07.as_mut().map(|l| matches!(l.conductor_child.try_wait(), Ok(None)))
    }

    /// Take a 0.7 line whose conductor has died out of the handle (its lair
    /// is stopped with it) so a fresh one can be attached. `/status` shows
    /// the line off meanwhile.
    pub fn drop_dead_line_07(&mut self) {
        if let Some(line) = self.line_07.take() {
            line.shutdown();
        }
        set_line_07_state(Line07State::Off);
    }

    /// Graceful shutdown of every line.
    pub fn shutdown(mut self) {
        if let Some(line) = self.line_07.take() {
            line.shutdown();
        }
        set_line_07_state(Line07State::Off);
        if let Some(line) = self.line_06.take() {
            line.shutdown();
        }
    }
}

/// Whether this identity's 0.6 line should run, from local facts alone:
/// - no marker: an identity from before 1.7.0 whose records have not moved
///   yet (or a pre-1.7.0 folder restored by hand) - yes, it is the primary;
/// - born on 1.7.0 - never;
/// - the signatures of the web key it came from are not carried yet - yes;
/// - a device record it holds on 0.7 names ANOTHER device still on 0.6 -
///   yes (this device's own record, carried from 1.6.1 with the old
///   generation and not rewritten yet when the Vault closed right after the
///   move, says nothing about where this device is: it is this build);
/// - otherwise no. A restored identity that has heard nothing yet decides
///   after its first round (`move_07::line_06_wanted_now`).
/// Never from the network; the decision is written into the marker.
pub fn line_06_wanted(data_dir: &Path, data_key: Option<&[u8; 32]>, own_install_id: Option<&str>) -> bool {
    let Some(m) = crate::move_07::marker(data_dir) else { return true };
    if m.born {
        return false;
    }
    if !m.web_era_carried {
        return true;
    }
    let Some(key) = data_key else { return false };
    crate::sealed::held_devices_on_07(data_dir, key)
        .iter()
        .any(|d| d.removed_at.is_none() && d.generation != Line::V07.generation() && own_install_id.map(|me| d.install_id != me).unwrap_or(true))
}

/// Where the 0.7 line stands, for `/status` and the app. Set by the start
/// sequence and by shutdown; a Vault built without the 0.7 sidecars reports
/// `Off` with the reason in the log.
#[derive(Clone, Copy, PartialEq, Debug, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Line07State {
    Off,
    Starting,
    Serving,
}

static LINE_07_STATE: std::sync::RwLock<Line07State> = std::sync::RwLock::new(Line07State::Off);

pub fn line_07_state() -> Line07State {
    *LINE_07_STATE.read().unwrap()
}

fn set_line_07_state(state: Line07State) {
    *LINE_07_STATE.write().unwrap() = state;
}

/// Conductor status reported to the frontend.
#[derive(Clone, serde::Serialize)]
#[serde(tag = "status")]
pub enum ConductorStatus {
    #[serde(rename = "stopped")]
    Stopped,
    #[serde(rename = "starting")]
    Starting { message: String },
    #[serde(rename = "ready")]
    Ready { admin_port: u16 },
    #[serde(rename = "error")]
    Error { message: String },
}

/// Find an available admin WS port from the 0.6 candidate list.
fn find_available_admin_port() -> Result<u16, String> {
    find_available_admin_port_in(ADMIN_WS_PORTS)
}

/// Find an available admin WS port from `candidates`.
fn find_available_admin_port_in(candidates: &[u16]) -> Result<u16, String> {
    for &port in candidates {
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(_listener) => {
                // Port is free - listener is dropped here, freeing the port for the conductor.
                log::info!("Using admin WS port {}", port);
                return Ok(port);
            }
            Err(_) => {
                // After the startup sweep this is a LIVE holder: another
                // Vault (staging beside production) - or, if the log shows
                // no such Vault, a conductor that survived the sweep, which
                // means two conductors on one agent key. Worth a warning.
                log::warn!("Admin WS port {} in use, trying next", port);
            }
        }
    }
    Err(format!(
        "All admin WS ports ({:?}) are unavailable",
        candidates
    ))
}

/// A resolved network entry: where this conductor session will do peer
/// discovery (bootstrap), SBD signaling, and Iroh relay. The primary is
/// Flowsta's auth-gated server; fallbacks are OPEN community/backup
/// bootstrap-srv instances (no auth material - the gate's hook dies with
/// the primary infrastructure, so fallbacks don't gate).
#[derive(Debug, Clone, PartialEq)]
pub struct BootstrapTarget {
    pub bootstrap_url: String,
    pub signal_url: String,
    /// Standard PADDED base64 (the conductor's decoder rejects unpadded).
    pub auth_material: Option<String>,
}

impl BootstrapTarget {
    fn primary() -> Self {
        let bootstrap_url = option_env!("FLOWSTA_BOOTSTRAP_URL")
            .unwrap_or("https://bootstrap.flowsta.com")
            .to_string();
        let signal_url = option_env!("FLOWSTA_SIGNAL_URL")
            .unwrap_or("wss://bootstrap.flowsta.com")
            .to_string();
        let auth_material = match option_env!("FLOWSTA_AUTH_MATERIAL") {
            Some(m) if !m.is_empty() => Some(m.to_string()),
            _ => None,
        };
        Self { bootstrap_url, signal_url, auth_material }
    }

    /// The 0.7 line's rendezvous: a 0.7.1 conductor speaks to a kitsune2
    /// 0.5.x bootstrap, served on its own host beside the 0.6 one
    /// (`bootstrap-7.flowsta.com`; the staging build points at the staging
    /// equivalent). The same auth material gates it; the relay is derived
    /// from the host as for 0.6. `signal_url` is unused by 0.7 and kept
    /// only so the struct has one shape.
    fn primary_07() -> Self {
        let bootstrap_url = option_env!("FLOWSTA_BOOTSTRAP_URL_07")
            .unwrap_or("https://bootstrap-7.flowsta.com")
            .to_string();
        let signal_url = bootstrap_url.replacen("https://", "wss://", 1);
        let auth_material = match option_env!("FLOWSTA_AUTH_MATERIAL") {
            Some(m) if !m.is_empty() => Some(m.to_string()),
            _ => None,
        };
        Self { bootstrap_url, signal_url, auth_material }
    }

    /// Comma-separated bootstrap URLs baked at build time
    /// (FLOWSTA_BOOTSTRAP_FALLBACKS). Signal derives from each URL's host;
    /// no auth material - fallbacks are open by design.
    fn fallbacks() -> Vec<Self> {
        option_env!("FLOWSTA_BOOTSTRAP_FALLBACKS")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|u| !u.is_empty())
            // The conductor rejects plaintext relay URLs outright
            // ("Disallowed plaintext relay URL") - a non-https fallback
            // could never work, so drop it loudly at parse time.
            .filter(|u| {
                let ok = u.starts_with("https://");
                if !ok {
                    log::error!(
                        "[bootstrap] ignoring non-https fallback {} - the conductor forbids plaintext relays",
                        u
                    );
                }
                ok
            })
            .map(|u| {
                let bootstrap_url = u.trim_end_matches('/').to_string();
                let host = bootstrap_url
                    .trim_start_matches("https://")
                    .trim_start_matches("http://");
                Self {
                    bootstrap_url: bootstrap_url.clone(),
                    signal_url: format!("wss://{}", host),
                    auth_material: None,
                }
            })
            .collect()
    }
}

/// Every rendezvous this build knows, for the registration keeper
/// (`rendezvous_keeper`): Flowsta's with this app's auth material first,
/// then the open community nodes. `(bootstrap url, base64 auth material)`.
/// The rendezvous the running conductor was configured with at launch (the
/// main one, or the first fallback that answered when it was dark). The
/// registration keeper calls a stall only against this one: the conductor
/// never registers anywhere else, so a missing note on a fallback is not a
/// stall (10-19: "did not reach node1.flowsta.com" every few minutes).
static CONDUCTOR_RENDEZVOUS: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub(crate) fn conductor_rendezvous() -> Option<String> {
    CONDUCTOR_RENDEZVOUS.lock().ok().and_then(|g| g.clone())
}

fn remember_conductor_rendezvous(url: &str) {
    if let Ok(mut g) = CONDUCTOR_RENDEZVOUS.lock() {
        *g = Some(url.trim_end_matches('/').to_string());
    }
}

pub(crate) fn rendezvous_servers() -> Vec<(String, Option<String>)> {
    let primary = BootstrapTarget::primary();
    let mut servers = vec![(primary.bootstrap_url, primary.auth_material)];
    for f in BootstrapTarget::fallbacks() {
        servers.push((f.bootstrap_url, None));
    }
    servers
}

/// The 0.7 line's rendezvous: its bootstrap host (`bootstrap-7`), with the
/// auth material; the fleet's fallbacks serve the 0.6 line only.
pub(crate) fn rendezvous_servers_07() -> Vec<(String, Option<String>)> {
    let primary = BootstrapTarget::primary_07();
    vec![(primary.bootstrap_url, primary.auth_material)]
}

/// Is a bootstrap server answering? kitsune2-bootstrap-srv serves
/// GET /health directly (200, no auth) - verified against the live
/// fleet; community nodes run the same binary, so the probe is
/// universal.
async fn bootstrap_alive(url: &str) -> bool {
    let health = format!("{}/health", url.trim_end_matches('/'));
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(2500))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    matches!(client.get(&health).send().await, Ok(r) if r.status().is_success())
}

/// Pick the network entry for this conductor session. With no fallbacks
/// baked in, this returns the primary immediately - no probes, no added
/// latency, byte-identical config to before. With fallbacks configured:
/// probe the primary; if it's dark, take the first live fallback
/// (rediscovery + relay re-home happen naturally on the new server).
/// If EVERYTHING is dark (fully offline), still use the primary - the
/// conductor works locally and reconnects when anything returns.
pub async fn resolve_bootstrap_target() -> BootstrapTarget {
    let primary = BootstrapTarget::primary();
    let fallbacks = BootstrapTarget::fallbacks();
    if fallbacks.is_empty() {
        return primary;
    }
    if bootstrap_alive(&primary.bootstrap_url).await {
        return primary;
    }
    log::warn!(
        "[bootstrap] primary {} unreachable - probing {} fallback(s)",
        primary.bootstrap_url,
        fallbacks.len()
    );
    for fb in fallbacks {
        if bootstrap_alive(&fb.bootstrap_url).await {
            log::warn!(
                "[bootstrap] using OPEN fallback {} for this session",
                fb.bootstrap_url
            );
            return fb;
        }
    }
    log::warn!("[bootstrap] no rendezvous reachable - keeping primary (offline mode)");
    primary
}

/// Canonical relay URL for a bootstrap server. kitsune2/Iroh want the
/// canonical FQDN form - trailing dot on the HOSTNAME, trailing slash:
/// `https://bootstrap.flowsta.com./`. The dot belongs to the hostname,
/// so with an explicit port it goes BEFORE the colon, and IP literals
/// never get one (a dotted IP is invalid).
fn derive_relay_url(bootstrap_url: &str) -> String {
    let trimmed = bootstrap_url.trim_end_matches('/');
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((s, r)) => (s, r),
        None => return format!("{}./", trimmed.trim_end_matches('.')),
    };
    let (host, port) = match rest.rsplit_once(':') {
        // rsplit handles hostname:port; a bare IPv4 has dots not colons.
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h, Some(p)),
        _ => (rest, None),
    };
    let is_ip_literal = host
        .trim_end_matches('.')
        .chars()
        .all(|c| c.is_ascii_digit() || c == '.')
        || host.contains('[');
    let canon_host = if is_ip_literal {
        host.trim_end_matches('.').to_string()
    } else {
        format!("{}.", host.trim_end_matches('.'))
    };
    match port {
        Some(p) => format!("{}://{}:{}/", scheme, canon_host, p),
        None => format!("{}://{}/", scheme, canon_host),
    }
}

/// Generate conductor-config.yaml for the desktop app.
///
/// Holochain 0.6.1 / Iroh config format. The config is regenerated from
/// scratch on every unlock, so an existing 0.6.0 user upgrading to this
/// build picks up the Iroh format automatically - no on-disk migration.
/// Uses the lair connection URL for keystore integration.
pub fn generate_conductor_config(
    conductor_dir: &Path,
    lair_connection_url: &str,
    admin_port: u16,
    target: &BootstrapTarget,
) -> Result<PathBuf, String> {
    std::fs::create_dir_all(conductor_dir)
        .map_err(|e| format!("Failed to create conductor directory: {}", e))?;

    // URLs and auth come pre-resolved (primary vs fallback) from
    // resolve_bootstrap_target() - see BootstrapTarget above.
    let bootstrap_url = target.bootstrap_url.as_str();
    let signal_url = target.signal_url.as_str();

    // Iroh's relay is hosted by the same server as peer discovery + SBD,
    // so the relay_url is *derived* from the bootstrap URL rather than
    // carried separately - a staging build can't point its relay at
    // production by accident, and fallbacks inherit their own relay.
    let relay_url = derive_relay_url(bootstrap_url);

    // Optional auth material for bootstraps that require it (Flowsta's
    // own bootstrap once `--authentication-hook-server` is on). Same value
    // goes into both `base64_auth_material_bootstrap` and
    // `base64_auth_material_relay` because the unified bootstrap+signal+
    // relay server still treats those as independent auth flows in
    // kitsune2.
    //
    // Encoding: base64::engine::general_purpose::STANDARD (standard
    // alphabet, REQUIRED `=` padding). The Holochain conductor docstring
    // claims url-safe-no-pad but the actual decoder is STANDARD - see
    // BOOTSTRAP_AUTH_PLAN.md for the gory details.
    //
    // Empty / unset env var → field omitted from the YAML, conductor
    // talks to bootstrap anonymously (works fine until the server flips
    // to required-auth).
    let auth_lines = match &target.auth_material {
        Some(material) if !material.is_empty() => format!(
            "  base64_auth_material_bootstrap: \"{m}\"\n  base64_auth_material_relay: \"{m}\"\n",
            m = material,
        ),
        _ => String::new(),
    };

    // Path values use SINGLE-quoted YAML strings - double-quoted YAML interprets
    // backslash escapes (e.g. "C:\Users\..." reads "\U" as the start of a Unicode
    // escape and bombs out at the first non-hex character). Single-quoted strings
    // pass backslashes through verbatim. The only character that needs escaping
    // inside single quotes is the single quote itself; doubling it is the YAML
    // convention.
    let data_root = conductor_dir.display().to_string().replace('\'', "''");
    let lair_url = lair_connection_url.replace('\'', "''");

    let config = format!(
        r#"data_root_path: '{data_root}'
keystore:
  type: lair_server
  connection_url: '{lair_url}'
admin_interfaces:
- driver:
    type: websocket
    port: {admin_port}
    allowed_origins: '{node_origins}'
network:
  bootstrap_url: {bootstrap_url}
  signal_url: {signal_url}
  relay_url: {relay_url}
{auth_lines}  # Default is 60s; on a fresh install of a returning agent the local
  # cell is empty and the signing zome's get_links / get calls hit
  # kitsune2's request_timeout while the DHT is warming up, returning
  # `get_links response channel dropped: likely response timeout` to
  # the zome. 240s comfortably covers a cold-start round so the first
  # query returns data instead of needing the front-end to retry.
  request_timeout_s: 240
"#,
        data_root = data_root,
        node_origins = node_origin(),
        admin_port = admin_port,
        lair_url = lair_url,
        bootstrap_url = bootstrap_url,
        signal_url = signal_url,
        relay_url = relay_url,
        auth_lines = auth_lines,
    );

    let config_path = conductor_dir.join("conductor-config.yaml");
    write_private(&config_path, &config)
        .map_err(|e| format!("Failed to write conductor config: {}", e))?;

    log::info!("Conductor config written to {:?}", config_path);
    Ok(config_path)
}

/// How many bytes of ops one gossip exchange may offer the 0.7 conductor
/// (kitsune2's default is 100 MB). Holochain 0.7.1 checks which offered ops
/// it already holds in one database query that binds every op id three
/// times, and SQLite refuses a query past 32,766 bound values: an exchange
/// offering more than ~10.9k ids is dropped, and two devices of a large
/// identity never finish a sync (2026-10-28: the move wrote ~14k ops on each
/// device; the Mac was ten backups short for days). Each conductor's own
/// figure bounds every batch offered to it, and the smallest ops are a few
/// hundred bytes, so 1 MiB keeps a batch to a few thousand ids; a larger
/// backlog arrives over several rounds.
pub const GOSSIP_OP_BYTES_07: u32 = 1024 * 1024;

/// Generate conductor-config.yaml for the Holochain 0.7.1 conductor.
///
/// The 0.7 shape: no `signal_url` (an unknown field fails the parse),
/// `request_timeout_s` under `network`, `db_sync_level` in place of
/// `db_sync_strategy`. Same origin as the 0.6 conductor (one value per
/// Vault start, see `node_origin`), so the app's connections present one
/// name to both.
pub fn generate_conductor_config_07(
    conductor_dir: &Path,
    lair_connection_url: &str,
    admin_port: u16,
    target: &BootstrapTarget,
) -> Result<PathBuf, String> {
    std::fs::create_dir_all(conductor_dir)
        .map_err(|e| format!("Failed to create the 0.7 conductor directory: {}", e))?;
    let bootstrap_url = target.bootstrap_url.as_str();
    let relay_url = derive_relay_url(bootstrap_url);
    let auth_lines = match &target.auth_material {
        Some(material) if !material.is_empty() => format!(
            "  base64_auth_material_bootstrap: \"{m}\"\n  base64_auth_material_relay: \"{m}\"\n",
            m = material,
        ),
        _ => String::new(),
    };
    let data_root = conductor_dir.display().to_string().replace('\'', "''");
    let lair_url = lair_connection_url.replace('\'', "''");
    let config = format!(
        r#"data_root_path: '{data_root}'
keystore:
  type: lair_server
  connection_url: '{lair_url}'
admin_interfaces:
- driver:
    type: websocket
    port: {admin_port}
    allowed_origins: '{node_origins}'
network:
  bootstrap_url: {bootstrap_url}
  relay_url: {relay_url}
{auth_lines}  request_timeout_s: 240
  advanced:
    k2Gossip:
      maxGossipOpBytes: {gossip_bytes}
      maxRequestGossipOpBytes: {gossip_bytes}
db_sync_level: Normal
"#,
        data_root = data_root,
        node_origins = node_origin(),
        admin_port = admin_port,
        lair_url = lair_url,
        bootstrap_url = bootstrap_url,
        relay_url = relay_url,
        auth_lines = auth_lines,
        gossip_bytes = GOSSIP_OP_BYTES_07,
    );
    let config_path = conductor_dir.join("conductor-config.yaml");
    write_private(&config_path, &config)
        .map_err(|e| format!("Failed to write the 0.7 conductor config: {}", e))?;
    log::info!("0.7 conductor config written to {:?}", config_path);
    Ok(config_path)
}

/// The one origin the conductor's admin and app interfaces accept: a random
/// value made for each conductor start. It is written to the conductor's
/// config file, which only this OS account can read, and held here for the
/// app's own connections. A web page always presents its own address as its
/// origin, and another account on the device cannot read the file, so
/// neither can open these interfaces.
static NODE_ORIGIN: std::sync::RwLock<String> = std::sync::RwLock::new(String::new());

/// The origin this app's connections to its conductor present.
pub fn node_origin() -> String {
    NODE_ORIGIN.read().unwrap().clone()
}

/// Make a new origin for a conductor that is about to start.
fn fresh_node_origin() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let origin = format!("fv-{}", hex::encode(bytes));
    *NODE_ORIGIN.write().unwrap() = origin.clone();
    origin
}

/// The current origin, made on first use - for tests that write their own
/// conductor config.
#[cfg(test)]
pub(crate) fn node_origin_for_tests() -> String {
    let current = node_origin();
    if current.is_empty() { fresh_node_origin() } else { current }
}

/// Write a file only this OS account can read.
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    flowsta_hc_lines::files::write_private(path, contents.as_bytes())
}

/// Start the holochain conductor process.
///
/// Redirects stdout/stderr to log files to avoid pipe buffer deadlocks.
/// After spawning, briefly checks if the process exited immediately (e.g. config error)
/// and reads the log file for a useful error message.
pub fn start_conductor_process(
    config_path: &Path,
    conductor_dir: &Path,
    passphrase: &str,
) -> Result<SidecarChild, String> {
    start_conductor_process_with(config_path, conductor_dir, passphrase, "vault-holochain")
}

/// Start a conductor from the named sidecar: `vault-holochain` (0.6.1) or
/// `vault-holochain-07` (0.7.1).
pub fn start_conductor_process_with(
    config_path: &Path,
    conductor_dir: &Path,
    passphrase: &str,
    binary: &str,
) -> Result<SidecarChild, String> {
    log::info!("Starting holochain conductor ({})...", binary);

    let stdout_path = conductor_dir.join("holochain-stdout.log");
    let stderr_path = conductor_dir.join("holochain-stderr.log");
    // Keep the previous run's logs: a restart is the usual cure for a
    // network problem, and it used to erase the only evidence.
    let _ = std::fs::rename(&stdout_path, conductor_dir.join("holochain-stdout.previous.log"));
    let _ = std::fs::rename(&stderr_path, conductor_dir.join("holochain-stderr.previous.log"));

    let stdout_file = std::fs::File::create(&stdout_path)
        .map_err(|e| format!("Failed to create conductor stdout log: {}", e))?;
    let stderr_file = std::fs::File::create(&stderr_path)
        .map_err(|e| format!("Failed to create conductor stderr log: {}", e))?;

    let holochain_bin = crate::resolve_sidecar_bin(binary);
    log::info!("Using holochain binary: {:?}", holochain_bin);

    // The conductor logs nothing unless RUST_LOG is set, and its stderr file
    // is the only place a stuck cell start or a network fault explains
    // itself. Warnings by default; a developer's own RUST_LOG wins. The
    // child inherits our environment on every platform.
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "warn");
    }

    // On Windows the conductor's console is created hidden (process_ext).
    // The `0xc0000005` access violation seen on first install of the
    // signing DNA happens regardless of window state - an upstream
    // holochain bug in the WASM compile path - and the start_holochain
    // auto-restart recovers from it.
    let spawn_start = std::time::Instant::now();
    let mut child = SidecarCommand::new(&holochain_bin)
        .arg("-c")
        .arg(config_path)
        .arg("--piped")
        .stdout(stdout_file)
        .stderr(stderr_file)
        .spawn()
        .map_err(|e| format!("Failed to spawn holochain conductor: {}", e))?;

    let pid = child.id();
    log::info!(
        "[conductor:{pid}] spawned in {}ms - writing passphrase to stdin",
        spawn_start.elapsed().as_millis()
    );

    // Pipe the passphrase for lair authentication.
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(format!("{}\n", passphrase).as_bytes())
            .map_err(|e| format!("Failed to write passphrase to conductor: {}", e))?;
    }

    log::info!("[conductor:{pid}] passphrase piped - sleeping 500ms before liveness check");

    // Give the process a moment to fail on config errors, then check if it's still alive.
    std::thread::sleep(std::time::Duration::from_millis(500));
    match child.try_wait() {
        Ok(Some(status)) => {
            let output = read_conductor_logs(conductor_dir);
            Err(format!(
                "Holochain conductor exited immediately (status {}): {}",
                status, output.trim()
            ))
        }
        Ok(None) => {
            log::info!(
                "[conductor:{pid}] alive after 500ms (total {}ms since spawn)",
                spawn_start.elapsed().as_millis()
            );
            Ok(child)
        }
        Err(e) => Err(format!("Failed to check conductor process status: {}", e)),
    }
}

/// Read conductor log files (stderr first, then stdout) for error diagnostics.
/// Returns the first 500 chars of the most useful output.
fn read_conductor_logs(conductor_dir: &Path) -> String {
    let stderr_path = conductor_dir.join("holochain-stderr.log");
    let stdout_path = conductor_dir.join("holochain-stdout.log");

    let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    let stdout = std::fs::read_to_string(&stdout_path).unwrap_or_default();

    let output = if !stderr.is_empty() { stderr } else { stdout };
    // Cut on a char boundary - a byte slice panics inside a multibyte
    // character (non-ASCII profile paths in the log), and this runs
    // exactly when we are reporting a failure.
    let cut = output.char_indices().nth(500).map(|(i, _)| i).unwrap_or(output.len());
    if cut < output.len() {
        format!("{}...", &output[..cut])
    } else {
        output
    }
}

/// Wait for the conductor admin WebSocket to be ready.
/// Also monitors the conductor process - if it exits during the wait,
/// reads log files and returns immediately with the actual error.
async fn wait_for_admin_ws(
    port: u16,
    timeout_secs: u64,
    conductor_child: &mut SidecarChild,
    conductor_dir: &Path,
) -> Result<(), String> {
    let url = format!("ws://localhost:{}", port);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut attempt = 0;

    while std::time::Instant::now() < deadline {
        attempt += 1;

        // Check if conductor process is still alive.
        match conductor_child.try_wait() {
            Ok(Some(status)) => {
                let output = read_conductor_logs(conductor_dir);
                return Err(format!(
                    "Conductor exited during startup (status {}): {}",
                    status,
                    output.trim()
                ));
            }
            Ok(None) => {} // Still running - continue waiting
            Err(e) => {
                return Err(format!("Failed to check conductor process: {}", e));
            }
        }

        match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
            Ok(_) => {
                log::info!(
                    "Conductor admin WS ready on port {} (attempt {})",
                    port,
                    attempt
                );
                return Ok(());
            }
            Err(_) => {
                if attempt <= 3 {
                    log::info!(
                        "Waiting for conductor admin WS on {} (attempt {})...",
                        url,
                        attempt
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    }

    // Timed out - grab whatever logs exist for diagnostics.
    let output = read_conductor_logs(conductor_dir);
    if !output.trim().is_empty() {
        Err(format!(
            "Conductor not ready after {}s (port {}). Logs: {}",
            timeout_secs, port, output.trim()
        ))
    } else {
        Err(format!(
            "Conductor admin WS not ready after {}s on port {}",
            timeout_secs, port
        ))
    }
}

/// Public entry point. Calls `start_holochain_attempt` once, and on failure
/// kills any leftover children, briefly waits for OS resources, and retries
/// once with a fresh conductor.
///
/// This automates the manual lock+unlock recovery: on Windows, the first
/// fresh-install of identity DNA can leave the conductor in a state where
/// its WS server stops responding (the conductor process itself eventually
/// exits). The fix is the same one users were doing by hand - restart the
/// conductor. Second attempt benefits from the WASM cache the first one
/// populated on disk, so it's typically fast (<2 s of DNA work).
pub async fn start_holochain(
    app_handle: tauri::AppHandle,
    data_dir: PathBuf,
    resource_dir: PathBuf,
    passphrase: String,
    // The seed the conductor's agent runs as, and its key-store tag
    // (`vault::conductor_lair_tag`).
    conductor_seed: [u8; 32],
    conductor_tag: String,
) -> Result<(ConductorHandle, Option<LineStarter>), String> {
    // A fresh conductor session gets fresh cap grants - drop any cached
    // credentials so the readiness probe re-verifies (and re-fills) them.
    let (data_key, private_v2_seed) = {
        let state = app_handle.state::<Arc<AppState>>();
        state.cell_credentials.lock().unwrap().clear();
        state.cell_credentials_07.lock().unwrap().clear();
        let cfg = state.vault_config.lock().unwrap();
        let key: Option<[u8; 32]> = cfg.as_ref().and_then(|c| c.data_key.as_deref()).and_then(|k| k.try_into().ok());
        let seed = cfg.as_ref().and_then(|c| if c.hosting_model.as_deref() == Some("device-hosted") { c.private_network_seed.clone() } else { None });
        (key, seed)
    };
    if crate::move_07::moved(&data_dir) {
        // The identity's records are on 0.7 (moved, restored on this
        // version, or born here): the 0.7 line is the primary one, Ready
        // when it is. The 0.6 line follows from a task only when something
        // on it is still wanted (`line_06_wanted`), never for a born identity.
        let own_install_id = { let state = app_handle.state::<Arc<AppState>>(); crate::paths::install_id(&state.data_dir) };
        let wanted_06 = line_06_wanted(&data_dir, data_key.as_ref(), own_install_id.as_deref());
        crate::move_07::record_line_06_decision(&data_dir, wanted_06);
        let handle = match start_holochain_07_only(&app_handle, &data_dir, &resource_dir, &passphrase, &conductor_seed, &conductor_tag).await {
            Ok(h) => h,
            Err(e) => {
                log::warn!("[start_holochain] the 0.7 line did not start ({}) - one more try", e);
                if e.contains(lair::LAIR_STOPPED_MARKER) {
                    match lair::quarantine_lair_dir(&crate::paths::lair_dir_07(&data_dir)) {
                        Ok(moved) => log::warn!("[start_holochain] 0.7 key store set aside at {:?} - rebuilding it from the device seed", moved),
                        Err(qe) => log::error!("[start_holochain] {}", qe),
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                start_holochain_07_only(&app_handle, &data_dir, &resource_dir, &passphrase, &conductor_seed, &conductor_tag).await?
            }
        };
        let starter = wanted_06.then(|| {
            log::info!("[0.6] this identity still has something on the 0.6 line - attaching it");
            LineStarter::V06(Line06Starter { data_dir, resource_dir, passphrase, conductor_seed, conductor_tag, private_v2_seed, session: handle.session })
        });
        if starter.is_none() {
            log::info!("[0.6] not started: nothing of this identity is on the 0.6 line");
        }
        return Ok((handle, starter));
    }
    match start_holochain_attempt(
        app_handle.clone(),
        data_dir.clone(),
        resource_dir.clone(),
        passphrase.clone(),
        conductor_seed,
        conductor_tag.clone(),
    )
    .await
    {
        Ok((h, starter)) => return Ok((h, Some(LineStarter::V07(starter)))),
        Err(e) => {
            log::warn!(
                "[start_holochain] first attempt failed: {} - auto-restarting conductor",
                e,
            );
            let mut message = "Finishing first-time setup...";
            if e.contains(lair::LAIR_STOPPED_MARKER) {
                // The keystore no longer opens with the passphrase that just
                // opened the vault file (the two got out of step - e.g. a
                // vault re-saved under an old password after a change). It
                // holds nothing that cannot be rebuilt from the vault's own
                // seed, so set it aside and let the second attempt
                // re-initialize it under the working passphrase.
                match lair::quarantine_lair_dir(&crate::paths::lair_dir(&data_dir)) {
                    Ok(moved) => {
                        log::warn!("[start_holochain] key store set aside at {:?} - rebuilding it from the device seed", moved);
                        message = "Rebuilding the key store...";
                    }
                    Err(qe) => log::error!("[start_holochain] {}", qe),
                }
            }
            let _ = app_handle.emit(
                "conductor-status",
                ConductorStatus::Starting {
                    message: message.into(),
                },
            );
            // Brief pause so the admin WS port is released and any process
            // tear-down completes before the second attempt binds it.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }

    start_holochain_attempt(app_handle, data_dir, resource_dir, passphrase, conductor_seed, conductor_tag)
        .await
        .map(|(h, starter)| (h, Some(LineStarter::V07(starter))))
}

/// The line a start hands back to be attached from a task: the 0.7 line
/// beside a 0.6 primary, or the 0.6 line beside a 0.7 primary.
pub enum LineStarter {
    V06(Line06Starter),
    V07(Line07Starter),
}

/// What the 0.6 line needs to start beside a running 0.7 primary.
pub struct Line06Starter {
    data_dir: PathBuf,
    resource_dir: PathBuf,
    passphrase: String,
    conductor_seed: [u8; 32],
    conductor_tag: String,
    private_v2_seed: Option<String>,
    session: u64,
}

/// Attach whichever line a start handed back.
pub fn attach_line(state: Arc<AppState>, starter: LineStarter) {
    match starter {
        LineStarter::V07(s) => attach_line_07(state, s),
        LineStarter::V06(s) => attach_line_06(state, s),
    }
}

static ATTACHING_06: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Start the 0.6 line in the background beside a running 0.7 primary and
/// attach it. Best effort; nothing waits for it. No status messages: the
/// Vault is Ready already.
pub fn attach_line_06(state: Arc<AppState>, starter: Line06Starter) {
    if ATTACHING_06.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    tauri::async_runtime::spawn(async move {
        struct Done;
        impl Drop for Done {
            fn drop(&mut self) {
                ATTACHING_06.store(false, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let _done = Done;
        let session = starter.session;
        match start_line_06(None, &starter.data_dir, &starter.resource_dir, &starter.passphrase, &starter.conductor_seed, &starter.conductor_tag, starter.private_v2_seed.as_deref()).await {
            Ok((line, _key)) => {
                let admin_port = line.admin_port;
                let attached = {
                    let mut guard = state.conductor_handle.lock().unwrap();
                    match guard.as_mut() {
                        Some(h) if h.session == session && h.line_06.is_none() => {
                            h.line_06 = Some(line);
                            true
                        }
                        _ => {
                            let _ = tokio::task::spawn_blocking(move || line.shutdown());
                            false
                        }
                    }
                };
                if attached {
                    log::info!("Holochain 0.6 conductor attached (admin: {}) - what it still holds is carried to 0.7 each round", admin_port);
                    crate::move_07::schedule_pass(state.clone(), "the 0.6 line came up");
                } else {
                    log::info!("[0.6] the 0.6 line came up after its 0.7 line had stopped - stopped it again");
                }
            }
            Err(e) => log::warn!("[0.6] the 0.6 line did not start (the Vault runs on 0.7 alone; tried again next round): {}", e),
        }
    });
}

/// Attach the 0.6 line to the identity unlocked now, from the Vault's
/// state (the devices round found a reason: a device record naming 0.6,
/// or nothing heard yet on a restored identity).
pub fn attach_line_06_now(state: Arc<AppState>, resource_dir: PathBuf, passphrase: String, reason: &str) {
    let (conductor_seed, conductor_tag, private_v2_seed) = {
        let cfg = state.vault_config.lock().unwrap();
        let Some(cfg) = cfg.as_ref() else { return };
        let Some((seed, tag)) = crate::commands::conductor_start_params(cfg) else { return };
        let private_v2_seed = if cfg.hosting_model.as_deref() == Some("device-hosted") { cfg.private_network_seed.clone() } else { None };
        (seed, tag, private_v2_seed)
    };
    let session = match state.conductor_handle.lock().unwrap().as_ref() {
        Some(h) if h.line_06.is_none() => h.session,
        _ => return,
    };
    let data_dir = state.identity_root();
    log::info!("[0.6] attaching the 0.6 line: {}", reason);
    crate::move_07::record_line_06_decision(&data_dir, true);
    attach_line_06(state.clone(), Line06Starter { data_dir, resource_dir, passphrase, conductor_seed, conductor_tag, private_v2_seed, session });
}

/// The start of an identity born on 1.7.0: the 0.7 line alone, Ready when
/// it is. The same lair, conductor, DNA and app-interface steps
/// `attach_line_07` runs for an older identity, with the status messages
/// the 0.6 start shows.
async fn start_holochain_07_only(
    app_handle: &tauri::AppHandle,
    data_dir: &Path,
    resource_dir: &Path,
    passphrase: &str,
    conductor_seed: &[u8; 32],
    conductor_tag: &str,
) -> Result<ConductorHandle, String> {
    let _ = app_handle.emit("conductor-status", ConductorStatus::Starting { message: "Starting the key store...".into() });
    let expected_pub_key = crate::key_derivation::public_key_of_seed(conductor_seed);
    let private_v2_seed: Option<String> = {
        let state = app_handle.state::<Arc<AppState>>();
        let cfg = state.vault_config.lock().unwrap();
        cfg.as_ref().and_then(|c| if c.hosting_model.as_deref() == Some("device-hosted") { c.private_network_seed.clone() } else { None })
    };
    let target = BootstrapTarget::primary_07();
    remember_conductor_rendezvous(&target.bootstrap_url);
    fresh_node_origin();
    let _ = app_handle.emit("conductor-status", ConductorStatus::Starting { message: "Starting Holochain conductor...".into() });
    let line = start_line_07(data_dir, resource_dir, passphrase, conductor_seed, conductor_tag, &expected_pub_key, private_v2_seed.as_deref()).await?;
    {
        let state = app_handle.state::<Arc<AppState>>();
        crate::dna::ensure_cells_ready_07(line.admin_port, &state).await;
    }
    set_line_07_state(Line07State::Serving);
    let session = CONDUCTOR_SESSION.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    let _ = app_handle.emit("conductor-status", ConductorStatus::Ready { admin_port: line.admin_port });
    log::info!("Holochain 0.7 conductor ready (admin: {}, app: {}) - this identity's primary line", line.admin_port, line.app_port);
    Ok(ConductorHandle { line_06: None, line_07: Some(line), primary: Line::V07, agent_key_32: expected_pub_key, session })
}

/// One full startup attempt: lair → seed import → conductor → connect → install DNAs.
///
/// Called after vault unlock. Runs in a background task.
/// Emits Tauri events for frontend status updates.
/// Start the 0.6 line: lair 0.6.3 in `lair/`, the seed imported, the
/// 0.6.1 conductor in `conductor/`, the 0.6 DNAs, the coordinator hot-swaps,
/// the app interface. `app_handle` = the primary start, which narrates its
/// steps to the window; `None` = attached in the background beside a 0.7
/// primary, silently. Returns the line and the key it runs as.
async fn start_line_06(
    app_handle: Option<&tauri::AppHandle>,
    data_dir: &Path,
    resource_dir: &Path,
    passphrase: &str,
    conductor_seed: &[u8; 32],
    conductor_tag: &str,
    private_v2_seed: Option<&str>,
) -> Result<(Line06Handle, [u8; 32]), String> {
    macro_rules! say {
        ($status:expr) => {
            if let Some(h) = app_handle {
                let _ = h.emit("conductor-status", $status);
            }
        };
    }
    let private_v2_seed: Option<String> = private_v2_seed.map(str::to_string);
    // Emit status: starting lair
    say!(ConductorStatus::Starting {
        message: "Starting lair-keystore...".into(),
    });

    // 1. Start lair-keystore process.
    let lair_dir = crate::paths::lair_dir(&data_dir);
    let (mut lair_child, connection_url) = lair::start_lair_process(&lair_dir, &passphrase)?;

    // Helper: kill lair on error so we don't leak orphan processes.
    // Dropping a Child in Rust does NOT kill the process.
    macro_rules! fail_with_lair_cleanup {
        ($err:expr) => {{
            log::warn!("Killing lair-keystore (pid {}) due to startup failure", lair_child.id());
            let _ = lair_child.kill();
            let _ = lair_child.wait();
            return Err($err);
        }};
    }

    // 2. Wait for lair socket to be ready (watching the process - see
    // wait_for_lair_socket for why a socket file alone proves nothing).
    if let Err(e) = lair::wait_for_lair_socket(&connection_url, 15, &mut lair_child, &lair_dir).await {
        fail_with_lair_cleanup!(e);
    }

    // 3. Connect to lair. The socket FILE appears before lair is actually
    // accepting connections, so wait_for_lair_socket can pass while a connect
    // still races and gets ConnectionReset. Retry the connect (against the same
    // healthy lair process) with a short backoff before giving up - this is the
    // common cold-start failure on slower/dev machines.
    say!(ConductorStatus::Starting {
        message: "Connecting to lair-keystore...".into(),
    });
    let lair_client = match lair::connect_with_retries(&connection_url, &passphrase, &mut lair_child, &lair_dir).await {
        Ok(c) => c,
        Err(e) => fail_with_lair_cleanup!(e),
    };
    log::info!("Connected to lair-keystore");

    // 4. Import device seed (if not already imported).
    say!(ConductorStatus::Starting {
        message: "Importing device key...".into(),
    });
    let seed_pub_key = match lair::import_seed_to_lair(&lair_client, &conductor_seed, &conductor_tag)
        .await
    {
        Ok(k) => k,
        Err(e) => fail_with_lair_cleanup!(format!("Failed to import device seed into lair: {}", e)),
    };
    let pub_key_hex = hex::encode(seed_pub_key);
    log::info!("Conductor seed imported under '{}', pub key: {}", conductor_tag, pub_key_hex);

    // Convert lair Ed25519 pub key → Holochain AgentPubKey for DNA installation.
    // The conductor runs as the key the Vault gave it (the identity seed on an
    // install made before devices had their own, else this device's own
    // seed), never a key from generate_agent_pub_key().
    let agent_pub_key = holochain_types::prelude::AgentPubKey::from_raw_32(seed_pub_key.to_vec());

    // 5. Generate conductor config.
    say!(ConductorStatus::Starting {
        message: "Starting Holochain conductor...".into(),
    });
    let conductor_dir = crate::paths::conductor_dir(&data_dir);
    let admin_port = match find_available_admin_port() {
        Ok(p) => p,
        Err(e) => fail_with_lair_cleanup!(e),
    };
    let bootstrap_target = resolve_bootstrap_target().await;
    remember_conductor_rendezvous(&bootstrap_target.bootstrap_url);
    // One origin per Vault start, shared by both conductors: the primary
    // start makes it; a 0.6 line attached beside a running 0.7 primary
    // keeps the one in force. A fresh origin here left the 0.7 conductor
    // refusing every connection with 400 from that moment (an identity
    // restored by phrase on 1.7.0 whose devices round attached 0.6 a
    // minute later - the beta9 devices leg).
    if app_handle.is_some() || node_origin().is_empty() {
        fresh_node_origin();
    }
    let config_path = match generate_conductor_config(
        &conductor_dir,
        &connection_url,
        admin_port,
        &bootstrap_target,
    ) {
        Ok(p) => p,
        Err(e) => fail_with_lair_cleanup!(e),
    };

    // 6. Start conductor process (needs passphrase for lair authentication via --piped).
    let mut conductor_child = match start_conductor_process(&config_path, &conductor_dir, &passphrase) {
        Ok(c) => c,
        Err(e) => fail_with_lair_cleanup!(e),
    };

    // 7. Wait for admin WebSocket to be ready (conductor takes 5-15s).
    //    Also monitors the conductor process - returns immediately with log output if it dies.
    say!(ConductorStatus::Starting {
        message: "Waiting for conductor...".into(),
    });
    if let Err(e) = wait_for_admin_ws(admin_port, 30, &mut conductor_child, &conductor_dir).await {
        let _ = conductor_child.kill();
        let _ = conductor_child.wait();
        fail_with_lair_cleanup!(e);
    }

    // 8. Install Flowsta DNAs (idempotent - skips if already installed).
    say!(ConductorStatus::Starting {
        message: "Installing DNAs...".into(),
    });
    // Helper: kill both processes on DNA install failure.
    macro_rules! fail_with_full_cleanup {
        ($err:expr) => {{
            log::warn!("Killing conductor + lair due to DNA install failure");
            let _ = conductor_child.kill();
            let _ = conductor_child.wait();
            fail_with_lair_cleanup!($err);
        }};
    }
    let install_start = std::time::Instant::now();
    log::info!("[conductor] starting DNA install sequence");
    // Device-hosted vaults also get the encrypted private DNA v2, installed
    // with the per-user network seed from the vault config (derived from the
    // recovery phrase at setup). Custodial-linked vaults skip it.
    let install_result = dna::install_dnas(
        admin_port,
        &resource_dir,
        agent_pub_key,
        dna::BUNDLED_PRIVATE_VERSION,
        dna::BUNDLED_IDENTITY_VERSION,
        dna::BUNDLED_SIGNING_VERSION,
        private_v2_seed.as_deref(),
        &mut conductor_child,
    ).await;
    let install_elapsed = install_start.elapsed();

    // Whether install succeeded or failed, capture conductor liveness +
    // log-file growth right now. This is the critical post-mortem on Windows:
    // if holochain.exe died mid-install, we want to record that *before*
    // dropping the child (which destroys the exit status).
    let conductor_alive = matches!(conductor_child.try_wait(), Ok(None));
    let stderr_len = std::fs::metadata(conductor_dir.join("holochain-stderr.log"))
        .map(|m| m.len())
        .unwrap_or(0);
    let stdout_len = std::fs::metadata(conductor_dir.join("holochain-stdout.log"))
        .map(|m| m.len())
        .unwrap_or(0);
    log::info!(
        "[conductor] DNA install finished in {}ms (ok={}, conductor_alive={}, stderr={}B, stdout={}B)",
        install_elapsed.as_millis(),
        install_result.is_ok(),
        conductor_alive,
        stderr_len,
        stdout_len,
    );

    let installed_dnas = match install_result {
        Ok(d) => d,
        Err(e) => fail_with_full_cleanup!(format!("DNA installation failed: {}", e)),
    };
    log::info!(
        "DNAs installed: private={}, identity={}, signing={}",
        installed_dnas.private_app_id,
        installed_dnas.identity_app_id,
        installed_dnas.signing_app_id,
    );
    if let Some(v2) = &installed_dnas.private_v2_app_id {
        log::info!("Encrypted private DNA v2 active: {}", v2);
    }

    // Coordinator-only fixes don't change the DNA hash, so an existing
    // signing cell keeps running the old zome code until hot-swapped -
    // and a reset/restore reinstall reverts it to the bundle's original.
    // Applied every start; non-fatal, retried on the next one.
    if let Err(e) = dna::ensure_signing_coordinators(admin_port, &resource_dir, &data_dir).await {
        log::warn!("Signing coordinator hot-swap failed (non-fatal): {}", e);
    }
    // The private cell's coordinator likewise. When it fails the record
    // layer falls back to the functions the original coordinator has.
    if let Err(e) = dna::ensure_private_v2_coordinators(admin_port, &resource_dir).await {
        log::warn!("Private v2 coordinator hot-swap failed (non-fatal): {}", e);
    }

    // 9. Attach app interface for zome calls (e.g. pairing code generation).
    say!(ConductorStatus::Starting {
        message: "Setting up app interface...".into(),
    });
    let app_port = match dna::setup_app_interface(admin_port).await {
        Ok(p) => p,
        Err(e) => fail_with_full_cleanup!(format!("App interface setup failed: {}", e)),
    };

    // 10. Emit ready status.
    say!(ConductorStatus::Ready {
        admin_port: admin_port,
    });
    log::info!("Holochain conductor ready (admin: {}, app: {})", admin_port, app_port);

    Ok((Line06Handle { lair_child, conductor_child, lair_client, admin_port, app_port }, seed_pub_key))
}

/// One full primary start on the 0.6 line (an identity whose records have
/// not moved yet), with the 0.7 line's starter beside it.
async fn start_holochain_attempt(
    app_handle: tauri::AppHandle,
    data_dir: PathBuf,
    resource_dir: PathBuf,
    passphrase: String,
    conductor_seed: [u8; 32],
    conductor_tag: String,
) -> Result<(ConductorHandle, Line07Starter), String> {
    let private_v2_seed: Option<String> = {
        let state = app_handle.state::<Arc<AppState>>();
        let cfg = state.vault_config.lock().unwrap();
        cfg.as_ref().and_then(|c| if c.hosting_model.as_deref() == Some("device-hosted") { c.private_network_seed.clone() } else { None })
    };
    let (line, agent_key_32) = start_line_06(Some(&app_handle), &data_dir, &resource_dir, &passphrase, &conductor_seed, &conductor_tag, private_v2_seed.as_deref()).await?;
    // The 0.7 line is started by the caller from a task, AFTER this handle
    // is stored: the Vault is Ready on 0.6 the moment the 0.6 line is, and
    // nothing waits for the second line.
    let session = CONDUCTOR_SESSION.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    let starter = Line07Starter {
        data_dir,
        resource_dir,
        passphrase,
        conductor_seed,
        conductor_tag,
        expected_pub_key: agent_key_32,
        private_v2_seed,
        session,
    };
    set_line_07_state(Line07State::Starting);
    Ok((
        ConductorHandle { line_06: Some(line), line_07: None, primary: Line::V06, agent_key_32, session },
        starter,
    ))
}

/// Numbers each 0.6 conductor start, so a 0.7 line that comes up late
/// attaches only to the 0.6 line it was started for.
static CONDUCTOR_SESSION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// What the 0.7 line needs to start, handed back beside the 0.6 handle.
/// The caller stores that handle, then `attach_line_07` starts this line
/// from a task and attaches it to the same handle.
pub struct Line07Starter {
    data_dir: PathBuf,
    resource_dir: PathBuf,
    passphrase: String,
    conductor_seed: [u8; 32],
    conductor_tag: String,
    expected_pub_key: [u8; 32],
    /// The identity's private-network seed (device-hosted vaults): the 0.7
    /// private cell is installed with it, as the 0.6 one was. None for a
    /// custodial-linked vault, which has no private cell on either line.
    private_v2_seed: Option<String>,
    session: u64,
}

/// A starter for the 0.7 line of the identity that is unlocked now, from
/// the Vault's state: for the watchdog, when a 0.7 conductor died
/// mid-session and the one the start sequence made was used up.
pub fn line_07_starter_from_state(state: &AppState, resource_dir: PathBuf, passphrase: String) -> Option<Line07Starter> {
    let (conductor_seed, conductor_tag, private_v2_seed) = {
        let cfg = state.vault_config.lock().unwrap();
        let cfg = cfg.as_ref()?;
        let (seed, tag) = crate::commands::conductor_start_params(cfg)?;
        let private_v2_seed = if cfg.hosting_model.as_deref() == Some("device-hosted") { cfg.private_network_seed.clone() } else { None };
        (seed, tag, private_v2_seed)
    };
    let session = state.conductor_handle.lock().unwrap().as_ref()?.session;
    Some(Line07Starter {
        data_dir: state.identity_root(),
        resource_dir,
        passphrase,
        conductor_seed,
        conductor_tag,
        expected_pub_key: crate::key_derivation::public_key_of_seed(&conductor_seed),
        private_v2_seed,
        session,
    })
}

/// Start the 0.7 line in the background and attach it to the running 0.6
/// handle. Best effort: the Vault is Ready on 0.6 whatever happens here.
/// If the 0.6 line it belongs to is gone by the time it is up (locked,
/// restarted under a new password), the new line is stopped again.
pub fn attach_line_07(state: Arc<AppState>, starter: Line07Starter) {
    tauri::async_runtime::spawn(async move {
        let session = starter.session;
        match start_line_07(
            &starter.data_dir,
            &starter.resource_dir,
            &starter.passphrase,
            &starter.conductor_seed,
            &starter.conductor_tag,
            &starter.expected_pub_key,
            starter.private_v2_seed.as_deref(),
        )
        .await
        {
            Ok(line) => {
                let admin_port = line.admin_port;
                let app_port = line.app_port;
                let attached = {
                    let mut guard = state.conductor_handle.lock().unwrap();
                    match guard.as_mut() {
                        Some(h) if h.session == session && h.line_07.is_none() => {
                            h.line_07 = Some(line);
                            true
                        }
                        _ => {
                            let _ = tokio::task::spawn_blocking(move || line.shutdown());
                            false
                        }
                    }
                };
                if attached {
                    set_line_07_state(Line07State::Serving);
                    log::info!("Holochain 0.7 conductor ready (admin: {}, app: {})", admin_port, app_port);
                    crate::dna::ensure_cells_ready_07(admin_port, &state).await;
                    crate::move_07::schedule_pass(state.clone(), "the 0.7 line came up");
                } else {
                    set_line_07_state(Line07State::Off);
                    log::info!("[0.7] the 0.7 line came up after its 0.6 line had stopped - stopped it again");
                }
            }
            Err(e) => {
                set_line_07_state(Line07State::Off);
                log::warn!("[0.7] the 0.7 line did not start (the Vault runs on 0.6 alone): {}", e);
            }
        }
    });
}

/// Start the 0.7 line: lair 0.7.1 in `lair-07/`, the same seed imported
/// under the same tag (refused unless it yields the 0.6 line's key), the
/// 0.7.1 conductor in `conductor-07/` on a port from `ADMIN_WS_PORTS_07`,
/// then identity 1.5 + signing 1.5. Any failure kills what it started and
/// returns the reason; nothing here touches the 0.6 line.
async fn start_line_07(
    data_dir: &Path,
    resource_dir: &Path,
    passphrase: &str,
    conductor_seed: &[u8; 32],
    conductor_tag: &str,
    expected_pub_key: &[u8; 32],
    private_v2_seed: Option<&str>,
) -> Result<Line07Handle, String> {
    set_line_07_state(Line07State::Starting);
    let lair_dir = crate::paths::lair_dir_07(data_dir);
    let (mut lair_child, connection_url) =
        lair::start_lair_process_with(&lair_dir, passphrase, "vault-lair-keystore-07")?;
    macro_rules! fail_with_lair_cleanup {
        ($err:expr) => {{
            let _ = lair_child.kill();
            let _ = lair_child.wait();
            return Err($err);
        }};
    }
    if let Err(e) = lair::wait_for_lair_socket(&connection_url, 15, &mut lair_child, &lair_dir).await {
        fail_with_lair_cleanup!(e);
    }
    let lair_client = match lair::connect_with_retries_07(&connection_url, passphrase, &mut lair_child, &lair_dir).await {
        Ok(c) => c,
        Err(e) => fail_with_lair_cleanup!(e),
    };
    let pub_key = match lair::import_seed_to_lair_07(&lair_client, conductor_seed, conductor_tag).await {
        Ok(k) => k,
        Err(e) => fail_with_lair_cleanup!(format!("seed import into the 0.7 key store failed: {}", e)),
    };
    if &pub_key != expected_pub_key {
        fail_with_lair_cleanup!("the 0.7 key store derived a different key from the same seed".to_string());
    }
    drop(lair_client);

    let conductor_dir = crate::paths::conductor_dir_07(data_dir);
    let admin_port = match find_available_admin_port_in(ADMIN_WS_PORTS_07) {
        Ok(p) => p,
        Err(e) => fail_with_lair_cleanup!(e),
    };
    let target = BootstrapTarget::primary_07();
    let config_path = match generate_conductor_config_07(&conductor_dir, &connection_url, admin_port, &target) {
        Ok(p) => p,
        Err(e) => fail_with_lair_cleanup!(e),
    };
    let mut conductor_child =
        match start_conductor_process_with(&config_path, &conductor_dir, passphrase, "vault-holochain-07") {
            Ok(c) => c,
            Err(e) => fail_with_lair_cleanup!(e),
        };
    macro_rules! fail_with_full_cleanup {
        ($err:expr) => {{
            let _ = conductor_child.kill();
            let _ = conductor_child.wait();
            fail_with_lair_cleanup!($err);
        }};
    }
    if let Err(e) = wait_for_admin_ws(admin_port, 30, &mut conductor_child, &conductor_dir).await {
        fail_with_full_cleanup!(e);
    }
    match dna::install_dnas_07(admin_port, resource_dir, &pub_key[..], private_v2_seed).await {
        Ok(apps) => log::info!("[0.7] apps: {}", apps.join(", ")),
        Err(e) => fail_with_full_cleanup!(format!("0.7 DNA installation failed: {}", e)),
    }
    // Non-fatal, like the 0.6 line's: retried at the next start.
    if let Err(e) = dna::ensure_signing_coordinators_07(admin_port, resource_dir).await {
        log::warn!("[0.7] signing coordinator hot-swap failed (non-fatal): {}", e);
    }
    let app_port = match dna::setup_app_interface_07(admin_port).await {
        Ok(p) => p,
        Err(e) => fail_with_full_cleanup!(format!("0.7 app interface setup failed: {}", e)),
    };
    Ok(Line07Handle { lair_child, conductor_child, admin_port, app_port })
}

#[cfg(test)]
mod bootstrap_target_tests {
    #[test]
    fn every_connection_to_the_conductor_presents_the_current_origin() {
        // No connection may carry a fixed origin name: the conductor accepts
        // only the value made for this start.
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let fixed = ["Some(", "\"flowsta-vault"].concat();
        let mut uses = 0;
        for entry in std::fs::read_dir(&src).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(!text.contains(&fixed), "{} connects under a fixed origin name", path.display());
            // Every websocket connection in the file presents the current
            // origin (a name handed to a helper that connects with it is
            // caught here: the helper then presents something else).
            let connects = text.matches("Websocket::connect").count();
            let presented = text.matches("crate::conductor::node_origin()").count();
            assert!(presented >= connects, "{}: {} connections, {} present the current origin", path.display(), connects, presented);
            uses += text.matches("Some(crate::conductor::node_origin())").count();
        }
        assert!(uses >= 10, "expected to find the app's connections, found {}", uses);
    }

    #[test]
    fn the_conductor_config_carries_a_fresh_origin_only_this_account_can_read() {
        let dir = std::env::temp_dir().join(format!("fv-origins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A config left by an earlier version, readable by everyone.
        std::fs::write(dir.join("conductor-config.yaml"), "old").unwrap();
        let target = super::BootstrapTarget { bootstrap_url: "https://example.test".into(), signal_url: "wss://example.test".into(), auth_material: None };
        super::fresh_node_origin();
        let path = super::generate_conductor_config(&dir, "unix:///tmp/x?k=y", 4455, &target).unwrap();
        let first = super::node_origin();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("allowed_origins: '*'"));
        assert!(first.starts_with("fv-") && first.len() == 35);
        assert!(text.contains(&format!("allowed_origins: '{}'", first)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // The 0.7 conductor's config carries the same origin as the 0.6 one.
        let path_07 = super::generate_conductor_config_07(&dir.join("07"), "unix:///tmp/x7?k=y", 4458, &target).unwrap();
        let text_07 = std::fs::read_to_string(&path_07).unwrap();
        assert!(text_07.contains(&format!("allowed_origins: '{}'", first)));
        // The next start gets another one.
        super::fresh_node_origin();
        super::generate_conductor_config(&dir, "unix:///tmp/x?k=y", 4455, &target).unwrap();
        assert_ne!(super::node_origin(), first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;

    #[test]
    fn relay_derivation_handles_ports_and_ips() {
        assert_eq!(
            derive_relay_url("https://bootstrap.flowsta.com"),
            "https://bootstrap.flowsta.com./"
        );
        assert_eq!(
            derive_relay_url("https://node1.example.com/"),
            "https://node1.example.com./"
        );
        assert_eq!(
            derive_relay_url("http://node1.example.com:18080"),
            "http://node1.example.com.:18080/"
        );
        assert_eq!(
            derive_relay_url("http://192.168.1.3:18080"),
            "http://192.168.1.3:18080/"
        );
    }

    #[test]
    fn fallback_target_config_omits_auth_and_derives_relay() {
        let dir = std::env::temp_dir().join("flowsta-test-conductor-fb");
        let _ = std::fs::remove_dir_all(&dir);
        let target = BootstrapTarget {
            bootstrap_url: "https://node1.example.com".into(),
            signal_url: "wss://node1.example.com".into(),
            auth_material: None,
        };
        let path = generate_conductor_config(&dir, "unix:///tmp/lair", 4444, &target).unwrap();
        let cfg = std::fs::read_to_string(path).unwrap();
        assert!(cfg.contains("bootstrap_url: https://node1.example.com"));
        assert!(cfg.contains("relay_url: https://node1.example.com./"));
        assert!(
            !cfg.contains("auth_material"),
            "open fallbacks must not carry auth material"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_07_config_has_the_07_shape() {
        let dir = std::env::temp_dir().join("flowsta-test-conductor-07");
        let _ = std::fs::remove_dir_all(&dir);
        let target = BootstrapTarget {
            bootstrap_url: "https://bootstrap-7.example.com".into(),
            signal_url: "wss://bootstrap-7.example.com".into(),
            auth_material: Some("eyJmb28iOiJiYXIifQ==".into()),
        };
        let path = generate_conductor_config_07(&dir, "unix:///tmp/lair07", 4458, &target).unwrap();
        let cfg = std::fs::read_to_string(path).unwrap();
        assert!(cfg.contains("bootstrap_url: https://bootstrap-7.example.com"));
        assert!(cfg.contains("relay_url: https://bootstrap-7.example.com./"));
        assert!(!cfg.contains("signal_url"), "0.7 rejects signal_url");
        assert!(cfg.contains("  request_timeout_s: 240"), "request_timeout_s belongs under network in 0.7");
        assert!(cfg.contains("db_sync_level: Normal"));
        assert!(!cfg.contains("db_sync_strategy"));
        // The gossip cap sits under network.advanced.k2Gossip (kitsune2's
        // module config, camelCase keys), one level below request_timeout_s.
        assert!(
            cfg.contains("  request_timeout_s: 240\n  advanced:\n    k2Gossip:\n      maxGossipOpBytes: 1048576\n      maxRequestGossipOpBytes: 1048576\ndb_sync_level: Normal"),
            "the gossip cap belongs under network.advanced.k2Gossip: {cfg}"
        );
        assert!(cfg.contains("base64_auth_material_relay: \"eyJmb28iOiJiYXIifQ==\""));
        assert!(cfg.contains("port: 4458"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_07_ports_never_overlap_the_06_ports() {
        for p in ADMIN_WS_PORTS_07 {
            assert!(!ADMIN_WS_PORTS.contains(p));
        }
    }

    #[test]
    fn primary_target_config_carries_auth_material() {
        let dir = std::env::temp_dir().join("flowsta-test-conductor-pri");
        let _ = std::fs::remove_dir_all(&dir);
        let target = BootstrapTarget {
            bootstrap_url: "https://bootstrap.example.com".into(),
            signal_url: "wss://bootstrap.example.com".into(),
            auth_material: Some("eyJmb28iOiJiYXIifQ==".into()),
        };
        let path = generate_conductor_config(&dir, "unix:///tmp/lair", 4444, &target).unwrap();
        let cfg = std::fs::read_to_string(path).unwrap();
        assert!(cfg.contains("base64_auth_material_bootstrap: \"eyJmb28iOiJiYXIifQ==\""));
        assert!(cfg.contains("base64_auth_material_relay: \"eyJmb28iOiJiYXIifQ==\""));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
