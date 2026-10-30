//! Holochain conductor lifecycle management.
//!
//! Manages the full startup sequence: lair-keystore → conductor → connect → install DNAs.
//! The conductor starts on vault unlock and stops on vault lock.

use crate::{dna, lair};
use std::path::{Path, PathBuf};
use tauri::{Emitter, Manager};
use crate::commands::AppState;
use crate::hc::Line;
use std::sync::Arc;
use flowsta_hc_lines::conductor::NetworkTuning;
use flowsta_hc_lines::rendezvous::Rendezvous;
use flowsta_hc_lines::supervisor::{self, KeySource, LineHooks, LineProcess, LineStart, LineState, Role, StartStep, Supervisor, Timeouts};

/// Candidate admin WebSocket ports for the conductor.
/// Tries each in order - allows staging and production vaults to coexist.
const ADMIN_WS_PORTS: &[u16] = &[4455, 4456, 4457];

/// Candidate admin WebSocket ports for the Holochain 0.7 conductor, the
/// second line of the 1.7.0 transition. Disjoint from the 0.6 list so a
/// staging Vault beside a production one still finds two free pairs.
const ADMIN_WS_PORTS_07: &[u16] = &[4458, 4459, 4460];

/// The running lines of the unlocked identity (flowsta-hc-lines
/// `Supervisor`): the 0.6 line (lair 0.6.3 + conductor 0.6.1, as every
/// identity ran before 1.7.0; never for one born on 1.7.0) and the 0.7 line
/// (lair 0.7.1 + conductor 0.7.1, the same agent key). The primary line is
/// the one the Vault is Ready on and the watchdog watches: 0.6 until the
/// identity's records have moved, 0.7 after (and from birth). The other
/// line joins from a task, only the session it was started for. One per
/// Vault, so every connection presents the same origin.
static SUPERVISOR: std::sync::LazyLock<Arc<Supervisor>> = std::sync::LazyLock::new(|| Arc::new(Supervisor::new("fv")));

pub fn supervisor() -> &'static Arc<Supervisor> {
    &SUPERVISOR
}

/// Stop every line of the unlocked identity (blocking: each process gets
/// its grace before it is killed). Returns whether any session ran.
pub fn stop_all_lines() -> bool {
    supervisor().stop()
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
    /// This target as flowsta-hc-lines names a rendezvous.
    fn rendezvous(&self) -> Rendezvous {
        Rendezvous {
            bootstrap_url: self.bootstrap_url.clone(),
            signal_url: Some(self.signal_url.clone()),
            auth_material: self.auth_material.clone(),
        }
    }

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

/// The Vault's network settings per line. kitsune2's request timeout is
/// 240 s (its default 60 s): on a fresh install of a returning agent the
/// local cell is empty, and the signing zome's first `get_links` / `get`
/// calls time out while the DHT warms up. On 0.7: the library's gossip cap
/// (`flowsta_hc_lines::conductor::GOSSIP_OP_BYTES_07`) and
/// `db_sync_level: Normal`.
fn vault_tuning(line: Line) -> NetworkTuning {
    let mut t = NetworkTuning::for_line(line);
    t.request_timeout_s = Some(240);
    if line == Line::V07 {
        t.db_sync_level = Some("Normal".into());
    }
    t
}

#[cfg(test)]
/// Write a line's conductor-config.yaml (flowsta-hc-lines), regenerated on
/// every unlock: the relay is derived from the bootstrap's host, the auth
/// material (when set) goes to both bootstrap and relay, the origin is this
/// start's.
fn write_conductor_config(line: Line, conductor_dir: &Path, lair_connection_url: &str, admin_port: u16, target: &BootstrapTarget) -> Result<PathBuf, String> {
    let origin = node_origin();
    let rendezvous = target.rendezvous();
    let tuning = vault_tuning(line);
    Ok(flowsta_hc_lines::conductor::write_config(&flowsta_hc_lines::conductor::ConfigInput {
        line,
        conductor_dir,
        lair_url: lair_connection_url,
        admin_port,
        origin: &origin,
        rendezvous: &rendezvous,
        tuning: &tuning,
    })?)
}

#[cfg(test)]
/// The 0.6 conductor's config.
pub fn generate_conductor_config(conductor_dir: &Path, lair_connection_url: &str, admin_port: u16, target: &BootstrapTarget) -> Result<PathBuf, String> {
    write_conductor_config(Line::V06, conductor_dir, lair_connection_url, admin_port, target)
}

#[cfg(test)]
/// The 0.7 conductor's config: no `signal_url` (an unknown field fails the
/// parse), the gossip cap, `db_sync_level`.
pub fn generate_conductor_config_07(conductor_dir: &Path, lair_connection_url: &str, admin_port: u16, target: &BootstrapTarget) -> Result<PathBuf, String> {
    write_conductor_config(Line::V07, conductor_dir, lair_connection_url, admin_port, target)
}

/// The one origin the conductor's admin and app interfaces accept: a random
/// value made for each conductor start (the supervisor's). It is written to
/// the conductor's config file, which only this OS account can read, and
/// held for the app's own connections. A web page always presents its own
/// address as its origin, and another account on the device cannot read the
/// file, so neither can open these interfaces.
pub fn node_origin() -> String {
    supervisor().origin()
}

/// Make a new origin for a conductor that is about to start.
fn fresh_node_origin() -> String {
    supervisor().fresh_origin()
}

/// The current origin, made on first use - for tests that write their own
/// conductor config.
#[cfg(test)]
pub(crate) fn node_origin_for_tests() -> String {
    supervisor().origin_or_fresh()
}

/// The status line the window shows for each step of a line's start.
fn step_message(step: StartStep) -> &'static str {
    match step {
        StartStep::KeyStore => "Starting lair-keystore...",
        StartStep::Connect => "Connecting to lair-keystore...",
        StartStep::Agents => "Importing device key...",
        StartStep::Conductor => "Starting Holochain conductor...",
        StartStep::WaitAdmin => "Waiting for conductor...",
        _ => "Starting...",
    }
}

/// Start one line's key store and conductor (flowsta-hc-lines
/// `start_line`): the device seed imported under its tag, the line's own
/// sidecars, folders and admin ports, this start's origin. A failure stops
/// what was started; the error is in the Vault's words.
async fn start_vault_line(
    line: Line,
    data_dir: &Path,
    passphrase: &str,
    conductor_seed: &[u8; 32],
    conductor_tag: &str,
    target: &BootstrapTarget,
    on_step: impl FnMut(StartStep) + Send,
) -> Result<LineProcess, String> {
    let (lair_name, conductor_name, lair_dir, conductor_dir, admin_ports) = match line {
        Line::V06 => ("vault-lair-keystore", "vault-holochain", crate::paths::lair_dir(data_dir), crate::paths::conductor_dir(data_dir), ADMIN_WS_PORTS),
        Line::V07 => ("vault-lair-keystore-07", "vault-holochain-07", crate::paths::lair_dir_07(data_dir), crate::paths::conductor_dir_07(data_dir), ADMIN_WS_PORTS_07),
    };
    let lair_bin = crate::resolve_sidecar_bin(lair_name);
    let conductor_bin = crate::resolve_sidecar_bin(conductor_name);
    let origin = node_origin();
    let rendezvous = target.rendezvous();
    let tuning = vault_tuning(line);
    let agents = [KeySource::Seed { seed: *conductor_seed, tag: conductor_tag.to_string() }];
    supervisor::start_line(
        &LineStart {
            line,
            lair_bin: &lair_bin,
            conductor_bin: &conductor_bin,
            lair_dir: &lair_dir,
            conductor_dir: &conductor_dir,
            passphrase,
            sockets: &crate::paths::socket_plan(),
            admin_ports,
            origin: &origin,
            rendezvous: &rendezvous,
            tuning: &tuning,
            agents: &agents,
            timeouts: Timeouts::default(),
        },
        on_step,
    )
    .await
    .map_err(|e| lair::start_error_text(e, line))
}

/// Start the unlocked identity's lines through flowsta-hc-lines
/// (`Supervisor::start_lines`): the primary first, Ready when it is, the
/// other from a task; nothing waits for the second line.
/// - Records on 0.7 (moved, restored on this version, or born here): 0.7 is
///   the primary; the 0.6 line follows only when something on it is still
///   wanted (`line_06_wanted`), never for a born identity.
/// - Otherwise 0.6 is the primary and the 0.7 line follows.
///
/// The primary gets one retry (`VaultLines::before_retry`). That automates
/// the manual lock+unlock recovery: on Windows the first install of the
/// identity DNA can leave the conductor's websocket unresponsive, and the
/// second attempt reuses the wasm cache the first one filled. Returns the
/// session.
pub async fn start_holochain(
    app_handle: tauri::AppHandle,
    data_dir: PathBuf,
    resource_dir: PathBuf,
    passphrase: String,
    // The seed the conductor's agent runs as, and its key-store tag
    // (`vault::conductor_lair_tag`).
    conductor_seed: [u8; 32],
    conductor_tag: String,
) -> Result<u64, String> {
    let state = app_handle.state::<Arc<AppState>>().inner().clone();
    // A fresh conductor session gets fresh cap grants - drop any cached
    // credentials so the readiness probe re-verifies (and re-fills) them.
    let (data_key, private_v2_seed) = {
        state.cell_credentials.lock().unwrap().clear();
        state.cell_credentials_07.lock().unwrap().clear();
        let cfg = state.vault_config.lock().unwrap();
        let key: Option<[u8; 32]> = cfg.as_ref().and_then(|c| c.data_key.as_deref()).and_then(|k| k.try_into().ok());
        let seed = cfg.as_ref().and_then(|c| if c.hosting_model.as_deref() == Some("device-hosted") { c.private_network_seed.clone() } else { None });
        (key, seed)
    };
    let (primary, secondary) = if crate::move_07::moved(&data_dir) {
        let own_install_id = crate::paths::install_id(&state.data_dir);
        let wanted_06 = line_06_wanted(&data_dir, data_key.as_ref(), own_install_id.as_deref());
        crate::move_07::record_line_06_decision(&data_dir, wanted_06);
        if wanted_06 {
            log::info!("[0.6] this identity still has something on the 0.6 line - attaching it");
        } else {
            log::info!("[0.6] not started: nothing of this identity is on the 0.6 line");
        }
        (Line::V07, wanted_06.then_some(Line::V06))
    } else {
        (Line::V06, Some(Line::V07))
    };
    let hooks = Arc::new(VaultLines {
        app: Some(app_handle),
        state: Some(state),
        data_dir,
        resource_dir,
        passphrase,
        expected_pub_key: crate::key_derivation::public_key_of_seed(&conductor_seed),
        conductor_seed,
        conductor_tag,
        private_v2_seed,
    });
    supervisor().start_lines(primary, secondary, hooks).await
}

/// Start `line` beside the running primary and attach it to the current
/// session, from the Vault's state: the watchdog after a 0.7 conductor died,
/// the devices round when the 0.6 line is wanted again (a device record
/// naming 0.6, or nothing heard yet on a restored identity).
pub fn attach_line_from_state(state: Arc<AppState>, line: Line, resource_dir: PathBuf, passphrase: String, reason: &str) -> Result<(), String> {
    let (conductor_seed, conductor_tag, private_v2_seed) = {
        let cfg = state.vault_config.lock().unwrap();
        let cfg = cfg.as_ref().ok_or("vault config not available")?;
        let (seed, tag) = crate::commands::conductor_start_params(cfg).ok_or("no conductor seed in the vault config")?;
        let private_v2_seed = if cfg.hosting_model.as_deref() == Some("device-hosted") { cfg.private_network_seed.clone() } else { None };
        (seed, tag, private_v2_seed)
    };
    let session = supervisor().session().ok_or("no conductor session")?;
    if supervisor().has(line) {
        return Ok(());
    }
    let data_dir = state.identity_root();
    log::info!("[{}] attaching the {} line: {}", line, line, reason);
    if line == Line::V06 {
        crate::move_07::record_line_06_decision(&data_dir, true);
    }
    let hooks = Arc::new(VaultLines {
        app: None,
        state: Some(state),
        data_dir,
        resource_dir,
        passphrase,
        expected_pub_key: crate::key_derivation::public_key_of_seed(&conductor_seed),
        conductor_seed,
        conductor_tag,
        private_v2_seed,
    });
    supervisor().attach_line(session, line, hooks);
    Ok(())
}

/// What the Vault's lines need (flowsta-hc-lines `LineHooks`): the identity's
/// folders, the device seed and its tag, the bundled DNAs, and the window to
/// narrate the primary's start to.
struct VaultLines {
    /// The window, for the primary's status messages; None for a line
    /// attached in the background, which starts silently.
    app: Option<tauri::AppHandle>,
    state: Option<Arc<AppState>>,
    data_dir: PathBuf,
    resource_dir: PathBuf,
    passphrase: String,
    conductor_seed: [u8; 32],
    conductor_tag: String,
    /// The key the seed derives: both lines must run as it.
    expected_pub_key: [u8; 32],
    /// The identity's private-network seed (device-hosted vaults): each
    /// line's private cell is installed with it. None for a custodial-linked
    /// vault, which has no private cell on either line.
    private_v2_seed: Option<String>,
}

impl VaultLines {
    fn emit(&self, role: Role, status: ConductorStatus) {
        if role == Role::Primary {
            if let Some(app) = &self.app {
                let _ = app.emit("conductor-status", status);
            }
        }
    }

    fn say(&self, role: Role, message: &str) {
        self.emit(role, ConductorStatus::Starting { message: message.into() });
    }

    /// The 0.6 line's DNAs (private v2.0 for a device-hosted vault, identity
    /// 1.3/1.4, signing 1.4), the coordinator hot-swaps, the app interface.
    async fn setup_06(&self, role: Role, process: &mut LineProcess) -> Result<u16, String> {
        macro_rules! say {
            ($status:expr) => {
                self.emit(role, $status)
            };
        }
        let seed_pub_key = process.agents[0];
        log::info!("Conductor seed imported under '{}', pub key: {}", self.conductor_tag, hex::encode(seed_pub_key));
        let admin_port = process.admin_port;
        let conductor_dir = process.conductor_dir.clone();

        // Convert lair Ed25519 pub key → Holochain AgentPubKey for DNA installation.
        // The conductor runs as the key the Vault gave it (the identity seed on an
        // install made before devices had their own, else this device's own
        // seed), never a key from generate_agent_pub_key().
        let agent_pub_key = holochain_types::prelude::AgentPubKey::from_raw_32(seed_pub_key.to_vec());

        // 8. Install Flowsta DNAs (idempotent - skips if already installed).
        say!(ConductorStatus::Starting {
            message: "Installing DNAs...".into(),
        });
        // A failure returns the reason; the supervisor stops both processes.
        macro_rules! fail_and_stop {
            ($err:expr) => {{
                return Err($err);
            }};
        }
        let install_start = std::time::Instant::now();
        log::info!("[conductor] starting DNA install sequence");
        // Device-hosted vaults also get the encrypted private DNA v2, installed
        // with the per-user network seed from the vault config (derived from the
        // recovery phrase at setup). Custodial-linked vaults skip it.
        let install_result = dna::install_dnas(
            admin_port,
            &self.resource_dir,
            agent_pub_key,
            dna::BUNDLED_PRIVATE_VERSION,
            dna::BUNDLED_IDENTITY_VERSION,
            dna::BUNDLED_SIGNING_VERSION,
            self.private_v2_seed.as_deref(),
            &mut process.conductor,
        ).await;
        let install_elapsed = install_start.elapsed();

        // Whether install succeeded or failed, capture conductor liveness +
        // log-file growth right now. This is the critical post-mortem on Windows:
        // if holochain.exe died mid-install, we want to record that *before*
        // the process is stopped (which destroys the exit status).
        let conductor_alive = process.conductor_alive();
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
            Err(e) => fail_and_stop!(format!("DNA installation failed: {}", e)),
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
        if let Err(e) = dna::ensure_signing_coordinators(admin_port, &self.resource_dir, &self.data_dir).await {
            log::warn!("Signing coordinator hot-swap failed (non-fatal): {}", e);
        }
        // The private cell's coordinator likewise. When it fails the record
        // layer falls back to the functions the original coordinator has.
        if let Err(e) = dna::ensure_private_v2_coordinators(admin_port, &self.resource_dir).await {
            log::warn!("Private v2 coordinator hot-swap failed (non-fatal): {}", e);
        }

        // 9. Attach app interface for zome calls (e.g. pairing code generation).
        say!(ConductorStatus::Starting {
            message: "Setting up app interface...".into(),
        });
        let app_port = match dna::setup_app_interface(admin_port).await {
            Ok(p) => p,
            Err(e) => fail_and_stop!(format!("App interface setup failed: {}", e)),
        };

        log::info!("Holochain conductor ready (admin: {}, app: {})", admin_port, app_port);
        Ok(app_port)
    }

    /// The 0.7 line: the same key as the seed derives (refused otherwise),
    /// identity 1.5 + signing 1.5 (+ private v2.1), the signing coordinator
    /// hot-swap, the app interface. As the primary it waits for its cells
    /// before the Vault says Ready.
    async fn setup_07(&self, role: Role, process: &mut LineProcess) -> Result<u16, String> {
        let pub_key = process.agents[0];
        if pub_key != self.expected_pub_key {
            return Err("the 0.7 key store derived a different key from the same seed".to_string());
        }
        let admin_port = process.admin_port;
        match dna::install_dnas_07(admin_port, &self.resource_dir, &pub_key[..], self.private_v2_seed.as_deref()).await {
            Ok(apps) => log::info!("[0.7] apps: {}", apps.join(", ")),
            Err(e) => return Err(format!("0.7 DNA installation failed: {}", e)),
        }
        // Non-fatal, like the 0.6 line's: retried at the next start.
        if let Err(e) = dna::ensure_signing_coordinators_07(admin_port, &self.resource_dir).await {
            log::warn!("[0.7] signing coordinator hot-swap failed (non-fatal): {}", e);
        }
        let app_port = dna::setup_app_interface_07(admin_port).await.map_err(|e| format!("0.7 app interface setup failed: {}", e))?;
        if role == Role::Primary {
            if let Some(state) = &self.state {
                crate::dna::ensure_cells_ready_07(admin_port, state).await;
            }
        }
        Ok(app_port)
    }
}

#[async_trait::async_trait]
impl LineHooks for VaultLines {
    async fn start(&self, line: Line, role: Role) -> Result<LineProcess, String> {
        let primary = role == Role::Primary;
        match line {
            Line::V06 => {
                // The network entry for this session: Flowsta's, or the first
                // live fallback while it is dark (see `resolve_bootstrap_target`).
                let target = resolve_bootstrap_target().await;
                remember_conductor_rendezvous(&target.bootstrap_url);
                // One origin per Vault start, shared by both conductors: the
                // primary start makes it; a 0.6 line attached beside a running
                // 0.7 primary keeps the one in force. A fresh origin here left
                // the 0.7 conductor refusing every connection with 400 from that
                // moment (an identity restored by phrase on 1.7.0 whose devices
                // round attached 0.6 a minute later - the beta9 devices leg).
                if primary || node_origin().is_empty() {
                    fresh_node_origin();
                }
                start_vault_line(Line::V06, &self.data_dir, &self.passphrase, &self.conductor_seed, &self.conductor_tag, &target, |step| {
                    self.say(role, step_message(step))
                })
                .await
            }
            Line::V07 => {
                supervisor().set_state(Line::V07, LineState::Starting);
                self.say(role, "Starting the key store...");
                let target = BootstrapTarget::primary_07();
                if primary {
                    remember_conductor_rendezvous(&target.bootstrap_url);
                    fresh_node_origin();
                }
                self.say(role, "Starting Holochain conductor...");
                start_vault_line(Line::V07, &self.data_dir, &self.passphrase, &self.conductor_seed, &self.conductor_tag, &target, |_| {}).await
            }
        }
    }

    async fn setup(&self, line: Line, role: Role, process: &mut LineProcess) -> Result<u16, String> {
        match line {
            Line::V06 => self.setup_06(role, process).await,
            Line::V07 => self.setup_07(role, process).await,
        }
    }

    /// A key store that stopped right after starting no longer opens with the
    /// passphrase that just opened the vault file (the two got out of step,
    /// e.g. a vault re-saved under an old password after a change). It holds
    /// nothing that cannot be rebuilt from the vault's own seed, so it is set
    /// aside and the second attempt re-initializes it under the working one.
    async fn before_retry(&self, line: Line, error: &str) {
        let lair_dir = match line {
            Line::V06 => crate::paths::lair_dir(&self.data_dir),
            Line::V07 => crate::paths::lair_dir_07(&self.data_dir),
        };
        let mut message = "Finishing first-time setup...";
        if error.contains(lair::LAIR_STOPPED_MARKER) {
            match lair::quarantine_lair_dir(&lair_dir) {
                Ok(moved) => {
                    log::warn!("[start_holochain] the {} key store set aside at {:?} - rebuilding it from the device seed", line, moved);
                    message = "Rebuilding the key store...";
                }
                Err(qe) => log::error!("[start_holochain] {}", qe),
            }
        }
        if line == Line::V06 {
            self.say(Role::Primary, message);
        }
    }

    async fn joined(&self, line: Line, role: Role, _session: u64, admin_port: u16, app_port: u16) {
        match (role, line) {
            (Role::Primary, Line::V06) => {
                self.emit(role, ConductorStatus::Ready { admin_port });
            }
            (Role::Primary, Line::V07) => {
                self.emit(role, ConductorStatus::Ready { admin_port });
                log::info!("Holochain 0.7 conductor ready (admin: {}, app: {}) - this identity's primary line", admin_port, app_port);
            }
            (Role::Secondary, Line::V07) => {
                log::info!("Holochain 0.7 conductor ready (admin: {}, app: {})", admin_port, app_port);
                if let Some(state) = &self.state {
                    crate::dna::ensure_cells_ready_07(admin_port, state).await;
                    crate::move_07::schedule_pass(state.clone(), "the 0.7 line came up");
                }
            }
            (Role::Secondary, Line::V06) => {
                log::info!("Holochain 0.6 conductor attached (admin: {}) - what it still holds is carried to 0.7 each round", admin_port);
                if let Some(state) = &self.state {
                    crate::move_07::schedule_pass(state.clone(), "the 0.6 line came up");
                }
            }
        }
    }

    async fn secondary_failed(&self, line: Line, error: &str) {
        match line {
            Line::V07 => log::warn!("[0.7] the 0.7 line did not start (the Vault runs on 0.6 alone): {}", error),
            Line::V06 => log::warn!("[0.6] the 0.6 line did not start (the Vault runs on 0.7 alone; tried again next round): {}", error),
        }
    }

    async fn secondary_late(&self, line: Line) {
        match line {
            Line::V07 => log::info!("[0.7] the 0.7 line came up after its 0.6 line had stopped - stopped it again"),
            Line::V06 => log::info!("[0.6] the 0.6 line came up after its 0.7 line had stopped - stopped it again"),
        }
    }
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
            flowsta_hc_lines::rendezvous::relay_url_for("https://bootstrap.flowsta.com"),
            "https://bootstrap.flowsta.com./"
        );
        assert_eq!(
            flowsta_hc_lines::rendezvous::relay_url_for("https://node1.example.com/"),
            "https://node1.example.com./"
        );
        assert_eq!(
            flowsta_hc_lines::rendezvous::relay_url_for("http://node1.example.com:18080"),
            "http://node1.example.com.:18080/"
        );
        assert_eq!(
            flowsta_hc_lines::rendezvous::relay_url_for("http://192.168.1.3:18080"),
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

#[cfg(test)]
mod live_line_tests {
    use super::*;

    /// Both line starts as the Vault runs them, with the real sidecars:
    /// each comes up through flowsta-hc-lines with the device seed's key,
    /// installs its DNAs and attaches its app interface, then stops on
    /// request. Offline: build with a dead rendezvous so no server is asked,
    /// `FLOWSTA_BOOTSTRAP_URL=https://127.0.0.1:9 FLOWSTA_SIGNAL_URL=wss://127.0.0.1:9
    /// FLOWSTA_BOOTSTRAP_URL_07=https://127.0.0.1:9 cargo test --lib -- --ignored live_each_line`
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "starts a real 0.6 conductor and a real 0.7 conductor"]
    async fn live_each_line_starts_installs_and_stops() {
        let dir = PathBuf::from(format!("/tmp/fvl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let resources = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources");
        let seed = [11u8; 32];
        let key = crate::key_derivation::public_key_of_seed(&seed);
        fresh_node_origin();

        let hooks = VaultLines {
            app: None,
            state: None,
            data_dir: dir.clone(),
            resource_dir: resources.clone(),
            passphrase: "live-test".into(),
            conductor_seed: seed,
            conductor_tag: "live-device-key".into(),
            expected_pub_key: key,
            private_v2_seed: None,
        };
        let mut p06 = hooks.start(Line::V06, Role::Secondary).await.expect("the 0.6 line");
        assert_eq!(p06.agents[0], key);
        let app06 = hooks.setup(Line::V06, Role::Secondary, &mut p06).await.expect("the 0.6 DNAs");
        assert!(p06.conductor_alive());
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", app06)).await.is_ok(), "0.6 app interface");

        let mut p07 = hooks.start(Line::V07, Role::Secondary).await.expect("the 0.7 line");
        let app07 = hooks.setup(Line::V07, Role::Secondary, &mut p07).await.expect("the 0.7 DNAs");
        assert!(p07.conductor_alive());
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", app07)).await.is_ok(), "0.7 app interface");
        let config = std::fs::read_to_string(crate::paths::conductor_dir_07(&dir).join("conductor-config.yaml")).unwrap();
        assert!(config.contains("maxGossipOpBytes: 1048576") && config.contains("https://127.0.0.1:9"), "{config}");

        for p in [&mut p07, &mut p06] {
            let r = p.stop();
            assert!(matches!(r.conductor, Ok(flowsta_hc_lines::process::StopOutcome::Exited)), "{:?}", r.conductor);
            assert!(matches!(r.lair, Ok(flowsta_hc_lines::process::StopOutcome::Exited)), "{:?}", r.lair);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
