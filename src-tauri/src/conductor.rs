//! Holochain conductor lifecycle management.
//!
//! Manages the full startup sequence: lair-keystore → conductor → connect → install DNAs.
//! The conductor starts on vault unlock and stops on vault lock.

use crate::{dna, lair};
use lair_keystore_api::prelude::*;
use std::path::{Path, PathBuf};
use crate::process_ext::CommandExt;
use std::process::{Child, Stdio};
use tauri::Emitter;

/// Candidate admin WebSocket ports for the conductor.
/// Tries each in order — allows staging and production vaults to coexist.
const ADMIN_WS_PORTS: &[u16] = &[4455, 4456, 4457];

/// Handle to a running conductor + lair-keystore pair.
/// Drop this to stop both processes.
pub struct ConductorHandle {
    pub lair_child: Child,
    pub conductor_child: Child,
    pub lair_client: LairClient,
    pub admin_port: u16,
    pub app_port: u16,
    pub seed_info: SeedInfo,
}

impl ConductorHandle {
    /// Graceful shutdown of conductor + lair.
    pub fn shutdown(mut self) {
        log::info!("Shutting down conductor...");
        if let Err(e) = self.conductor_child.kill() {
            log::warn!("Failed to kill conductor process: {}", e);
        }
        let _ = self.conductor_child.wait();

        log::info!("Shutting down lair-keystore...");
        if let Err(e) = self.lair_child.kill() {
            log::warn!("Failed to kill lair-keystore process: {}", e);
        }
        let _ = self.lair_child.wait();

        log::info!("Conductor and lair-keystore stopped");
    }
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

/// Find an available admin WS port from the candidate list.
fn find_available_admin_port() -> Result<u16, String> {
    for &port in ADMIN_WS_PORTS {
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(_listener) => {
                // Port is free — listener is dropped here, freeing the port for the conductor.
                log::info!("Using admin WS port {}", port);
                return Ok(port);
            }
            Err(_) => {
                log::info!("Admin WS port {} in use, trying next", port);
            }
        }
    }
    Err(format!(
        "All admin WS ports ({:?}) are unavailable",
        ADMIN_WS_PORTS
    ))
}

/// Generate conductor-config.yaml for the desktop app.
///
/// Holochain 0.6.1 / Iroh config format. The config is regenerated from
/// scratch on every unlock, so an existing 0.6.0 user upgrading to this
/// build picks up the Iroh format automatically — no on-disk migration.
/// Uses the lair connection URL for keystore integration.
pub fn generate_conductor_config(
    conductor_dir: &Path,
    lair_connection_url: &str,
    admin_port: u16,
) -> Result<PathBuf, String> {
    std::fs::create_dir_all(conductor_dir)
        .map_err(|e| format!("Failed to create conductor directory: {}", e))?;

    // Bootstrap/signal URLs default to production. Override at compile time
    // (option_env! is read at `cargo build` time) for staging/dev — see the
    // `tauri:dev-staging` script in package.json.
    let bootstrap_url = option_env!("FLOWSTA_BOOTSTRAP_URL")
        .unwrap_or("https://bootstrap.flowsta.com");
    let signal_url = option_env!("FLOWSTA_SIGNAL_URL")
        .unwrap_or("wss://bootstrap.flowsta.com");

    // Iroh's relay is hosted by the same Flowsta bootstrap server as peer
    // discovery + SBD, so the relay_url is *derived* from the bootstrap URL
    // rather than carried as a separate env var — that makes it impossible
    // for a staging build to point its relay at production by accident.
    // kitsune2 requires the canonical FQDN form: a trailing dot on the host
    // plus a trailing slash, e.g. https://bootstrap.flowsta.com./
    let relay_url = format!(
        "{}./",
        bootstrap_url.trim_end_matches('/').trim_end_matches('.'),
    );

    // Path values use SINGLE-quoted YAML strings — double-quoted YAML interprets
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
    allowed_origins: '*'
network:
  bootstrap_url: {bootstrap_url}
  signal_url: {signal_url}
  relay_url: {relay_url}
  # Default is 60s; on a fresh install of a returning agent the local
  # cell is empty and the signing zome's get_links / get calls hit
  # kitsune2's request_timeout while the DHT is warming up, returning
  # `get_links response channel dropped: likely response timeout` to
  # the zome. 240s comfortably covers a cold-start round so the first
  # query returns data instead of needing the front-end to retry.
  request_timeout_s: 240
"#,
        data_root = data_root,
        admin_port = admin_port,
        lair_url = lair_url,
        bootstrap_url = bootstrap_url,
        signal_url = signal_url,
        relay_url = relay_url,
    );

    let config_path = conductor_dir.join("conductor-config.yaml");
    std::fs::write(&config_path, &config)
        .map_err(|e| format!("Failed to write conductor config: {}", e))?;

    log::info!("Conductor config written to {:?}", config_path);
    Ok(config_path)
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
) -> Result<Child, String> {
    log::info!("Starting holochain conductor...");

    let stdout_path = conductor_dir.join("holochain-stdout.log");
    let stderr_path = conductor_dir.join("holochain-stderr.log");

    let stdout_file = std::fs::File::create(&stdout_path)
        .map_err(|e| format!("Failed to create conductor stdout log: {}", e))?;
    let stderr_file = std::fs::File::create(&stderr_path)
        .map_err(|e| format!("Failed to create conductor stderr log: {}", e))?;

    let holochain_bin = crate::resolve_sidecar_bin("holochain");
    log::info!("Using holochain binary: {:?}", holochain_bin);

    // Hide the conductor's console window on Windows via post-spawn
    // ShowWindow(SW_HIDE). Earlier RCs avoided this on the theory that
    // hiding caused the `0xc0000005` access violation we saw on first
    // install of signing DNA. The diagnostic logging added in beta1 and
    // the conductor exit-code captured in beta5 proved that crash
    // happens *regardless* of window state — it's an upstream holochain
    // bug in the WASM compile path, not anything to do with the console.
    // Now that the start_holochain auto-restart catches that crash and
    // recovers transparently, the window can be hidden safely.
    let spawn_start = std::time::Instant::now();
    let mut child = std::process::Command::new(&holochain_bin)
        .arg("-c")
        .arg(config_path)
        .arg("--piped")
        .stdin(Stdio::piped())
        .stdout(stdout_file)
        .stderr(stderr_file)
        .tie_to_parent()
        .spawn_hidden()
        .map_err(|e| format!("Failed to spawn holochain conductor: {}", e))?;

    let pid = child.id();
    log::info!(
        "[conductor:{pid}] spawned in {}ms — writing passphrase to stdin",
        spawn_start.elapsed().as_millis()
    );

    // Pipe the passphrase for lair authentication.
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(format!("{}\n", passphrase).as_bytes())
            .map_err(|e| format!("Failed to write passphrase to conductor: {}", e))?;
    }

    log::info!("[conductor:{pid}] passphrase piped — sleeping 500ms before liveness check");

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
    if output.len() > 500 {
        format!("{}...", &output[..500])
    } else {
        output
    }
}

/// Wait for the conductor admin WebSocket to be ready.
/// Also monitors the conductor process — if it exits during the wait,
/// reads log files and returns immediately with the actual error.
async fn wait_for_admin_ws(
    port: u16,
    timeout_secs: u64,
    conductor_child: &mut Child,
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
            Ok(None) => {} // Still running — continue waiting
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

    // Timed out — grab whatever logs exist for diagnostics.
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
/// exits). The fix is the same one users were doing by hand — restart the
/// conductor. Second attempt benefits from the WASM cache the first one
/// populated on disk, so it's typically fast (<2 s of DNA work).
pub async fn start_holochain(
    app_handle: tauri::AppHandle,
    data_dir: PathBuf,
    resource_dir: PathBuf,
    passphrase: String,
    device_seed: [u8; 32],
) -> Result<ConductorHandle, String> {
    match start_holochain_attempt(
        app_handle.clone(),
        data_dir.clone(),
        resource_dir.clone(),
        passphrase.clone(),
        device_seed,
    )
    .await
    {
        Ok(h) => return Ok(h),
        Err(e) => {
            log::warn!(
                "[start_holochain] first attempt failed: {} — auto-restarting conductor",
                e,
            );
            let _ = app_handle.emit(
                "conductor-status",
                ConductorStatus::Starting {
                    message: "Finishing first-time setup...".into(),
                },
            );
            // Brief pause so the admin WS port is released and any process
            // tear-down completes before the second attempt binds it.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }

    start_holochain_attempt(app_handle, data_dir, resource_dir, passphrase, device_seed).await
}

/// One full startup attempt: lair → seed import → conductor → connect → install DNAs.
///
/// Called after vault unlock. Runs in a background task.
/// Emits Tauri events for frontend status updates.
async fn start_holochain_attempt(
    app_handle: tauri::AppHandle,
    data_dir: PathBuf,
    resource_dir: PathBuf,
    passphrase: String,
    device_seed: [u8; 32],
) -> Result<ConductorHandle, String> {
    // Emit status: starting lair
    let _ = app_handle.emit("conductor-status", ConductorStatus::Starting {
        message: "Starting lair-keystore...".into(),
    });

    // 1. Start lair-keystore process.
    let lair_dir = data_dir.join("lair");
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

    // 2. Wait for lair socket to be ready.
    if let Err(e) = lair::wait_for_lair_socket(&connection_url, 15).await {
        fail_with_lair_cleanup!(e);
    }

    // 3. Connect to lair.
    let _ = app_handle.emit("conductor-status", ConductorStatus::Starting {
        message: "Connecting to lair-keystore...".into(),
    });
    let lair_client = match lair::connect_to_lair(&connection_url, &passphrase).await {
        Ok(c) => c,
        Err(e) => fail_with_lair_cleanup!(e),
    };
    log::info!("Connected to lair-keystore");

    // 4. Import device seed (if not already imported).
    let _ = app_handle.emit("conductor-status", ConductorStatus::Starting {
        message: "Importing device key...".into(),
    });
    let seed_info = match lair::import_seed_to_lair(&lair_client, &device_seed, "flowsta-device-1")
        .await
    {
        Ok(s) => s,
        Err(e) => fail_with_lair_cleanup!(format!("Failed to import device seed into lair: {}", e)),
    };
    let pub_key_hex = hex::encode(&*seed_info.ed25519_pub_key.0);
    log::info!("Device seed imported, pub key: {}", pub_key_hex);

    // Convert lair Ed25519 pub key → Holochain AgentPubKey for DNA installation.
    // This ensures the conductor uses our deterministic identity (from the mnemonic)
    // rather than a random key from generate_agent_pub_key().
    let agent_pub_key = holochain_types::prelude::AgentPubKey::from_raw_32(
        seed_info.ed25519_pub_key.0.to_vec(),
    );

    // 5. Generate conductor config.
    let _ = app_handle.emit("conductor-status", ConductorStatus::Starting {
        message: "Starting Holochain conductor...".into(),
    });
    let conductor_dir = data_dir.join("conductor");
    let admin_port = match find_available_admin_port() {
        Ok(p) => p,
        Err(e) => fail_with_lair_cleanup!(e),
    };
    let config_path = match generate_conductor_config(&conductor_dir, &connection_url, admin_port)
    {
        Ok(p) => p,
        Err(e) => fail_with_lair_cleanup!(e),
    };

    // 6. Start conductor process (needs passphrase for lair authentication via --piped).
    let mut conductor_child = match start_conductor_process(&config_path, &conductor_dir, &passphrase) {
        Ok(c) => c,
        Err(e) => fail_with_lair_cleanup!(e),
    };

    // 7. Wait for admin WebSocket to be ready (conductor takes 5-15s).
    //    Also monitors the conductor process — returns immediately with log output if it dies.
    let _ = app_handle.emit("conductor-status", ConductorStatus::Starting {
        message: "Waiting for conductor...".into(),
    });
    if let Err(e) = wait_for_admin_ws(admin_port, 30, &mut conductor_child, &conductor_dir).await {
        let _ = conductor_child.kill();
        let _ = conductor_child.wait();
        fail_with_lair_cleanup!(e);
    }

    // 8. Install Flowsta DNAs (idempotent — skips if already installed).
    let _ = app_handle.emit("conductor-status", ConductorStatus::Starting {
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
    let install_result = dna::install_dnas(
        admin_port,
        &resource_dir,
        agent_pub_key,
        dna::BUNDLED_PRIVATE_VERSION,
        dna::BUNDLED_IDENTITY_VERSION,
        dna::BUNDLED_SIGNING_VERSION,
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

    // 9. Attach app interface for zome calls (e.g. pairing code generation).
    let _ = app_handle.emit("conductor-status", ConductorStatus::Starting {
        message: "Setting up app interface...".into(),
    });
    let app_port = match dna::setup_app_interface(admin_port).await {
        Ok(p) => p,
        Err(e) => fail_with_full_cleanup!(format!("App interface setup failed: {}", e)),
    };

    // 10. Emit ready status.
    let _ = app_handle.emit("conductor-status", ConductorStatus::Ready {
        admin_port: admin_port,
    });
    log::info!("Holochain conductor ready (admin: {}, app: {})", admin_port, app_port);

    Ok(ConductorHandle {
        lair_child,
        conductor_child,
        lair_client,
        admin_port: admin_port,
        app_port,
        seed_info,
    })
}
