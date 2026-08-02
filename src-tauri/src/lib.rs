mod backup;
mod commands;
mod conductor;
mod device_identity;
mod dna;
mod dna_updater;
pub mod file_analyzer;
mod ipc_server;
mod key_derivation;
mod lair;
mod mau;
mod migration;
mod process_ext;
mod quota_cache;
mod relay_login;
mod sealed;
mod vault;

use commands::AppState;
use std::path::PathBuf;
use std::sync::Arc;

/// Resolve a sidecar binary path.
///
/// In production (bundled app), binaries are next to the main executable
/// (e.g. Contents/MacOS/vault-holochain on macOS). In development, look
/// inside `src-tauri/binaries/` first (matching how CI populates that
/// directory) so devs don't need a `vault-`-prefixed binary on PATH.
pub fn resolve_sidecar_bin(name: &str) -> PathBuf {
    if cfg!(debug_assertions) {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let binaries = std::path::Path::new(manifest).join("binaries");
        let prefix = format!("{}-", name);
        if let Ok(entries) = std::fs::read_dir(&binaries) {
            for entry in entries.flatten() {
                if let Some(s) = entry.file_name().to_str() {
                    if s.starts_with(&prefix) {
                        return entry.path();
                    }
                }
            }
        }
        return PathBuf::from(name);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = if cfg!(target_os = "windows") {
                dir.join(format!("{}.exe", name))
            } else {
                dir.join(name)
            };
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from(name)
}
use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem},
    tray::TrayIconBuilder,
    Emitter, Listener, Manager, WindowEvent,
};

/// Push files queued by the OS file-explorer integration into AppState
/// and notify the frontend. Used by:
///   - the initial CLI-arg parser at startup
///   - the single-instance plugin callback (Vault already running)
///   - `RunEvent::Opened` (macOS Apple Events, file-association handlers)
fn enqueue_sign_paths(app: &tauri::AppHandle, paths: Vec<PathBuf>) {
    if paths.is_empty() {
        return;
    }
    let count = paths.len();
    let state = app.state::<Arc<AppState>>();
    {
        let mut queue = state.pending_sign_paths.lock().unwrap();
        queue.extend(paths);
    }
    log::info!(
        "Queued {} file(s) from OS file-explorer integration",
        count,
    );
    let _ = app.emit("sign-files-requested", ());
    // Bring the window to the front so the user sees the new flow.
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_always_on_top(true);
        let _ = window.set_focus();
        let _ = window.set_always_on_top(false);
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        // ⚠️ ORDER MATTERS: single-instance MUST be registered before deep-link
        // on Linux/Windows - deep-link forwards flowsta:// URLs through the
        // single-instance callback. Registering deep-link first wedges startup.
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            // Another instance tried to launch. flowsta:// URLs MUST be
            // routed before sign-file extraction - an auth deep link misread
            // as a file path would silently do nothing.
            let (urls, rest): (Vec<&String>, Vec<&String>) = args
                .iter()
                .skip(1)
                .partition(|a| relay_login::is_flowsta_url(a));
            for url in &urls {
                relay_login::handle_flowsta_url(app, url);
            }
            // Skip the binary-name arg, then queue any file paths and bring
            // the existing window to front.
            let paths = commands::extract_sign_paths_from_args(rest.into_iter());
            if !paths.is_empty() {
                enqueue_sign_paths(app, paths);
            } else if urls.is_empty() {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.unminimize();
                    let _ = window.set_always_on_top(true);
                    let _ = window.set_focus();
                    let _ = window.set_always_on_top(false);
                }
            }
        }))
        // flowsta:// scheme - registered AFTER single-instance so URL
        // forwarding works. Lets a browser wake a closed-but-installed Vault
        // for "Sign in with your Vault"; the single-instance callback above
        // focuses the window on wake. macOS delivers via RunEvent::Opened.
        .plugin(tauri_plugin_deep_link::init())
        // Start Flowsta Vault at login so its local bridge is always
        // available to Flowsta pages and apps. When launched at login the
        // plugin passes `--autostart-hidden`; the setup hook below starts
        // the app in the tray (locked, conductor not yet running) instead
        // of popping the unlock window on every boot.
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--autostart-hidden"]),
        ))
        .setup(|app| {
            app.handle().plugin(
                tauri_plugin_log::Builder::default()
                    .level(log::LevelFilter::Info)
                    .build(),
            )?;

            // Set up data directory for vault storage.
            // Debug builds honor FLOWSTA_VAULT_DATA_DIR so test instances
            // (e.g. the two-device restore harness) can run beside a dev
            // vault without sharing its data. Never active in release.
            let data_dir = {
                let override_dir = if cfg!(debug_assertions) {
                    std::env::var("FLOWSTA_VAULT_DATA_DIR").ok().map(std::path::PathBuf::from)
                } else {
                    None
                };
                override_dir.unwrap_or_else(|| {
                    app.path()
                        .app_data_dir()
                        .expect("Failed to get app data directory")
                })
            };
            std::fs::create_dir_all(&data_dir).expect("Failed to create data directory");

            log::info!("Flowsta Vault starting up (v{})", env!("CARGO_PKG_VERSION"));
            log::info!("Data dir: {:?}", data_dir);
            if let Ok(log_dir) = app.path().app_log_dir() {
                log::info!("Log dir: {:?}", log_dir);
            }

            // Initialize app state (shared between Tauri commands and IPC server)
            let app_state = Arc::new(AppState::new(data_dir));

            // Share state with Tauri commands
            app.manage(app_state.clone());

            // If we were launched from a file-explorer "Sign with Flowsta
            // Vault" action, the OS passed the file path(s) as positional
            // CLI args. A flowsta:// deep link cold-launching a closed Vault
            // ALSO arrives here - route those first (same rule as the
            // single-instance callback). The relay code is
            // queued in AppState and drained by the frontend after mount.
            let (startup_urls, startup_rest): (Vec<String>, Vec<String>) =
                std::env::args().skip(1).partition(|a| relay_login::is_flowsta_url(a));
            for u in &startup_urls {
                match relay_login::parse_relay_code(u) {
                    Some(code) => {
                        log::info!("flowsta:// relay code received via launch args");
                        let mut pending = app_state.pending_relay_code.lock().unwrap();
                        *pending = Some(code);
                    }
                    None => log::warn!("Unrecognized flowsta:// URL in launch args"),
                }
            }
            let startup_paths = commands::extract_sign_paths_from_args(startup_rest);
            if !startup_paths.is_empty() {
                let count = startup_paths.len();
                let mut queue = app_state.pending_sign_paths.lock().unwrap();
                queue.extend(startup_paths);
                log::info!("Queued {} file(s) from launch args", count);
            }

            // Start the IPC server on its OWN dedicated thread + tokio
            // runtime, isolated from the main async runtime that the
            // Holochain conductor runs on. Rationale: in 0.6.1 the IPC
            // server shared the conductor's runtime, so heavy post-unlock
            // conductor work (cell enablement, agent-link queries) could
            // starve the IPC accept loop until it permanently wedged
            // (connections piled in the accept queue; /status went dark).
            // A separate runtime means conductor churn can never block the
            // IPC accept loop. (Surfaced building Your Own AI's Vault
            // sign-in.)
            let ipc_state = app_state.clone();
            let app_handle = app.handle().clone();
            std::thread::Builder::new()
                .name("flowsta-ipc".into())
                .spawn(move || {
                    let rt = match tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(4)
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(e) => {
                            log::error!("Failed to build IPC runtime: {}", e);
                            return;
                        }
                    };
                    rt.block_on(async move {
                        match ipc_server::start_ipc_server(ipc_state, app_handle).await {
                            Ok(port) => log::info!("IPC server started on port {} (dedicated runtime)", port),
                            Err(e) => log::error!("Failed to start IPC server: {}", e),
                        }
                        // start_ipc_server spawns the serve task and returns
                        // the port; keep this runtime alive so that task runs.
                        std::future::pending::<()>().await;
                    });
                })
                .expect("failed to spawn IPC server thread");

            // Catch SIGTERM / SIGINT (Ctrl+C, system shutdown, dpkg postinst kill,
            // `kill <pid>`) and route them through app.exit() so RunEvent::Exit
            // fires and ConductorHandle::shutdown() kills the holochain conductor
            // and lair-keystore children cleanly.
            let signal_app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{signal, SignalKind};
                    let mut sigterm = match signal(SignalKind::terminate()) {
                        Ok(s) => s,
                        Err(e) => {
                            log::error!("Failed to register SIGTERM handler: {}", e);
                            return;
                        }
                    };
                    tokio::select! {
                        _ = sigterm.recv() => log::info!("SIGTERM received, exiting"),
                        _ = tokio::signal::ctrl_c() => log::info!("SIGINT received, exiting"),
                    }
                }
                #[cfg(not(unix))]
                {
                    if tokio::signal::ctrl_c().await.is_err() {
                        log::error!("Failed to register Ctrl+C handler");
                        return;
                    }
                    log::info!("Ctrl+C received, exiting");
                }
                signal_app_handle.exit(0);
            });

            // --- System tray ---
            let open_item = MenuItemBuilder::with_id("open", "Open Flowsta Vault").build(app)?;
            let lock_item = MenuItemBuilder::with_id("lock", "Lock Vault").build(app)?;
            let separator = PredefinedMenuItem::separator(app)?;
            let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

            let tray_menu = MenuBuilder::new(app)
                .item(&open_item)
                .item(&lock_item)
                .item(&separator)
                .item(&quit_item)
                .build()?;

            let tray_icon = Image::from_path("icons/32x32.png")
                .or_else(|_| Image::from_path("src-tauri/icons/32x32.png"))
                .unwrap_or_else(|_| Image::from_bytes(include_bytes!("../icons/32x32.png")).expect("Failed to load tray icon"));

            let _tray = TrayIconBuilder::new()
                .icon(tray_icon)
                .tooltip("Flowsta Vault")
                .menu(&tray_menu)
                .on_menu_event(move |app, event| match event.id().as_ref() {
                    "open" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            // On Linux, set_focus alone may not raise the window.
                            // Briefly setting always-on-top forces it to the foreground.
                            let _ = window.set_always_on_top(true);
                            let _ = window.set_focus();
                            let _ = window.set_always_on_top(false);
                        }
                    }
                    "lock" => {
                        // Emit lock event to frontend - it handles the actual lock logic
                        let _ = app.emit("vault-lock-requested", ());
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::Click { button: tauri::tray::MouseButton::Left, .. } = event {
                        if let Some(window) = tray.app_handle().get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_always_on_top(true);
                            let _ = window.set_focus();
                            let _ = window.set_always_on_top(false);
                        }
                    }
                })
                .build(app)?;

            // Window starts visible (required for Tauri #11856 - decoration buttons
            // are unresponsive on Linux Wayland when starting with visible:false).
            // The dark bg-gray-900 body style in global.css prevents white flash.

            // Autostart is DEFAULT ON for new installs: enable it once, gated
            // by a marker so a user who later turns it off in Settings stays
            // off. Best-effort - a failure here never blocks startup. Release
            // only: a debug build would register the dev binary / cargo runner
            // into the user's login items, polluting a developer's machine.
            #[cfg(not(debug_assertions))]
            {
                use tauri_plugin_autostart::ManagerExt;
                let marker = app_state.data_dir.join("autostart-initialized");
                if !marker.exists() {
                    match app.autolaunch().enable() {
                        Ok(_) => log::info!("Autostart enabled (default-on, first run)"),
                        Err(e) => log::warn!("Could not enable autostart (non-fatal): {}", e),
                    }
                    let _ = std::fs::write(&marker, b"1");
                }
            }

            // Launched at login (`--autostart-hidden`): stay in the tray
            // rather than showing the unlock window. The window was created
            // visible (the Wayland caveat above is about STARTING hidden, not
            // hiding after creation), so hide it now. Anything that needs the
            // user - a page asking to sign, a relay code - already raises the
            // window through the existing bridge/deep-link paths.
            if std::env::args().any(|a| a == "--autostart-hidden") {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.hide();
                }
                log::info!("Launched at login - starting hidden to the tray");
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            // Close to tray instead of quitting
            if let WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_conductor_status,
            commands::get_vault_status,
            commands::update_local_profile,
            commands::setup_vault,
            device_identity::generate_new_mnemonic,
            device_identity::register_device_identity,
            device_identity::vault_grant_login,
            device_identity::restore_device_identity,
            device_identity::attempt_account_reconcile,
            device_identity::update_pending_registration_email,
            relay_login::relay_claim,
            relay_login::relay_approve,
            relay_login::relay_deny,
            relay_login::take_pending_relay_code,
            sealed::sealed_store,
            sealed::sealed_list,
            migration::migration_new_phrase,
            migration::phrase_migration_login,
            migration::migrate_custodial_account,
            commands::respond_profile_update_request,
            commands::respond_cell_op_request,
            commands::unlock_vault,
            commands::lock_vault,
            commands::reset_vault,
            commands::get_identity,
            commands::validate_recovery_phrase,
            commands::phrase_matches_vault,
            commands::check_account_hosting,
            commands::authenticate_web_account,
            commands::authenticate_2fa,
            commands::check_recovery_phrase_status,
            commands::fetch_web_profile,
            commands::refresh_cached_profile,
            commands::verify_phrase_matches_web_key,
            commands::get_vault_display_info,
            commands::check_api_connectivity,
            commands::get_auto_lock_minutes,
            commands::set_auto_lock_minutes,
            commands::get_autostart_enabled,
            commands::set_autostart_enabled,
            commands::change_vault_password,
            commands::link_web_account,
            commands::get_linked_agents,
            commands::get_connected_sites,
            commands::revoke_site,
            commands::get_pending_auth,
            commands::respond_auth_request,
            commands::toggle_site_trust,
            commands::get_approved_apps,
            commands::revoke_approved_app,
            commands::get_pending_link_identity,
            commands::respond_link_identity_request,
            commands::respond_document_sign_request,
            commands::respond_raw_sign_request,
            commands::get_pending_document_sign,
            commands::hash_file,
            commands::cancel_hash,
            commands::get_file_size,
            commands::take_pending_sign_paths,
            commands::analyze_file,
            commands::generate_perceptual_hash,
            commands::generate_thumbnail,
            commands::set_thumbnail,
            commands::sign_file,
            commands::read_quota_cache,
            commands::write_quota_cache,
            commands::increment_quota_used,
            commands::sync_quota_to_server,
            commands::claim_web_username,
            commands::set_web_email,
            commands::get_my_signatures,
            commands::get_my_own_signatures,
            commands::get_my_linked_signatures,
            commands::revoke_signature,
            commands::get_linked_third_party_apps,
            commands::get_all_linked_app_scopes,
            commands::revoke_linked_third_party_app,
            commands::get_backup_stats,
            commands::delete_app_backup,
            commands::export_all_data,
            commands::export_all_data_to_file,
            commands::export_skip_signatures,
            commands::import_vault_export,
            commands::restore_choice_pending,
            commands::resolve_restore_choice,
            commands::list_app_backup_details,
            commands::export_single_backup,
            commands::export_single_backup_to_file,
            commands::delete_single_backup,
            commands::write_json_file,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            match event {
                tauri::RunEvent::Exit => {
                    let state: Arc<AppState> = app_handle.state::<Arc<AppState>>().inner().clone();
                    if let Ok(mut lock) = state.conductor_handle.lock() {
                        if let Some(handle) = lock.take() {
                            handle.shutdown();
                        }
                    };
                }
                // Triggered on macOS / iOS when the OS opens files with our
                // app via Apple Events (Services menu, Open With, drag onto
                // dock icon). Linux + Windows route through CLI args instead,
                // handled in the setup hook + single-instance callback.
                #[cfg(any(target_os = "macos", target_os = "ios"))]
                tauri::RunEvent::Opened { urls } => {
                    // flowsta:// first - see the single-instance
                    // callback for why the order is load-bearing.
                    let (deep_links, rest): (Vec<String>, Vec<String>) = urls
                        .iter()
                        .map(|u| u.as_str().to_string())
                        .partition(|s| relay_login::is_flowsta_url(s));
                    for url in &deep_links {
                        relay_login::handle_flowsta_url(app_handle, url);
                    }
                    let paths = commands::extract_sign_paths_from_args(rest);
                    enqueue_sign_paths(app_handle, paths);
                }
                _ => {}
            }
        });
}
