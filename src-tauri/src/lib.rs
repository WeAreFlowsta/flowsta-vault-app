mod backup;
mod commands;
mod conductor;
mod dna;
mod dna_updater;
pub mod file_analyzer;
mod ipc_server;
mod key_derivation;
mod lair;
mod mau;
mod vault;

use commands::AppState;
use std::path::PathBuf;
use std::sync::Arc;

/// Resolve a sidecar binary path.
///
/// In production (bundled app), binaries are next to the main executable
/// (e.g. Contents/MacOS/holochain on macOS). In development, they're on PATH
/// via cargo install.
pub fn resolve_sidecar_bin(name: &str) -> PathBuf {
    if cfg!(debug_assertions) {
        // Dev mode: use PATH (cargo-installed binary)
        return PathBuf::from(name);
    }
    // Production: binary is next to our executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // On Windows, binaries have .exe extension
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
    // Fallback to PATH
    PathBuf::from(name)
}
use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem},
    tray::TrayIconBuilder,
    Emitter, Listener, Manager, WindowEvent,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Another instance tried to launch — bring existing window to front
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_always_on_top(true);
                let _ = window.set_focus();
                let _ = window.set_always_on_top(false);
            }
        }))
        .setup(|app| {
            app.handle().plugin(
                tauri_plugin_log::Builder::default()
                    .level(log::LevelFilter::Info)
                    .build(),
            )?;

            // Set up data directory for vault storage
            let data_dir = app
                .path()
                .app_data_dir()
                .expect("Failed to get app data directory");
            std::fs::create_dir_all(&data_dir).expect("Failed to create data directory");

            log::info!("Flowsta Vault starting up...");
            log::info!("Data dir: {:?}", data_dir);

            // Initialize app state (shared between Tauri commands and IPC server)
            let app_state = Arc::new(AppState::new(data_dir));

            // Share state with Tauri commands
            app.manage(app_state.clone());

            // Start IPC server in background (needs AppHandle for event emission)
            let ipc_state = app_state.clone();
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                match ipc_server::start_ipc_server(ipc_state, app_handle).await {
                    Ok(port) => log::info!("IPC server started on port {}", port),
                    Err(e) => log::error!("Failed to start IPC server: {}", e),
                }
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
                        // Emit lock event to frontend — it handles the actual lock logic
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

            // Window starts visible (required for Tauri #11856 — decoration buttons
            // are unresponsive on Linux Wayland when starting with visible:false).
            // The dark bg-gray-900 body style in global.css prevents white flash.

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
            commands::setup_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::reset_vault,
            commands::get_identity,
            commands::validate_recovery_phrase,
            commands::authenticate_web_account,
            commands::authenticate_2fa,
            commands::check_recovery_phrase_status,
            commands::fetch_web_profile,
            commands::refresh_cached_profile,
            commands::verify_phrase_matches_web_key,
            commands::get_vault_display_info,
            commands::check_web_password,
            commands::check_api_connectivity,
            commands::re_encrypt_vault,
            commands::get_auto_lock_minutes,
            commands::set_auto_lock_minutes,
            commands::change_password,
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
            commands::get_pending_document_sign,
            commands::hash_file,
            commands::analyze_file,
            commands::generate_perceptual_hash,
            commands::generate_thumbnail,
            commands::set_thumbnail,
            commands::sign_file,
            commands::get_my_signatures,
            commands::revoke_signature,
            commands::get_linked_third_party_apps,
            commands::get_all_linked_app_scopes,
            commands::revoke_linked_third_party_app,
            commands::get_backup_stats,
            commands::delete_app_backup,
            commands::export_all_data,
            commands::list_app_backup_details,
            commands::export_single_backup,
            commands::delete_single_backup,
            commands::write_json_file,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            if let tauri::RunEvent::Exit = event {
                let state: Arc<AppState> = app_handle.state::<Arc<AppState>>().inner().clone();
                if let Ok(mut lock) = state.conductor_handle.lock() {
                    if let Some(handle) = lock.take() {
                        handle.shutdown();
                    }
                };
            }
        });
}
