//! The Vault's own updates: checked on start and every few hours, downloaded
//! in the background, installed at "Restart to update" or on quit.
//!
//! Two signatures stand behind an update. Tauri's updater signature on the
//! file (the release build's key) is checked by the plugin as it downloads.
//! The release manifest, signed by Team Flowsta in the Vault, names the
//! version, the channel and every file's SHA-256, and is checked here with
//! `flowsta-update-check` before anything is downloaded; the download is
//! then checked against it. Both checks are local. The requests are plain
//! GETs of two public files and carry nothing about this install.

use flowsta_update_check::{check, check_file, Installed, Refused, Trust};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;
use tauri::{Emitter, Manager};
use tauri_plugin_updater::UpdaterExt;

const APP_ID: &str = "com.flowsta.vault";
/// The identities whose signature on a release manifest this build accepts:
/// Team Flowsta, as for the node manifests.
const SIGNERS: &[&str] = &["did:flowsta:uhCAkWuA-Ehm9EVzcsPE2Wo_vpc9ImljHN8NMMEXpbtG5BdooOV9a"];
const RELEASES: &str = "https://github.com/WeAreFlowsta/flowsta-vault-app/releases";
const FIRST_CHECK_AFTER: Duration = Duration::from_secs(90);
const CHECK_EVERY: Duration = Duration::from_secs(4 * 60 * 60);

/// Where a channel's two files live: stable, the latest release's assets;
/// beta, one fixed pre-release whose two files each beta replaces.
fn channel_base(channel: &str) -> String {
    if channel == "beta" {
        format!("{RELEASES}/download/vault-beta")
    } else {
        format!("{RELEASES}/latest/download")
    }
}

pub(crate) fn latest_json_url(channel: &str) -> String {
    format!("{}/latest.json", channel_base(channel))
}

pub(crate) fn manifest_url(channel: &str) -> String {
    format!("{}/release-manifest.json", channel_base(channel))
}

/// This build's platform, in the Tauri updater's names.
fn platform() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("darwin-aarch64"),
        ("macos", "x86_64") => Some("darwin-x86_64"),
        ("windows", "x86_64") => Some("windows-x86_64"),
        ("linux", "x86_64") => Some("linux-x86_64"),
        _ => None,
    }
}

/// The package this copy was installed from: an update replaces it with the
/// same kind. None for a copy run from a build folder (no updates).
fn kind() -> Option<&'static str> {
    use tauri::utils::config::BundleType as B;
    match tauri::utils::platform::bundle_type()? {
        B::App => Some("app-tarball"),
        B::Nsis => Some("nsis"),
        B::Msi => Some("msi"),
        B::Deb => Some("deb"),
        B::Rpm => Some("rpm"),
        _ => None,
    }
}

/// What the updater keeps on disk: the person's choices, the newest
/// manifest sequence accepted per channel (no replay of an older one), the
/// rollout ticket (a number made once, never sent), and the version this
/// copy was updated from (said once after the restart).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
struct Saved {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auto: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
    #[serde(default)]
    last_sequence: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollout_ticket: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    updated_from: Option<UpdatedFrom>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct UpdatedFrom {
    pub version: String,
    pub to: String,
    pub notes_url: String,
}

impl Saved {
    fn auto(&self) -> bool {
        self.auto.unwrap_or(true)
    }
    fn channel(&self) -> &str {
        match self.channel.as_deref() {
            Some("beta") => "beta",
            _ => "stable",
        }
    }
}

fn load(data_dir: &Path) -> Saved {
    std::fs::read(crate::paths::updates_path(data_dir)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save(data_dir: &Path, saved: &Saved) {
    let path = crate::paths::updates_path(data_dir);
    match serde_json::to_vec_pretty(saved) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(&path, bytes) {
                log::warn!("[update] {} not written: {}", path.display(), e);
            }
        }
        Err(e) => log::warn!("[update] state not serialized: {}", e),
    }
}

/// The rollout ticket, made on first use and kept.
fn ticket(data_dir: &Path, saved: &mut Saved) -> u8 {
    if let Some(t) = saved.rollout_ticket {
        return t;
    }
    let t = rand::random::<u8>() % 100;
    saved.rollout_ticket = Some(t);
    save(data_dir, saved);
    t
}

/// An update downloaded and checked, waiting for "Restart to update" or quit.
struct Ready {
    update: tauri_plugin_updater::Update,
    bytes: Vec<u8>,
    version: String,
    notes_url: String,
    changes_line: bool,
    channel: String,
    sequence: u64,
}

static READY: Mutex<Option<Ready>> = Mutex::new(None);
/// Something the person should know that the updater cannot do for them
/// (install another version first, an MSI install).
static NOTICE: Mutex<Option<String>> = Mutex::new(None);

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct UpdateStatus {
    pub auto: bool,
    pub channel: String,
    pub version: String,
    /// A downloaded, checked update waiting for a restart.
    pub ready: Option<ReadyInfo>,
    pub notice: Option<String>,
    /// Set once after an update: what this copy was updated from.
    pub updated: Option<UpdatedFrom>,
    /// Whether this copy can update itself (installed from a package).
    pub can_update: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct ReadyInfo {
    pub version: String,
    pub notes_url: String,
    pub changes_line: bool,
}

/// Check once: the manifest, then (only if it passes) the download.
async fn check_once(app: &tauri::AppHandle, data_dir: &Path) {
    let mut saved = load(data_dir);
    if !saved.auto() || READY.lock().unwrap().is_some() {
        return;
    }
    let (Some(platform), Some(kind)) = (platform(), kind()) else {
        return;
    };
    let channel = saved.channel().to_string();
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(30)).build() {
        Ok(c) => c,
        Err(e) => {
            log::warn!("[update] no HTTP client: {}", e);
            return;
        }
    };
    let manifest = match client.get(manifest_url(&channel)).send().await {
        Ok(r) if r.status().is_success() => match r.bytes().await {
            Ok(b) => b,
            Err(e) => {
                log::info!("[update] the {} manifest was not read: {}", channel, e);
                return;
            }
        },
        // No manifest published on this channel yet, or offline: nothing to do.
        Ok(r) => {
            log::debug!("[update] no {} manifest ({})", channel, r.status());
            return;
        }
        Err(e) => {
            log::debug!("[update] the {} manifest was not fetched: {}", channel, e);
            return;
        }
    };
    let rollout_ticket = ticket(data_dir, &mut saved);
    let installed = Installed { version: env!("CARGO_PKG_VERSION"), last_sequence: saved.last_sequence.get(&channel).copied(), rollout_ticket };
    let release = match check(&manifest, &Trust { app: APP_ID, channel: &channel, signers: SIGNERS }, &installed) {
        Ok(r) => r,
        Err(Refused::NotNewer { .. }) | Err(Refused::Replayed { .. }) | Err(Refused::NotYet { .. }) => return,
        Err(Refused::InstallFirst(first)) => {
            *NOTICE.lock().unwrap() = Some(format!("A newer Flowsta Vault is out, and it updates from {first} or later. Install {first} from flowsta.com first; this copy then updates itself again."));
            return;
        }
        Err(e) => {
            log::warn!("[update] the {} manifest was refused: {}", channel, e);
            return;
        }
    };
    let Some(file) = release.file(platform, kind).cloned() else {
        log::info!("[update] {} {} has no {} for {}", APP_ID, release.version, kind, platform);
        return;
    };
    if kind == "msi" {
        // An MSI install is managed by whoever deployed it: say so, never replace it.
        *NOTICE.lock().unwrap() = Some(format!("Flowsta Vault {} is out. This copy was installed with the Windows Installer (MSI), so it does not update itself: get it from flowsta.com.", release.version));
        return;
    }
    let endpoint = match url::Url::parse(&latest_json_url(&channel)) {
        Ok(u) => u,
        Err(e) => {
            log::warn!("[update] bad endpoint: {}", e);
            return;
        }
    };
    let updater = match app.updater_builder().endpoints(vec![endpoint]).and_then(|b| b.build()) {
        Ok(u) => u,
        Err(e) => {
            log::warn!("[update] the updater did not start: {}", e);
            return;
        }
    };
    let update = match updater.check().await {
        Ok(Some(u)) => u,
        Ok(None) => return,
        Err(e) => {
            log::info!("[update] the {} version file was not read: {}", channel, e);
            return;
        }
    };
    if update.version != release.version {
        log::warn!("[update] the version file names {} but the signed manifest {}: not downloaded", update.version, release.version);
        return;
    }
    log::info!("[update] downloading {} {} ({} bytes)", APP_ID, release.version, file.size);
    let bytes = match update.download(|_, _| {}, || {}).await {
        Ok(b) => b,
        Err(e) => {
            log::warn!("[update] the download failed or its updater signature did not verify: {}", e);
            return;
        }
    };
    if let Err(e) = check_file(&file, &bytes) {
        log::warn!("[update] the download is not the file the manifest names: {}", e);
        return;
    }
    log::info!("[update] {} ready: installs at \"Restart to update\" or on quit", release.version);
    let info = ReadyInfo { version: release.version.clone(), notes_url: release.notes_url.clone(), changes_line: release.changes_line };
    *READY.lock().unwrap() = Some(Ready {
        update,
        bytes,
        version: release.version,
        notes_url: release.notes_url,
        changes_line: release.changes_line,
        channel,
        sequence: release.sequence,
    });
    let _ = app.emit("update-ready", info);
}

/// Check on start and every few hours, while this run of the Vault lasts.
pub fn spawn(app: tauri::AppHandle, data_dir: std::path::PathBuf) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(FIRST_CHECK_AFTER).await;
        loop {
            check_once(&app, &data_dir).await;
            tokio::time::sleep(CHECK_EVERY).await;
        }
    });
}

/// Install the waiting update: the sequence and the "updated from" line are
/// kept first, the lines stopped cleanly (Windows cannot replace files in
/// use; a clean stop protects the databases), then the package installed.
/// Returns whether one was installed.
pub fn install_ready(data_dir: &Path) -> Result<bool, String> {
    let Some(ready) = READY.lock().unwrap().take() else {
        return Ok(false);
    };
    let mut saved = load(data_dir);
    saved.last_sequence.insert(ready.channel.clone(), ready.sequence);
    saved.updated_from = Some(UpdatedFrom { version: env!("CARGO_PKG_VERSION").into(), to: ready.version.clone(), notes_url: ready.notes_url.clone() });
    save(data_dir, &saved);
    crate::conductor::stop_all_lines();
    log::info!("[update] installing {}{}", ready.version, if ready.changes_line { " (it moves the data to another Holochain line on its first start)" } else { "" });
    ready.update.install(&ready.bytes).map_err(|e| format!("the update did not install: {e}"))?;
    Ok(true)
}

/// On quit: install a waiting update where that needs no one (Windows,
/// macOS). Linux asks for a password, so it installs at the button or the
/// next start's prompt instead.
pub fn install_on_quit(data_dir: &Path) {
    if cfg!(target_os = "linux") {
        return;
    }
    if let Err(e) = install_ready(data_dir) {
        log::warn!("[update] {}", e);
    }
}

fn status_of(data_dir: &Path) -> UpdateStatus {
    let saved = load(data_dir);
    let updated = saved.updated_from.clone().filter(|u| u.to == env!("CARGO_PKG_VERSION"));
    UpdateStatus {
        auto: saved.auto(),
        channel: saved.channel().into(),
        version: env!("CARGO_PKG_VERSION").into(),
        ready: READY.lock().unwrap().as_ref().map(|r| ReadyInfo { version: r.version.clone(), notes_url: r.notes_url.clone(), changes_line: r.changes_line }),
        notice: NOTICE.lock().unwrap().clone(),
        updated,
        can_update: platform().is_some() && matches!(kind(), Some(k) if k != "msi"),
    }
}

#[tauri::command]
pub fn update_status(app: tauri::AppHandle) -> UpdateStatus {
    status_of(&app.state::<std::sync::Arc<crate::commands::AppState>>().data_dir)
}

/// The person's choices: automatic updates on or off, stable or beta.
#[tauri::command]
pub fn set_update_prefs(app: tauri::AppHandle, auto: bool, channel: String) -> UpdateStatus {
    let data_dir = app.state::<std::sync::Arc<crate::commands::AppState>>().data_dir.clone();
    let mut saved = load(&data_dir);
    saved.auto = Some(auto);
    saved.channel = Some(if channel == "beta" { "beta".into() } else { "stable".into() });
    save(&data_dir, &saved);
    if !auto {
        // Off stops the check itself; a download already waiting is dropped.
        *READY.lock().unwrap() = None;
    }
    status_of(&data_dir)
}

/// After the "updated" line has been seen.
#[tauri::command]
pub fn dismiss_updated(app: tauri::AppHandle) {
    let data_dir = app.state::<std::sync::Arc<crate::commands::AppState>>().data_dir.clone();
    let mut saved = load(&data_dir);
    if saved.updated_from.take().is_some() {
        save(&data_dir, &saved);
    }
}

#[tauri::command]
pub fn restart_to_update(app: tauri::AppHandle) -> Result<(), String> {
    let data_dir = app.state::<std::sync::Arc<crate::commands::AppState>>().data_dir.clone();
    if install_ready(&data_dir)? {
        app.restart();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_channel_reads_its_own_two_files() {
        assert_eq!(latest_json_url("stable"), "https://github.com/WeAreFlowsta/flowsta-vault-app/releases/latest/download/latest.json");
        assert_eq!(manifest_url("stable"), "https://github.com/WeAreFlowsta/flowsta-vault-app/releases/latest/download/release-manifest.json");
        assert_eq!(manifest_url("beta"), "https://github.com/WeAreFlowsta/flowsta-vault-app/releases/download/vault-beta/release-manifest.json");
    }

    #[test]
    fn the_saved_choices_default_to_automatic_and_stable() {
        let dir = tempfile::tempdir().unwrap();
        let mut saved = load(dir.path());
        assert!(saved.auto());
        assert_eq!(saved.channel(), "stable");
        // The ticket is made once and kept.
        let t = ticket(dir.path(), &mut saved);
        assert!(t < 100);
        assert_eq!(load(dir.path()).rollout_ticket, Some(t));
        let mut again = load(dir.path());
        assert_eq!(ticket(dir.path(), &mut again), t);
        // An unknown channel reads as stable.
        saved.channel = Some("nightly".into());
        assert_eq!(saved.channel(), "stable");
    }

    #[test]
    fn the_signer_list_holds_team_flowsta() {
        assert_eq!(SIGNERS, &["did:flowsta:uhCAkWuA-Ehm9EVzcsPE2Wo_vpc9ImljHN8NMMEXpbtG5BdooOV9a"]);
    }
}
