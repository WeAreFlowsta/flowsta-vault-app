//! The kit cache (flowsta-hc-lines `kit`): once a run, after the primary
//! line is up, the 0.7 kit is set aside in `<device root>/kits/`, and the
//! 0.6 kit while an identity on this device may still need 0.6; a 0.6 kit
//! nothing needs is removed. A later Vault that no longer bundles 0.6 runs
//! it from here, offline, after checking every file against the hashes it
//! compiles in.

use flowsta_hc_lines::kit::{previous_line_needed, KitCache, KitDescriptor};
use flowsta_hc_lines::Line;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

static REFRESHED: AtomicBool = AtomicBool::new(false);

/// `refresh`, once a run, on a blocking thread.
pub fn refresh_once(device_root: PathBuf, resources: PathBuf) {
    if REFRESHED.swap(true, Ordering::SeqCst) {
        return;
    }
    tauri::async_runtime::spawn_blocking(move || refresh(&device_root, &resources));
}

pub fn refresh(device_root: &Path, resources: &Path) {
    let cache = KitCache::new(crate::paths::kits_dir(device_root));
    let sidecars = crate::sidecar_source();
    let put = |kit: &KitDescriptor| match cache.put(kit, &sidecars, resources) {
        Ok(p) if p.written.is_empty() => log::debug!("[kit] the {} kit is cached as it is ({} KB)", p.line, p.packed / 1024),
        Ok(p) => log::info!("[kit] the {} kit cached: {} written, {} as before ({} KB)", p.line, p.written.join(", "), p.kept, p.packed / 1024),
        Err(e) => log::warn!("[kit] the {} kit not cached: {}", kit.line, e),
    };
    put(&crate::dna::KIT_07);
    if needs_06(device_root) {
        put(&crate::dna::KIT_06);
    } else {
        match cache.prune(&[Line::V07]) {
            Ok(0) => {}
            Ok(freed) => log::info!("[kit] the 0.6 kit removed ({} KB): no identity on this device needs 0.6", freed / 1024),
            Err(e) => log::warn!("[kit] the 0.6 kit not removed: {}", e),
        }
    }
}

/// Whether an identity on this device may still need the 0.6 line: one
/// that has not moved and has a 0.6 conductor folder, or one whose marker
/// still wants 0.6 or records no complete carry yet.
pub fn needs_06(device_root: &Path) -> bool {
    let roots: Vec<PathBuf> = crate::identities::list_on_disk(device_root, device_root).into_iter().map(|e| PathBuf::from(e.root)).collect();
    previous_line_needed(&roots, &crate::move_07::MARKER_SPEC, |root| crate::paths::conductor_dir(root).exists())
}

/// Each line's kit by the cache's own record (for the harness).
pub fn status(device_root: &Path) -> serde_json::Value {
    let cache = KitCache::new(crate::paths::kits_dir(device_root));
    let line = |l: Line| match cache.manifest(l) {
        Some(m) => serde_json::json!({ "entries": m.entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>(), "packed": m.packed_bytes(), "target": m.target }),
        None => serde_json::Value::Null,
    };
    serde_json::json!({ "holochain-0.6": line(Line::V06), "holochain-0.7": line(Line::V07) })
}

/// Restore a line's kit and run each binary's `--version` (the harness's
/// proof that a cached kit comes back runnable). The release accepts no
/// binary build yet, so this accepts exactly the bundled ones.
#[cfg(debug_assertions)]
pub fn restore_for_test(device_root: &Path, line: Line) -> Result<serde_json::Value, String> {
    let bundled = match line {
        Line::V06 => crate::dna::KIT_06,
        Line::V07 => crate::dna::KIT_07,
    };
    let accept = |bin: &flowsta_hc_lines::kit::KitBinary| -> Result<&'static [(&'static str, &'static str)], String> {
        let path = flowsta_hc_lines::resolve_sidecar(bin.sidecar, &flowsta_hc_lines::SidecarSource { allow_path_lookup: false, ..crate::sidecar_source() }).map_err(|e| e.to_string())?;
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {}", path.display(), e))?;
        use sha2::Digest;
        let sha = Box::leak(hex::encode(sha2::Sha256::digest(&bytes)).into_boxed_str());
        Ok(Box::leak(vec![(flowsta_hc_lines::TARGET_TRIPLE, &*sha)].into_boxed_slice()))
    };
    let kit = KitDescriptor {
        conductor: flowsta_hc_lines::kit::KitBinary { accepted: accept(&bundled.conductor)?, ..bundled.conductor },
        lair: flowsta_hc_lines::kit::KitBinary { accepted: accept(&bundled.lair)?, ..bundled.lair },
        ..bundled
    };
    let restored = KitCache::new(crate::paths::kits_dir(device_root)).restore(&kit).map_err(|e| e.to_string())?;
    let version = |bin: &Path| -> String {
        let mut cmd = std::process::Command::new(bin);
        cmd.arg("--version");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        match cmd.output() {
            Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
            Err(e) => format!("did not run: {}", e),
        }
    };
    Ok(serde_json::json!({
        "dir": restored.dir,
        "conductor": version(&restored.conductor),
        "lair": version(&restored.lair),
        "files": kit.files.iter().filter(|f| restored.dir.join(f.name).is_file()).count(),
    }))
}
