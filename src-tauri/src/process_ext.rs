//! Cross-platform helpers for spawning child processes that are tied to the
//! lifetime of the parent vault process.
//!
//! Without this, lair-keystore and the holochain conductor outlive the vault
//! when the vault is killed (SIGKILL, OOM, dev-mode reload, dpkg upgrade, …)
//! and they then hold the conductor admin-WS port, blocking the next launch.
//!
//! Linux: `prctl(PR_SET_PDEATHSIG, SIGTERM)`.
//! Windows: `CREATE_NO_WINDOW` so console-mode children don't open a terminal.
//! Lifetime tying on Windows (Job Objects) and macOS (kqueue) is still TODO —
//! clean exits work via the `RunEvent::Exit` path; only abnormal terminations
//! there will leak children.

use std::process::Command;

pub trait CommandExt {
    /// Configure the child to be managed as a vault sidecar:
    /// - Linux: kernel sends `SIGTERM` when the parent dies.
    /// - Windows: no console window is allocated for the child.
    /// - macOS: no-op for now.
    fn tie_to_parent(&mut self) -> &mut Self;
}

impl CommandExt for Command {
    #[cfg(target_os = "linux")]
    fn tie_to_parent(&mut self) -> &mut Self {
        use std::os::unix::process::CommandExt as _;
        // SAFETY: prctl with PR_SET_PDEATHSIG is async-signal-safe and only
        // touches the calling thread's signal disposition; safe to invoke
        // between fork and exec.
        unsafe {
            self.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) == -1 {
                    let err = std::io::Error::last_os_error();
                    eprintln!("warning: prctl(PR_SET_PDEATHSIG) failed: {err}");
                }
                Ok(())
            });
        }
        self
    }

    #[cfg(target_os = "windows")]
    fn tie_to_parent(&mut self) -> &mut Self {
        use std::os::windows::process::CommandExt as _;
        // CREATE_NO_WINDOW = 0x08000000. Suppresses the console window that
        // would otherwise pop up for console-mode children like
        // lair-keystore.exe and holochain.exe.
        self.creation_flags(0x08000000);
        self
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn tie_to_parent(&mut self) -> &mut Self {
        self
    }
}
