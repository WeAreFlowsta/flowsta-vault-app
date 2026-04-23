//! Cross-platform helpers for spawning child processes that are tied to the
//! lifetime of the parent vault process.
//!
//! Without this, lair-keystore and the holochain conductor outlive the vault
//! when the vault is killed (SIGKILL, OOM, dev-mode reload, dpkg upgrade, …)
//! and they then hold the conductor admin-WS port, blocking the next launch.
//!
//! Today we cover Linux via `prctl(PR_SET_PDEATHSIG, SIGTERM)`. macOS and
//! Windows fall back to a no-op — clean exits still work via the existing
//! `RunEvent::Exit` shutdown path; only abnormal terminations there will leak.
//! Job Objects (Windows) and a `kqueue` watcher (macOS) are TODO.

use std::process::Command;

pub trait CommandExt {
    /// Configure the child so that the kernel sends it `SIGTERM` when the
    /// parent process dies, regardless of how the parent exits.
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

    #[cfg(not(target_os = "linux"))]
    fn tie_to_parent(&mut self) -> &mut Self {
        self
    }
}
