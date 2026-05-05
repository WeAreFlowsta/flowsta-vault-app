//! Cross-platform helpers for spawning child processes that are tied to the
//! lifetime of the parent vault process.
//!
//! Without this, lair-keystore and the holochain conductor outlive the vault
//! when the vault is killed (SIGKILL, OOM, dev-mode reload, dpkg upgrade, …)
//! and they then hold the conductor admin-WS port, blocking the next launch.
//!
//! Linux: `prctl(PR_SET_PDEATHSIG, SIGTERM)`.
//! Windows + macOS: no-op for now. Clean exits work via the `RunEvent::Exit`
//! path; only abnormal terminations there will leak children. Job Objects
//! (Windows) and kqueue (macOS) remain TODO.
//!
//! ## Why there's no console-window hiding here
//!
//! v0.5.0 set `CREATE_NO_WINDOW` (0x08000000) on Windows to hide the
//! terminal windows that pop up for `lair-keystore.exe` and `holochain.exe`.
//! That flag does more than hide the window — it tells Windows not to
//! allocate a console handle at all. `holochain.exe` then crashed with an
//! access violation in `MSVCP140.dll` during signing-DNA WASM compilation
//! (LLVM/cranelift's stdio path dereferences the null console handle).
//!
//! v0.5.1 reverts to v0.4.2 behaviour: terminals are visible again on
//! Windows, but installs work reliably. The proper fix is to spawn via
//! `CreateProcessW` with `STARTUPINFO` configured for
//! `STARTF_USESHOWWINDOW + SW_HIDE`, which keeps the console handle valid
//! while hiding its window. That requires raw `windows-sys` / a custom
//! Child wrapper and is scheduled for a future release with Windows-VM
//! testing.

use std::process::Command;

pub trait CommandExt {
    /// Configure the child to be managed as a vault sidecar:
    /// - Linux: kernel sends `SIGTERM` when the parent dies.
    /// - Windows / macOS: no-op for now.
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
