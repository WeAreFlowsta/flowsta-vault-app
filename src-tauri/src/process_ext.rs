//! Cross-platform helpers for spawning child processes that are tied to the
//! lifetime of the parent vault process and (on Windows) don't pop up a
//! console window.
//!
//! Without `tie_to_parent`, lair-keystore and the holochain conductor outlive
//! the vault when the vault is killed (SIGKILL, OOM, dev-mode reload, dpkg
//! upgrade, …) and hold the conductor admin-WS port, blocking the next
//! launch.
//!
//! Without `spawn_hidden`, on Windows every Vault launch flashes two terminal
//! windows (lair-keystore.exe + holochain.exe) — visually unprofessional and
//! confusing for end users.
//!
//! Linux: `prctl(PR_SET_PDEATHSIG, SIGTERM)`.
//! Windows: post-spawn `EnumWindows` + `ShowWindow(SW_HIDE)` for the new
//! process's top-level console windows.
//! macOS: no-op for now. Clean exits work via `RunEvent::Exit`; abnormal
//! terminations on macOS / Windows can still leak children. Job Objects
//! (Windows) and kqueue (macOS) remain TODO.
//!
//! ## Why post-spawn hide instead of `CREATE_NO_WINDOW`
//!
//! v0.5.0 set `CREATE_NO_WINDOW` (0x08000000) on Windows to suppress the
//! console windows. That flag does more than hide the window — it prevents
//! Windows from allocating a console handle at all. `holochain.exe` then
//! crashed with `0xc0000005` access violation in `MSVCP140.dll` during
//! signing-DNA WASM compilation, because LLVM/cranelift's stdio path
//! dereferences the (null) console handle. v0.5.1 reverted to default flags
//! to restore reliable installs but at the cost of visible terminals.
//!
//! v0.5.2's approach: spawn normally so the console is allocated and
//! handles work, then enumerate the new process's top-level windows and
//! `ShowWindow(SW_HIDE)` each one. There's a brief flash (~50ms) while we
//! find and hide the window, but no crashes. The polled hide thread retries
//! for up to 2 seconds, so even if the window appears late we still catch
//! it. To eliminate the flash entirely, a future change could spawn with
//! `CREATE_SUSPENDED` via raw `CreateProcessW`, hide the window, then
//! `ResumeThread` — much more invasive and not necessary for the MVP.

use std::io;
use std::process::{Child, Command};

pub trait CommandExt {
    /// Configure the child to be managed as a vault sidecar:
    /// - Linux: kernel sends `SIGTERM` when the parent dies.
    /// - Windows / macOS: no-op for now.
    fn tie_to_parent(&mut self) -> &mut Self;

    /// Spawn the child, then on Windows asynchronously hide its console
    /// window. On other platforms, identical to `spawn()`.
    fn spawn_hidden(&mut self) -> io::Result<Child>;
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

    #[cfg(target_os = "windows")]
    fn spawn_hidden(&mut self) -> io::Result<Child> {
        let child = self.spawn()?;
        windows_hide::hide_console_for_pid_async(child.id());
        Ok(child)
    }

    #[cfg(not(target_os = "windows"))]
    fn spawn_hidden(&mut self) -> io::Result<Child> {
        self.spawn()
    }
}

#[cfg(target_os = "windows")]
mod windows_hide {
    //! Find any top-level windows owned by `pid` and hide them. Used to
    //! suppress the console windows that pop up when we spawn console-mode
    //! sidecars on Windows.
    //!
    //! We poll instead of using a synchronous EnumWindows call because the
    //! window may not exist yet at the moment we return from
    //! `Command::spawn` — Windows creates the console host process
    //! asynchronously. Retrying for up to 2 seconds catches it reliably
    //! across machines + load conditions.
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowThreadProcessId, IsWindowVisible, ShowWindow, SW_HIDE,
    };

    struct EnumState {
        target_pid: u32,
        hidden: bool,
    }

    unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let state = unsafe { &mut *(lparam as *mut EnumState) };
        let mut wnd_pid: u32 = 0;
        unsafe {
            GetWindowThreadProcessId(hwnd, &mut wnd_pid);
        }
        if wnd_pid == state.target_pid {
            // Only hide currently-visible windows so we don't flap if the
            // child legitimately uses a hidden window for IPC.
            if unsafe { IsWindowVisible(hwnd) } != 0 {
                unsafe {
                    ShowWindow(hwnd, SW_HIDE);
                }
                state.hidden = true;
            }
        }
        // Continue enumeration — a process may legitimately own multiple
        // top-level windows; we want to hide all of them.
        1
    }

    fn try_hide_once(target_pid: u32) -> bool {
        let mut state = EnumState {
            target_pid,
            hidden: false,
        };
        unsafe {
            EnumWindows(
                Some(enum_proc),
                &mut state as *mut EnumState as LPARAM,
            );
        }
        state.hidden
    }

    pub(super) fn hide_console_for_pid_async(pid: u32) {
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if try_hide_once(pid) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            // Window never appeared, or we couldn't find it. Not fatal —
            // worst case is a visible terminal window. Keep silent rather
            // than spamming logs.
        });
    }
}
