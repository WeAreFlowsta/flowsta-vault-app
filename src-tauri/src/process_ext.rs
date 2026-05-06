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
        let pid = child.id();
        log::info!("[hide] spawned child pid {pid}, dispatching async hide thread");
        windows_hide::hide_console_for_pid_async(pid);
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
    //! ## Why always-hide on every poll
    //!
    //! The previous implementation exited early when it found a matching
    //! window that wasn't currently visible (`IsWindowVisible == 0`),
    //! reasoning the child was using a hidden IPC window we shouldn't
    //! flap. That was wrong — Windows console hosts (conhost) create
    //! their window with WS_VISIBLE off and toggle it on later, often
    //! after our few-poll budget had already elapsed. Result: terminal
    //! windows reliably appeared after we'd "given up".
    //!
    //! Now we poll for the full 3 s budget at 50 ms intervals and call
    //! `ShowWindow(SW_HIDE)` on every match every iteration regardless of
    //! current visibility. `SW_HIDE` is idempotent on already-hidden
    //! windows, so the worst case is a 50 ms visibility flicker between
    //! the OS toggling `WS_VISIBLE` on and our next poll catching it.
    //!
    //! We also log the window class on the first match per pid so we can
    //! verify we're finding the actual `ConsoleWindowClass` window vs.
    //! some unrelated internal window.
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameW, GetWindowThreadProcessId, IsWindowVisible, ShowWindow, SW_HIDE,
    };

    struct EnumState {
        target_pid: u32,
        hides: u32,
        hides_while_visible: u32,
        first_class: Option<String>,
    }

    fn get_window_class(hwnd: HWND) -> String {
        let mut buf = [0u16; 256];
        let len = unsafe { GetClassNameW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
        if len > 0 {
            String::from_utf16_lossy(&buf[..len as usize])
        } else {
            String::new()
        }
    }

    unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let state = unsafe { &mut *(lparam as *mut EnumState) };
        let mut wnd_pid: u32 = 0;
        unsafe {
            GetWindowThreadProcessId(hwnd, &mut wnd_pid);
        }
        if wnd_pid == state.target_pid {
            if state.first_class.is_none() {
                state.first_class = Some(get_window_class(hwnd));
            }
            // Always hide regardless of current visibility. ShowWindow(SW_HIDE)
            // on an already-hidden window is a cheap no-op; this catches the
            // race where conhost toggles WS_VISIBLE on between our polls.
            let was_visible = unsafe { IsWindowVisible(hwnd) } != 0;
            unsafe {
                ShowWindow(hwnd, SW_HIDE);
            }
            state.hides += 1;
            if was_visible {
                state.hides_while_visible += 1;
            }
        }
        // Continue enumeration — a process may legitimately own multiple
        // top-level windows; we want to hide all of them.
        1
    }

    fn try_hide_once(target_pid: u32) -> EnumState {
        let mut state = EnumState {
            target_pid,
            hides: 0,
            hides_while_visible: 0,
            first_class: None,
        };
        unsafe {
            EnumWindows(
                Some(enum_proc),
                &mut state as *mut EnumState as LPARAM,
            );
        }
        state
    }

    pub(super) fn hide_console_for_pid_async(pid: u32) {
        std::thread::spawn(move || {
            let started = Instant::now();
            let deadline = started + Duration::from_secs(3);
            log::info!("[hide:{pid}] thread started");
            let mut iter: u32 = 0;
            let mut total_hides: u32 = 0;
            let mut total_visible_hides: u32 = 0;
            let mut logged_class = false;
            while Instant::now() < deadline {
                iter += 1;
                let state = try_hide_once(pid);
                total_hides += state.hides;
                total_visible_hides += state.hides_while_visible;
                if !logged_class {
                    if let Some(class) = state.first_class.as_ref() {
                        log::info!(
                            "[hide:{pid}] first match window class: '{}' (after {}ms)",
                            class,
                            started.elapsed().as_millis(),
                        );
                        logged_class = true;
                    }
                }
                if state.hides_while_visible > 0 {
                    log::info!(
                        "[hide:{pid}] hid {} visible window(s) on iter {} ({}ms elapsed)",
                        state.hides_while_visible,
                        iter,
                        started.elapsed().as_millis(),
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            log::info!(
                "[hide:{pid}] thread exited after {}ms ({} iters, {} total hide calls, {} hides-while-visible, class={:?})",
                started.elapsed().as_millis(),
                iter,
                total_hides,
                total_visible_hides,
                logged_class,
            );
        });
    }
}
