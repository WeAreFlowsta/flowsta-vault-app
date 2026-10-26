//! Orphaned sidecars from an earlier launch.
//!
//! The Vault runs two child processes, `vault-lair-keystore` and
//! `vault-holochain`. When the app dies without its exit path (macOS kills
//! a running app whose bundle was replaced under it; a crash; a forced
//! quit; an installer), the children live on. The Vault then picks the
//! NEXT admin port and starts a second conductor on the same agent key -
//! two conductors, one key, and gossip quietly fails for both (memory:
//! agent-key uniqueness). Seen in ProofPoll on the 2026-09-27 Mac drive;
//! the Vault has the same shape.
//!
//! Linux ties the children to the parent with `PR_SET_PDEATHSIG` and
//! Windows with a kill-on-close job (`process_ext.rs`); macOS has neither.
//! So every launch sweeps first: a sidecar whose parent is gone, or whose
//! parent is not a live Vault, belongs to nobody and is stopped. A sidecar
//! whose parent is a live Vault that is not us is left alone - that covers
//! the staging build running beside production (same binary name, another
//! path) and a second copy in another user account.
//!
//! Matching is by executable file name (the sidecar names are ours alone;
//! the kernel's short process name is cut to 15/16 bytes and would miss
//! "vault-lair-keystore"), never by port or directory, and every kill
//! names one pid.

const SIDECAR_STEMS: &[&str] = &["vault-holochain", "vault-lair-keystore", "vault-holochain-07", "vault-lair-keystore-07"];

/// What we know about a candidate process's parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Parent {
    /// The parent pid is not in the process table.
    Gone,
    /// The parent is this very process: our own child.
    Us,
    /// The parent is another live Vault (same executable name: production
    /// beside staging, or another user's copy).
    OtherVault,
    /// The parent is some live process that is not a Vault.
    Foreign,
    /// The parent is itself one of our sidecars: a thread of a running
    /// sidecar (Linux lists every thread as a process) or its own child.
    /// Part of something alive - never stopped.
    Sidecar,
}

/// The file name without a Windows extension, lower-case.
pub(crate) fn stem_of(name: &str) -> String {
    let n = name.to_lowercase();
    n.strip_suffix(".exe").map(str::to_string).unwrap_or(n)
}

pub(crate) fn is_sidecar_name(name: &str) -> bool {
    SIDECAR_STEMS.contains(&stem_of(name).as_str())
}

/// The one decision: reaped when nothing of ours holds it. `Foreign`
/// covers a sidecar adopted by a subreaper (systemd user session, a
/// terminal that ran the app): its Vault is gone all the same.
pub(crate) fn should_reap(name: &str, parent: Parent) -> bool {
    is_sidecar_name(name) && matches!(parent, Parent::Gone | Parent::Foreign)
}

/// Stop every orphaned Vault sidecar. Returns how many were stopped. Call
/// before the first sidecar of this launch spawns.
pub fn reap_orphaned_sidecars() -> u32 {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind};

    let me = sysinfo::Pid::from_u32(std::process::id());
    let my_exe = std::env::current_exe().ok();
    let my_name = my_exe
        .as_ref()
        .and_then(|p| p.file_name().map(|n| stem_of(&n.to_string_lossy())));

    let sys = System::new_with_specifics(
        RefreshKind::nothing()
            .with_processes(ProcessRefreshKind::nothing().with_exe(UpdateKind::Always)),
    );
    let procs = sys.processes();
    let full_name = |p: &sysinfo::Process| -> String {
        match p.exe().and_then(|e| e.file_name()) {
            Some(n) => n.to_string_lossy().to_string(),
            None => p.name().to_string_lossy().to_string(),
        }
    };
    // Another Vault = the same executable path, OR the same executable
    // file name at another path (staging beside production).
    let is_vault = |pid: &sysinfo::Pid| -> bool {
        procs
            .get(pid)
            .map(|p| {
                let same_path = matches!((p.exe(), my_exe.as_deref()), (Some(e), Some(mine)) if e == mine);
                same_path || Some(stem_of(&full_name(p))) == my_name
            })
            .unwrap_or(false)
    };

    let mut reaped = 0u32;
    for (pid, proc_) in procs {
        if *pid == me {
            continue;
        }
        let name = full_name(proc_);
        if !is_sidecar_name(&name) {
            continue;
        }
        // Linux lists each thread as a process; stopping a thread's id stops
        // its whole process, which may be a live sidecar of another app copy.
        if proc_.thread_kind().is_some() {
            continue;
        }
        let parent = match proc_.parent() {
            None => Parent::Gone,
            Some(pp) if pp == me => Parent::Us,
            Some(pp) if !procs.contains_key(&pp) => Parent::Gone,
            Some(pp) if procs.get(&pp).map(|q| is_sidecar_name(&full_name(q))).unwrap_or(false) => Parent::Sidecar,
            Some(pp) if is_vault(&pp) => Parent::OtherVault,
            Some(_) => Parent::Foreign,
        };
        if should_reap(&name, parent) {
            log::warn!(
                "[instance] stopping orphaned sidecar {} (pid {}, parent {:?})",
                name,
                pid,
                parent
            );
            if proc_.kill() {
                reaped += 1;
            } else {
                log::warn!("[instance] could not stop pid {}", pid);
            }
        } else if parent == Parent::OtherVault {
            log::info!(
                "[instance] sidecar {} (pid {}) belongs to another running Vault - left alone",
                name,
                pid
            );
        }
    }
    if reaped > 0 {
        // Give the kernel a beat to release the admin port.
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
    reaped
}

/// A Vault of this same install already running: the port its IPC server
/// bound and the id it minted (`paths::ipc_port_path`, written at bind). A
/// probe of its `/status` answering with that id is that Vault. A stale
/// file points at nothing, or at another account's Vault with another id,
/// and both read as "not running".
pub(crate) fn running_vault_of(data_dir: &std::path::Path) -> Option<u16> {
    let text = std::fs::read_to_string(crate::paths::ipc_port_path(data_dir)).ok()?;
    let (port, id) = parse_port_file(&text)?;
    let answer = local_http(port, "GET", "/status")?;
    answers_as(&answer, &id).then_some(port)
}

/// Ask the running Vault to show its window (`POST /show`, local callers only).
pub(crate) fn show_running_vault(port: u16) {
    let _ = local_http(port, "POST", "/show");
}

pub(crate) fn parse_port_file(text: &str) -> Option<(u16, String)> {
    let mut lines = text.lines();
    let port: u16 = lines.next()?.trim().parse().ok()?;
    let id = lines.next()?.trim().to_string();
    (!id.is_empty()).then_some((port, id))
}

pub(crate) fn answers_as(status_body: &str, instance_id: &str) -> bool {
    status_body.contains(&format!("\"instance_id\":\"{}\"", instance_id))
}

/// One short plain-HTTP exchange with the loopback server, without the
/// async runtime (this runs in setup, before anything else starts).
fn local_http(port: u16, method: &str, path: &str) -> Option<String> {
    use std::io::{Read, Write};
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(800)).ok()?;
    stream.set_read_timeout(Some(std::time::Duration::from_millis(1500))).ok()?;
    stream.set_write_timeout(Some(std::time::Duration::from_millis(800))).ok()?;
    write!(stream, "{} {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", method, path, port).ok()?;
    let mut out = String::new();
    let _ = stream.read_to_string(&mut out);
    Some(out)
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    #[test]
    fn the_port_file_names_a_port_and_an_id_and_the_status_must_carry_that_id() {
        assert_eq!(parse_port_file("27777\nabc123\n"), Some((27777, "abc123".to_string())));
        assert_eq!(parse_port_file("27777\n"), None, "no id, no match");
        assert_eq!(parse_port_file("port\nabc"), None);
        let body = "HTTP/1.1 200 OK\r\n\r\n{\"unlocked\":true,\"instance_id\":\"abc123\",\"version\":\"1.7.0\"}";
        assert!(answers_as(body, "abc123"));
        assert!(!answers_as(body, "abc124"), "another install's Vault on that port is not this one");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_our_sidecar_names_match_with_or_without_exe() {
        assert!(is_sidecar_name("vault-holochain"));
        assert!(is_sidecar_name("vault-lair-keystore.exe"));
        assert!(is_sidecar_name("Vault-Holochain.EXE"));
        assert!(!is_sidecar_name("holochain"));
        assert!(!is_sidecar_name("proofpoll-holochain"));
        assert!(!is_sidecar_name("yourowai-lair-keystore"));
        assert!(!is_sidecar_name("flowsta-vault"));
    }

    #[test]
    fn a_sidecar_is_reaped_only_when_no_live_vault_holds_it() {
        assert!(should_reap("vault-holochain", Parent::Gone));
        assert!(should_reap("vault-lair-keystore", Parent::Foreign), "adopted by a subreaper = its Vault is gone");
        assert!(!should_reap("vault-holochain", Parent::Us));
        assert!(!should_reap("vault-holochain", Parent::Sidecar), "a thread of a live sidecar is part of it");
        assert!(!should_reap("vault-holochain", Parent::OtherVault), "staging beside production keeps its children");
        assert!(!should_reap("holochain", Parent::Gone), "never anything but our own sidecars");
    }

    /// Live: a process NAMED like our sidecar, double-forked so its parent is
    /// gone, is stopped; one we spawned ourselves is kept. Ignored because it
    /// stops any orphaned Vault sidecar on the box (that is its job).
    #[test]
    #[ignore = "kills real orphaned sidecars on this machine"]
    #[cfg(unix)]
    fn live_sweep_stops_a_parentless_sidecar_and_keeps_our_own_child() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("vault-holochain");
        std::fs::copy("/bin/sleep", &fake).unwrap();
        std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("nohup {} 300 >/dev/null 2>&1 &", fake.display()))
            .status()
            .unwrap();
        let mut mine = std::process::Command::new(&fake).arg("300").spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));

        let reaped = reap_orphaned_sidecars();
        assert!(reaped >= 1, "the parentless one is stopped ({} reaped)", reaped);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(mine.try_wait().unwrap().is_none(), "our own child is kept");
        let _ = mine.kill();
        let _ = mine.wait();
        let left = std::process::Command::new("pgrep").arg("-f").arg(fake.to_string_lossy().as_ref()).output().unwrap();
        assert!(String::from_utf8_lossy(&left.stdout).trim().is_empty(), "no fake sidecar left: {:?}", left);
    }
}
