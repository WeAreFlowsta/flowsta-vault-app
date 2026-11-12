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

/// Stop every orphaned Vault sidecar (the rule and the sweep live in
/// `flowsta-hc-lines`). Returns how many were stopped. Call before the
/// first sidecar of this launch spawns.
pub fn reap_orphaned_sidecars() -> u32 {
    flowsta_hc_lines::reap::reap_orphaned_sidecars(SIDECAR_STEMS)
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

/// What holds a local-API port this start could not bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Holder {
    /// It answered an HTTP request: a running Vault (another account's, or
    /// another install's) or some other program. Never touched.
    pub answers: bool,
    /// The process listening there, when the system names it.
    pub pid: Option<u32>,
    /// That process runs this same program file, as this same user.
    pub same_program_and_user: bool,
}

/// Pure: a holder that is this same Vault program, run by this same user,
/// and no longer answers is a Vault that did not finish closing (seen on
/// Windows after an update install: the old process kept port 27777, the
/// new one moved to 27778, then 27779). It is ended so this start takes
/// the port every app looks at first. Anything that answers, or is not
/// ours, is left alone.
pub(crate) fn holder_to_end(h: &Holder, my_pid: u32) -> Option<u32> {
    match h.pid {
        Some(pid) if !h.answers && h.same_program_and_user && pid != my_pid => Some(pid),
        _ => None,
    }
}

/// The pids LISTENING on `port` in `netstat -ano -p TCP` output; a line
/// whose FOREIGN address is the port is a client connection, not a holder.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn netstat_listening_pids(text: &str, port: u16) -> Vec<u32> {
    let suffix = format!(":{port}");
    text.lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 5 || cols[0] != "TCP" || !cols[1].ends_with(&suffix) || cols[3] != "LISTENING" {
                return None;
            }
            cols[4].parse().ok()
        })
        .collect()
}

#[cfg(windows)]
fn listening_pid(port: u16) -> Option<u32> {
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new("netstat")
        .args(["-ano", "-p", "TCP"])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output()
        .ok()?;
    netstat_listening_pids(&String::from_utf8_lossy(&out.stdout), port).into_iter().next()
}

/// Only Windows has shown a Vault that stays behind holding its port; the
/// other systems keep today's behavior (the next port).
#[cfg(not(windows))]
fn listening_pid(_port: u16) -> Option<u32> {
    None
}

/// Read what holds `port`: does it answer (three tries, a busy Vault
/// answers `/status` from its own runtime in milliseconds), which process
/// it is, and whether that process is this program run by this user.
pub(crate) fn holder_of(port: u16) -> Holder {
    let answers = (0..3).any(|i| {
        if i > 0 {
            std::thread::sleep(std::time::Duration::from_millis(700));
        }
        local_http(port, "GET", "/status").is_some_and(|a| a.starts_with("HTTP/"))
    });
    if answers {
        return Holder { answers, pid: None, same_program_and_user: false };
    }
    let pid = listening_pid(port);
    let same_program_and_user = pid.is_some_and(|pid| {
        use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind};
        let sys = System::new_with_specifics(RefreshKind::nothing().with_processes(
            ProcessRefreshKind::nothing().with_exe(UpdateKind::Always).with_user(UpdateKind::Always),
        ));
        let me = sys.process(sysinfo::Pid::from_u32(std::process::id()));
        let it = sys.process(sysinfo::Pid::from_u32(pid));
        match (me, it) {
            (Some(me), Some(it)) => me.exe().is_some() && me.exe() == it.exe() && me.user_id().is_some() && me.user_id() == it.user_id(),
            _ => false,
        }
    });
    Holder { answers, pid, same_program_and_user }
}

/// End the Vault that stayed behind on `port`, when that is what holds it.
/// Returns whether one was ended (the caller then binds the port again).
pub(crate) fn end_vault_left_behind(port: u16) -> bool {
    let holder = holder_of(port);
    let Some(pid) = holder_to_end(&holder, std::process::id()) else {
        log::info!("[instance] port {port} is held by {}", match (&holder.answers, holder.pid) {
            (true, _) => "a program that answers: left alone".to_string(),
            (false, Some(pid)) => format!("process {pid}, which does not answer and is not this Vault program run by this user: left alone"),
            (false, None) => "something that does not answer; its process was not read".to_string(),
        });
        return false;
    };
    use sysinfo::{ProcessRefreshKind, RefreshKind, System};
    let mut sys = System::new_with_specifics(RefreshKind::nothing().with_processes(ProcessRefreshKind::nothing()));
    let target = sysinfo::Pid::from_u32(pid);
    let killed = sys.process(target).is_some_and(|p| p.kill());
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[target]), true);
        if sys.process(target).is_none() {
            log::warn!("[instance] an earlier Vault (process {pid}) still held port {port} and did not answer: ended, and this start takes the port");
            return true;
        }
    }
    log::warn!("[instance] an earlier Vault (process {pid}) holds port {port} and does not answer; it could not be ended (asked: {killed})");
    false
}

#[cfg(test)]
mod left_behind_tests {
    use super::*;

    #[test]
    fn only_a_silent_vault_of_this_program_and_user_is_ended() {
        let silent_ours = Holder { answers: false, pid: Some(4242), same_program_and_user: true };
        assert_eq!(holder_to_end(&silent_ours, 1), Some(4242));
        assert_eq!(holder_to_end(&Holder { answers: true, ..silent_ours.clone() }, 1), None, "a Vault that answers is running: the hand-over or the next port");
        assert_eq!(holder_to_end(&Holder { same_program_and_user: false, ..silent_ours.clone() }, 1), None, "another program, another install or another user's Vault");
        assert_eq!(holder_to_end(&Holder { pid: None, ..silent_ours.clone() }, 1), None, "no process named: nothing to end");
        assert_eq!(holder_to_end(&silent_ours, 4242), None, "never this process");
    }

    #[test]
    fn netstat_names_the_process_listening_on_the_port() {
        let text = "\r\nActive Connections\r\n\r\n  Proto  Local Address          Foreign Address        State           PID\r\n  TCP    127.0.0.1:27777        0.0.0.0:0              LISTENING       18204\r\n  TCP    127.0.0.1:27778        0.0.0.0:0              LISTENING       5548\r\n  TCP    127.0.0.1:51000        127.0.0.1:27777        ESTABLISHED     900\r\n  TCP    127.0.0.1:127777       0.0.0.0:0              LISTENING       7\r\n";
        assert_eq!(netstat_listening_pids(&text, 27777), vec![18204]);
        assert_eq!(netstat_listening_pids(&text, 27778), vec![5548]);
        assert!(netstat_listening_pids(&text, 27779).is_empty());
    }
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
    fn the_vault_names_all_four_of_its_sidecars() {
        use flowsta_hc_lines::reap::is_sidecar_name;
        for n in ["vault-holochain", "vault-lair-keystore.exe", "vault-holochain-07", "Vault-Lair-Keystore-07.EXE"] {
            assert!(is_sidecar_name(n, SIDECAR_STEMS), "{n}");
        }
        assert!(!is_sidecar_name("proofpoll-holochain", SIDECAR_STEMS));
        assert!(!is_sidecar_name("flowsta-vault", SIDECAR_STEMS));
    }
}
