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
