//! Which account on this computer is talking to the Vault.
//!
//! The Vault listens on 127.0.0.1, and loopback ports are shared by every
//! user account on the computer. The Vault answers only its own account.
//!
//! Every connection is traced to the process at the other end:
//!
//! - Linux: `/proc/net/tcp(6)` lists every socket with its owner's uid.
//! - macOS: `lsof` for the client's port, limited to this account's
//!   processes. Without admin rights `lsof` cannot see other accounts'
//!   processes at all, so "not one of mine" is the answer for them.
//! - Windows: the TCP table names the owning pid; the connection is ours
//!   when that process runs in this Windows session. Another account's
//!   process is in another session, or cannot be queried at all.
//!
//! The lookup runs once per connection (the first request on it) and the
//! answer stays with that connection only, so a port that another account
//! reuses later is checked afresh. When the lookup itself cannot run
//! (`Unknown`), the Vault answers and logs it: a broken tool must never lock
//! the owner out of their own Vault.

use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A process of this account.
    Mine,
    /// Another account's process (or one this account cannot see).
    Other,
    /// The lookup could not run; treated as mine, logged.
    Unknown,
}

/// Per-connection info axum hands to every request on that connection.
#[derive(Clone, Debug)]
pub struct Peer {
    pub remote: SocketAddr,
    pub local_port: u16,
    verdict: Arc<tokio::sync::OnceCell<Verdict>>,
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_>> for Peer {
    fn connect_info(target: axum::serve::IncomingStream<'_>) -> Self {
        Peer {
            remote: target.remote_addr(),
            local_port: target.local_addr().map(|a| a.port()).unwrap_or(0),
            verdict: Arc::new(tokio::sync::OnceCell::new()),
        }
    }
}

impl Peer {
    /// A connection whose owner is already known (tests only).
    #[cfg(test)]
    pub fn known(verdict: Verdict) -> Self {
        let cell = tokio::sync::OnceCell::new();
        let _ = cell.set(verdict);
        Peer {
            remote: SocketAddr::from(([127, 0, 0, 1], 50000)),
            local_port: 27777,
            verdict: Arc::new(cell),
        }
    }

    /// Whose connection this is. Looked up on first use, then remembered for
    /// the life of the connection.
    pub async fn verdict(&self) -> Verdict {
        let remote = self.remote;
        let local_port = self.local_port;
        *self
            .verdict
            .get_or_init(|| async move {
                let started = std::time::Instant::now();
                let v = tokio::task::spawn_blocking(move || lookup(remote, local_port))
                    .await
                    .unwrap_or(Verdict::Unknown);
                let ms = started.elapsed().as_millis();
                match v {
                    Verdict::Mine => log::debug!("[owner] {remote} is this account ({ms} ms)"),
                    Verdict::Other => log::warn!("[owner] {remote} belongs to another account on this computer - refused ({ms} ms)"),
                    Verdict::Unknown => log::warn!("[owner] could not tell who owns {remote} - answering ({ms} ms)"),
                }
                v
            })
            .await
    }
}

fn lookup(remote: SocketAddr, local_port: u16) -> Verdict {
    if !remote.ip().is_loopback() {
        // The server binds 127.0.0.1 only; anything else is not local.
        return Verdict::Other;
    }
    platform::lookup(remote.port(), local_port)
}

// ── Linux ────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod platform {
    use super::Verdict;

    pub fn lookup(peer_port: u16, local_port: u16) -> Verdict {
        // SAFETY: getuid cannot fail.
        let me = unsafe { libc::getuid() };
        let mut read_any = false;
        for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(text) = std::fs::read_to_string(f) {
                read_any = true;
                if let Some(uid) = super::proc_net_client_uid(&text, peer_port, local_port) {
                    return if uid == me { Verdict::Mine } else { Verdict::Other };
                }
            }
        }
        if read_any {
            // Every socket is listed here whoever owns it: absent = already
            // closed. Nothing to answer.
            Verdict::Other
        } else {
            Verdict::Unknown
        }
    }
}

// ── macOS ────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod platform {
    use super::Verdict;
    use std::time::{Duration, Instant};

    pub fn lookup(peer_port: u16, _local_port: u16) -> Verdict {
        // SAFETY: getuid cannot fail.
        let me = unsafe { libc::getuid() };
        let child = std::process::Command::new("/usr/sbin/lsof")
            .args([
                "-nP",
                "-w",
                "-a",
                "-u",
                &me.to_string(),
                &format!("-iTCP:{peer_port}"),
                "-Fpun",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(_) => return Verdict::Unknown,
        };
        // A wedged lsof must not hold the request: 1 s, then give up.
        let deadline = Instant::now() + Duration::from_millis(1000);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Verdict::Unknown;
                }
            }
        }
        let mut out = String::new();
        if let Some(mut so) = child.stdout.take() {
            use std::io::Read;
            let _ = so.read_to_string(&mut out);
        }
        match super::lsof_client_uid(&out, peer_port, std::process::id()) {
            Some(uid) if uid == me => Verdict::Mine,
            // Listed only with admin rights; without them another account's
            // process is simply absent.
            Some(_) | None => Verdict::Other,
        }
    }
}

// ── Windows ──────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod platform {
    use super::Verdict;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;

    fn owning_pid(peer_port: u16, local_port: u16) -> Result<Option<u32>, ()> {
        let mut size: u32 = 0;
        // SAFETY: a null buffer with size 0 asks for the needed size.
        unsafe {
            GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        }
        for _ in 0..3 {
            // u32 words keep the table aligned for its u32 fields.
            let mut buf: Vec<u32> = vec![0; (size as usize + 3) / 4 + 64];
            let mut cap = (buf.len() * 4) as u32;
            // SAFETY: buf holds `cap` bytes; the call writes at most that.
            let rc = unsafe {
                GetExtendedTcpTable(buf.as_mut_ptr() as *mut _, &mut cap, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0)
            };
            if rc == 122 {
                // ERROR_INSUFFICIENT_BUFFER: the table grew; retry bigger.
                size = cap;
                continue;
            }
            if rc != 0 {
                return Err(());
            }
            // SAFETY: on success the buffer starts with a MIB_TCPTABLE_OWNER_PID
            // followed by dwNumEntries rows, all inside the buffer.
            let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
            let n = unsafe { (*table).dwNumEntries } as usize;
            let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr() as *const MIB_TCPROW_OWNER_PID, n) };
            for r in rows {
                let lp = u16::from_be((r.dwLocalPort & 0xffff) as u16);
                let rp = u16::from_be((r.dwRemotePort & 0xffff) as u16);
                if lp == peer_port && rp == local_port {
                    return Ok(Some(r.dwOwningPid));
                }
            }
            return Ok(None);
        }
        Err(())
    }

    fn session_of(pid: u32) -> Option<u32> {
        let mut sid: u32 = 0;
        // SAFETY: out-pointer to a u32.
        if unsafe { ProcessIdToSessionId(pid, &mut sid) } == 0 {
            None
        } else {
            Some(sid)
        }
    }

    pub fn lookup(peer_port: u16, local_port: u16) -> Verdict {
        let pid = match owning_pid(peer_port, local_port) {
            Ok(Some(pid)) => pid,
            // Listed whoever owns it: absent = already closed.
            Ok(None) => return Verdict::Other,
            Err(()) => return Verdict::Unknown,
        };
        // SAFETY: no arguments.
        let me = match session_of(unsafe { GetCurrentProcessId() }) {
            Some(s) => s,
            None => return Verdict::Unknown,
        };
        match session_of(pid) {
            Some(s) if s == me => Verdict::Mine,
            // Another session, or a process this account may not query.
            _ => Verdict::Other,
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod platform {
    use super::Verdict;
    pub fn lookup(_peer_port: u16, _local_port: u16) -> Verdict {
        Verdict::Unknown
    }
}

// ── Parsers (platform-independent so they are tested everywhere) ─────────

/// The uid owning the CLIENT end of a loopback connection in a
/// /proc/net/tcp(6) table: the row whose local port is the client's port
/// and whose remote port is ours.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn proc_net_client_uid(text: &str, peer_port: u16, local_port: u16) -> Option<u32> {
    let port_of = |addr: &str| addr.rsplit(':').next().and_then(|p| u16::from_str_radix(p, 16).ok());
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        if port_of(cols[1]) == Some(peer_port) && port_of(cols[2]) == Some(local_port) {
            return cols[7].parse().ok();
        }
    }
    None
}

/// The uid owning the CLIENT end of a connection in `lsof -Fpun` output:
/// a file whose name starts "<addr>:<peer_port>->", in a process other
/// than ours (our own socket names the same port as its remote end).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn lsof_client_uid(text: &str, peer_port: u16, our_pid: u32) -> Option<u32> {
    let mut pid: Option<u32> = None;
    let mut uid: Option<u32> = None;
    let needle = format!(":{peer_port}->");
    for line in text.lines() {
        let (tag, val) = match line.chars().next() {
            Some(c) => (c, &line[c.len_utf8()..]),
            None => continue,
        };
        match tag {
            'p' => {
                pid = val.parse().ok();
                uid = None;
            }
            'u' => uid = val.parse().ok(),
            'n' => {
                if pid != Some(our_pid) {
                    if let Some(arrow) = val.find("->") {
                        if val[..arrow + 2].ends_with(&needle) {
                            return uid;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_net_names_the_client_end() {
        // 127.0.0.1:52341 (0xCC75) -> 127.0.0.1:27777 (0x6C81), uid 1001;
        // the Vault's own end 27777 -> 52341, uid 1000.
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:6C81 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11 1 0 100 0 0 10 0
   1: 0100007F:6C81 0100007F:CC75 01 00000000:00000000 00:00000000 00000000  1000        0 12 1 0 20 4 30 10 -1
   2: 0100007F:CC75 0100007F:6C81 01 00000000:00000000 00:00000000 00000000  1001        0 13 1 0 20 4 30 10 -1";
        assert_eq!(proc_net_client_uid(text, 52341, 27777), Some(1001));
        assert_eq!(proc_net_client_uid(text, 52342, 27777), None);
        // The listener and the Vault's own end are never mistaken for the client.
        assert_eq!(proc_net_client_uid(text, 27777, 52341), Some(1000));
    }

    /// A real loopback connection from this process is this account's.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn a_real_connection_from_this_account_is_mine() {
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server_port = server.local_addr().unwrap().port();
        let client = std::net::TcpStream::connect(("127.0.0.1", server_port)).unwrap();
        let (_accepted, remote) = server.accept().unwrap();
        assert_eq!(remote.port(), client.local_addr().unwrap().port());
        assert_eq!(lookup(remote, server_port), Verdict::Mine);
        // A port nobody holds is not ours to answer.
        drop(client);
        drop(_accepted);
    }

    #[test]
    fn lsof_names_the_client_end_and_skips_our_own_socket() {
        let text = "p500\nu501\nf22\nn127.0.0.1:27777->127.0.0.1:52341\np812\nu501\nf40\nn127.0.0.1:52341->127.0.0.1:27777\n";
        assert_eq!(lsof_client_uid(text, 52341, 500), Some(501));
        // Only our own socket listed (the client is another account's
        // process, invisible to us): no client found.
        let ours_only = "p500\nu501\nf22\nn127.0.0.1:27777->127.0.0.1:52341\n";
        assert_eq!(lsof_client_uid(ours_only, 52341, 500), None);
        // A different port that merely contains the digits does not match.
        let other = "p812\nu501\nf40\nn127.0.0.1:152341->127.0.0.1:27777\n";
        assert_eq!(lsof_client_uid(other, 52341, 500), None);
        assert_eq!(lsof_client_uid("", 52341, 500), None);
    }
}
