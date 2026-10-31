//! How a backup file travels between two devices of one identity.
//!
//! In pieces, as signals through the conductor both devices already run
//! (the private network's `send_piece`): no new connection, no server, and
//! it works wherever the devices' records sync. The device that wants a
//! file asks for it a few pieces at a time; the device that holds it
//! answers. What travels is the encrypted file as it sits on disk.
//!
//! A fetch that stops (the other device went to sleep) keeps the pieces it
//! has and carries on from there the next time. The wait for each answer
//! follows how long the answers have been taking.

use crate::commands::AppState;
use crate::hc::{AppClient, Line};
use holochain_types::prelude::AgentPubKey;
use holochain_types::signal::Signal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const PIECE_BYTES: usize = 512 * 1000;
/// Pieces asked for at a time.
pub const WINDOW: u32 = 4;
const FIRST_WAIT: Duration = Duration::from_secs(20);
const SHORTEST_WAIT: Duration = Duration::from_secs(15);
const LONGEST_WAIT: Duration = Duration::from_secs(180);
/// A window that does not arrive is asked for again this many times.
const TRIES_PER_WINDOW: u32 = 3;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Piece {
    /// The SHA-256 of the file this piece belongs to.
    pub id: String,
    /// "want", "data" or "none" (a backup file), or "device" (a sibling's
    /// own device record, sealed - see sealed::accept_device_piece).
    pub kind: String,
    pub seq: u32,
    pub total: u32,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Deserialize, Debug)]
struct PieceFrom {
    from: AgentPubKey,
    piece: Piece,
}

#[derive(Serialize, Debug)]
struct SendPieceInput {
    to: AgentPubKey,
    piece: Piece,
}

/// What a device asks another for: pieces `from_seq ..` of one backup file.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Want {
    pub client_id: String,
    pub label: String,
    pub sha256: String,
    pub from_seq: u32,
    pub count: u32,
}

pub fn pieces_of(len: u64) -> u32 {
    (len as usize).div_ceil(PIECE_BYTES).max(1) as u32
}

fn piece_of(bytes: &[u8], seq: u32) -> &[u8] {
    let start = (seq as usize * PIECE_BYTES).min(bytes.len());
    let end = (start + PIECE_BYTES).min(bytes.len());
    &bytes[start..end]
}

/// How long to wait for the next window, from how long the last one took.
pub fn next_wait(last_window: Option<Duration>) -> Duration {
    match last_window {
        None => FIRST_WAIT,
        Some(took) => (took * 4).clamp(SHORTEST_WAIT, LONGEST_WAIT),
    }
}

/// Where the pieces of an unfinished fetch are kept.
pub fn partial_path(identity_root: &Path, sha256: &str) -> PathBuf {
    crate::paths::backup_copies_dir(identity_root).join(".partial").join(format!("{}.part", sha256))
}

/// How many whole pieces of a file are already here (anything after the
/// last whole piece is cut off).
pub fn pieces_held(partial: &Path, total: u32) -> u32 {
    let len = std::fs::metadata(partial).map(|m| m.len()).unwrap_or(0) as usize;
    let whole = (len / PIECE_BYTES) as u32;
    let whole = whole.min(total.saturating_sub(1));
    if len != whole as usize * PIECE_BYTES {
        if let Ok(file) = std::fs::OpenOptions::new().write(true).open(partial) {
            let _ = file.set_len(whole as u64 * PIECE_BYTES as u64);
        }
    }
    whole
}

/// One end of the lane on one line: the private cell's client and role.
struct End {
    line: Line,
    client: AppClient,
    role: String,
}

/// One device's end of the lane, for as long as its conductors run: an end
/// on every line that runs here (0.6 and 0.7 while an identity has both;
/// 0.7 alone for one born on 1.7.0). A piece goes out on the line the
/// other device listens on (its device record's generation) and is
/// answered on the line it arrived on.
pub struct Lane {
    ends: Vec<End>,
    /// The agent this device runs in the private network (the same key on
    /// both lines).
    pub me: AgentPubKey,
    waiting: Mutex<BTreeMap<String, tokio::sync::mpsc::UnboundedSender<Piece>>>,
    /// The last file served, so a file is read once for all its windows.
    serving: Mutex<Option<(String, Arc<Vec<u8>>)>>,
}

/// A piece with the line it arrived on.
struct Arrived {
    line: Line,
    from: AgentPubKey,
    piece: Piece,
}

impl Lane {
    /// The lines this lane was opened on.
    pub fn lines(&self) -> Vec<Line> {
        self.ends.iter().map(|e| e.line).collect()
    }

    /// Open the lane: let sibling devices deliver pieces, and listen, on
    /// every line that runs.
    pub async fn open(state: &Arc<AppState>) -> Result<Arc<Lane>, String> {
        let mut ends = Vec::new();
        for line in [Line::V06, Line::V07] {
            if crate::hc::line_ports(state, line).is_err() {
                continue;
            }
            match crate::sealed::connect_sealed_client(state, line).await {
                Ok((client, role)) => ends.push(End { line, client, role }),
                Err(e) => log::info!("[backups] the lane did not open on the {} line: {}", line, e.chars().take(120).collect::<String>()),
            }
        }
        let first = ends.first().ok_or("no private cell reachable on any line")?;
        let me = match &first.client {
            AppClient::V06(ws) => ws.my_pub_key.clone(),
            AppClient::V07(ws) => AgentPubKey::from_raw_39(ws.my_pub_key.get_raw_39().to_vec()),
        };
        let lane = Arc::new(Lane { ends, me, waiting: Mutex::new(BTreeMap::new()), serving: Mutex::new(None) });
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Arrived>();
        for end in &lane.ends {
            lane.call_on(end.line, "ensure_piece_grant", rmp_serde::to_vec_named(&()).map_err(|e| e.to_string())?).await?;
            let tx = tx.clone();
            let line = end.line;
            match &end.client {
                AppClient::V06(ws) => {
                    ws.on_signal(move |signal| {
                        if let Signal::App { signal, .. } = signal {
                            if let Ok(arrived) = signal.into_inner().decode::<PieceFrom>() {
                                let _ = tx.send(Arrived { line, from: arrived.from, piece: arrived.piece });
                            }
                        }
                    })
                    .await;
                }
                AppClient::V07(ws) => {
                    ws.on_signal(move |signal| {
                        if let holochain_types_07::signal::Signal::App { signal, .. } = signal {
                            if let Ok(arrived) = signal.into_inner().decode::<PieceFrom>() {
                                let _ = tx.send(Arrived { line, from: arrived.from, piece: arrived.piece });
                            }
                        }
                    })
                    .await;
                }
            }
        }
        drop(tx);
        let weak = Arc::downgrade(&lane);
        let state = state.clone();
        tokio::spawn(async move {
            while let Some(arrived) = rx.recv().await {
                let Some(lane) = weak.upgrade() else { break };
                match arrived.piece.kind.as_str() {
                    "want" => {
                        let root = state.identity_root();
                        tokio::spawn(async move {
                            if let Err(e) = lane.serve(&root, arrived.from, arrived.piece, arrived.line).await {
                                log::info!("[backups] a piece was not sent: {}", e);
                            }
                        });
                    }
                    "data" | "none" => {
                        if let Some(waiting) = lane.waiting.lock().unwrap().get(&arrived.piece.id) {
                            let _ = waiting.send(arrived.piece);
                        }
                    }
                    // A sibling says it is here, with its record: the list
                    // shows it at once, and a sibling new to this device
                    // hears back about this one, on the line it spoke on.
                    "device" => match crate::sealed::accept_device_piece(&state, &arrived.piece.data) {
                        Ok(got) => {
                            crate::devices::heard_from(&arrived.from);
                            if let Some(install_id) = got.device.as_deref() {
                                crate::devices::note_heard(install_id);
                            }
                            if let (Some(install_id), Some(holds)) = (got.device.as_deref(), got.holds) {
                                crate::devices::note_holds(install_id, holds);
                            }
                            if got.new_here {
                                log::info!("[devices] a sibling's record arrived directly ({}...)", got.device.as_deref().unwrap_or("").chars().take(8).collect::<String>());
                                let state = state.clone();
                                let to = arrived.from.clone();
                                let line = arrived.line;
                                tokio::spawn(async move { crate::devices::announce_to(&state, &lane, &to, line).await });
                            }
                        }
                        Err(e) => log::info!("[devices] a device piece was not used: {}", e),
                    },
                    _ => {}
                }
            }
        });
        Ok(lane)
    }

    /// The line a sibling device listens on, from its record's generation:
    /// that line when this lane has an end on it, else whatever end there is.
    pub fn line_for(&self, generation: &str) -> Line {
        let wanted = if generation == Line::V07.generation() { Line::V07 } else { Line::V06 };
        if self.ends.iter().any(|e| e.line == wanted) {
            wanted
        } else {
            self.ends.first().map(|e| e.line).unwrap_or(wanted)
        }
    }

    fn end(&self, line: Line) -> &End {
        self.ends.iter().find(|e| e.line == line).or_else(|| self.ends.first()).expect("a lane has at least one end")
    }

    async fn call_on(&self, line: Line, function: &str, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        let end = self.end(line);
        Ok(end.client.call(&end.role, "private_data", function, payload).await?)
    }

    /// Whether every conductor this lane is open on still answers.
    pub async fn alive(&self) -> bool {
        let Ok(nothing) = rmp_serde::to_vec_named(&()) else { return false };
        for end in &self.ends {
            if self.call_on(end.line, "ensure_piece_grant", nothing.clone()).await.is_err() {
                return false;
            }
        }
        true
    }

    /// Send this device's sealed device record to a sibling.
    pub async fn send_device(&self, to: &AgentPubKey, sealed_record: Vec<u8>, line: Line) -> Result<(), String> {
        self.send(to, Piece { id: "device".into(), kind: "device".into(), seq: 0, total: 1, data: sealed_record }, line).await
    }

    async fn send(&self, to: &AgentPubKey, piece: Piece, line: Line) -> Result<(), String> {
        let input = rmp_serde::to_vec_named(&SendPieceInput { to: to.clone(), piece }).map_err(|e| e.to_string())?;
        self.call_on(line, "send_piece", input).await.map(|_| ())
    }

    /// Answer a sibling device's request with the pieces it asked for, on
    /// the line it asked on.
    async fn serve(&self, identity_root: &Path, to: AgentPubKey, request: Piece, line: Line) -> Result<(), String> {
        let want: Want = serde_json::from_slice(&request.data).map_err(|e| e.to_string())?;
        let cached = self.serving.lock().unwrap().as_ref().filter(|(sha, _)| *sha == want.sha256).map(|(_, b)| b.clone());
        let bytes = match cached {
            Some(bytes) => Some(bytes),
            None => crate::backup_sync::own_file_matching(identity_root, &want.client_id, &want.label, &want.sha256).map(|bytes| {
                let bytes = Arc::new(bytes);
                *self.serving.lock().unwrap() = Some((want.sha256.clone(), bytes.clone()));
                bytes
            }),
        };
        let Some(bytes) = bytes else {
            return self.send(&to, Piece { id: want.sha256, kind: "none".into(), seq: 0, total: 0, data: Vec::new() }, line).await;
        };
        let total = pieces_of(bytes.len() as u64);
        for seq in want.from_seq..want.from_seq.saturating_add(want.count.min(WINDOW)).min(total) {
            let piece = Piece { id: want.sha256.clone(), kind: "data".into(), seq, total, data: piece_of(&bytes, seq).to_vec() };
            self.send(&to, piece, line).await?;
        }
        Ok(())
    }

    /// Fetch one backup file from a sibling device. `size` and `sha256` are
    /// what that device's index says. Returns the file's bytes; the pieces
    /// of a fetch that stops stay on disk for the next try.
    /// `heard`: the device has reached this one directly this session. A
    /// device never heard from (closed, asleep, off) gets ONE short try,
    /// not three windows of up to 180 s each - the Mac's round spent 20
    /// minutes on a sleeping sibling (10-26).
    pub async fn fetch(
        &self,
        identity_root: &Path,
        from: &AgentPubKey,
        line: Line,
        client_id: &str,
        label: &str,
        size: u64,
        sha256: &str,
        heard: bool,
        progress: impl Fn(u32, u32),
    ) -> Result<Vec<u8>, String> {
        use std::io::Write;
        let total = pieces_of(size);
        let partial = partial_path(identity_root, sha256);
        if let Some(dir) = partial.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let mut next = pieces_held(&partial, total);

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Piece>();
        self.waiting.lock().unwrap().insert(sha256.to_string(), tx);
        let result: Result<(), String> = async {
            let mut last_window: Option<Duration> = None;
            while next < total {
                let count = WINDOW.min(total - next);
                let mut window: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
                let mut tries = 0;
                while (window.len() as u32) < count {
                    tries += 1;
                    if tries > if heard { TRIES_PER_WINDOW } else { 1 } {
                        return Err(if heard {
                            "the other device stopped answering".to_string()
                        } else {
                            "the other device has not been heard from this session".to_string()
                        });
                    }
                    let want = Want { client_id: client_id.into(), label: label.into(), sha256: sha256.into(), from_seq: next, count };
                    let request = Piece { id: sha256.into(), kind: "want".into(), seq: next, total, data: serde_json::to_vec(&want).map_err(|e| e.to_string())? };
                    self.send(from, request, line).await?;
                    let started = std::time::Instant::now();
                    let wait = if heard { next_wait(last_window) } else { FIRST_WAIT };
                    while (window.len() as u32) < count {
                        let Some(left) = wait.checked_sub(started.elapsed()) else { break };
                        match tokio::time::timeout(left, rx.recv()).await {
                            Ok(Some(piece)) if piece.kind == "none" => return Err("the other device no longer holds it".to_string()),
                            Ok(Some(piece)) if piece.total == total && piece.seq >= next && piece.seq < next + count => {
                                window.insert(piece.seq, piece.data);
                            }
                            Ok(Some(_)) => {}
                            Ok(None) | Err(_) => break,
                        }
                    }
                    if (window.len() as u32) == count {
                        last_window = Some(started.elapsed());
                    }
                }
                let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&partial).map_err(|e| e.to_string())?;
                for (_, data) in window {
                    file.write_all(&data).map_err(|e| e.to_string())?;
                }
                next += count;
                progress(next, total);
            }
            Ok(())
        }
        .await;
        self.waiting.lock().unwrap().remove(sha256);
        result?;
        let bytes = std::fs::read(&partial).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(&partial);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_is_cut_into_pieces_that_join_back() {
        assert_eq!(pieces_of(0), 1);
        assert_eq!(pieces_of(PIECE_BYTES as u64), 1);
        assert_eq!(pieces_of(PIECE_BYTES as u64 + 1), 2);
        let bytes: Vec<u8> = (0..(PIECE_BYTES * 2 + 7)).map(|i| (i % 251) as u8).collect();
        let total = pieces_of(bytes.len() as u64);
        assert_eq!(total, 3);
        let joined: Vec<u8> = (0..total).flat_map(|seq| piece_of(&bytes, seq).to_vec()).collect();
        assert_eq!(joined, bytes);
        assert_eq!(piece_of(&bytes, 2).len(), 7);
        assert!(piece_of(&bytes, 9).is_empty());
    }

    #[test]
    fn the_wait_follows_how_long_answers_take() {
        assert_eq!(next_wait(None), FIRST_WAIT);
        assert_eq!(next_wait(Some(Duration::from_secs(1))), SHORTEST_WAIT);
        assert_eq!(next_wait(Some(Duration::from_secs(20))), Duration::from_secs(80));
        assert_eq!(next_wait(Some(Duration::from_secs(600))), LONGEST_WAIT);
    }

    #[test]
    fn a_fetch_carries_on_from_the_whole_pieces_it_has() {
        let tmp = tempfile::tempdir().unwrap();
        let partial = partial_path(tmp.path(), "abc");
        assert_eq!(pieces_held(&partial, 5), 0);
        std::fs::create_dir_all(partial.parent().unwrap()).unwrap();
        std::fs::write(&partial, vec![1u8; PIECE_BYTES * 2 + 100]).unwrap();
        assert_eq!(pieces_held(&partial, 5), 2);
        assert_eq!(std::fs::metadata(&partial).unwrap().len(), (PIECE_BYTES * 2) as u64, "the part piece is cut off");
        // Never counts the last piece as held: it is shorter and is fetched again.
        std::fs::write(&partial, vec![1u8; PIECE_BYTES * 5]).unwrap();
        assert_eq!(pieces_held(&partial, 5), 4);
    }
}
