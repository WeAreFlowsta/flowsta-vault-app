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
use holochain_client::{AppWebsocket, ZomeCallTarget};
use holochain_types::prelude::{AgentPubKey, ExternIO};
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
    /// "want", "data" or "none".
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

/// One device's end of the lane, for as long as its conductor runs.
pub struct Lane {
    ws: AppWebsocket,
    role: String,
    /// The agent this device runs in the private network.
    pub me: AgentPubKey,
    waiting: Mutex<BTreeMap<String, tokio::sync::mpsc::UnboundedSender<Piece>>>,
    /// The last file served, so a file is read once for all its windows.
    serving: Mutex<Option<(String, Arc<Vec<u8>>)>>,
}

impl Lane {
    /// Open the lane: let sibling devices deliver pieces, and listen.
    pub async fn open(state: &Arc<AppState>) -> Result<Arc<Lane>, String> {
        let (admin_port, app_port) = crate::sealed::conductor_ports(state)?;
        let (ws, role) = crate::sealed::connect_sealed_app_ws(state, admin_port, app_port).await?;
        let lane = Arc::new(Lane {
            me: ws.my_pub_key.clone(),
            ws,
            role,
            waiting: Mutex::new(BTreeMap::new()),
            serving: Mutex::new(None),
        });
        lane.call("ensure_piece_grant", ExternIO::encode(()).map_err(|e| e.to_string())?).await?;

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PieceFrom>();
        lane.ws
            .on_signal(move |signal| {
                if let Signal::App { signal, .. } = signal {
                    if let Ok(arrived) = signal.into_inner().decode::<PieceFrom>() {
                        let _ = tx.send(arrived);
                    }
                }
            })
            .await;
        let weak = Arc::downgrade(&lane);
        let state = state.clone();
        tokio::spawn(async move {
            while let Some(arrived) = rx.recv().await {
                let Some(lane) = weak.upgrade() else { break };
                match arrived.piece.kind.as_str() {
                    "want" => {
                        let root = state.identity_root();
                        tokio::spawn(async move {
                            if let Err(e) = lane.serve(&root, arrived.from, arrived.piece).await {
                                log::info!("[backups] a piece was not sent: {}", e);
                            }
                        });
                    }
                    "data" | "none" => {
                        if let Some(waiting) = lane.waiting.lock().unwrap().get(&arrived.piece.id) {
                            let _ = waiting.send(arrived.piece);
                        }
                    }
                    _ => {}
                }
            }
        });
        Ok(lane)
    }

    async fn call(&self, function: &str, payload: ExternIO) -> Result<ExternIO, String> {
        self.ws
            .call_zome(ZomeCallTarget::RoleName(self.role.clone()), "private_data".into(), function.into(), payload)
            .await
            .map_err(|e| format!("{} failed: {:?}", function, e))
    }

    /// Whether the conductor still answers on this lane.
    pub async fn alive(&self) -> bool {
        match ExternIO::encode(()) {
            Ok(nothing) => self.call("ensure_piece_grant", nothing).await.is_ok(),
            Err(_) => false,
        }
    }

    async fn send(&self, to: &AgentPubKey, piece: Piece) -> Result<(), String> {
        let input = ExternIO::encode(SendPieceInput { to: to.clone(), piece }).map_err(|e| e.to_string())?;
        self.call("send_piece", input).await.map(|_| ())
    }

    /// Answer a sibling device's request with the pieces it asked for.
    async fn serve(&self, identity_root: &Path, to: AgentPubKey, request: Piece) -> Result<(), String> {
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
            return self.send(&to, Piece { id: want.sha256, kind: "none".into(), seq: 0, total: 0, data: Vec::new() }).await;
        };
        let total = pieces_of(bytes.len() as u64);
        for seq in want.from_seq..want.from_seq.saturating_add(want.count.min(WINDOW)).min(total) {
            let piece = Piece { id: want.sha256.clone(), kind: "data".into(), seq, total, data: piece_of(&bytes, seq).to_vec() };
            self.send(&to, piece).await?;
        }
        Ok(())
    }

    /// Fetch one backup file from a sibling device. `size` and `sha256` are
    /// what that device's index says. Returns the file's bytes; the pieces
    /// of a fetch that stops stay on disk for the next try.
    pub async fn fetch(
        &self,
        identity_root: &Path,
        from: &AgentPubKey,
        client_id: &str,
        label: &str,
        size: u64,
        sha256: &str,
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
                    if tries > TRIES_PER_WINDOW {
                        return Err("the other device stopped answering".to_string());
                    }
                    let want = Want { client_id: client_id.into(), label: label.into(), sha256: sha256.into(), from_seq: next, count };
                    let request = Piece { id: sha256.into(), kind: "want".into(), seq: next, total, data: serde_json::to_vec(&want).map_err(|e| e.to_string())? };
                    self.send(from, request).await?;
                    let started = std::time::Instant::now();
                    let wait = next_wait(last_window);
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
