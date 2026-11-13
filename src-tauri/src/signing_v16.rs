//! Signing v1.6 on the 0.7 line: a carried record's original as the DNA
//! checks it (the exact bytes its author signed, the signature, the entry),
//! from a v1.5 record this device wrote (its source chain) or a v1.5 copy of
//! a v1.4 record (its stored signed action, the entry rebuilt), checked here
//! first, so nothing is submitted that the network refuses. `pass` carries
//! what this device wrote on v1.5 and switches its writes to v1.6.
//!
//! Each line's own types re-encode a decoded action to exactly the bytes its
//! author signed (both lines use one serializer); the signature check below
//! is what proves it on each record.

use crate::commands::AppState;
use crate::hc::{AppClient, Line};
use holochain_types_07::prelude::{ActionHash, AgentPubKey, Signature, Timestamp};
use serde::Serialize;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// The signing zome's entry kinds on v1.4 and v1.5 (zome 0, this order).
pub(crate) const SIGNATURE_ENTRY: u8 = 0;
pub(crate) const REVOCATION_ENTRY: u8 = 1;
pub(crate) const THUMBNAIL_ENTRY: u8 = 2;

/// The coordinator's `Original`, field for field.
#[derive(Serialize, Debug, Clone)]
pub(crate) struct Original {
    pub dna: String,
    pub action_hash: ActionHash,
    pub author: AgentPubKey,
    pub timestamp: Timestamp,
    #[serde(with = "serde_bytes")]
    pub action: Vec<u8>,
    pub signature: Signature,
    #[serde(with = "serde_bytes")]
    pub entry: Vec<u8>,
}

fn blake2b_256(bytes: &[u8]) -> Vec<u8> {
    use blake2::Digest;
    blake2::Blake2b::<blake2::digest::consts::U32>::digest(bytes).to_vec()
}

/// A v1.4 original from its 0.6 signed action (MessagePack of a
/// `SignedActionHashed`, as a record view keeps it) and its entry's bytes.
pub(crate) fn from_06(signed_action: &[u8], entry: &[u8]) -> Result<Original, String> {
    let sah: holochain_types::prelude::SignedActionHashed =
        rmp_serde::from_slice(signed_action).map_err(|e| format!("the 0.6 signed action does not decode: {e}"))?;
    let action = holochain_types::prelude::encode(sah.action()).map_err(|e| format!("encode the 0.6 action: {e}"))?;
    Ok(Original {
        dna: "1.4".into(),
        action_hash: ActionHash::from_raw_32(blake2b_256(&action)),
        author: AgentPubKey::from_raw_39(sah.action().author().get_raw_39().to_vec()),
        timestamp: Timestamp::from_micros(sah.action().timestamp().as_micros()),
        action,
        signature: Signature(sah.signature().0),
        entry: entry.to_vec(),
    })
}

/// The v1.4 original of a v1.5 copy: the action from the copy's stored 0.6
/// signed action, the entry the copy's bytes without its `carried_from` (the
/// last field; v1.4 wrote the same fields before it), with
/// `signature_action` put back to the v1.4 signature's hash for a revocation
/// or a thumbnail. None when the copy stored no signed action.
pub(crate) fn from_v15_copy(copy_entry: &[u8], v14_signature: Option<&[u8]>) -> Result<Option<Original>, String> {
    let Some(signed_action) = stored_signed_action(copy_entry)? else { return Ok(None) };
    let entry = v14_entry(copy_entry, v14_signature)?;
    from_06(&signed_action, &entry).map(Some)
}

/// The steps the DNA takes (1-3): the action decodes on its line, names the
/// author and time, hashes to the action hash, its signature verifies; the
/// entry hashes to the entry the action names, of the expected kind.
pub(crate) fn check(o: &Original, entry_index: u8) -> Result<(), String> {
    let (author, micros, entry_hash, kind) = match o.dna.as_str() {
        "1.4" => {
            use holochain_types::prelude::{Action, EntryType};
            let a: Action = holochain_types::prelude::decode(&o.action).map_err(|e| format!("the original action does not decode: {e}"))?;
            let Some((hash, EntryType::App(def))) = a.entry_data() else { return Err("the original is not an app entry".into()) };
            (a.author().get_raw_39().to_vec(), a.timestamp().as_micros(), hash.get_raw_39().to_vec(), (def.zome_index.0, def.entry_index.0))
        }
        "1.5" => {
            use holochain_types_07::prelude::{Action, EntryType};
            let a: Action = holochain_types_07::prelude::decode(&o.action).map_err(|e| format!("the original action does not decode: {e}"))?;
            let Some((hash, EntryType::App(def))) = a.entry_data() else { return Err("the original is not an app entry".into()) };
            (a.author().get_raw_39().to_vec(), a.timestamp().as_micros(), hash.get_raw_39().to_vec(), (def.zome_index.0, def.entry_index.0))
        }
        other => return Err(format!("records are not carried from DNA {other}")),
    };
    if author != o.author.get_raw_39() || micros != o.timestamp.as_micros() {
        return Err("the original action names another author or time".into());
    }
    if blake2b_256(&o.action) != o.action_hash.get_raw_32() {
        return Err("the original action does not hash to its action hash".into());
    }
    let key: [u8; 32] = o.author.get_raw_32().try_into().map_err(|_| "an agent key is 32 bytes".to_string())?;
    let verifies = ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map(|k| k.verify_strict(&o.action, &ed25519_dalek::Signature::from_bytes(&o.signature.0)).is_ok())
        .unwrap_or(false);
    if !verifies {
        return Err("the original author's signature does not verify".into());
    }
    use holochain_types_07::prelude::{AppEntryBytes, Entry, EntryHash, SerializedBytes, UnsafeBytes};
    let hashed = EntryHash::with_data_sync(&Entry::App(AppEntryBytes(SerializedBytes::from(UnsafeBytes::from(o.entry.clone())))));
    if hashed.get_raw_39() != entry_hash.as_slice() {
        return Err("the original entry does not hash to the entry its action names".into());
    }
    if kind != (0, entry_index) {
        return Err("the original is another kind of record".into());
    }
    Ok(())
}

// ── MessagePack, as far as the rebuild needs it ─────────────────────────

/// The end of the MessagePack value starting at `at`.
fn skip(b: &[u8], at: usize) -> Result<usize, String> {
    let short = || "the entry is cut short".to_string();
    let m = *b.get(at).ok_or_else(short)?;
    let be = |from: usize, n: usize| -> Result<usize, String> {
        let s = b.get(from..from + n).ok_or_else(short)?;
        Ok(s.iter().fold(0usize, |v, x| (v << 8) | *x as usize))
    };
    let items = |mut pos: usize, n: usize| -> Result<usize, String> {
        for _ in 0..n {
            pos = skip(b, pos)?;
        }
        Ok(pos)
    };
    Ok(match m {
        0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => at + 1,
        0x80..=0x8f => items(at + 1, 2 * (m & 0x0f) as usize)?,
        0x90..=0x9f => items(at + 1, (m & 0x0f) as usize)?,
        0xa0..=0xbf => at + 1 + (m & 0x1f) as usize,
        0xc4 | 0xd9 => at + 2 + be(at + 1, 1)?,
        0xc5 | 0xda => at + 3 + be(at + 1, 2)?,
        0xc6 | 0xdb => at + 5 + be(at + 1, 4)?,
        0xc7 => at + 3 + be(at + 1, 1)?,
        0xc8 => at + 4 + be(at + 1, 2)?,
        0xc9 => at + 6 + be(at + 1, 4)?,
        0xca | 0xce | 0xd2 => at + 5,
        0xcb | 0xcf | 0xd3 => at + 9,
        0xcc | 0xd0 => at + 2,
        0xcd | 0xd1 => at + 3,
        0xd4 => at + 3,
        0xd5 => at + 4,
        0xd6 => at + 6,
        0xd7 => at + 10,
        0xd8 => at + 18,
        0xdc => items(at + 3, be(at + 1, 2)?)?,
        0xdd => items(at + 5, be(at + 1, 4)?)?,
        0xde => items(at + 3, 2 * be(at + 1, 2)?)?,
        0xdf => items(at + 5, 2 * be(at + 1, 4)?)?,
        0xc1 => return Err("the entry holds a reserved MessagePack marker".into()),
    })
}

/// A top-level map's pairs: (key start, value start, value end), after a
/// header of `header` bytes.
fn map_pairs(b: &[u8]) -> Result<(usize, usize, Vec<(usize, usize, usize)>), String> {
    let (count, header) = match *b.first().ok_or("the entry is empty")? {
        m @ 0x80..=0x8f => ((m & 0x0f) as usize, 1),
        0xde => (u16::from_be_bytes([b[1], b[2]]) as usize, 3),
        _ => return Err("the entry is not a map".into()),
    };
    let mut pos = header;
    let mut pairs = Vec::with_capacity(count);
    for _ in 0..count {
        let key = pos;
        let value = skip(b, key)?;
        pos = skip(b, value)?;
        pairs.push((key, value, pos));
    }
    Ok((count, header, pairs))
}

fn key_is(b: &[u8], key_start: usize, value_start: usize, name: &str) -> bool {
    let k = &b[key_start..value_start];
    k.len() == name.len() + 1 && k[0] as usize == 0xa0 + name.len() && &k[1..] == name.as_bytes()
}

/// The copy's stored 0.6 signed action (`carried_from.original_signed_action`).
fn stored_signed_action(copy_entry: &[u8]) -> Result<Option<Vec<u8>>, String> {
    #[derive(serde::Deserialize)]
    struct From {
        #[serde(default)]
        original_signed_action: Option<serde_bytes::ByteBuf>,
    }
    #[derive(serde::Deserialize)]
    struct Copy {
        carried_from: Option<From>,
    }
    let c: Copy = rmp_serde::from_slice(copy_entry).map_err(|e| format!("the copy does not decode: {e}"))?;
    Ok(c.carried_from.and_then(|f| f.original_signed_action).map(|b| b.into_vec()))
}

/// The v1.4 entry: the copy's map without its last pair (`carried_from`),
/// and `signature_action` set to `v14_signature` when given.
fn v14_entry(copy_entry: &[u8], v14_signature: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let (count, header, pairs) = map_pairs(copy_entry)?;
    let &(last_key, last_value, _) = pairs.last().ok_or("the entry is an empty map")?;
    if !key_is(copy_entry, last_key, last_value, "carried_from") {
        return Err("the copy's last field is not carried_from".into());
    }
    if count - 1 > 15 {
        return Err("the entry has more fields than a v1.4 record".into());
    }
    let mut out = Vec::with_capacity(copy_entry.len());
    out.push(0x80 | (count - 1) as u8);
    for &(key, value, end) in &pairs[..count - 1] {
        out.extend_from_slice(&copy_entry[key..value]);
        match v14_signature {
            Some(hash) if key_is(copy_entry, key, value, "signature_action") => {
                let v = &copy_entry[value..end];
                if v.len() != 41 || v[0] != 0xc4 || v[1] != 39 || hash.len() != 39 {
                    return Err("signature_action is not a 39-byte hash".into());
                }
                out.extend_from_slice(&[0xc4, 39]);
                out.extend_from_slice(hash);
            }
            _ => out.extend_from_slice(&copy_entry[value..end]),
        }
    }
    let _ = header;
    Ok(out)
}

// ── The carry calls ──────────────────────────────────────────────────────

fn mp<T: Serialize>(v: &T) -> Result<Vec<u8>, String> {
    rmp_serde::to_vec_named(v).map_err(|e| format!("MessagePack: {}", e))
}

/// `carry_signature`: the record's fields as its original's entry bytes
/// (they decode as the record, `carried_from` absent), and the original.
pub(crate) async fn carry_signature(client: &AppClient, role: &str, original: &Original) -> Result<Vec<u8>, String> {
    check(original, SIGNATURE_ENTRY)?;
    let mut buf = Vec::with_capacity(original.entry.len() * 2 + original.action.len() + 256);
    rmp::encode::write_map_len(&mut buf, 2).map_err(|e| e.to_string())?;
    rmp::encode::write_str(&mut buf, "record").map_err(|e| e.to_string())?;
    buf.extend_from_slice(&original.entry);
    rmp::encode::write_str(&mut buf, "original").map_err(|e| e.to_string())?;
    buf.extend_from_slice(&mp(original)?);
    let result = client.call(role, "signing", "carry_signature", buf).await?;
    let h: ActionHash = rmp_serde::from_slice(&result).map_err(|e| format!("carry_signature decode: {}", e))?;
    Ok(h.get_raw_39().to_vec())
}

/// `carry_revocation` onto `signature_here` (the copy here of the signature
/// the original named).
pub(crate) async fn carry_revocation(client: &AppClient, role: &str, signature_here: &[u8], original: &Original) -> Result<Vec<u8>, String> {
    check(original, REVOCATION_ENTRY)?;
    #[derive(serde::Deserialize)]
    struct Fields {
        revoked_at: i64,
        reason: Option<String>,
    }
    #[derive(Serialize)]
    struct Input<'a> {
        signature_action: ActionHash,
        revoked_at: i64,
        reason: Option<String>,
        original: &'a Original,
    }
    let f: Fields = rmp_serde::from_slice(&original.entry).map_err(|e| format!("the revocation does not decode: {e}"))?;
    let input = Input { signature_action: ActionHash::from_raw_39(signature_here.to_vec()), revoked_at: f.revoked_at, reason: f.reason, original };
    let result = client.call(role, "signing", "carry_revocation", mp(&input)?).await?;
    let h: ActionHash = rmp_serde::from_slice(&result).map_err(|e| format!("carry_revocation decode: {}", e))?;
    Ok(h.get_raw_39().to_vec())
}

/// `carry_thumbnail` onto `signature_here`.
pub(crate) async fn carry_thumbnail(client: &AppClient, role: &str, signature_here: &[u8], original: &Original) -> Result<Vec<u8>, String> {
    check(original, THUMBNAIL_ENTRY)?;
    #[derive(serde::Deserialize)]
    struct Fields {
        thumbnail: String,
        #[serde(default)]
        updated_at: i64,
    }
    #[derive(Serialize)]
    struct Input<'a> {
        signature_action: ActionHash,
        thumbnail: String,
        updated_at: i64,
        original: &'a Original,
    }
    let f: Fields = rmp_serde::from_slice(&original.entry).map_err(|e| format!("the thumbnail does not decode: {e}"))?;
    let input = Input { signature_action: ActionHash::from_raw_39(signature_here.to_vec()), thumbnail: f.thumbnail, updated_at: f.updated_at, original };
    let result = client.call(role, "signing", "carry_thumbnail", mp(&input)?).await?;
    let h: ActionHash = rmp_serde::from_slice(&result).map_err(|e| format!("carry_thumbnail decode: {}", e))?;
    Ok(h.get_raw_39().to_vec())
}

// ── The move from v1.5 ───────────────────────────────────────────────────

/// The signing v1.6 app on the 0.7 conductor.
pub(crate) fn app_id() -> String {
    crate::dna::make_app_id("signing", crate::dna::BUNDLED_SIGNING_VERSION_V16)
}

/// In the identity root once a pass has carried everything this device
/// wrote on v1.5: from then on its writes go to v1.6.
const SWITCHED: &str = "signing-v16";

pub(crate) fn switched(root: &Path) -> bool {
    root.join(SWITCHED).exists()
}

/// The v1.6 cell's app client, with its role.
pub(crate) async fn client(state: &Arc<AppState>) -> Result<(AppClient, String), String> {
    let (admin_port, app_port) = crate::hc::line_ports(state, Line::V07)?;
    let (ws, role) = crate::hc::connect_app_07(state, admin_port, app_port, &app_id(), "flowsta_signing").await?;
    Ok((AppClient::V07(ws), role))
}

static RUNNING: AtomicBool = AtomicBool::new(false);

/// A pass in the background unless one is running or the move is done.
pub(crate) fn schedule(state: Arc<AppState>) {
    // The matrix holds the pass to write on v1.5 first (debug builds only).
    if cfg!(debug_assertions) && std::env::var_os("VAULT_TEST_HOLD_V16").is_some() {
        return;
    }
    if switched(&state.identity_root()) || RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    tauri::async_runtime::spawn(async move {
        match pass(&state).await {
            Ok(r) if r.carried + r.waiting + r.failed > 0 || r.switched => log::info!(
                "[signing 1.6] {} carried, {} already there, {}{} failed{}",
                r.carried,
                r.already,
                if r.waiting > 0 { format!("{} for the next round (the network did not answer in time), ", r.waiting) } else { String::new() },
                r.failed,
                if r.switched { "; writes go to 1.6 from now" } else { "" }
            ),
            Ok(_) => {}
            Err(e) => log::info!("[signing 1.6] not moved this round: {}", e),
        }
        RUNNING.store(false, Ordering::SeqCst);
    });
}

#[derive(Default, Debug)]
pub(crate) struct PassReport {
    pub carried: usize,
    pub already: usize,
    /// Carries whose call ran out of time on a network read inside the
    /// conductor (a `Timeout`: nothing was written); the next pass tries
    /// them again.
    pub waiting: usize,
    pub failed: usize,
    pub switched: bool,
}

/// One record of a signing cell's source chain, as its conductor holds it:
/// what `own_key` keeps of the cells an install ran as the identity's key,
/// so their records are carried under its new key.
#[derive(Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
pub(crate) struct ChainRecord {
    /// "1.5" or "1.6": the signing DNA whose cell wrote it.
    pub cell: String,
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
    pub kind: u8,
    pub timestamp: i64,
    #[serde(with = "serde_bytes")]
    pub author: Vec<u8>,
    /// The action as its author signed it, and the signature.
    #[serde(with = "serde_bytes")]
    pub action: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub entry: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct HasCarried {
    #[serde(default)]
    carried_from: Option<serde::de::IgnoredAny>,
}

impl ChainRecord {
    pub(crate) fn carried(&self) -> bool {
        rmp_serde::from_slice::<HasCarried>(&self.entry).map(|c| c.carried_from.is_some()).unwrap_or(false)
    }

    /// The record as its own original (a record signed on its cell).
    fn native(&self) -> Result<Original, String> {
        Ok(Original {
            dna: self.cell.clone(),
            action_hash: ActionHash::from_raw_39(self.hash.clone()),
            author: AgentPubKey::from_raw_39(self.author.clone()),
            timestamp: Timestamp::from_micros(self.timestamp),
            action: self.action.clone(),
            signature: Signature(self.signature.as_slice().try_into().map_err(|_| "a signature that is not 64 bytes")?),
            entry: self.entry.clone(),
        })
    }

    /// The original a v1.6 copy carries inside it (`CarriedFrom`), exactly
    /// as the DNA checked it when the copy was written.
    fn original_in_v16_copy(&self) -> Result<Option<Original>, String> {
        #[derive(serde::Deserialize)]
        struct From {
            original_dna: String,
            original_action_hash: ActionHash,
            original_author: AgentPubKey,
            original_timestamp: Timestamp,
            #[serde(with = "serde_bytes")]
            original_action: Vec<u8>,
            original_signature: Signature,
            #[serde(with = "serde_bytes")]
            original_entry: Vec<u8>,
        }
        #[derive(serde::Deserialize)]
        struct Copy {
            #[serde(default)]
            carried_from: Option<From>,
        }
        let copy: Copy = rmp_serde::from_slice(&self.entry).map_err(|e| format!("a v1.6 record does not decode: {e}"))?;
        Ok(copy.carried_from.map(|f| Original {
            dna: f.original_dna,
            action_hash: f.original_action_hash,
            author: f.original_author,
            timestamp: f.original_timestamp,
            action: f.original_action,
            signature: f.original_signature,
            entry: f.original_entry,
        }))
    }
}

/// Every signing record on the source chain of the 0.7 conductor's cell for
/// `app_id` ("1.5" or "1.6" names it in the records). An app that is not
/// installed has none.
pub(crate) async fn chain_of(state: &Arc<AppState>, app_id: &str, cell: &str) -> Result<Vec<ChainRecord>, String> {
    use holochain_client_07::{AdminWebsocket, CellInfo};
    use holochain_types_07::prelude::{Entry, EntryType};
    let (admin_port, _) = crate::hc::line_ports(state, Line::V07)?;
    let admin = AdminWebsocket::connect(format!("localhost:{}", admin_port), Some(crate::conductor::node_origin()))
        .await
        .map_err(|e| format!("0.7 admin: {}", e))?;
    let apps = admin.list_apps(None).await.map_err(|e| format!("list_apps: {}", e))?;
    let Some(cell_id) = apps.iter().find(|a| a.installed_app_id == app_id).and_then(|app| {
        app.cell_info.values().flat_map(|c| c.iter()).find_map(|c| match c {
            CellInfo::Provisioned(p) => Some(p.cell_id.clone()),
            _ => None,
        })
    }) else {
        return Ok(Vec::new());
    };
    let dump = admin.dump_full_state(cell_id, None, None).await.map_err(|e| format!("dump {}: {}", app_id, e))?;
    let mut out = Vec::new();
    for rec in dump.source_chain_dump.records {
        let Some((_, EntryType::App(def))) = rec.action.entry_data() else { continue };
        if def.zome_index.0 != 0 {
            continue;
        }
        let Some(Entry::App(bytes)) = rec.entry.as_ref() else { continue };
        out.push(ChainRecord {
            cell: cell.to_string(),
            hash: rec.action_address.get_raw_39().to_vec(),
            kind: def.entry_index.0,
            timestamp: rec.action.timestamp().as_micros(),
            author: rec.action.author().get_raw_39().to_vec(),
            action: holochain_types_07::prelude::encode(&rec.action).map_err(|e| format!("encode a {} action: {e}", cell))?,
            signature: rec.signature.0.to_vec(),
            entry: bytes.bytes().to_vec(),
        });
    }
    Ok(out)
}

/// One record this device wrote on v1.5.
struct Mine {
    hash: Vec<u8>,
    kind: u8,
    entry: Vec<u8>,
    timestamp: i64,
    /// Its original when it is native here (it is its own original).
    native: Original,
    carried: bool,
}

/// Every record this device's v1.5 cell wrote (its source chain).
async fn mine_on_v15(state: &Arc<AppState>) -> Result<Vec<Mine>, String> {
    mine_of(&chain_of(state, &crate::signing_07::signing_app_id(Line::V07), "1.5").await?)
}

fn mine_of(chain: &[ChainRecord]) -> Result<Vec<Mine>, String> {
    chain
        .iter()
        .map(|r| Ok(Mine { hash: r.hash.clone(), kind: r.kind, entry: r.entry.clone(), timestamp: r.timestamp, native: r.native()?, carried: r.carried() }))
        .collect()
}

/// The hash a v1.5 record names in `signature_action`.
fn names(entry: &[u8]) -> Option<Vec<u8>> {
    #[derive(serde::Deserialize)]
    struct Named {
        signature_action: ActionHash,
    }
    rmp_serde::from_slice::<Named>(entry).ok().map(|n| n.signature_action.get_raw_39().to_vec())
}

/// One pass: every record this device wrote on v1.5 carried to v1.6 with
/// its true original (idempotent by the original's hash), signatures first.
/// Writes switch to v1.6 once a pass leaves nothing, after the move to 0.7
/// and the web-era carry (they still write to v1.5 until then).
/// A carry that failed only because a network read inside the call ran out
/// of time (the zome's `must_get_valid_record` of a copy not yet answered
/// for): it wrote nothing, and a later pass carries it.
fn network_wait(e: &str) -> bool {
    flowsta_hc_lines::kind_of_message(e) == crate::hc::ZomeErrorKind::Timeout
}

pub(crate) async fn pass(state: &Arc<AppState>) -> Result<PassReport, String> {
    let root = state.identity_root();
    let mine = mine_on_v15(state).await?;
    let mut report = carry_mine(state, &mine).await?;
    let web_era_done = crate::move_07::marker(&root).map(|m| m.web_era_carried).unwrap_or(true);
    if report.failed == 0 && report.waiting == 0 && crate::move_07::moved(&root) && web_era_done {
        std::fs::write(root.join(SWITCHED), b"").map_err(|e| format!("write {}: {}", SWITCHED, e))?;
        report.switched = true;
    }
    Ok(report)
}

/// Carry v1.5 chain records to this device's v1.6 cell with their true
/// originals (idempotent by the original's hash), signatures first.
async fn carry_mine(state: &Arc<AppState>, mine: &[Mine]) -> Result<PassReport, String> {
    let mut report = PassReport::default();
    let (c16, r16) = client(state).await?;
    // v1.5 signature hash -> the hash its copy is carried under here (its
    // own for a native one, its v1.4 original's for a copy).
    let mut key_of: std::collections::HashMap<Vec<u8>, Vec<u8>> = std::collections::HashMap::new();
    // v1.5 signature hashes whose carry waits for the next pass: their
    // revocations and thumbnails wait with them.
    let mut waiting_sigs: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    for m in mine.iter().filter(|m| m.kind == SIGNATURE_ENTRY) {
        let original = if m.carried { from_v15_copy(&m.entry, None) } else { Ok(Some(m.native.clone())) };
        match original {
            Ok(Some(o)) => {
                let key = o.action_hash.get_raw_39().to_vec();
                if crate::signing_07::carried(&c16, &r16, &key).await?.is_some() {
                    report.already += 1;
                } else if let Err(e) = carry_signature(&c16, &r16, &o).await {
                    if network_wait(&e) {
                        report.waiting += 1;
                        waiting_sigs.insert(m.hash.clone());
                        log::info!("[signing 1.6] a signature waits for the next round: {}", e);
                    } else {
                        report.failed += 1;
                        log::info!("[signing 1.6] a signature not carried: {}", e);
                    }
                    continue;
                } else {
                    report.carried += 1;
                }
                key_of.insert(m.hash.clone(), key);
            }
            Ok(None) => report.failed += 1,
            Err(e) => {
                report.failed += 1;
                log::info!("[signing 1.6] a signature's original not rebuilt: {}", e);
            }
        }
    }
    // Revocations, and each signature's latest thumbnail by this device.
    let mut latest_thumb: std::collections::HashMap<Vec<u8>, &Mine> = std::collections::HashMap::new();
    for m in mine.iter().filter(|m| m.kind == THUMBNAIL_ENTRY) {
        let Some(sig) = names(&m.entry) else { continue };
        if latest_thumb.get(&sig).map(|t| t.timestamp < m.timestamp).unwrap_or(true) {
            latest_thumb.insert(sig, m);
        }
    }
    let children = mine.iter().filter(|m| m.kind == REVOCATION_ENTRY).chain(latest_thumb.values().copied());
    for m in children {
        let Some(named) = names(&m.entry) else { report.failed += 1; continue };
        let Some(key) = key_of.get(&named).cloned() else {
            if waiting_sigs.contains(&named) { report.waiting += 1 } else { report.failed += 1 }
            continue;
        };
        let original = if m.carried { from_v15_copy(&m.entry, Some(&key)) } else { Ok(Some(m.native.clone())) };
        let o = match original {
            Ok(Some(o)) => o,
            Ok(None) => { report.failed += 1; continue }
            Err(e) => { report.failed += 1; log::info!("[signing 1.6] an original not rebuilt: {}", e); continue }
        };
        if crate::signing_07::carried(&c16, &r16, o.action_hash.get_raw_39()).await?.is_some() {
            report.already += 1;
            continue;
        }
        let Some(here) = crate::signing_07::carried(&c16, &r16, &key).await? else { report.failed += 1; continue };
        let done = if m.kind == REVOCATION_ENTRY { carry_revocation(&c16, &r16, &here, &o).await } else { carry_thumbnail(&c16, &r16, &here, &o).await };
        match done {
            Ok(_) => report.carried += 1,
            Err(e) if network_wait(&e) => { report.waiting += 1; log::info!("[signing 1.6] a revocation or thumbnail waits for the next round: {}", e) }
            Err(e) => { report.failed += 1; log::info!("[signing 1.6] a revocation or thumbnail not carried: {}", e) }
        }
    }
    Ok(report)
}

/// What `carry_kept` did with the records an install kept of its old cells.
#[derive(Default, Debug, PartialEq)]
pub(crate) struct KeptReport {
    pub carried: usize,
    pub already: usize,
    pub waiting: usize,
    pub failed: usize,
    /// Records signed on v1.6 itself by the key the install ran as. The DNA
    /// carries only v1.4 and v1.5 originals, so these cannot be copies: the
    /// device signs the file again with its own key, the stated time, tags
    /// and note kept (Eric, 2026-11-13), and writes its revocation or
    /// thumbnail on the new record.
    pub signed_again: usize,
    /// A v1.6 revocation of a signature that is a copy here: only the
    /// signature's signer may revoke it, and this device is its witness.
    pub unplaceable: usize,
}

impl KeptReport {
    /// Nothing kept is still owed: the kept records may go.
    pub(crate) fn settled(&self) -> bool {
        self.waiting == 0 && self.failed == 0 && self.unplaceable == 0
    }
}

/// A native signature's entry with another signer and signature: every other
/// field byte for byte (the file hash, the stated time, the tags, the note).
fn entry_signed_by(entry: &[u8], signer: &AgentPubKey, signature: &[u8]) -> Result<Vec<u8>, String> {
    let (_, header, pairs) = map_pairs(entry)?;
    let mut out = entry[..header].to_vec();
    let (mut put_signer, mut put_signature) = (false, false);
    for (key, value, end) in pairs {
        out.extend_from_slice(&entry[key..value]);
        if key_is(entry, key, value, "signer") {
            out.extend_from_slice(&mp(signer)?);
            put_signer = true;
        } else if key_is(entry, key, value, "signature") {
            out.extend_from_slice(&mp(&signature.to_vec())?);
            put_signature = true;
        } else {
            out.extend_from_slice(&entry[value..end]);
        }
    }
    if !(put_signer && put_signature) {
        return Err("the record has no signer or no signature".into());
    }
    Ok(out)
}

#[derive(serde::Deserialize)]
struct SignedWhat {
    file_hash: Vec<u8>,
    signed_at: i64,
}

/// The records signed on v1.6 itself under the key the install ran as,
/// written again by this device: each signature signed with its own key
/// (found again by file and stated time, so a repeat signs nothing twice),
/// then the revocations and each signature's latest thumbnail on the new
/// records.
async fn sign_kept_natives_again(state: &Arc<AppState>, kept: &[ChainRecord], report: &mut KeptReport) -> Result<(), String> {
    let natives = native_on_v16(kept);
    if natives.is_empty() {
        return Ok(());
    }
    let seed = state.vault_config.lock().unwrap().as_ref().and_then(|c| c.conductor_seed_bytes()).ok_or("vault_locked")?;
    let me = AgentPubKey::from_raw_32(crate::key_derivation::public_key_of_seed(&seed).to_vec());
    let (c16, r16) = client(state).await?;
    let here = chain_of(state, &app_id(), "1.6").await?;
    let what = |entry: &[u8]| rmp_serde::from_slice::<SignedWhat>(entry).ok().map(|w| (w.file_hash, w.signed_at));
    let mut mine: std::collections::HashMap<(Vec<u8>, i64), Vec<u8>> =
        here.iter().filter(|r| r.kind == SIGNATURE_ENTRY && !r.carried()).filter_map(|r| what(&r.entry).map(|w| (w, r.hash.clone()))).collect();
    // The old cell's hash of a signature -> its record here.
    let mut now: std::collections::HashMap<Vec<u8>, Vec<u8>> = std::collections::HashMap::new();
    for r in natives.iter().filter(|r| r.kind == SIGNATURE_ENTRY) {
        let Some(w) = what(&r.entry) else { report.failed += 1; continue };
        if let Some(hash) = mine.get(&w) {
            now.insert(r.hash.clone(), hash.clone());
            report.already += 1;
            continue;
        }
        let signature = crate::key_derivation::sign_with_device_seed(&seed, &w.0);
        let payload = entry_signed_by(&r.entry, &me, &signature[..])?;
        match c16.call(&r16, "signing", "create_signature", payload).await.map_err(String::from) {
            Ok(result) => {
                let h: ActionHash = rmp_serde::from_slice(&result).map_err(|e| format!("create_signature decode: {}", e))?;
                mine.insert(w, h.get_raw_39().to_vec());
                now.insert(r.hash.clone(), h.get_raw_39().to_vec());
                report.signed_again += 1;
            }
            Err(e) => {
                report.failed += 1;
                log::info!("[signing 1.6] a kept signature not signed again: {}", e);
            }
        }
    }
    // Copies the old cell held: where each is here.
    let mut copy_here: std::collections::HashMap<Vec<u8>, Option<Vec<u8>>> = std::collections::HashMap::new();
    for r in kept.iter().filter(|r| r.cell == "1.6" && r.kind == SIGNATURE_ENTRY) {
        if let Ok(Some(o)) = r.original_in_v16_copy() {
            copy_here.insert(r.hash.clone(), crate::signing_07::carried(&c16, &r16, o.action_hash.get_raw_39()).await?);
        }
    }
    let names_here = |kind: u8, target: &[u8]| here.iter().filter(|r| r.kind == kind && !r.carried()).any(|r| names(&r.entry).as_deref() == Some(target));
    #[derive(serde::Deserialize)]
    struct Revoked {
        reason: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Thumb {
        thumbnail: String,
    }
    #[derive(Serialize)]
    struct Revoke {
        signature_action: ActionHash,
        reason: Option<String>,
    }
    #[derive(Serialize)]
    struct SetThumb {
        signature_action: ActionHash,
        thumbnail: String,
    }
    let mut latest_thumb: std::collections::HashMap<Vec<u8>, &ChainRecord> = std::collections::HashMap::new();
    for r in natives.iter().filter(|r| r.kind == THUMBNAIL_ENTRY) {
        let Some(sig) = names(&r.entry) else { continue };
        if latest_thumb.get(&sig).map(|t| t.timestamp < r.timestamp).unwrap_or(true) {
            latest_thumb.insert(sig, r);
        }
    }
    for r in natives.iter().filter(|r| r.kind == REVOCATION_ENTRY).copied().chain(latest_thumb.values().copied()) {
        let Some(named) = names(&r.entry) else { report.failed += 1; continue };
        let (target, is_copy) = match (now.get(&named), copy_here.get(&named)) {
            (Some(new), _) => (new.clone(), false),
            (None, Some(Some(copy))) => (copy.clone(), true),
            // Its signature's copy is not here yet.
            (None, Some(None)) => { report.waiting += 1; continue }
            (None, None) => { report.failed += 1; continue }
        };
        if r.kind == REVOCATION_ENTRY && is_copy {
            report.unplaceable += 1;
            log::warn!("[signing 1.6] a revocation made under the shared key names a signature this device may not revoke (it is its witness, not its signer): kept, not written");
            continue;
        }
        if names_here(r.kind, &target) {
            report.already += 1;
            continue;
        }
        let call = if r.kind == REVOCATION_ENTRY {
            let Ok(f) = rmp_serde::from_slice::<Revoked>(&r.entry) else { report.failed += 1; continue };
            c16.call(&r16, "signing", "revoke_signature", mp(&Revoke { signature_action: ActionHash::from_raw_39(target), reason: f.reason })?).await.map_err(String::from)
        } else {
            let Ok(f) = rmp_serde::from_slice::<Thumb>(&r.entry) else { report.failed += 1; continue };
            c16.call(&r16, "signing", "set_thumbnail", mp(&SetThumb { signature_action: ActionHash::from_raw_39(target), thumbnail: f.thumbnail })?).await.map_err(String::from)
        };
        match call {
            Ok(_) => report.signed_again += 1,
            Err(e) if network_wait(&e) => report.waiting += 1,
            Err(e) => {
                report.failed += 1;
                log::info!("[signing 1.6] a kept revocation or thumbnail not written again: {}", e);
            }
        }
    }
    Ok(())
}

/// Which kept v1.6 records are signed on v1.6 itself (no original inside).
pub(crate) fn native_on_v16(kept: &[ChainRecord]) -> Vec<&ChainRecord> {
    kept.iter().filter(|r| r.cell == "1.6" && !r.carried()).collect()
}

/// Carry the signing records an install kept of the cells it ran as the
/// identity's key (`own_key`) into this device's v1.6 cell: what it wrote on
/// v1.5 as `pass` carries it, and the v1.6 copies by the original each
/// holds. Idempotent by the original's hash; a repeat writes nothing.
pub(crate) async fn carry_kept(state: &Arc<AppState>, kept: &[ChainRecord]) -> Result<KeptReport, String> {
    let on_v15: Vec<ChainRecord> = kept.iter().filter(|r| r.cell == "1.5").cloned().collect();
    let first = carry_mine(state, &mine_of(&on_v15)?).await?;
    let mut report = KeptReport { carried: first.carried, already: first.already, waiting: first.waiting, failed: first.failed, ..Default::default() };
    let (c16, r16) = client(state).await?;
    let copies: Vec<(&ChainRecord, Original)> = kept
        .iter()
        .filter(|r| r.cell == "1.6")
        .filter_map(|r| match r.original_in_v16_copy() {
            Ok(Some(o)) => Some((r, o)),
            Ok(None) => None,
            Err(e) => {
                report.failed += 1;
                log::info!("[signing 1.6] a kept record not read: {}", e);
                None
            }
        })
        .collect();
    // The old cell's copy of a signature -> the original it was carried by.
    let key_of: std::collections::HashMap<&[u8], Vec<u8>> =
        copies.iter().filter(|(r, _)| r.kind == SIGNATURE_ENTRY).map(|(r, o)| (r.hash.as_slice(), o.action_hash.get_raw_39().to_vec())).collect();
    let (signatures, children): (Vec<_>, Vec<_>) = copies.iter().partition(|(r, _)| r.kind == SIGNATURE_ENTRY);
    for (r, o) in signatures.into_iter().chain(children) {
        if crate::signing_07::carried(&c16, &r16, o.action_hash.get_raw_39()).await?.is_some() {
            report.already += 1;
            continue;
        }
        let done = if r.kind == SIGNATURE_ENTRY {
            carry_signature(&c16, &r16, o).await
        } else {
            // The copy here of the signature the old copy named.
            let here = match names(&r.entry).and_then(|named| key_of.get(named.as_slice()).cloned()) {
                Some(key) => crate::signing_07::carried(&c16, &r16, &key).await?,
                None => None,
            };
            let Some(here) = here else {
                // Its signature waits for a later round.
                report.waiting += 1;
                continue;
            };
            if r.kind == REVOCATION_ENTRY { carry_revocation(&c16, &r16, &here, o).await } else { carry_thumbnail(&c16, &r16, &here, o).await }
        };
        match done {
            Ok(_) => report.carried += 1,
            Err(e) if network_wait(&e) => {
                report.waiting += 1;
                log::info!("[signing 1.6] a kept record waits for the next round: {}", e)
            }
            Err(e) => {
                report.failed += 1;
                log::info!("[signing 1.6] a kept record not carried: {}", e)
            }
        }
    }
    sign_kept_natives_again(state, kept, &mut report).await?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_signature_signed_again_keeps_every_other_field() {
        use super::*;
        #[derive(Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Rec {
            file_hash: Vec<u8>,
            signature: Vec<u8>,
            signer: AgentPubKey,
            signed_at: i64,
            tags: Option<Vec<String>>,
            comment: Option<String>,
            carried_from: Option<u8>,
        }
        let old = Rec { file_hash: vec![7; 32], signature: vec![1; 64], signer: AgentPubKey::from_raw_32(vec![2; 32]), signed_at: 1_790_000_000_000, tags: Some(vec!["a".into()]), comment: Some("note".into()), carried_from: None };
        let device = AgentPubKey::from_raw_32(vec![9; 32]);
        let again: Rec = rmp_serde::from_slice(&entry_signed_by(&mp(&old).unwrap(), &device, &[5u8; 64]).unwrap()).unwrap();
        assert_eq!(again, Rec { signature: vec![5; 64], signer: device.clone(), ..old });
        assert!(entry_signed_by(&mp(&(1u8, 2u8)).unwrap(), &device, &[5u8; 64]).is_err(), "not a record");
    }

    use super::*;

    /// A map with a nested value, a binary hash and a trailing field: the
    /// skipper walks it, and the rebuild drops the last field and swaps the
    /// hash.
    /// The error a thumbnail's carry meets on a device with peers waits for
    /// the next round; a refusal by the zome stays a failure.
    #[test]
    fn a_network_timeout_waits_and_a_refusal_fails() {
        let field = r#"carry_thumbnail failed: ExternalApiWireError(InternalError("Source chain error: Other: Wasm runtime error while working with Ribosome: RuntimeError: holochain::core::ribosome::host_fn::must_get_valid_record:71: Host(\"Other: get response channel dropped: likely response timeout\")"))"#;
        assert!(network_wait(field));
        let refused = r#"carry_thumbnail failed: ExternalApiWireError(InternalError("Source chain error: InvalidCommit error: the original author's signature does not verify"))"#;
        assert!(!network_wait(refused));
        assert!(!network_wait("the thumbnail does not decode: missing field"));
    }

    #[test]
    fn the_rebuild_drops_carried_from_and_puts_the_old_hash_back() {
        #[derive(Serialize)]
        struct WithCarried {
            #[serde(with = "serde_bytes")]
            signature_action: Vec<u8>,
            revoked_at: i64,
            reason: Option<String>,
            nested: Vec<(u8, String)>,
            carried_from: Option<std::collections::BTreeMap<String, u64>>,
        }
        #[derive(Serialize)]
        struct Without {
            #[serde(with = "serde_bytes")]
            signature_action: Vec<u8>,
            revoked_at: i64,
            reason: Option<String>,
            nested: Vec<(u8, String)>,
        }
        let copy = rmp_serde::to_vec_named(&WithCarried {
            signature_action: vec![1; 39],
            revoked_at: 1_761_800_000_000,
            reason: Some("x".into()),
            nested: vec![(3, "y".into())],
            carried_from: Some([("witness".to_string(), 7u64)].into_iter().collect()),
        })
        .unwrap();
        let want = rmp_serde::to_vec_named(&Without { signature_action: vec![2; 39], revoked_at: 1_761_800_000_000, reason: Some("x".into()), nested: vec![(3, "y".into())] }).unwrap();
        assert_eq!(v14_entry(&copy, Some(&[2; 39])).unwrap(), want);
        let keep = rmp_serde::to_vec_named(&Without { signature_action: vec![1; 39], revoked_at: 1_761_800_000_000, reason: Some("x".into()), nested: vec![(3, "y".into())] }).unwrap();
        assert_eq!(v14_entry(&copy, None).unwrap(), keep);
        assert_eq!(skip(&copy, 0).unwrap(), copy.len());
    }
}
