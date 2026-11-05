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
            Ok(r) if r.carried + r.failed > 0 || r.switched => log::info!(
                "[signing 1.6] {} carried, {} already there, {} failed{}",
                r.carried,
                r.already,
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
    pub failed: usize,
    pub switched: bool,
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
    use holochain_client_07::{AdminWebsocket, CellInfo};
    use holochain_types_07::prelude::{Entry, EntryType};
    let (admin_port, _) = crate::hc::line_ports(state, Line::V07)?;
    let admin = AdminWebsocket::connect(format!("localhost:{}", admin_port), Some(crate::conductor::node_origin()))
        .await
        .map_err(|e| format!("0.7 admin: {}", e))?;
    let v15 = crate::signing_07::signing_app_id(Line::V07);
    let apps = admin.list_apps(None).await.map_err(|e| format!("list_apps: {}", e))?;
    let Some(cell_id) = apps.iter().find(|a| a.installed_app_id == v15).and_then(|app| {
        app.cell_info.values().flat_map(|c| c.iter()).find_map(|c| match c {
            CellInfo::Provisioned(p) => Some(p.cell_id.clone()),
            _ => None,
        })
    }) else {
        return Ok(Vec::new());
    };
    let dump = admin.dump_full_state(cell_id, None, None).await.map_err(|e| format!("dump {}: {}", v15, e))?;
    #[derive(serde::Deserialize)]
    struct Carried {
        #[serde(default)]
        carried_from: Option<serde::de::IgnoredAny>,
    }
    let mut out = Vec::new();
    for rec in dump.source_chain_dump.records {
        let Some((_, EntryType::App(def))) = rec.action.entry_data() else { continue };
        if def.zome_index.0 != 0 {
            continue;
        }
        let Some(Entry::App(bytes)) = rec.entry.as_ref() else { continue };
        let entry = bytes.bytes().to_vec();
        let carried = rmp_serde::from_slice::<Carried>(&entry).map(|c| c.carried_from.is_some()).unwrap_or(false);
        let action = holochain_types_07::prelude::encode(&rec.action).map_err(|e| format!("encode a v1.5 action: {e}"))?;
        out.push(Mine {
            hash: rec.action_address.get_raw_39().to_vec(),
            kind: def.entry_index.0,
            timestamp: rec.action.timestamp().as_micros(),
            native: Original {
                dna: "1.5".into(),
                action_hash: rec.action_address.clone(),
                author: rec.action.author().clone(),
                timestamp: rec.action.timestamp(),
                action,
                signature: rec.signature.clone(),
                entry: entry.clone(),
            },
            entry,
            carried,
        });
    }
    Ok(out)
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
pub(crate) async fn pass(state: &Arc<AppState>) -> Result<PassReport, String> {
    let root = state.identity_root();
    let mut report = PassReport::default();
    let mine = mine_on_v15(state).await?;
    let (c16, r16) = client(state).await?;
    // v1.5 signature hash -> the hash its copy is carried under here (its
    // own for a native one, its v1.4 original's for a copy).
    let mut key_of: std::collections::HashMap<Vec<u8>, Vec<u8>> = std::collections::HashMap::new();
    for m in mine.iter().filter(|m| m.kind == SIGNATURE_ENTRY) {
        let original = if m.carried { from_v15_copy(&m.entry, None) } else { Ok(Some(m.native.clone())) };
        match original {
            Ok(Some(o)) => {
                let key = o.action_hash.get_raw_39().to_vec();
                if crate::signing_07::carried(&c16, &r16, &key).await?.is_some() {
                    report.already += 1;
                } else if let Err(e) = carry_signature(&c16, &r16, &o).await {
                    report.failed += 1;
                    log::info!("[signing 1.6] a signature not carried: {}", e);
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
        let Some(key) = key_of.get(&named).cloned() else { report.failed += 1; continue };
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
            Err(e) => { report.failed += 1; log::info!("[signing 1.6] a revocation or thumbnail not carried: {}", e) }
        }
    }
    let web_era_done = crate::move_07::marker(&root).map(|m| m.web_era_carried).unwrap_or(true);
    if report.failed == 0 && crate::move_07::moved(&root) && web_era_done {
        std::fs::write(root.join(SWITCHED), b"").map_err(|e| format!("write {}: {}", SWITCHED, e))?;
        report.switched = true;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A map with a nested value, a binary hash and a trailing field: the
    /// skipper walks it, and the rebuild drops the last field and swaps the
    /// hash.
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
