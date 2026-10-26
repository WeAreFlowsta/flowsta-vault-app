//! The signing cell on either line, and the signing side of the move.
//!
//! The 0.6 line's signing cell (v1.4) is written and read by the code in
//! `commands.rs` as it always was. This module adds the 0.7 line's cell
//! (v1.5): the same writes (`create_signature`, `revoke_signature`,
//! `set_thumbnail`) and reads (`get_my_signatures` with its revocation and
//! thumbnail enrichment), plus the carries that move a person's own
//! records from v1.4 to v1.5 (`carry_signature` / `carry_revocation` /
//! `carry_thumbnail`, idempotent by the old action hash - R1 in
//! `planning/HOLOCHAIN_0.7_UPGRADE.md`).
//!
//! A carried record is byte-identical to the v1.4 record (its `supersedes`
//! still names the v1.4 hash); the view the Vault shows re-points that
//! chain at read time (`merge_own`), so provenance stays exact on the
//! network and the history reads right in the app.

use crate::commands::AppState;
use crate::hc::{AppClient, Line, RecordView};
use holochain_types::prelude::{ActionHash, AgentPubKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The bundled signing app on each line.
pub fn signing_app_id(line: Line) -> String {
    match line {
        Line::V06 => crate::dna::make_app_id("signing", crate::dna::BUNDLED_SIGNING_VERSION),
        Line::V07 => crate::dna::make_app_id("signing", crate::dna::BUNDLED_SIGNING_VERSION_07),
    }
}

/// The `signing_app_id` a record carries in the app's JSON, naming the line.
pub fn signing_app_label(line: Line) -> String {
    match line {
        Line::V06 => signing_app_id(line),
        Line::V07 => format!("{}@{}", signing_app_id(line), line.generation()),
    }
}

/// The signing cell's app client on one line, with the role name.
pub(crate) async fn signing_client(state: &Arc<AppState>, line: Line) -> Result<(AppClient, String), String> {
    match line {
        Line::V06 => {
            let (admin_ws, app_port, _apps, signing_apps) = crate::commands::open_signing_conductor(state).await?;
            let app = signing_apps.first().ok_or("Signing DNA not installed")?;
            let (ws, role) = crate::commands::connect_signing_app_ws(state, &admin_ws, app_port, app)
                .await
                .ok_or_else(|| format!("connect_signing_app_ws failed for {}", app.installed_app_id))?;
            Ok((AppClient::V06(ws), role))
        }
        Line::V07 => {
            let (admin_port, app_port) = crate::hc::line_ports(state, line)?;
            let (ws, role) = crate::hc::connect_app_07(state, admin_port, app_port, &signing_app_id(line), "flowsta_signing").await?;
            Ok((AppClient::V07(ws), role))
        }
    }
}

fn mp<T: Serialize>(v: &T) -> Result<Vec<u8>, String> {
    rmp_serde::to_vec_named(v).map_err(|e| format!("MessagePack: {}", e))
}

/// Retry a committing call on the failures that mean "not committed":
/// a moved chain head, a cell not running yet. Timeouts are not retried -
/// an ambiguous commit retried blindly could publish twice.
async fn committing<F, Fut>(what: &str, mut call: F) -> Result<Vec<u8>, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, String>>,
{
    let mut last_err = String::new();
    for attempt in 1..=3u32 {
        match call().await {
            Ok(r) => return Ok(r),
            Err(e) => {
                last_err = e;
                let retriable = ["chain head has moved", "CellDisabled", "CellNotRunning"].iter().any(|m| last_err.contains(m));
                log::warn!("{} attempt {}/3 failed (0.7): {}", what, attempt, last_err);
                if !retriable || attempt == 3 {
                    break;
                }
                let gap = if last_err.contains("Cell") { 5 } else { 2 };
                tokio::time::sleep(std::time::Duration::from_secs(gap)).await;
            }
        }
    }
    Err(last_err)
}

fn action_hash_hex(bytes: &[u8]) -> Result<String, String> {
    let h: ActionHash = rmp_serde::from_slice(bytes).map_err(|e| format!("Failed to decode ActionHash from zome result: {}", e))?;
    Ok(hex::encode(h.get_raw_39()))
}

// ── Writes on the 0.7 line ──────────────────────────────────────────────

/// `create_signature` on the 0.7 cell: `payload_mp` is the msgpack of the
/// same `SignatureRecord` shape the 0.6 write sends (v1.5 adds only the
/// optional `carried_from`, absent on a native record).
pub(crate) async fn create_signature(state: &Arc<AppState>, payload_mp: Vec<u8>) -> Result<String, String> {
    let (client, role) = signing_client(state, Line::V07).await?;
    let result = committing("create_signature", || client.call_zome(&role, "signing", "create_signature", payload_mp.clone())).await?;
    let hex = action_hash_hex(&result)?;
    log::info!("Signature committed on the 0.7 line, action_hash: {}", hex);
    Ok(hex)
}

pub(crate) async fn revoke_signature(state: &Arc<AppState>, action_hash_39: Vec<u8>, reason: Option<String>) -> Result<String, String> {
    #[derive(Serialize)]
    struct RevokeInput {
        signature_action: ActionHash,
        reason: Option<String>,
    }
    let payload = mp(&RevokeInput { signature_action: ActionHash::from_raw_39(action_hash_39), reason })?;
    let (client, role) = signing_client(state, Line::V07).await?;
    let result = committing("revoke_signature", || client.call_zome(&role, "signing", "revoke_signature", payload.clone())).await?;
    let hex = hex::encode(&result);
    log::info!("Signature revoked on the 0.7 line, revocation_hash: {}", hex);
    Ok(hex)
}

pub(crate) async fn set_thumbnail(state: &Arc<AppState>, action_hash_39: Vec<u8>, thumbnail: String) -> Result<String, String> {
    #[derive(Serialize)]
    struct SetThumbnailInput {
        signature_action: ActionHash,
        thumbnail: String,
    }
    let payload = mp(&SetThumbnailInput { signature_action: ActionHash::from_raw_39(action_hash_39), thumbnail })?;
    let (client, role) = signing_client(state, Line::V07).await?;
    let result = committing("set_thumbnail", || client.call_zome(&role, "signing", "set_thumbnail", payload.clone())).await?;
    Ok(hex::encode(&result))
}

// ── Reads ───────────────────────────────────────────────────────────────

/// A signing record's entry as the Vault reads it, on either line.
#[derive(Deserialize, Debug)]
pub(crate) struct SignatureEntry {
    pub file_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer: AgentPubKey,
    pub signed_at: i64,
    pub intent: Option<String>,
    pub ai_generation: Option<String>,
    pub content_rights: Option<serde_json::Value>,
    pub integrity_report: Option<serde_json::Value>,
    pub perceptual_hash: Option<serde_json::Value>,
    #[serde(default)]
    pub supersedes: Option<Vec<u8>>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub comment: Option<String>,
    /// v1.5: set on a record carried from the previous network.
    #[serde(default)]
    pub carried_from: Option<CarriedFromEntry>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct CarriedFromEntry {
    pub original_author: AgentPubKey,
    pub original_timestamp: i64,
    pub original_action_hash: Vec<u8>,
    #[serde(default)]
    pub original_signed_action: Option<Vec<u8>>,
    pub witness: AgentPubKey,
}

#[derive(Deserialize)]
struct RevocationEntry {
    revoked_at: i64,
    reason: Option<String>,
}

#[derive(Deserialize)]
struct ThumbnailEntry {
    thumbnail: String,
    #[serde(default)]
    updated_at: i64,
}

/// Enrichment calls are DHT-bound; a cold network must not hold the list.
const ENRICH_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

async fn revocation_of(client: &AppClient, role: &str, hash: &ActionHash) -> (bool, Option<i64>, Option<String>) {
    let Ok(payload) = mp(hash) else { return (false, None, None) };
    let call = client.call_zome(role, "signing", "get_own_revocations_for_signature", payload);
    let bytes = match tokio::time::timeout(ENRICH_WAIT, call).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            log::warn!("revocation lookup failed for {} ({}): {}", hash, client.line(), e);
            return (false, None, None);
        }
        Err(_) => return (false, None, None),
    };
    let records = match crate::hc::records(client.line(), &bytes) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("revocation records decode failed for {}: {}", hash, e);
            return (false, None, None);
        }
    };
    let Some(first) = records.first() else { return (false, None, None) };
    match first.entry_as::<RevocationEntry>() {
        Ok(rev) => (true, Some(rev.revoked_at), rev.reason),
        Err(_) => (true, None, None),
    }
}

async fn thumbnail_of(client: &AppClient, role: &str, hash: &ActionHash) -> Option<String> {
    let payload = mp(hash).ok()?;
    let call = client.call_zome(role, "signing", "get_thumbnail", payload);
    let bytes = match tokio::time::timeout(ENRICH_WAIT, call).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            log::warn!("thumbnail lookup failed for {} ({}): {}", hash, client.line(), e);
            return None;
        }
        Err(_) => return None,
    };
    crate::hc::record_opt(client.line(), &bytes).ok()??.entry_as::<ThumbnailEntry>().ok().map(|t| t.thumbnail)
}

/// The JSON the app shows for one record (the shape `build_own_signature_json`
/// in `commands.rs` makes), plus `original_action_hash` on a carried record.
fn signature_json(record: &RecordView, entry: &SignatureEntry, label: &str, revocation: (bool, Option<i64>, Option<String>), thumbnail: Option<String>) -> serde_json::Value {
    let raw_32 = entry.signer.get_raw_32();
    let pub_key_arr: [u8; 32] = raw_32.try_into().unwrap_or([0u8; 32]);
    let mut v = serde_json::json!({
        "file_hash": hex::encode(&entry.file_hash),
        "signature": crate::key_derivation::base64_standard_encode(&entry.signature),
        "agent_pub_key": crate::key_derivation::construct_agent_pub_key_string(&pub_key_arr),
        "signed_at": entry.signed_at,
        "action_hash": hex::encode(&record.action_hash),
        "signing_app_id": label,
        "intent": entry.intent,
        "ai_generation": entry.ai_generation,
        "content_rights": entry.content_rights,
        "integrity_report": entry.integrity_report,
        "perceptual_hash": entry.perceptual_hash,
        "supersedes": entry.supersedes.as_ref().map(hex::encode),
        "expires_at": entry.expires_at,
        "tags": entry.tags,
        "comment": entry.comment,
        "revoked": revocation.0,
        "revoked_at": revocation.1,
        "revocation_reason": revocation.2,
        "thumbnail": thumbnail,
    });
    if let Some(from) = &entry.carried_from {
        v["original_action_hash"] = serde_json::json!(hex::encode(&from.original_action_hash));
    }
    v
}

/// The person's own records on the 0.7 cell, enriched, as the app shows
/// them. `Err` when the cell cannot be reached (the caller keeps the 0.6
/// view rather than showing a partial count).
pub(crate) async fn own_signatures(state: &Arc<AppState>) -> Result<Vec<serde_json::Value>, String> {
    let (client, role) = signing_client(state, Line::V07).await?;
    let bytes = client.call_zome(&role, "signing", "get_my_signatures", mp(&())?).await?;
    let records = crate::hc::records(Line::V07, &bytes)?;
    log::info!("Got {} signatures from {}", records.len(), signing_app_label(Line::V07));
    let label = signing_app_label(Line::V07);
    let entries: Vec<(RecordView, SignatureEntry)> =
        records.into_iter().filter_map(|r| r.entry_as::<SignatureEntry>().ok().map(|e| (r, e))).collect();
    let futures = entries.iter().map(|(record, entry)| async {
        let hash = ActionHash::from_raw_39(record.action_hash.clone());
        let (revocation, thumbnail) = tokio::join!(revocation_of(&client, &role, &hash), thumbnail_of(&client, &role, &hash));
        signature_json(record, entry, &label, revocation, thumbnail)
    });
    Ok(futures::future::join_all(futures).await)
}

/// Signatures of linked agents (a migrated web account's key) on the 0.7
/// cell: carried there by Flowsta's node, or native once the account moved.
pub(crate) async fn linked_signatures(state: &Arc<AppState>, linked_keys: &[AgentPubKey]) -> Result<Vec<serde_json::Value>, String> {
    let (client, role) = signing_client(state, Line::V07).await?;
    let label = signing_app_label(Line::V07);
    let mut all = Vec::new();
    for key in linked_keys {
        let bytes = client.call_zome(&role, "signing", "get_signatures_for_agent", mp(key)?).await?;
        let records = crate::hc::records(Line::V07, &bytes)?;
        for record in records {
            let Ok(entry) = record.entry_as::<SignatureEntry>() else { continue };
            let hash = ActionHash::from_raw_39(record.action_hash.clone());
            let thumbnail = thumbnail_of(&client, &role, &hash).await;
            all.push(signature_json(&record, &entry, &label, (false, None, None), thumbnail));
        }
    }
    Ok(all)
}

/// One list from the 0.6 view and the 0.7 view: a record carried to 0.7
/// replaces its 0.6 original (the carried copy is the one that stays), and
/// a `supersedes` that names a carried original is re-pointed at the
/// carried copy so the chain reads whole.
pub(crate) fn merge_own(mut from_06: Vec<serde_json::Value>, from_07: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    let carried: std::collections::HashMap<String, String> = from_07
        .iter()
        .filter_map(|s| Some((s.get("original_action_hash")?.as_str()?.to_string(), s.get("action_hash")?.as_str()?.to_string())))
        .collect();
    from_06.retain(|s| s.get("action_hash").and_then(|h| h.as_str()).map(|h| !carried.contains_key(h)).unwrap_or(true));
    let mut all = from_07;
    all.append(&mut from_06);
    for s in all.iter_mut() {
        let Some(sup) = s.get("supersedes").and_then(|v| v.as_str()).map(String::from) else { continue };
        if let Some(new_hash) = carried.get(&sup) {
            s["supersedes"] = serde_json::json!(new_hash);
        }
    }
    all
}

// ── The carries (the move) ──────────────────────────────────────────────

/// The hash on the 0.7 network of a record carried from `original` (39
/// bytes), or None when it has not been carried.
pub(crate) async fn carried(client: &AppClient, role: &str, original: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let bytes = client.call_zome(role, "signing", "get_carried", mp(&ActionHash::from_raw_39(original.to_vec()))?).await?;
    let h: Option<ActionHash> = rmp_serde::from_slice(&bytes).map_err(|e| format!("get_carried decode: {}", e))?;
    Ok(h.map(|h| h.get_raw_39().to_vec()))
}

/// `carry_signature`: the v1.4 record's entry bytes spliced in as `record`
/// unchanged (byte-identical provenance), with where it came from. Returns
/// the record's hash on the 0.7 network (the existing one on a repeat).
pub(crate) async fn carry_signature(client: &AppClient, role: &str, original: &RecordView) -> Result<Vec<u8>, String> {
    let entry = original.entry.as_ref().ok_or("the signature record has no entry")?;
    let mut buf = Vec::with_capacity(entry.len() + original.signed_action.len() + 128);
    rmp::encode::write_map_len(&mut buf, 4).map_err(|e| e.to_string())?;
    rmp::encode::write_str(&mut buf, "record").map_err(|e| e.to_string())?;
    buf.extend_from_slice(entry);
    rmp::encode::write_str(&mut buf, "original_action_hash").map_err(|e| e.to_string())?;
    buf.extend_from_slice(&mp(&ActionHash::from_raw_39(original.action_hash.clone()))?);
    rmp::encode::write_str(&mut buf, "original_timestamp").map_err(|e| e.to_string())?;
    buf.extend_from_slice(&mp(&original.timestamp_us)?);
    rmp::encode::write_str(&mut buf, "original_signed_action").map_err(|e| e.to_string())?;
    buf.extend_from_slice(&mp(&Some(original.signed_action.clone()))?);
    let result = committing("carry_signature", || client.call_zome(role, "signing", "carry_signature", buf.clone())).await?;
    let h: ActionHash = rmp_serde::from_slice(&result).map_err(|e| format!("carry_signature decode: {}", e))?;
    Ok(h.get_raw_39().to_vec())
}

/// A v1.4 revocation record, read for the carry.
pub(crate) struct Revocation06 {
    pub record: RecordView,
    pub revoked_at: i64,
    pub reason: Option<String>,
}

/// The person's own revocations of one v1.4 signature.
pub(crate) async fn revocations_06(client: &AppClient, role: &str, signature_action: &[u8]) -> Result<Vec<Revocation06>, String> {
    let bytes = client
        .call_zome(role, "signing", "get_own_revocations_for_signature", mp(&ActionHash::from_raw_39(signature_action.to_vec()))?)
        .await?;
    let records = crate::hc::records(client.line(), &bytes)?;
    Ok(records
        .into_iter()
        .filter_map(|record| {
            let e = record.entry_as::<RevocationEntry>().ok()?;
            Some(Revocation06 { record, revoked_at: e.revoked_at, reason: e.reason })
        })
        .collect())
}

/// `carry_revocation` for one revocation, against the signature's hash on
/// the 0.7 network.
pub(crate) async fn carry_revocation(client: &AppClient, role: &str, signature_on_07: &[u8], rev: &Revocation06) -> Result<Vec<u8>, String> {
    #[derive(Serialize)]
    struct Input {
        signature_action: ActionHash,
        revoked_at: i64,
        reason: Option<String>,
        original_author: AgentPubKey,
        original_action_hash: ActionHash,
        original_timestamp: i64,
        original_signed_action: Vec<u8>,
    }
    let payload = mp(&Input {
        signature_action: ActionHash::from_raw_39(signature_on_07.to_vec()),
        revoked_at: rev.revoked_at,
        reason: rev.reason.clone(),
        original_author: AgentPubKey::from_raw_39(rev.record.author.clone()),
        original_action_hash: ActionHash::from_raw_39(rev.record.action_hash.clone()),
        original_timestamp: rev.record.timestamp_us,
        original_signed_action: rev.record.signed_action.clone(),
    })?;
    let result = committing("carry_revocation", || client.call_zome(role, "signing", "carry_revocation", payload.clone())).await?;
    let h: ActionHash = rmp_serde::from_slice(&result).map_err(|e| format!("carry_revocation decode: {}", e))?;
    Ok(h.get_raw_39().to_vec())
}

/// A v1.4 thumbnail record (the latest one), read for the carry.
pub(crate) struct Thumbnail06 {
    pub record: RecordView,
    pub thumbnail: String,
    pub updated_at: i64,
}

pub(crate) async fn thumbnail_06(client: &AppClient, role: &str, signature_action: &[u8]) -> Result<Option<Thumbnail06>, String> {
    let bytes = client.call_zome(role, "signing", "get_thumbnail", mp(&ActionHash::from_raw_39(signature_action.to_vec()))?).await?;
    let Some(record) = crate::hc::record_opt(client.line(), &bytes)? else { return Ok(None) };
    let e = record.entry_as::<ThumbnailEntry>()?;
    let updated_at = if e.updated_at > 0 { e.updated_at } else { record.timestamp_us / 1000 };
    Ok(Some(Thumbnail06 { record, thumbnail: e.thumbnail, updated_at }))
}

pub(crate) async fn carry_thumbnail(client: &AppClient, role: &str, signature_on_07: &[u8], thumb: &Thumbnail06) -> Result<Vec<u8>, String> {
    #[derive(Serialize)]
    struct Input {
        signature_action: ActionHash,
        thumbnail: String,
        updated_at: i64,
        original_author: AgentPubKey,
        original_action_hash: ActionHash,
        original_timestamp: i64,
        original_signed_action: Vec<u8>,
    }
    let payload = mp(&Input {
        signature_action: ActionHash::from_raw_39(signature_on_07.to_vec()),
        thumbnail: thumb.thumbnail.clone(),
        updated_at: thumb.updated_at,
        original_author: AgentPubKey::from_raw_39(thumb.record.author.clone()),
        original_action_hash: ActionHash::from_raw_39(thumb.record.action_hash.clone()),
        original_timestamp: thumb.record.timestamp_us,
        original_signed_action: thumb.record.signed_action.clone(),
    })?;
    let result = committing("carry_thumbnail", || client.call_zome(role, "signing", "carry_thumbnail", payload.clone())).await?;
    let h: ActionHash = rmp_serde::from_slice(&result).map_err(|e| format!("carry_thumbnail decode: {}", e))?;
    Ok(h.get_raw_39().to_vec())
}

/// The person's own v1.4 records (native ones; a v1.4 cell carries none),
/// oldest first, as the carry wants them.
pub(crate) async fn own_records_06(client: &AppClient, role: &str) -> Result<Vec<(RecordView, SignatureEntry)>, String> {
    let bytes = client.call_zome(role, "signing", "get_my_signatures", mp(&())?).await?;
    let records = crate::hc::records(client.line(), &bytes)?;
    let mut entries: Vec<(RecordView, SignatureEntry)> =
        records.into_iter().filter_map(|r| r.entry_as::<SignatureEntry>().ok().map(|e| (r, e))).collect();
    entries.sort_by_key(|(_, e)| e.signed_at);
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(hash: &str, supersedes: Option<&str>, original: Option<&str>) -> serde_json::Value {
        let mut v = serde_json::json!({ "action_hash": hash, "supersedes": supersedes, "signed_at": 1 });
        if let Some(o) = original {
            v["original_action_hash"] = serde_json::json!(o);
        }
        v
    }

    #[test]
    fn a_carried_record_replaces_its_original_and_keeps_the_chain() {
        let from_06 = vec![sig("aa", None, None), sig("bb", Some("aa"), None), sig("cc", None, None)];
        // aa and bb carried; cc not yet.
        let from_07 = vec![sig("a7", None, Some("aa")), sig("b7", Some("aa"), Some("bb"))];
        let all = merge_own(from_06, from_07);
        let hashes: Vec<&str> = all.iter().map(|s| s["action_hash"].as_str().unwrap()).collect();
        assert_eq!(hashes, vec!["a7", "b7", "cc"]);
        // b7's supersedes named the 0.6 hash of aa; it now names aa's carried copy.
        assert_eq!(all[1]["supersedes"], "a7");
    }

    #[test]
    fn nothing_carried_leaves_the_list_as_it_was() {
        let from_06 = vec![sig("aa", None, None), sig("bb", Some("aa"), None)];
        let all = merge_own(from_06.clone(), Vec::new());
        assert_eq!(all, from_06);
    }

    #[test]
    fn the_carry_input_is_the_record_spliced_in_unchanged() {
        // The spliced map decodes as the DNA's CarrySignatureInput shape,
        // with the entry bytes exactly as they were.
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Rec {
            file_hash: Vec<u8>,
            signed_at: i64,
        }
        #[derive(Deserialize)]
        struct Input {
            record: Rec,
            original_action_hash: ActionHash,
            original_timestamp: i64,
            original_signed_action: Option<Vec<u8>>,
        }
        let rec = Rec { file_hash: vec![1, 2, 3], signed_at: 42 };
        // Real-shaped hashes: 39 bytes = a type prefix and 32 bytes of hash.
        let hash_39 = ActionHash::from_raw_32(vec![5u8; 32]).get_raw_39().to_vec();
        let view = RecordView {
            action_hash: hash_39.clone(),
            author: AgentPubKey::from_raw_32(vec![6u8; 32]).get_raw_39().to_vec(),
            timestamp_us: 1_000,
            entry: Some(rmp_serde::to_vec_named(&rec).unwrap()),
            signed_action: vec![9, 9, 9],
            line: Line::V06,
        };
        let mut buf = Vec::new();
        rmp::encode::write_map_len(&mut buf, 4).unwrap();
        rmp::encode::write_str(&mut buf, "record").unwrap();
        buf.extend_from_slice(view.entry.as_ref().unwrap());
        rmp::encode::write_str(&mut buf, "original_action_hash").unwrap();
        buf.extend_from_slice(&mp(&ActionHash::from_raw_39(view.action_hash.clone())).unwrap());
        rmp::encode::write_str(&mut buf, "original_timestamp").unwrap();
        buf.extend_from_slice(&mp(&view.timestamp_us).unwrap());
        rmp::encode::write_str(&mut buf, "original_signed_action").unwrap();
        buf.extend_from_slice(&mp(&Some(view.signed_action.clone())).unwrap());
        let input: Input = rmp_serde::from_slice(&buf).unwrap();
        assert_eq!(input.record, rec);
        assert_eq!(input.original_action_hash.get_raw_39(), &hash_39[..]);
        assert_eq!(input.original_timestamp, 1_000);
        assert_eq!(input.original_signed_action, Some(vec![9, 9, 9]));
    }
}
