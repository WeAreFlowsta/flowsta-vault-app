//! Adding a device with a code.
//!
//! The new device shows a code; the person types it into a device that
//! already has the identity. The code has two parts: the first names a
//! mailbox the two devices talk through, the rest is a password that never
//! leaves the two devices. From the password both derive one key (SPAKE2):
//! whoever carries the messages learns nothing and gets one guess.
//!
//!   1. new      -> its SPAKE2 message
//!   2. existing -> its SPAKE2 message + proof it derived the same key
//!   3. new      -> its proof + (sealed) this device's name and key
//!   4. existing -> (sealed) the identity, once the person approves
//!
//! This module is the ceremony only. It does not know how messages travel:
//! the caller hands each one to a transport (today a mailbox on Flowsta's
//! API; a direct connection between the devices can replace it).

use hmac::{Hmac, Mac};
use lair_keystore_api::dependencies::sodoken;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};

pub const PAIR_PREFIX: &str = "flowsta-device-pair:v1:";

/// No vowels (no words), no lookalikes.
const ALPHABET: &[u8] = b"BCDFGHJKMNPQRSTVWXYZ";
pub const MAILBOX_LETTERS: usize = 4;
pub const PASSWORD_LETTERS: usize = 8;

const TAG_BYTES: usize = 32;
const NONCE_BYTES: usize = sodoken::secretbox::XSALSA_NONCEBYTES;
const MAC_BYTES: usize = sodoken::secretbox::XSALSA_MACBYTES;

#[derive(Debug, PartialEq)]
pub enum PairError {
    /// The two devices did not use the same code.
    CodeMismatch,
    /// A message was not what this step expects.
    Malformed,
    Crypto(String),
}

impl std::fmt::Display for PairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PairError::CodeMismatch => write!(f, "code_mismatch"),
            PairError::Malformed => write!(f, "malformed_message"),
            PairError::Crypto(e) => write!(f, "pairing_failed: {}", e),
        }
    }
}

/// A fresh password: the part of the code only the two devices know.
pub fn new_password() -> Result<String, PairError> {
    let mut letters = String::with_capacity(PASSWORD_LETTERS);
    while letters.len() < PASSWORD_LETTERS {
        let mut byte = [0u8; 1];
        sodoken::random::randombytes_buf(&mut byte).map_err(|e| PairError::Crypto(e.to_string()))?;
        // 240 = 12 * 20: bytes above it would favor the first letters.
        if byte[0] < 240 {
            letters.push(ALPHABET[(byte[0] % 20) as usize] as char);
        }
    }
    Ok(letters)
}

/// The code as shown: `MMMM-PPPP-PPPP`.
pub fn format_code(mailbox: &str, password: &str) -> String {
    format!("{}-{}-{}", mailbox, &password[..4], &password[4..])
}

/// The mailbox and the password of a typed code, however it was typed
/// (lower case, spaces, dashes). `None` when it is not a code.
pub fn parse_code(input: &str) -> Option<(String, String)> {
    let letters: String = input
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if letters.len() != MAILBOX_LETTERS + PASSWORD_LETTERS || !letters.bytes().all(|b| ALPHABET.contains(&b)) {
        return None;
    }
    Some((letters[..MAILBOX_LETTERS].to_string(), letters[MAILBOX_LETTERS..].to_string()))
}

fn side(mailbox: &str, name: &str) -> Identity {
    Identity::new(format!("{}{}:{}", PAIR_PREFIX, mailbox, name).as_bytes())
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The channel the two devices share once both used the same code.
pub struct Channel {
    new_to_existing: [u8; 32],
    existing_to_new: [u8; 32],
    proof_of_new: [u8; 32],
    proof_of_existing: [u8; 32],
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.new_to_existing.fill(0);
        self.existing_to_new.fill(0);
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum From {
    New,
    Existing,
}

impl Channel {
    fn derive(shared: &[u8], first: &[u8], second: &[u8]) -> Self {
        let label = |name: &str| hmac(shared, &[PAIR_PREFIX.as_bytes(), name.as_bytes(), first, second]);
        Channel {
            new_to_existing: label("new-to-existing"),
            existing_to_new: label("existing-to-new"),
            proof_of_new: label("proof-new"),
            proof_of_existing: label("proof-existing"),
        }
    }

    fn key(&self, from: From) -> &[u8; 32] {
        match from {
            From::New => &self.new_to_existing,
            From::Existing => &self.existing_to_new,
        }
    }

    /// Encrypt for the other device: nonce, then the cipher.
    pub fn seal(&self, from: From, plain: &[u8]) -> Result<Vec<u8>, PairError> {
        let mut nonce = [0u8; NONCE_BYTES];
        sodoken::random::randombytes_buf(&mut nonce).map_err(|e| PairError::Crypto(e.to_string()))?;
        let mut cipher = vec![0u8; plain.len() + MAC_BYTES];
        sodoken::secretbox::xsalsa_easy(&mut cipher, &nonce, plain, self.key(from))
            .map_err(|e| PairError::Crypto(e.to_string()))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&cipher);
        Ok(out)
    }

    /// Decrypt what the other device sealed. Fails on any change to it.
    pub fn open(&self, from: From, sealed: &[u8]) -> Result<Vec<u8>, PairError> {
        if sealed.len() < NONCE_BYTES + MAC_BYTES {
            return Err(PairError::Malformed);
        }
        let (nonce, cipher) = sealed.split_at(NONCE_BYTES);
        let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| PairError::Malformed)?;
        let mut plain = vec![0u8; cipher.len() - MAC_BYTES];
        sodoken::secretbox::xsalsa_open_easy(&mut plain, cipher, &nonce, self.key(from))
            .map_err(|_| PairError::CodeMismatch)?;
        Ok(plain)
    }
}

/// The new device's side.
pub struct NewDevice {
    spake: Spake2<Ed25519Group>,
    first: Vec<u8>,
}

impl NewDevice {
    /// Step 1. Returns the state to keep and the message to send.
    pub fn start(mailbox: &str, password: &str) -> (Self, Vec<u8>) {
        let (spake, first) = Spake2::<Ed25519Group>::start_a(
            &Password::new(password.as_bytes()),
            &side(mailbox, "new"),
            &side(mailbox, "existing"),
        );
        (NewDevice { spake, first: first.clone() }, first)
    }

    /// Step 3. Checks the existing device's proof; returns the channel and
    /// this device's own proof, to send in front of its sealed introduction.
    pub fn finish(self, message2: &[u8]) -> Result<(Channel, [u8; TAG_BYTES]), PairError> {
        if message2.len() <= TAG_BYTES {
            return Err(PairError::Malformed);
        }
        let (second, proof) = message2.split_at(message2.len() - TAG_BYTES);
        let shared = self.spake.finish(second).map_err(|_| PairError::Malformed)?;
        let channel = Channel::derive(&shared, &self.first, second);
        if !same(proof, &channel.proof_of_existing) {
            return Err(PairError::CodeMismatch);
        }
        let own = channel.proof_of_new;
        Ok((channel, own))
    }
}

/// The existing device's side.
pub struct ExistingDevice {
    channel: Channel,
}

impl ExistingDevice {
    /// Step 2. Returns the state to keep and the message to send.
    pub fn answer(mailbox: &str, password: &str, message1: &[u8]) -> Result<(Self, Vec<u8>), PairError> {
        let (spake, second) = Spake2::<Ed25519Group>::start_b(
            &Password::new(password.as_bytes()),
            &side(mailbox, "new"),
            &side(mailbox, "existing"),
        );
        let shared = spake.finish(message1).map_err(|_| PairError::Malformed)?;
        let channel = Channel::derive(&shared, message1, &second);
        let mut message2 = second;
        message2.extend_from_slice(&channel.proof_of_existing);
        Ok((ExistingDevice { channel }, message2))
    }

    /// Step 3, received: the new device proves it used the same code and
    /// introduces itself. Nothing is sent to it before this passes.
    pub fn confirm(self, message3: &[u8]) -> Result<(Channel, DeviceIntro), PairError> {
        if message3.len() <= TAG_BYTES {
            return Err(PairError::Malformed);
        }
        let (proof, sealed) = message3.split_at(TAG_BYTES);
        if !same(proof, &self.channel.proof_of_new) {
            return Err(PairError::CodeMismatch);
        }
        let intro: DeviceIntro =
            serde_json::from_slice(&self.channel.open(From::New, sealed)?).map_err(|_| PairError::Malformed)?;
        Ok((self.channel, intro))
    }
}

/// Step 3's message: the proof, then the sealed introduction.
pub fn introduction(channel: &Channel, proof: &[u8; TAG_BYTES], intro: &DeviceIntro) -> Result<Vec<u8>, PairError> {
    let plain = serde_json::to_vec(intro).map_err(|e| PairError::Crypto(e.to_string()))?;
    let mut message = proof.to_vec();
    message.extend_from_slice(&channel.seal(From::New, &plain)?);
    Ok(message)
}

/// What the new device says about itself. The person sees `name` in the
/// approve dialog on the existing device.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DeviceIntro {
    pub name: String,
    pub platform: String,
    pub install_id: String,
    /// The key this device's conductor will run (standard base64, 32 bytes).
    pub device_key: String,
}

/// What the existing device hands over once the person approves:
/// everything a device derives from the recovery phrase, what the account
/// is called, and its approval of the new device for the registry.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Handover {
    pub identity_seed: Vec<u8>,
    pub data_key: Vec<u8>,
    pub backup_key: Vec<u8>,
    pub private_network_seed: String,
    pub recovery_lookup_hash: Option<String>,
    pub hosting_model: Option<String>,
    pub web_agent_pub_key: Option<String>,
    pub web_email: Option<String>,
    pub email_verified: Option<bool>,
    pub web_username: Option<String>,
    pub display_name: Option<String>,
    pub approval: crate::device_registry::Approval,
}

impl Drop for Handover {
    fn drop(&mut self) {
        self.identity_seed.fill(0);
        self.data_key.fill(0);
        self.backup_key.fill(0);
    }
}

/// Why this device cannot hand the identity over yet.
#[derive(Debug, PartialEq)]
pub enum HandoverGap {
    Locked,
    /// It was set up before these keys were kept: the recovery phrase,
    /// typed once on this device, fills them in.
    NeedsPhraseOnce,
}

impl Handover {
    /// From the unlocked vault of the existing device.
    pub fn from_config(
        config: Option<&crate::vault::VaultConfig>,
        approval: crate::device_registry::Approval,
    ) -> Result<Handover, HandoverGap> {
        let cfg = config.ok_or(HandoverGap::Locked)?;
        let identity_seed = cfg.device_seed.clone().filter(|s| s.len() == 32).ok_or(HandoverGap::Locked)?;
        let (Some(data_key), Some(backup_key), Some(private_network_seed)) = (
            cfg.data_key.clone().filter(|k| k.len() == 32),
            cfg.backup_key.clone().filter(|k| k.len() == 32),
            cfg.private_network_seed.clone(),
        ) else {
            return Err(HandoverGap::NeedsPhraseOnce);
        };
        Ok(Handover {
            identity_seed,
            data_key,
            backup_key,
            private_network_seed,
            recovery_lookup_hash: cfg.recovery_lookup_hash.clone(),
            hosting_model: cfg.hosting_model.clone(),
            web_agent_pub_key: cfg.web_agent_pub_key.clone(),
            web_email: cfg.web_email.clone(),
            email_verified: cfg.email_verified,
            web_username: cfg.web_username.clone(),
            display_name: cfg.display_name.clone(),
            approval,
        })
    }

    /// Step 4's message.
    pub fn seal(&self, channel: &Channel) -> Result<Vec<u8>, PairError> {
        let mut plain = serde_json::to_vec(self).map_err(|e| PairError::Crypto(e.to_string()))?;
        let sealed = channel.seal(From::Existing, &plain);
        plain.fill(0);
        sealed
    }

    /// Step 4, received on the new device.
    pub fn open(channel: &Channel, message4: &[u8]) -> Result<Handover, PairError> {
        let mut plain = channel.open(From::Existing, message4)?;
        let handover = serde_json::from_slice(&plain).map_err(|_| PairError::Malformed);
        plain.fill(0);
        handover
    }
}

// ── Carrying the messages ───────────────────────────────────────────────────

/// How the four messages travel. The ceremony above does not depend on it.
pub(crate) trait Transport {
    async fn send(&mut self, message: &[u8]) -> Result<(), String>;
    /// The other device's next message, waiting up to `wait` for it.
    async fn next(&mut self, wait: std::time::Duration) -> Result<Vec<u8>, String>;
    async fn close(&mut self);
}

/// A mailbox on Flowsta's API: it stores the messages for a few minutes
/// and cannot read them. It is not told which identity is involved.
pub struct Mailbox {
    base: String,
    token: String,
    read: u64,
    http: reqwest::Client,
}

impl Mailbox {
    fn http() -> Result<reqwest::Client, String> {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("HTTP client build failed: {}", e))
    }

    async fn post(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value, String> {
        let resp = self
            .http
            .post(format!("{}/auth/pair/{}", self.base, path))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("api_unreachable: {}", e))?;
        let ok = resp.status().is_success();
        let value: serde_json::Value = resp.json().await.unwrap_or_default();
        if ok {
            Ok(value)
        } else {
            Err(value.get("error").and_then(|e| e.as_str()).unwrap_or("pair_failed").to_string())
        }
    }

    /// The new device opens a mailbox. Returns it and its name (the first
    /// part of the code).
    pub async fn open(api_url: &str) -> Result<(Mailbox, String), String> {
        let mut mailbox = Mailbox { base: api_url.trim_end_matches('/').to_string(), token: String::new(), read: 0, http: Self::http()? };
        let opened = mailbox.post("open", serde_json::json!({})).await?;
        mailbox.token = opened["token"].as_str().ok_or("pair_failed")?.to_string();
        let id = opened["mailbox"].as_str().ok_or("pair_failed")?.to_string();
        Ok((mailbox, id))
    }

    /// The existing device claims the mailbox a typed code names.
    pub async fn claim(api_url: &str, mailbox_id: &str) -> Result<Mailbox, String> {
        let mut mailbox = Mailbox { base: api_url.trim_end_matches('/').to_string(), token: String::new(), read: 0, http: Self::http()? };
        let claimed = mailbox.post("claim", serde_json::json!({ "mailbox": mailbox_id })).await?;
        mailbox.token = claimed["token"].as_str().ok_or("pair_failed")?.to_string();
        Ok(mailbox)
    }
}

impl Transport for Mailbox {
    async fn send(&mut self, message: &[u8]) -> Result<(), String> {
        let body = crate::key_derivation::base64_standard_encode(message);
        self.post("send", serde_json::json!({ "token": self.token, "body": body })).await.map(|_| ())
    }

    async fn next(&mut self, wait: std::time::Duration) -> Result<Vec<u8>, String> {
        let deadline = std::time::Instant::now() + wait;
        loop {
            let answer = self.post("receive", serde_json::json!({ "token": self.token, "after": self.read })).await?;
            if let Some(first) = answer["messages"].as_array().and_then(|m| m.first()) {
                self.read = first["seq"].as_u64().unwrap_or(self.read + 1);
                return crate::commands::base64_standard_decode(first["body"].as_str().unwrap_or(""))
                    .map_err(|_| PairError::Malformed.to_string());
            }
            if answer["closed"].as_bool() == Some(true) {
                return Err("pair_closed".into());
            }
            if std::time::Instant::now() >= deadline {
                return Err("pair_timeout".into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        }
    }

    async fn close(&mut self) {
        let _ = self.post("close", serde_json::json!({ "token": self.token })).await;
    }
}

/// How long the new device waits for the code to be typed on the other one.
const WAIT_FOR_CODE: std::time::Duration = std::time::Duration::from_secs(5 * 60);
/// How long either waits for the other's next step once they are talking
/// (the person reads a dialog and approves in this time).
const WAIT_FOR_STEP: std::time::Duration = std::time::Duration::from_secs(9 * 60);

/// The new device's whole side: returns the identity once the person
/// approved on the other device. `on_met` runs when the other device has
/// answered with the same code (the person is now reading its question).
pub(crate) async fn run_new_device<T: Transport>(
    transport: &mut T,
    mailbox: &str,
    password: &str,
    intro: &DeviceIntro,
    on_met: impl Fn(),
) -> Result<Handover, String> {
    let (state, first) = NewDevice::start(mailbox, password);
    transport.send(&first).await?;
    let second = transport.next(WAIT_FOR_CODE).await?;
    let (channel, proof) = match state.finish(&second) {
        Ok(done) => done,
        Err(e) => {
            transport.close().await;
            return Err(e.to_string());
        }
    };
    transport.send(&introduction(&channel, &proof, intro).map_err(|e| e.to_string())?).await?;
    on_met();
    let fourth = transport.next(WAIT_FOR_STEP).await?;
    let handover = Handover::open(&channel, &fourth).map_err(|e| e.to_string());
    transport.close().await;
    handover
}

/// The existing device, up to the question for the person: who is asking.
pub(crate) async fn meet_new_device<T: Transport>(
    transport: &mut T,
    mailbox: &str,
    password: &str,
) -> Result<(Channel, DeviceIntro), String> {
    let first = transport.next(std::time::Duration::from_secs(20)).await?;
    let (state, second) = ExistingDevice::answer(mailbox, password, &first).map_err(|e| e.to_string())?;
    transport.send(&second).await?;
    let third = transport.next(std::time::Duration::from_secs(60)).await?;
    match state.confirm(&third) {
        Ok(met) => Ok(met),
        Err(e) => {
            transport.close().await;
            Err(e.to_string())
        }
    }
}

/// The existing device, after the person approved.
pub(crate) async fn hand_over<T: Transport>(transport: &mut T, channel: &Channel, handover: &Handover) -> Result<(), String> {
    transport.send(&handover.seal(channel).map_err(|e| e.to_string())?).await
}

// ── The two devices' commands ───────────────────────────────────────────────

use crate::commands::AppState;
use std::sync::{Arc, Mutex};
use tauri::{Emitter, State};

/// What the new device's screen follows (`pair-status` events).
#[derive(Serialize, Clone)]
#[serde(tag = "state", rename_all = "snake_case")]
enum PairStatus {
    /// The other device answered; the person is reading its question.
    WaitingForApproval,
    Done { agent_pub_key: String, did: String },
    Failed { reason: String },
}

/// The new device's running ceremony (one at a time).
static NEW_SIDE: Mutex<Option<tauri::async_runtime::JoinHandle<()>>> = Mutex::new(None);

/// The existing device, between the typed code and the person's answer.
struct Met {
    mailbox: Mailbox,
    channel: Channel,
    intro: DeviceIntro,
}
static MET: tokio::sync::Mutex<Option<Met>> = tokio::sync::Mutex::const_new(None);

fn device_name() -> String {
    sysinfo::System::host_name()
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "New device".to_string())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// New device: open a mailbox and show the code. The rest runs in the
/// background and reports through `pair-status`; when the other device
/// approves, this device's vault is created under `password`.
#[tauri::command]
pub async fn pair_begin(
    api_url: String,
    password: String,
    app_handle: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    pair_begin_inner(api_url, password, app_handle, state.inner().clone()).await
}

pub(crate) async fn pair_begin_inner(
    api_url: String,
    password: String,
    app_handle: tauri::AppHandle,
    state: Arc<AppState>,
) -> Result<String, String> {
    crate::commands::validate_vault_password(&password)?;
    if state.vault_config.lock().unwrap().is_some() {
        return Err("Lock this Vault before adding another identity.".into());
    }
    pair_cancel().await?;

    let install_id = crate::paths::install_id(&state.data_dir).ok_or("no install id")?;
    let conductor_seed = crate::key_derivation::new_conductor_seed();
    let intro = DeviceIntro {
        name: device_name(),
        platform: std::env::consts::OS.to_string(),
        install_id,
        device_key: crate::key_derivation::base64_standard_encode(&crate::key_derivation::public_key_of_seed(&conductor_seed)),
    };
    let (mut mailbox, mailbox_id) = Mailbox::open(&api_url).await?;
    let code_password = new_password().map_err(|e| e.to_string())?;
    let code = format_code(&mailbox_id, &code_password);

    let task = tauri::async_runtime::spawn(async move {
        let met_handle = app_handle.clone();
        let handover = run_new_device(&mut mailbox, &mailbox_id, &code_password, &intro, move || {
            let _ = met_handle.emit("pair-status", PairStatus::WaitingForApproval);
        })
        .await;
        let status = match handover.and_then(|h| join_identity(h, password, conductor_seed, app_handle.clone(), &state)) {
            Ok(done) => PairStatus::Done { agent_pub_key: done.agent_pub_key, did: done.did },
            Err(reason) => PairStatus::Failed { reason },
        };
        let _ = app_handle.emit("pair-status", status);
    });
    *NEW_SIDE.lock().unwrap() = Some(task);
    Ok(code)
}

/// New device: create the vault from what the other device handed over.
fn join_identity(
    handover: Handover,
    password: String,
    conductor_seed: [u8; 32],
    app_handle: tauri::AppHandle,
    state: &Arc<AppState>,
) -> Result<crate::commands::SetupResult, String> {
    let malformed = || PairError::Malformed.to_string();
    let keys = crate::commands::IdentityKeys {
        identity_seed: handover.identity_seed.as_slice().try_into().map_err(|_| malformed())?,
        recovery_lookup_hash: handover.recovery_lookup_hash.clone(),
        data_key: handover.data_key.as_slice().try_into().map_err(|_| malformed())?,
        private_network_seed: handover.private_network_seed.clone(),
        backup_key: handover.backup_key.as_slice().try_into().map_err(|_| malformed())?,
    };
    // This device registers with the approval of the one that added it.
    crate::device_registry::hold_approval(Some(handover.approval.clone()));
    let result = crate::commands::setup_vault_from_keys(
        keys,
        password,
        handover.web_agent_pub_key.clone(),
        handover.web_email.clone(),
        handover.email_verified,
        handover.web_username.clone(),
        handover.display_name.clone(),
        None, // the picture arrives with the identity's records
        handover.hosting_model.clone(),
        false,
        false,
        Some(conductor_seed),
        app_handle,
        state,
    );
    match &result {
        Ok(_) => state.activity.record("device_joined", "Added this device to your identity", None, None, None),
        Err(_) => crate::device_registry::hold_approval(None),
    }
    result
}

/// New device: stop waiting (the person went back).
#[tauri::command]
pub async fn pair_cancel() -> Result<(), String> {
    if let Some(task) = NEW_SIDE.lock().unwrap().take() {
        task.abort();
    }
    Ok(())
}

/// Existing device: the person typed the code shown on the new device.
/// Returns who is asking, for the approve question.
#[tauri::command]
pub async fn pair_claim(api_url: String, code: String, state: State<'_, Arc<AppState>>) -> Result<DeviceIntro, String> {
    pair_claim_inner(api_url, code, state.inner()).await
}

pub(crate) async fn pair_claim_inner(api_url: String, code: String, state: &Arc<AppState>) -> Result<DeviceIntro, String> {
    let (mailbox_id, code_password) = parse_code(&code).ok_or("invalid_code")?;
    {
        let config = state.vault_config.lock().unwrap();
        let cfg = config.as_ref().ok_or("vault_locked")?;
        if cfg.data_key.is_none() || cfg.backup_key.is_none() || cfg.private_network_seed.is_none() {
            return Err("needs_phrase_once".into());
        }
    }
    let mut mailbox = Mailbox::claim(&api_url, &mailbox_id).await?;
    let (channel, intro) = meet_new_device(&mut mailbox, &mailbox_id, &code_password).await?;
    let mut met = MET.lock().await;
    if let Some(mut earlier) = met.take() {
        earlier.mailbox.close().await;
    }
    *met = Some(Met { mailbox, channel, intro: intro.clone() });
    Ok(intro)
}

/// Existing device: the person approved. Hands the identity over.
#[tauri::command]
pub async fn pair_approve(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    pair_approve_inner(state.inner()).await
}

pub(crate) async fn pair_approve_inner(state: &Arc<AppState>) -> Result<(), String> {
    let mut met = MET.lock().await.take().ok_or("pair_closed")?;
    let mut added_key = [0u8; 32];
    let handover = {
        let config = state.vault_config.lock().unwrap();
        let cfg = config.as_ref().ok_or("vault_locked")?;
        let identity_seed: [u8; 32] = cfg.device_seed.as_deref().and_then(|s| s.try_into().ok()).ok_or("vault_locked")?;
        let approver_seed = cfg.conductor_seed_bytes().ok_or("vault_locked")?;
        let new_device: [u8; 32] = crate::commands::base64_standard_decode(&met.intro.device_key)
            .ok()
            .and_then(|k| k.as_slice().try_into().ok())
            .ok_or_else(|| PairError::Malformed.to_string())?;
        added_key = new_device;
        let approval = crate::device_registry::approve_device(
            &crate::key_derivation::public_key_of_seed(&identity_seed),
            &approver_seed,
            &new_device,
            &met.intro.install_id,
            now_ms(),
        );
        Handover::from_config(Some(cfg), approval).map_err(|gap| match gap {
            HandoverGap::Locked => "vault_locked".to_string(),
            HandoverGap::NeedsPhraseOnce => "needs_phrase_once".to_string(),
        })?
    };
    let sent = hand_over(&mut met.mailbox, &met.channel, &handover).await;
    if sent.is_ok() {
        crate::devices::remember_added(state, &met.intro.install_id, &added_key);
        state.activity.record("device_added", format!("Added {} as one of your devices", met.intro.name), None, None, None);
    } else {
        met.mailbox.close().await;
    }
    sent
}

/// Existing device: the person said no. The new device is told at once.
#[tauri::command]
pub async fn pair_decline() -> Result<(), String> {
    if let Some(mut met) = MET.lock().await.take() {
        met.mailbox.close().await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both devices' real code through a running API's mailbox (never production).
    ///   FLOWSTA_TEST_API=https://... cargo test --lib pairing::tests::live -- --ignored
    #[tokio::test]
    #[ignore]
    async fn live_two_devices_pair_through_the_mailbox() {
        let api = std::env::var("FLOWSTA_TEST_API").expect("FLOWSTA_TEST_API");
        assert!(!api.contains("//auth-api.flowsta.com"), "not against production");

        let (mut new_box, mailbox) = Mailbox::open(&api).await.unwrap();
        let password = new_password().unwrap();
        let code = format_code(&mailbox, &password);
        println!("code {}", code);

        let api_for_new = mailbox.clone();
        let password_for_new = password.clone();
        let new_side = tokio::spawn(async move {
            run_new_device(&mut new_box, &api_for_new, &password_for_new, &intro(), || {}).await
        });

        // The person types the code on the existing device.
        let (typed_mailbox, typed_password) = parse_code(&code.to_lowercase()).unwrap();
        let mut old_box = Mailbox::claim(&api, &typed_mailbox).await.unwrap();
        assert_eq!(Mailbox::claim(&api, &typed_mailbox).await.err().as_deref(), Some("already_claimed"));
        let (channel, introduced) = meet_new_device(&mut old_box, &typed_mailbox, &typed_password).await.unwrap();
        assert_eq!(introduced, intro());
        hand_over(&mut old_box, &channel, &handover()).await.unwrap();

        let received = new_side.await.unwrap().unwrap();
        assert!(received == handover());

        // A wrong password: the new device notices, nothing is handed over.
        let (mut new_box, mailbox) = Mailbox::open(&api).await.unwrap();
        let new_side = tokio::spawn({
            let mailbox = mailbox.clone();
            async move { run_new_device(&mut new_box, &mailbox, "GHJKMNPQ", &intro(), || {}).await }
        });
        let mut old_box = Mailbox::claim(&api, &mailbox).await.unwrap();
        let met = meet_new_device(&mut old_box, &mailbox, "GHJKMNPR").await;
        assert_eq!(new_side.await.unwrap().err().as_deref(), Some("code_mismatch"));
        assert_eq!(met.err().as_deref(), Some("pair_closed"));
    }

    fn intro() -> DeviceIntro {
        DeviceIntro {
            name: "Office PC".into(),
            platform: "windows".into(),
            install_id: "0123456789abcdef0123456789abcdef".into(),
            device_key: "a2V5".into(),
        }
    }

    fn handover() -> Handover {
        Handover {
            identity_seed: vec![1; 32],
            data_key: vec![2; 32],
            backup_key: vec![3; 32],
            private_network_seed: "seed".into(),
            recovery_lookup_hash: Some("hash".into()),
            hosting_model: Some("device-hosted".into()),
            web_agent_pub_key: None,
            web_email: Some("a@example.com".into()),
            email_verified: Some(true),
            web_username: Some("someone".into()),
            display_name: Some("Someone".into()),
            approval: crate::device_registry::Approval {
                approver_key: "k".into(),
                approver_signature: "s".into(),
                timestamp: 7,
            },
        }
    }

    #[test]
    fn a_code_is_three_groups_and_reads_back_however_it_is_typed() {
        let password = new_password().unwrap();
        assert_eq!(password.len(), PASSWORD_LETTERS);
        assert!(password.bytes().all(|b| ALPHABET.contains(&b)));
        assert_ne!(password, new_password().unwrap());
        let code = format_code("BCDF", "GHJKMNPQ");
        assert_eq!(code, "BCDF-GHJK-MNPQ");
        assert_eq!(parse_code(&code), Some(("BCDF".into(), "GHJKMNPQ".into())));
        assert_eq!(parse_code(" bcdf ghjk mnpq "), Some(("BCDF".into(), "GHJKMNPQ".into())));
        assert_eq!(parse_code("BCDF-GHJK-MNP"), None);
        assert_eq!(parse_code("BCDF-GHJK-MNPA"), None, "a vowel is not in the alphabet");
    }

    #[test]
    fn the_same_code_on_both_devices_carries_the_identity_across() {
        let (new_device, m1) = NewDevice::start("BCDF", "GHJKMNPQ");
        let (existing, m2) = ExistingDevice::answer("BCDF", "GHJKMNPQ", &m1).unwrap();
        let (new_channel, proof) = new_device.finish(&m2).unwrap();
        let m3 = introduction(&new_channel, &proof, &intro()).unwrap();
        let (existing_channel, introduced) = existing.confirm(&m3).unwrap();
        assert_eq!(introduced, intro());
        let m4 = handover().seal(&existing_channel).unwrap();
        let received = Handover::open(&new_channel, &m4).unwrap();
        assert!(received == handover());
    }

    #[test]
    fn a_wrong_code_is_noticed_by_the_new_device_before_it_says_anything_about_itself() {
        let (new_device, m1) = NewDevice::start("BCDF", "GHJKMNPQ");
        let (_, m2) = ExistingDevice::answer("BCDF", "GHJKMNPR", &m1).unwrap();
        assert_eq!(new_device.finish(&m2).err(), Some(PairError::CodeMismatch));
    }

    #[test]
    fn a_wrong_code_gets_nothing_from_the_existing_device() {
        // Someone who claimed the mailbox with a guessed password.
        let (guesser, m1) = NewDevice::start("BCDF", "ZZZZZZZZ");
        let (existing, m2) = ExistingDevice::answer("BCDF", "GHJKMNPQ", &m1).unwrap();
        assert!(guesser.finish(&m2).is_err());
        // Whatever it sends next, the existing device hands nothing over.
        let (other, _) = NewDevice::start("BCDF", "ZZZZZZZZ");
        let (_, m2b) = ExistingDevice::answer("BCDF", "ZZZZZZZZ", &other.first.clone()).unwrap();
        let (channel, proof) = other.finish(&m2b).unwrap();
        let forged = introduction(&channel, &proof, &intro()).unwrap();
        assert_eq!(existing.confirm(&forged).err(), Some(PairError::CodeMismatch));
    }

    #[test]
    fn the_same_password_in_another_mailbox_is_another_key() {
        let (new_device, m1) = NewDevice::start("BCDF", "GHJKMNPQ");
        let (_, m2) = ExistingDevice::answer("BCDG", "GHJKMNPQ", &m1).unwrap();
        assert_eq!(new_device.finish(&m2).err(), Some(PairError::CodeMismatch));
    }

    #[test]
    fn what_is_sealed_cannot_be_changed_or_sent_back() {
        let (new_device, m1) = NewDevice::start("BCDF", "GHJKMNPQ");
        let (existing, m2) = ExistingDevice::answer("BCDF", "GHJKMNPQ", &m1).unwrap();
        let (new_channel, proof) = new_device.finish(&m2).unwrap();
        let m3 = introduction(&new_channel, &proof, &intro()).unwrap();

        let mut changed = m3.clone();
        *changed.last_mut().unwrap() ^= 1;
        let (existing_channel, _) = existing.confirm(&m3).unwrap();
        assert!(existing_channel.open(From::New, &changed[TAG_BYTES..]).is_err());
        // The new device's own message, played back to it as if from the existing one.
        assert!(Handover::open(&new_channel, &m3[TAG_BYTES..]).is_err());
        // Nothing readable travels: the name is not in the message.
        assert!(!m3.windows(9).any(|w| w == b"Office PC"));
        let m4 = handover().seal(&existing_channel).unwrap();
        assert!(!m4.windows(13).any(|w| w == b"a@example.com"));
    }

    #[test]
    fn a_device_without_the_shared_keys_says_what_it_needs_first() {
        let approval = handover().approval.clone();
        assert_eq!(Handover::from_config(None, approval.clone()).err(), Some(HandoverGap::Locked));
        let mut cfg: crate::vault::VaultConfig = serde_json::from_str(
            r#"{"agent_pub_key":"uhCAkTest","did":"did:flowsta:uhCAkTest","installed_app_ids":[],"created_at":1}"#,
        )
        .unwrap();
        cfg.device_seed = Some(vec![1; 32]);
        assert_eq!(Handover::from_config(Some(&cfg), approval.clone()).err(), Some(HandoverGap::NeedsPhraseOnce));
        cfg.data_key = Some(vec![2; 32]);
        cfg.backup_key = Some(vec![3; 32]);
        cfg.private_network_seed = Some("seed".into());
        assert!(Handover::from_config(Some(&cfg), approval).is_ok());
    }
}
