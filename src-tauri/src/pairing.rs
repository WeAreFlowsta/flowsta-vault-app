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

#[cfg(test)]
mod tests {
    use super::*;

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
