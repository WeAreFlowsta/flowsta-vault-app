# Flowsta Vault

The home of your [Flowsta](https://flowsta.com) identity. Your account is created in the Vault and lives on your device - your keys, your data, and every approval, with no one in control but you.

Built with [Tauri v2](https://tauri.app) (Rust backend), [Qwik](https://qwik.dev) (frontend), and [Holochain](https://www.holochain.org) (distributed identity).

## What is Flowsta Vault?

Flowsta Vault is where a Flowsta account begins. Create your free identity in the Vault - it derives your keys from a 24-word recovery phrase that never leaves your device - then use it everywhere: sign in across the web and partner apps, cryptographically sign your work with Sign It, and run third-party Holochain apps beside your identity.

When you unlock the Vault, it starts a local Holochain conductor that joins the Flowsta network. Websites and apps talk to the Vault through a local bridge, and every sign-in, link, and signature is approved by you, on your machine. Because your identity and data live on your device, they keep working even when Flowsta's servers don't - restore is from your phrase, confirmation comes from community nodes.

For full documentation, visit [docs.flowsta.com/vault](https://docs.flowsta.com/vault/).

## How It Works

- **BIP39 key derivation** - Deterministic Ed25519 keys from a 24-word recovery phrase; the same phrase always rebuilds the same identity, on any machine
- **Vault password** - AES-256-GCM encryption with Argon2id key derivation protects everything at rest
- **Local Holochain conductor** - Runs the Identity, Signing, and encrypted Private DNAs on your device
- **Sign It** - Sign any file locally (up to 10 GB, right-click from your file manager) and publish verifiable proof of authorship to a public signing network
- **Identity linking** - Cryptographic attestations (`IsSamePersonEntry`) on the DHT let apps verify your identity with no server trust required; you approve every link
- **Local bridge** - HTTP server on `localhost:27777` that websites and SDKs use for sign-ins, signing, and backups - every request needs your approval
- **App backups & full data export** - Connected apps store their data (and the keys to use it) encrypted in your Vault, on your device. Export all of it anytime as a Cryptographic Autonomy License (CAL) compliant copy you can take anywhere.

## Your data, your keys

Flowsta Vault is where the apps you connect keep their data - and where you stay in control of it.

- **Apps back up to your Vault, locally.** Through the bridge, a connected app can store an encrypted backup of its data in your Vault. Backups are scoped per app, encrypted at rest, and never leave your machine - there is no Flowsta cloud holding your data.
- **Backups are CAL-complete.** Each one includes not just your *data* but the *cryptographic keys to operate it* - the Cryptographic Autonomy License (CAL-1.0) §4.2.1 promise. You can take your data to any compatible system and keep using it, with no lock-in.
- **Export everything, anytime.** The **Your Data** screen has an **Export All Data** button that produces one CAL-1.0 export of every connected app's data plus the key material, in a readable, portable form. (Backups live on your device, so exporting is how you keep a copy off it.)
- **Recovery.** Your identity restores from your 24-word recovery phrase, your public records re-sync from the network, and your private data and app backups restore from your export. Your phrase restores your identity; your export restores your data.

Developer API: `POST /backup`, `GET /backup/list`, `POST /backup/retrieve`, `POST /backup/delete` on `localhost:27777` - see the [Vault IPC reference](https://docs.flowsta.com/vault/ipc-reference).

## Architecture

```
Flowsta Vault (Tauri v2)
  |
  +-- Lair Keystore (local key management)
  +-- Holochain Conductor (Identity + Signing + Private DNAs)
  +-- Local Bridge (localhost:27777)
       |
       +-- Websites (Sign in with Flowsta, dashboard signing)
       +-- Third-party Holochain apps (@flowsta/holochain SDK)
```

## Downloads

Installers for Linux, macOS, and Windows are on the [Releases](https://github.com/WeAreFlowsta/flowsta-vault-app/releases) page, each with a `SHA256SUMS.txt` to verify your download.

**Only download Flowsta Vault from this repository's releases or the buttons on [flowsta.com/vault](https://flowsta.com/vault/).** The Vault is where you enter your recovery phrase - no third-party mirror or app store is a safe source.

## Building from Source

Prerequisites: [Node.js 20+](https://nodejs.org), [Rust 1.77+](https://rustup.rs), and the [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/) for your platform.

```bash
npm install
cargo tauri build
```

Produces platform-specific installers in `src-tauri/target/release/bundle/`.

## Environment Configuration

All URLs default to production, baked in at compile time. To build against a different environment, copy `.env.example` to `.env` and update the values. See `.env.example` for available variables.

## Project Structure

```
src/                    # Qwik frontend
  components/           # UI components (vault, dashboard, common)
  routes/               # File-based routing (overview, sign-it, your-data, settings)
src-tauri/              # Rust backend
  src/
    commands.rs         # Tauri IPC commands (setup, unlock, lock, identity)
    conductor.rs        # Holochain conductor lifecycle management
    key_derivation.rs   # BIP39 + HMAC-SHA256 key derivation
    vault.rs            # Vault password encryption (Argon2id + AES-256-GCM)
    migration.rs        # Account upgrade from flowsta.com
    ipc_server.rs       # Localhost bridge for websites and SDKs
    sealed.rs           # Encrypted private records
    backup.rs           # App backups + CAL data export
  resources/            # Holochain DNA hApp bundles
```

## Related

- [Flowsta](https://flowsta.com) - Your identity, on your device
- [Documentation](https://docs.flowsta.com) - Full developer documentation
- [@flowsta/auth](https://www.npmjs.com/package/@flowsta/auth) - Sign in with Flowsta + Vault-first signing for web apps
- [@flowsta/holochain](https://www.npmjs.com/package/@flowsta/holochain) - SDK for Holochain app integration

## Why Open Source?

Flowsta Vault holds your cryptographic keys and identity. We believe you should be able to verify exactly what the software running on your machine does with your keys. This repository is open source for transparency - you can audit the code, verify the builds, and confirm that your keys never leave your device.

## License

MIT - see [LICENSE](LICENSE) for details.
