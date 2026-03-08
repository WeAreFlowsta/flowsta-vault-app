# Flowsta Vault

Desktop identity manager for [Flowsta Auth](https://flowsta.com). Runs a local Holochain conductor and lair keystore, giving you full control over your cryptographic identity.

Built with [Tauri v2](https://tauri.app) (Rust backend), [Qwik](https://qwik.dev) (frontend), and [Holochain](https://www.holochain.org) (distributed identity).

## What is Flowsta Vault?

Flowsta Vault is the desktop companion to Flowsta Auth. It manages your cryptographic keys locally on your device — your recovery phrase and private keys never leave your machine.

When you unlock Flowsta Vault, it starts a local Holochain conductor that joins the Flowsta DHT network. Third-party apps can request identity linking through a local IPC server, allowing them to cryptographically verify that your desktop and web identities belong to the same person.

For full documentation, visit [docs.flowsta.com/vault](https://docs.flowsta.com/vault/).

## How It Works

- **BIP39 key derivation** — Deterministic Ed25519 keypair from a 24-word recovery phrase
- **Master password vault** — AES-256-GCM encryption with Argon2id key derivation
- **Local Holochain conductor** — Runs Identity DNA and Private DNA on your device
- **Agent linking** — Cryptographic attestations (`IsSamePersonEntry`) on the DHT prove your desktop and web identities are the same person. No server trust required.
- **IPC server** — Local HTTP server on `localhost:27777` for SDK communication with third-party apps
- **Auto-backups** — CAL-compliant source chain backup support

## Architecture

```
Flowsta Vault (Tauri v2)
  |
  +-- Lair Keystore (local key management)
  +-- Holochain Conductor (Identity DNA + Private DNA)
  +-- IPC Server (localhost:27777)
       |
       +-- Third-party Holochain apps (@flowsta/holochain SDK)
       +-- Third-party Tauri apps (@flowsta/auth-tauri SDK)
```

## Downloads

Pre-built binaries for Linux, macOS, and Windows are available on the [Releases](https://github.com/WeAreFlowsta/flowsta-vault/releases) page.

## Building from Source

Prerequisites: [Node.js 20+](https://nodejs.org), [Rust 1.77+](https://rustup.rs), and the [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/) for your platform.

```bash
npm install
cargo tauri build
```

Produces platform-specific installers in `src-tauri/target/release/bundle/`.

## Environment Configuration

All URLs default to production. To configure for a different environment, copy `.env.example` to `.env` and update the values. See `.env.example` for available variables.

## Project Structure

```
src/                    # Qwik frontend
  components/           # UI components (vault, dashboard, common)
  routes/               # File-based routing (overview, identities, settings)
src-tauri/              # Rust backend
  src/
    commands.rs         # Tauri IPC commands (setup, unlock, lock, identity)
    conductor.rs        # Holochain conductor lifecycle management
    key_derivation.rs   # BIP39 + HMAC-SHA256 key derivation
    vault.rs            # Master password encryption (Argon2id + AES-256-GCM)
    ipc_server.rs       # Localhost HTTP server for SDK bridge
    mau.rs              # Monthly active user tracking
  resources/            # Holochain DNA hApp bundles
```

## Related

- [Flowsta Auth](https://flowsta.com) — Decentralized authentication service
- [Documentation](https://docs.flowsta.com) — Full developer documentation
- [@flowsta/holochain](https://www.npmjs.com/package/@flowsta/holochain) — SDK for Holochain app integration
- [@flowsta/auth-tauri](https://www.npmjs.com/package/@flowsta/auth-tauri) — SDK for Tauri app authentication

## Why Open Source?

Flowsta Vault manages your cryptographic keys and identity. We believe you should be able to verify exactly what the software running on your machine does with your keys. This repository is open source for transparency — you can audit the code, verify the builds, and confirm that your keys never leave your device.

## License

MIT — see [LICENSE](LICENSE) for details.
