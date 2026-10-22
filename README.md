# Flowsta Vault

The home of your [Flowsta](https://flowsta.com) identity. Your account is
created in the Vault and lives on your devices: your keys, your data, and
every approval, with no one in control but you.

Built with [Tauri v2](https://tauri.app) (Rust backend),
[Qwik](https://qwik.dev) (frontend), and
[Holochain](https://www.holochain.org) (distributed identity).

**[Download](https://flowsta.com/vault/)** ·
**[Documentation](https://docs.flowsta.com/vault/)** ·
**[Releases](https://github.com/WeAreFlowsta/flowsta-vault-app/releases)**

## What is Flowsta Vault?

Flowsta Vault is where a Flowsta account begins. Create your free identity
in the Vault, which derives your keys from a 24-word recovery phrase that
never leaves your device, then use it everywhere: sign in across the web
and partner apps, sign your work with Sign It, and run apps that keep
their data beside your identity.

When you unlock the Vault, it starts a local Holochain conductor that
joins the Flowsta network. Websites and apps talk to the Vault through a
local bridge, and every sign-in, link, and signature is approved by you,
on your machine. Because your identity and data live on your devices,
they keep working even when Flowsta's servers do not: restore is from
your phrase, and your devices find each other through Flowsta's meeting
point or an open community node.

## What it does

- **One identity, every desktop you own.** Add a second computer with a
  short code and your recovery phrase. Your identity, your settings, and
  the data of every app you connected arrive there, and from then on the
  Vaults keep each other in step, peer to peer and encrypted with your
  own keys, even while one of them is locked. Settings shows each device,
  what is moving between them, and lets you remove one; a removed device
  can no longer sign in or sync.
- **More than one identity.** Keep several identities in one Vault and
  switch between them. Apps are told which identity answered, and an app
  open as one identity is never answered as another.
- **Made for shared computers.** The Vault answers only the apps and
  browsers of your own account on the computer, never another user's.
- **Sign in, one step at a time.** A request from an app shows one
  dialog that says who is asking, what for, and which identity would
  answer. Your email is decided here: an app that asks for it gets
  exactly the one you choose, or none.
- **Sign It.** Sign any file locally, up to 10 GB, from the app or your
  file manager, and publish verifiable proof of authorship to the public
  signing network. Anyone can check a signed file at flowsta.com without
  trusting you or us.
- **An Activity page.** Everything that happened in this Vault, newest
  first: sign-ins and what they shared, email grants, remembered sites,
  app links, signatures, backups, email and password changes. All of it
  is read from this device; nothing is fetched from Flowsta.
- **Your data, your keys.** Connected apps keep encrypted backups of their
  data in your Vault, on your device, and never on a Flowsta server. Each
  backup carries the keys to operate the data, the promise of the
  Cryptographic Autonomy License. **Export Data** on the Your Data page
  produces one readable, portable copy of everything, and **Import Data**
  brings it back on a new computer.
- **Recovery that says what it is doing.** Restore from your phrase and
  the Vault tells you what has arrived from the network and what is still
  on its way. Your phrase restores your identity; your export, or one of
  your other devices, restores your data.

## How it works

- **BIP39 key derivation.** Deterministic Ed25519 keys from a 24-word
  recovery phrase; the same phrase always rebuilds the same identity, on
  any machine. Adding a device needs the phrase, so only you can add one.
- **Vault password.** AES-256-GCM encryption with Argon2id key derivation
  protects everything at rest.
- **Local Holochain conductor.** Runs the Identity, Signing, and encrypted
  Private DNAs on your device, over Holochain's Iroh transport.
- **Identity linking.** Cryptographic attestations on the DHT let apps
  verify your identity with no server trust required; you approve every
  link.
- **Local bridge.** An HTTP server on `localhost:27777` that websites and
  SDKs use for sign-ins, signing, and backups. Every request names the
  identity it is for and needs your approval; a Vault open as a different
  identity refuses it.
- **Device sync.** Your devices exchange encrypted records directly, and
  a device that is off catches up from the others when it returns.

Developer API: `POST /backup`, `GET /backup/list`, `POST /backup/retrieve`,
`POST /backup/delete` and the sign-in and signing routes on
`localhost:27777`. See the
[Vault IPC reference](https://docs.flowsta.com/vault/ipc-reference).

## Architecture

```
Flowsta Vault (Tauri v2)
  |
  +-- Lair Keystore (local key management)
  +-- Holochain Conductor (Identity + Signing + Private DNAs, Iroh transport)
  +-- Local Bridge (localhost:27777)
       |
       +-- Websites (Sign in with Flowsta, dashboard signing)
       +-- Desktop apps (Your Own AI and others, backups and sync)
       +-- Third-party Holochain apps (@flowsta/holochain SDK)
  |
  +-- Your other devices (peer to peer, through the meeting point
      or a community node)
```

## Downloads

Installers for Linux (`.deb`, `.rpm`), macOS (Apple Silicon and Intel)
and Windows (`.exe` and `.msi`) are on the
[Releases](https://github.com/WeAreFlowsta/flowsta-vault-app/releases)
page, each with a `SHA256SUMS.txt` to verify your download. Windows
installers are code-signed; macOS builds are signed and notarized.

**Only download Flowsta Vault from this repository's releases or the
buttons on [flowsta.com/vault](https://flowsta.com/vault/).** The Vault is
where you enter your recovery phrase; no third-party mirror or app store
is a safe source.

## Building from source

Prerequisites: [Node.js 22+](https://nodejs.org), [Rust 1.77+](https://rustup.rs),
and the [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/)
for your platform.

```bash
npm install
cargo tauri build
```

Produces platform-specific installers in `src-tauri/target/release/bundle/`.
Rust tests run with `cargo test` in `src-tauri/`; the UI suites drive the
real window (`npm run e2e`, see `e2e/README.md`).

## Environment configuration

All URLs default to production, baked in at compile time. To build against
a different environment, copy `.env.example` to `.env` and set
`VITE_API_URL`, `VITE_WEB_URL`, `FLOWSTA_API_URL`, `FLOWSTA_BOOTSTRAP_URL`
and `FLOWSTA_SIGNAL_URL`.

## Project structure

```
src/                      # Qwik frontend
  components/             # UI components
  routes/                 # overview, identities, activity, sign-it, your-data, settings
src-tauri/                # Rust backend
  src/
    commands.rs           # Tauri IPC commands (setup, unlock, lock, identity)
    identities.rs         # several identities in one Vault
    key_derivation.rs     # BIP39 + HMAC-SHA256 key derivation
    vault.rs              # Vault password encryption (Argon2id + AES-256-GCM)
    conductor.rs          # Holochain conductor lifecycle
    dna_updater.rs        # keeps the bundled DNAs current
    ipc_server.rs         # the localhost bridge for websites, SDKs and apps
    relay_login.rs        # sign-in through a code when the browser is elsewhere
    device_identity.rs    # this device's own key and registration
    device_registry.rs    # the account's devices
    devices.rs            # adding and removing devices
    pairing.rs            # the code that adds a device
    backup.rs             # app backups + data export
    backup_sync.rs        # backups kept in step across devices
    backup_lane.rs        # the records that carry them between Vaults
    activity.rs           # the Activity page
    rendezvous_keeper.rs  # keeps this device findable by the others
    sealed.rs             # encrypted private records
    migration.rs          # account upgrade from flowsta.com
  resources/              # Holochain DNA hApp bundles
```

## Related

- [Flowsta](https://flowsta.com) - your identity, on your devices
- [Documentation](https://docs.flowsta.com) - full developer documentation
- [@flowsta/auth](https://www.npmjs.com/package/@flowsta/auth) - Sign in
  with Flowsta and Vault-first signing for web apps
- [@flowsta/holochain](https://www.npmjs.com/package/@flowsta/holochain) -
  SDK for Holochain app integration
- [Your Own AI](https://github.com/WeAreFlowsta/Your-Own-AI) - a desktop
  app built on the Vault

## Why open source?

Flowsta Vault holds your cryptographic keys and identity. You should be
able to verify exactly what the software running on your machine does
with them. This repository is open source for transparency: audit the
code, verify the builds, and confirm that your keys never leave your
devices.

## License

MIT - see [LICENSE](LICENSE) for details.
