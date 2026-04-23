# Changelog

All notable changes to Flowsta Vault are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] — 2026-04-23

### Child-process cleanup
- On Linux, `lair-keystore` and the `holochain` conductor are now tied to the parent vault's lifetime via `PR_SET_PDEATHSIG`. They get `SIGTERM` automatically if the vault dies for any reason — crash, OOM kill, force-quit, `dpkg` upgrade, or `tauri dev` reload. This eliminates the "All Admin WS ports are unavailable" error on the next launch caused by stale child processes holding ports.
- `SIGTERM` and `SIGINT` (Ctrl+C, system shutdown) now route through `app.exit()` so the existing graceful-shutdown path runs instead of the kernel killing us mid-operation.
- macOS and Windows still rely on the existing graceful-exit path; equivalent kernel-level guarantees are planned for a follow-up.

## [0.4.0] — 2026-04-23

### Windows code signing
- Windows installers (`.exe` and `.msi`) and bundled binaries are now signed with the FLOWSTA SSL.com OV code-signing certificate.
- SmartScreen will still show "Windows protected your PC" until the certificate accumulates download reputation, but the signature is valid, the publisher displays as **FLOWSTA**, and antivirus tools will see a verified chain.
- Signatures include an RFC 3161 timestamp, so installers stay verifiable beyond the certificate's expiry.

### Recovery phrase verification fix
- Setting up a fresh vault from a recovery phrase no longer fails with **"This phrase doesn't match the account for ..."**. The check was comparing the agent key from `/auth/login` against the agent key from `/auth/agent-key-by-lookup-hash` as raw strings, but those endpoints return the same key in two different encodings. The vault now decodes both sides to bytes before comparing.

## [0.3.0] — 2026-04-15

### Sign It is production-ready
- Signing DNA v1.4 with cross-conductor thumbnail editing.
- Phase 8 usage quotas with offline cache and sync on window focus.
- Signature revocation.
- Each sign syncs to the server immediately so the dashboard reflects vault activity without a manual refresh.

### Improved agent linking
- Auto-link on unlock now uses the linked web agent key.
- Fixed multi-version cross-cell `linked_agents` query and action hash deserialization.
- Fixed `CellDisabled`-on-restart race — apps are always enabled at startup.
- Thumbnail editing UX improvements.

### DNA update reliability
- The DNA updater now pulls the agent key from lair rather than from the stored `VaultConfig`. This fixes private DNA v1.11 installation for vaults whose stored agent key drifted from the key actually held by lair.

### Security
- IPC `/sign` and `/backup/*` now require the caller to be a linked app with matching `client_id`. Closes forge-signature and backup IDOR pre-launch.

### Image cropping (profile pictures + Sign It thumbnails)
- Shared `ImageCropper` component with proper aspect ratio, race-free initial crop, and modal-fit sizing.
- No more letterbox around edge-to-edge images.
- "Save" without adjusting the selection now produces a correctly framed output.

### Platform notes
- **Windows binaries in this release are unsigned.** On launch, Windows SmartScreen will show a "Windows protected your PC" warning and list the publisher as unknown. Click **More info → Run anyway** to install. Code signing is planned for v0.4.0 once the certificate is issued.
- **macOS** binaries are signed and notarized.
- **Linux** `.AppImage` and `.deb` as usual.

## [0.2.0] — 2026-03-30

- Version bump and internal improvements.

## [0.1.0] — 2026-03-29

- Initial release.
