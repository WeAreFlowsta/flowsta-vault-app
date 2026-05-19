# Changelog

All notable changes to Flowsta Vault are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.3] — 2026-05-20

### Vault reset + first-load polish (beta2)
- **Vault reset now actually clears everything.** Previously the
  "Reset Vault" action in settings deleted the encrypted vault
  config file but left the lair keystore and the conductor data
  directory in place. On the next vault create, lair handed back the
  original device seed but rejected the new vault's passphrase,
  producing repeated `Failed to connect to lair: early eof` errors.
  The reset now stops the conductor + lair processes and removes
  both subdirectories alongside the vault file.
- **Overview tile no longer flashes "0 signatures" on fresh
  unlocks.** Signatures load runs twice on every unlock — once when
  the conductor reports ready, again when the post-unlock auto-link
  fires `profile-synced`. The first pass briefly returned zero
  because the linked-agent key wasn't cached yet, producing a brief
  flash of an inaccurate count before the real number landed.
  Loading state is now gated on either a non-empty result or
  `profile-synced` so the skeleton stays visible through the
  partial-fetch window.
- **Image cropper UX.** Default crop sits at 95% so the resize
  handles always have visible margin against the image edge. The
  selection is clamped to the cropper-image's live bounding rect on
  every move/resize, so it can't be dragged into the empty corners
  that appear when the user pans the image. min-scale floored at
  fit prevents below-fit zoom-out (which otherwise creates those
  same empty corners). Same component, same fixes, on Vault + the
  flowsta.com dashboard.

## [0.5.3-beta1] — 2026-05-17

Sign It Bundle A release. Adds the comment field, amend flow, edit
history, and expiry / tags display agreed in the Sign It Track 1 plan,
plus several UX refinements landed since v0.5.2.

### Sign It — Bundle A
- **Comment field** on every signature (≤280 chars). Visible inline
  on the sign form, on the sign-result screen, and on each signature
  card.
- **Amend flow.** Re-sign an existing record under the same chain
  with a new metadata version; the original entry stays on the DHT
  (public-permanence guarantee). Wrapped behind a new contextual `…`
  menu alongside Revoke. Pre-fills license / AI / commercial /
  AI-training / contact preference from the signature being amended.
  Carries the original thumbnail across to the new chain head.
- **Edit-history expander.** Walks the supersedes chain backwards
  (capped at 20 versions for cycle defence) and renders a diff
  summary between consecutive versions.
- **Expiry + tags display.** Signatures list shows an "Expires
  <date>" badge when `expires_at` is set, and renders tags as small
  pills. No creation UI yet — display catches signatures populated
  via API or external tooling.
- **License + AI-generation badges** on each signature card in the
  Recent Signatures view, matching the all-signatures listing.
- **Human-readable labels** throughout (license + AI-generation).

### Sign It — UX from v0.5.2 main
- **Content rights expanded by default** on the sign form. AI
  Generation, License, Commercial Licensing, AI Training, and Contact
  Preference all render inline rather than behind a disclosure.
- **File-type badge on thumbnails.** When a custom thumbnail is
  uploaded, a small audio / image / video / file icon overlays the
  thumbnail corner so the format remains visible. (Default-SVG
  thumbnails are their own type indicator and don't get the overlay.)
- **File-type text pill** in the signature metadata row beside the
  date — works whether a custom thumbnail was uploaded or not.
- **Edit-Thumbnail parity** on the Recent Signatures view (was
  previously only available in the all-signatures list).

### Reliability
- **Identity-keyed signatures cache.** Cache storage keys are now
  scoped per-agent (`flowsta_vault_sigs_v2_<agent_pub_key>`) so reset
  Vault → sign in as a different user no longer surfaces the previous
  user's cached signatures. Reset Vault explicitly clears the cache
  too.

## [0.5.2] — 2026-05-11

Stability and signing-history release. Adds reliability infrastructure
for the Holochain conductor (auto-restart, runtime watchdog, resilient
install/enable paths), bundles all five signing-DNA versions so a
fresh install shows full signature history end-to-end, hides both
Windows sidecar terminals, and gates Sign It on Windows behind a clear
placeholder pending upstream conductor fixes.

### Reliability infrastructure
- **Conductor auto-restart on first-install hiccups.** If the conductor
  errors during DNA install on a fresh data directory, vault restarts
  it once and warm-starts against the on-disk state. The user sees a
  brief "Finishing first-time setup..." and the vault comes up.
- **Runtime conductor watchdog.** Detects conductor-process exits
  during normal operation and restarts in-place using cached unlock
  credentials. The lair passphrase is held in a memory-locked,
  zeroed-on-drop buffer for the unlocked session and cleared on lock.
- **Resilient install / enable paths.** WS-reset errors during DNA
  install are caught, the call retried on a fresh connection, and
  long compiles tracked via `Child::try_wait()` so the inner retry
  bails fast when the conductor has actually exited.
- **App / cell normalisation pass.** A previous interrupted unlock
  that left an app `Disabled(NeverStarted)` is auto-recovered on the
  next unlock — no manual lock+unlock required.

### Sign It history
- **Bundles all five signing-DNA versions** (v1.0–v1.4) and
  back-installs the older ones on first launch so the user's full
  signature history is visible end-to-end on a fresh install. Linux
  + macOS only in this release; gated on Windows (see below).

### Windows
- **Both sidecar terminals hidden** (`lair-keystore.exe`,
  `holochain.exe`) via post-spawn `ShowWindow(SW_HIDE)` polling +
  conhost-parent tracking. Brief flicker may still be visible on
  the conductor; will be eliminated in a future release.
- **Sign It UI gated on Windows.** The page shows a clear placeholder
  message directing users to flowsta.com or other platforms. Other
  features (vault, identity, connected apps, backups) work normally.
  The Windows gate will be lifted in a future release.

### File-explorer integration
- Right-click label changed from *"Sign with Flowsta Vault"* to
  *"Sign It with Flowsta Vault"* on Linux + Windows.

### CI / build
- Pinned Windows builds to `windows-2022` runner image
  (`windows-latest` rolled to a VS 2026 image whose newer MSVC
  headers broke `aws-lc-sys` C11 atomics).
- Skip MSI bundle on pre-release tags (Tauri's MSI bundler requires
  numeric-only pre-release identifiers; NSIS has no such restriction
  and is what end users install).
- Mark pre-release tags as GitHub pre-releases so they don't take
  over the "Latest" slot.
- Bundle-sync check (`scripts/check-bundle-sync.sh`) regex updated
  to allow digits in `BUNDLED_*_HAPP_FILE` constant names.

## [0.5.1] — 2026-05-05

### Windows: fresh installs failed during signing DNA setup

A reported regression in v0.5.0: fresh installs on Windows failed with
**"DNA installation failed: Failed to install signing DNA: Websocket error:
Websocket closed: ConnectionClosed"**, leaving the conductor in an HC Error
state. Existing installs that already had DNAs installed weren't affected.

Root cause: v0.5.0 set `CREATE_NO_WINDOW` on the Windows spawn flags for
`lair-keystore.exe` and `holochain.exe` to hide their terminal windows.
That flag also prevents Windows from allocating a console handle for the
child process. During signing-DNA WASM compilation (the largest of the three
bundled DNAs), `holochain.exe`'s LLVM/cranelift stdio path dereferenced the
null console handle and crashed with `0xc0000005` access violation in
`MSVCP140.dll`. Private + identity DNAs were small enough to install via a
code path that didn't touch the affected stdio.

Reverted to the v0.4.2 behaviour: terminal windows are visible again on
Windows, but installs work reliably. A proper fix using `STARTUPINFO` with
`STARTF_USESHOWWINDOW + SW_HIDE` (which hides the window without preventing
console allocation) is scheduled for a future release.

## [0.5.0] — 2026-05-05

### Sign with Flowsta Vault from your file manager
- Right-click any file in your operating system's file manager and choose **"Sign with Flowsta Vault"** to send it straight to the Sign It page. Multi-select sends the whole batch at once. If Vault isn't open, it launches; if it's locked, the file is queued and signed after you unlock.
- Linux: ships a `.desktop` entry with a broad MIME-type list — appears in Nautilus / Dolphin / Thunar's "Open With" menus.
- Windows: NSIS installer registers an HKCU registry entry, so the menu item appears for any file. Per-user install means no admin prompt. On Windows 11 the entry lives under "Show more options".
- macOS: `Info.plist` declares Vault as an "Open With" handler for any file via `LSHandlerRank=Alternate` — never overrides your default opener for any file type.

### Sign It UX overhaul
- The Sign It signature list, Overview signature count, and All Signatures page are now backed by a single shared store. Navigating between the three pages no longer triggers fresh fetches, and the list survives lock/unlock so the app reopens instantly with your last-known signatures.
- New **Signatures** tile on the Overview page with a count of your active signatures, replacing the redundant "Web Account" tile (linking is implicit).
- The "Loading signatures…" indicator now rotates through informative messages while the conductor warms up so the wait doesn't feel stuck.

### Sign large files (up to 10 GB), with progress and cancel
- Files up to 10 GB can now be signed. Anything over 50 MB shows a progress bar with a Cancel button while hashing.
- Files larger than 500 MB skip the in-memory hidden-content scan with a clear explanation — the hash and signature are unaffected. Files over 10 GB are rejected with a clear message.
- Heavy file operations (hash, integrity analysis, perceptual hash, thumbnail) now run on a background thread so the UI stays responsive on low-resource systems. Previous versions could freeze the window on multi-GB hashes; the OS would mark the app "not responding".

### Faster signatures load on cold start
- The signatures fetch now queries all installed signing DNA versions in parallel, with per-signature revocation + thumbnail lookups also running concurrently. On a cold conductor this drops the load from roughly 3 minutes to 30–60 seconds; on a warm conductor it's typically under 2 seconds.
- A pending-refresh dedup pattern collapses duplicate fetches: if a refresh is requested while one is already in flight, a single follow-up runs after the current one finishes, instead of two parallel calls each doing the full work.

### Hide background terminal windows on Windows
- On Windows, the bundled `lair-keystore.exe` and `holochain.exe` no longer pop up console windows when Vault starts. The `tie_to_parent()` helper now applies `CREATE_NO_WINDOW` for sidecar process spawns.

### Linux: AppImage dropped from release artifacts
- The AppImage hit two separate failure modes in the wild — a WebKit GTK input-rendering glitch on some setups, and a `lair-keystore` TLS handshake hang on a fresh setup that we reproduced locally. Both stem from AppImage's bundled-libs runtime environment differing from the system libs the `.deb` uses, and both would need multi-day work to fix properly.
- The `.deb` is now the only Linux release artifact. Most Debian and Ubuntu users can install it directly; users on other distros can convert with `alien` or wait for a future Flatpak / Snap target.

### Lair-keystore connect now fails fast instead of hanging
- The `connect_to_lair` IPC handshake is now wrapped in a 30-second timeout. If the handshake hangs (e.g., a runtime-library mismatch between our embedded `lair_keystore_api` and the bundled `lair-keystore` binary), users get a clear error message suggesting a reinstall, instead of an indefinite spinner.

### Other fixes
- The sidebar Lock Vault button and status indicators are no longer hidden on long pages (Your Data, Settings). The dashboard wrapper now uses `h-screen` + `min-h-0` on the inner row so `<main>` scrolls internally instead of expanding the whole document.
- `.env.staging` and other per-environment env files are now ignored by `.gitignore`. Only `.env.example` should be tracked.

## [0.4.2] — 2026-04-24

### First-launch DNA installation
- **Linux**: fresh installs of v0.4.0 / v0.4.1 hit `DNA installation failed: Identity hApp bundle not found at .../flowsta_identity_v1_4_happ.happ` because the bundled hApp resources were stuck on older versions (v1.3 identity / v1.10 private / v1.1 signing) while the code was looking for v1.4 / v1.11 / v1.4. The bundle now ships the matching files. Existing installs whose conductor managed to download the newer DNAs in the background were unaffected; clean installs were broken until now.
- **Windows**: Holochain conductor failed on first launch with `did not find expected hexadecimal number at line 1 column 22, while parsing a quoted scalar`. The auto-generated `conductor-config.yaml` wrote `data_root_path` as a double-quoted YAML string, so the leading `\U` of `C:\Users\...` was interpreted as a Unicode escape. Switched to single-quoted YAML strings (which don't interpret escapes) for the path values.

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
