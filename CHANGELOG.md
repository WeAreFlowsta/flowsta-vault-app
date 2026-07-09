# Changelog

All notable changes to Flowsta Vault are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-beta2] — 2026-07-09

### Upgrading your account
- **Migrating with your email and password no longer asks for your recovery
  phrase.** After you sign in, you choose how to set up your phrase — enter
  one you already have, or create a fresh one on the spot. Your password
  already proves the account is yours, so having your old phrase in hand is
  never required to move your account onto this device.

## [1.0.0-beta1] — 2026-07-09

Your account lives in your Vault now. Existing vaults upgrade in place — your
data, identity, and Sign It history carry over.

### Your account, on your device
- **Create your Flowsta account directly in Vault.** The recovery-phrase
  ceremony seeds your identity on this device — with a download-as-file
  option and a write-down check. No web signup.
- **Upgrade an existing flowsta.com account** by signing in with your
  password — or with your recovery phrase alone, no password needed. Your
  personal data moves into an encrypted private space on this device, and
  sign-ins everywhere switch from your password to Vault approval. Your
  identity, username, and signatures stay exactly as they are.
- **Existing Vault installs upgrade from the dashboard.** If your account
  still lives on Flowsta's servers, an upgrade card appears on the Overview
  and moves it into your Vault in place — your vault password and history
  are untouched.

### Works even without Flowsta
- **Restore from your recovery phrase with Flowsta's servers unreachable.**
  Your keys re-derive locally, the community network returns your public
  records, and your account details reattach automatically when Flowsta is
  reachable again.
- **Create a new identity offline.** It joins the network and can act
  immediately; your Flowsta account attaches when the servers are reachable.
- **Community rendezvous fallback** is built in: if Flowsta's primary
  network door is down, Vault finds the network through community nodes.

### Your data
- **Export everything, import it back.** A single encrypted export of your
  records and backups; importing is safe to re-run and verifies itself.
- **Vault is your profile editor**: display name, picture, and your
  flowsta.com/username claim all live on the Overview's Public Profile card.
- **Change your vault password** — fully local, and safe for the network
  stack underneath.
- **Email stays yours.** Apps only receive your email address if you
  explicitly consent when connecting.

### Sign It
- **Everything works from flowsta.com too**: sign & publish, amend, revoke,
  and thumbnails on the web dashboard all route through your Vault, each
  with its own approval — including while the Vault is locked (it waits for
  your unlock) or still starting.
- **Sponsored signing**: when an app sponsors your signature from its
  organization's pool, the approval dialog says exactly whose quota pays.
- **Faster, steadier history views** — your own records paint immediately
  and never disappear behind a temporary read failure.

### Connections
- **One Connections page** — every app and website that can use your
  identity, with plain-language permissions and revoke in one place. The
  web dashboard shows the same registry, read-only.

### Under the hood
- Hardened the local bridge and approval windows.
- Signing credentials authorize once per session instead of on every call.
- Release downloads keep the SHA256SUMS verification file.

## [0.7.0] — 2026-06-14

A reliability and design release. Existing vaults upgrade in place — no migration.

### Apps & sign-in
- **Signing in to Flowsta apps is far more reliable.** The local connection apps
  use to talk to Vault now runs independently of Vault's own network activity,
  so it no longer stalls while Vault is busy right after you unlock. This also
  fixes a hang where signing in could get stuck after you approved it.
- **One approval instead of two** the first time an app both links your identity
  and signs you in: approving the link now also approves that sign-in for the
  session.
- **Locking Vault cleanly dismisses any open approval request** instead of
  leaving it waiting.

### Connected apps
- **The Overview's connected-apps list updates live.** When an app links or you
  revoke one, it appears or disappears immediately instead of only after you
  reload the page.

### Appearance
- **Refreshed look across the app.** Identities, Settings, Your Data, the
  dashboard, and Sign It now share one consistent surface style, with clearer
  depth between cards and backgrounds.
- **Sign It signature lists restyled** so each signature reads as its own card.

### Downloads
- **Release downloads include a SHA256SUMS file** so you can verify what you
  downloaded.

### Under the hood
- **More consistent installers.** The build toolchain is now pinned, so the
  Windows installer behaves the same from one release to the next.

## [0.6.1] — 2026-06-01

A polish release focused on the cross-app sign-in experience and Windows.
Existing vaults upgrade in place — no migration.

### Sign-in & Connected Apps
- The approval dialog **reliably comes to the front** when an app asks to
  connect — on macOS and Linux as well as Windows (previously it could open
  behind the app you were in).
- **Focus returns to the app you came from** after you approve or deny,
  instead of leaving you on the Vault window.
- **Connected Apps shows one entry per app.** An app installed on several
  devices (or reinstalled) no longer appears many times; revoking it unlinks
  all of that app's connections at once.

### Windows
- **No more stray console windows** from the bundled Holochain/lair processes
  — including when your default terminal is Windows Terminal.
- **Background processes shut down with the app** instead of being left
  running after you quit.

### Privacy
- **"Reset Vault" is now a true full erase** — it also clears connected-app
  links, granted permissions, and saved app backups, so resetting a device is
  a genuine clean slate. The confirmation spells out exactly what's removed;
  your identity and signatures still come back with your recovery phrase.

### Networking & developers
- Vault now presents the access credential the Flowsta network's bootstrap
  requires (gated since shortly after 0.6.0), keeping peer discovery working
  on the current network.
- **Data-export (CAL) support** for apps built on Vault, to help them meet
  Cryptographic Autonomy License obligations.

## [0.6.0] — 2026-05-24

The Holochain 0.6.1 / Iroh networking release. The peer-to-peer
transport moves from WebRTC to Iroh (kitsune2 0.4.1), matching the
upgraded Flowsta network. Existing vaults upgrade in place on first
launch — no migration, your data is read as-is. Sign It is now
available on Windows. The bulk of the release polishes the cold-start
experience: Vault now handles the multi-minute DHT warmup on a
returning agent's new device cleanly, without flashing partial counts
or losing thumbnails between refreshes.

### Holochain 0.6.1 / Iroh transport
- **Bundled conductor binary is now Holochain 0.6.1**, `holochain_client`
  0.8.1, kitsune2 0.4.1. lair-keystore unchanged (0.6.3).
- **Pre-0.6.0 Vaults use the older WebRTC transport** and can no
  longer gossip with the upgraded network. Updating to this build
  restores sync.
- **Update banner.** If the Flowsta network reports your Vault is
  below the minimum supported version, Vault shows a banner with an
  update link. The vault stays fully usable and your local data is
  always accessible — but you won't sync with the network until you
  update.

### Sign It
- **Sign It is now available on Windows.** Holochain 0.6.1 fixes the
  upstream WASM-compile crash that gated Sign It on Windows in 0.5.2.
  All three DNAs install cleanly on the first launch.
- **Edit Thumbnail button now shows on a freshly-signed entry**
  without requiring a refresh.
- **Sign It quota meter on the Sign It page** now correctly hits the
  production API. Previously a wiring bug had all five Sign It API
  calls reading `(window as any).__API_URL__`, which is always
  undefined — they fell back to a hard-coded staging URL, and the
  quota widget vanished when staging didn't have the production
  account's record.
- **Bundled signing-DNA is v1.4 only.** Vault no longer ships
  v1.0–v1.3. Those versions hold no real signing data (the per-user
  signing-cell architecture started at v1.4) and querying empty
  cells on cold start used to block the whole refresh round.
  Existing Vaults upgrading from earlier builds keep the four
  orphaned older cells in their conductor; the new code path
  ignores them.

### Cold-start sync — handles the DHT warmup cleanly
- **Two independent fetches for your signatures.** Your own
  signatures (local source-chain query) and your linked accounts'
  signatures (DHT-bound cross-agent query) run as separate calls
  in parallel, so the slower linked path never blocks the local one.
- **Never display a partial count.** The signatures tile stays in
  "Syncing — first load takes a few minutes" until both fetches
  authoritatively succeed (either with data or with a confirmed
  no-data answer). Previously a partial 4-of-6 could appear briefly
  while the second fetch was still in flight.
- **First-install cold sync is ~ 4–5 minutes**, then instant from
  cache on every subsequent unlock or app restart. Cache is keyed
  per agent and preserved across lock cycles, restarts, and even
  partial refreshes.
- **Cache never downgrades.** A refresh round that returns fewer
  signatures than the cache (linked-agent timeout, mid-refresh
  lock, cold-DHT cell readiness race) no longer wipes the cache —
  sigs the round missed are preserved.
- **Thumbnails and revocation status accumulate.** Per-sig
  enrichment is bounded at 15 s so the main sig query isn't blocked
  for minutes; any thumbnail or revocation entry that hasn't
  gossiped yet returns null this round but the cached value is
  preserved via a field-level merge. Subsequent refreshes pick up
  the data as gossip arrives.
- **Background retry every 30 s** while signatures haven't fully
  loaded, so a fresh install eventually fills in without user
  action.

### Refresh on demand
- **Window focus triggers a refresh.** Signing on flowsta.com or
  another linked device while Vault is open in the background now
  appears as soon as you bring Vault back to the foreground —
  subject to kitsune2 gossip latency for the new entry to reach
  your peers.

### Overview — Recent Activity feed
- **Unified Recent Activity** across signatures, backups, and
  linked apps, sorted in time order.
- **Sig timestamps display correctly.** Signature `signed_at` is
  committed in milliseconds by the signing DNA; backup + linked-app
  timestamps are in seconds. The shared `timeAgo` helper assumes
  seconds, so every signature row was reading "just now". Fixed.

### Reliability — Holochain integration
- **Conductor request timeout 60 s → 240 s** in the generated
  conductor config. Cold-DHT zome calls (`get_links`, `get`)
  routinely exceed a minute on first run waiting for peers to
  gossip data; the default 60 s budget was firing before the data
  arrived.
- **WebSocket request timeout 300 s** on the AppWebsocket used for
  the signatures fetch path, covering realistic cold-start DHT
  warmup.
- **Cell readiness budget 15 × 3 s = 45 s on unlock.** Cells
  routinely took ~21 s to come ready after the conductor restarted
  on some Windows machines, just past the previous 18 s budget.
  After the old budget elapsed, every signing-DNA auth-creds call
  returned `CellDisabled` and the round blanked to zero.
- **Auto-link race closed.** The linked-signatures fetch waits for
  the post-unlock auto-link to populate the cached web agent key
  before returning an authoritative empty — previously the
  conductor-ready event could fire the first refresh before
  auto-link finished, producing a false "no linked agents" reading.

## [0.5.3] — 2026-05-20

A Sign It feature release. Adds comments, amendments, edit history,
and several display refinements. Also includes a sizable UX pass on
the image cropper and a fix to Reset Vault that was preventing some
users from setting up a second identity on the same machine.

### Sign It — new metadata + edits
- **Comments on signatures.** Add a note (up to 280 characters) when
  signing. Visible inline on the signature card in Vault and on each
  signature's public page.
- **Amend a signature.** Edit the metadata of a published signature
  while keeping the original cryptographic record permanent on the
  public DHT. Open the `…` menu on any of your signatures, choose
  Amend, change what you need (license, AI declaration, commercial
  terms, contact preference, comment, thumbnail), and Vault publishes
  a new version linked to the original. Previous versions stay on
  the network for verifiers.
- **Edit history.** Each signature that has been amended shows an
  expandable history on its card. Open it to walk back through every
  revision and see what changed.
- **Expiry and tags shown.** Signatures created via the API or
  external tooling now display their expiry date as a badge and any
  tags as pills on the signature card. (Setting expiry/tags from the
  Vault signing form is on the roadmap.)
- **Cleaner signing form.** License, AI Generation, Commercial
  Licensing, AI Training, and Contact Preference now appear inline by
  default instead of behind a disclosure.

### Signature display polish
- **File-type pill on every signature.** A small badge (Image, Audio,
  Video, Document) appears next to the date in the signature metadata
  row, whether you uploaded a custom thumbnail or kept the default.
- **Small file-type icon overlay** on custom thumbnails, so the
  format is still visible at a glance.
- **License + AI badges** on the Overview's Recent Signatures view,
  matching the All Signatures listing.
- **Human-readable labels** for license and AI generation throughout
  ("MIT" instead of `Mit`, "AI-assisted" instead of `AiAssisted`,
  etc.).
- **Edit Thumbnail** is now available from the Recent Signatures view
  as well as from All Signatures.

### Image cropper UX (thumbnails + profile pictures)
- **Selection fills the image by default**, with a small margin so
  the resize handles are visible. The previous default left a
  noticeable gap on every upload.
- **Selection can't leave the image.** Dragging the crop rectangle
  toward an edge stops at the image bounds — no more selections that
  include empty / transparent space.
- **Zoom-out below fit is blocked**, eliminating the source of empty
  canvas corners. Zoom-in for precision crops still works.

### Reliability
- **Reset Vault now actually clears everything.** The previous
  behaviour deleted the encrypted vault file but left the local
  keystore and conductor data in place. On the next setup, the
  keystore retained the old encryption keys, producing repeated
  `Failed to connect to lair` errors and an unreachable conductor.
  Reset now stops all running processes and removes the keystore and
  conductor data alongside the vault file.
- **Signature cache is keyed per identity.** If you reset Vault and
  set up again as a different identity, you no longer see the
  previous identity's cached signatures briefly appear on the
  Overview or All Signatures pages.
- **Overview no longer flashes "0 signatures" on fresh unlocks.** The
  loading skeleton now stays visible until the post-unlock identity
  link completes, so the count goes straight from loading to the
  correct number.

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
