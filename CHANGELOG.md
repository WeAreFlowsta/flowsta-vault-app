# Changelog

All notable changes to Flowsta Vault are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0-beta11] — 2026-05-24

Three small fixes; no architectural changes.

### Fixed
- **Recent Activity timestamps for signatures.** The Overview's Recent
  Activity feed mixes signatures, backups, and linked-app events
  through a single `timeAgo(unixSecs)` helper, but `signed_at` is
  committed by the signing DNA in milliseconds (the other two sources
  are seconds). Every signature row read "just now". Converted at the
  call site; signatures now sort and render against the other rows in
  correct time order.
- **Overview signature tile caption** changed from `"Syncing from the
  network…"` to `"Syncing — first load takes a few minutes"` so a
  first-install user has the expected wait calibrated. (Sign It and
  All Signatures already cycle through staged messages over the
  cold-start window via `LoadingSignatures`.)

### Changed
- Removed the beta10 `[diag:*]` frontend log calls. Behaviour validated
  on Linux + Windows for fresh install (~5 min DHT cold-start),
  lock + unlock (instant from in-memory signal), and restart (instant
  from localStorage cache). `@tauri-apps/plugin-log` + the `log:default`
  capability are kept for future ad-hoc diagnostics.

## [0.6.0-beta10] — 2026-05-24

Diagnostic-only release. **No behavior change** — same code paths as
beta9. The frontend signatures refresh now logs its state transitions
through `tauri-plugin-log` so they land in the same log file as the
Rust side, making the next investigation evidence-based rather than
guess-based.

### Added
- `@tauri-apps/plugin-log` JS bridge + `log:default` capability.
- Frontend log events tagged `[diag:refresh]`, `[diag:own]`,
  `[diag:linked]`, `[diag:hydrate]`, `[diag:trigger]`, `[diag:bg]`
  covering: refreshSignatures enter/exit, each fetchOwn/fetchLinked
  attempt with elapsed time + result, combined.length per iteration,
  signaturesSig + signaturesLoaded writes, cache hydrate (cached
  count, adopt vs skip), profile-synced + conductor-ready triggers,
  background interval ticks.

### How to read the log
On Linux: `tail -f ~/.local/share/com.flowsta.vault/logs/flowsta-vault.log`.
On Windows: `%LOCALAPPDATA%\com.flowsta.vault\logs\flowsta-vault.log`.
Filter with `grep diag:` (or just search for the bracketed tag) to see
only the FE refresh story.

## [0.6.0-beta9] — 2026-05-24

Ninth 0.6.1 / Iroh beta. Two-fold cold-start time cut so a fresh
install actually finishes refreshing before the user gives up.

### Fixed
- **`fetch_linked_agent_keys` uses the cached web agent key first**,
  then dispatches the DHT `get_linked_agents` lookup with a 10 s
  opportunistic budget instead of letting it sit on the 240 s
  kitsune2 timeout before falling back. Same in-memory cache it used
  to wait 240 s to consult.
- **Per-signature thumbnail + revocation enrichment capped at 15 s
  each.** On cold DHT every call would otherwise wait the full 240 s
  before defaulting; in beta8 testing this added 2 + minutes to the
  refresh after the primary records had already returned. Defaults
  (no thumbnail, not-revoked) fill in on the next refresh round once
  gossip catches up.

### Effect
- Cold-start total time on a returning agent's new device drops from
  ~6.5 min observed in beta8 to ~4 min (bounded by the primary
  `get_my_signatures` zome call's own DHT warmup).
- Warm-DHT refresh is unchanged — both timeouts are well above
  typical sub-second response times.

## [0.6.0-beta8] — 2026-05-24

Eighth 0.6.1 / Iroh beta. Splits the signatures fetch into two
independent commands so the cold-DHT linked-agent path can't make
the UI display a partial count.

### Changed
- **`get_my_signatures` split into `get_my_own_signatures` +
  `get_my_linked_signatures`.** Own (local source-chain query) and
  linked (DHT-bound cross-agent query) now run as separate Tauri
  commands. The combined call is kept for `export_all_data`.
- **Linked command returns `{signatures, has_linked_agents}`.** Lets
  the frontend distinguish "no linked accounts" from "linked accounts
  exist but the DHT hasn't gossiped their sigs yet" — the latter
  triggers a retry; the former is authoritative.
- **Linked helpers propagate errors instead of swallowing them.**
  `query_linked_sigs_for_version` and `query_own_sigs_for_version`
  now return `Result`; a kitsune2 timeout no longer masquerades as an
  empty result.
- **`get_my_linked_signatures` returns `Err` until auto-link has
  populated the cached web agent key.** Closes a race where the
  conductor-ready event fired the first refresh before auto-link
  finished, producing a false "no linked agents" reading.

### Fixed
- **No partial sig counts shown.** The signatures-loaded gate now
  promotes only when the linked side returns a confident result
  (either "no linked agents", non-empty sigs, or three consecutive
  ok-but-empty attempts). While loading, the count tile shows the
  skeleton, the Recent Activity feed omits signatures, and the
  Recent Signatures list shows the loading indicator — even if the
  own query has already returned.
- **Background retry every 30 s while not loaded.** A `useVisibleTask$`
  fires `refreshSignatures()` on a timer until the linked side
  becomes confident, so a fresh install eventually fills in once the
  DHT warms up.

### Effect
- On a fresh install of a returning agent: own sigs are fetched
  immediately, the UI stays in "Syncing from the network…" until
  the cold-DHT linked query gossips the linked-agent sigs, then
  promotes once to the full count. No intermediate partial count.
- On lock + unlock with a prior cache: the cached count keeps
  showing throughout the refresh; the cache merge never downgrades.

## [0.6.0-beta7] — 2026-05-24

Seventh 0.6.1 / Iroh beta. Drops the pre-v1.4 signing DNAs from the
bundle — those versions hold no real signing data (per-user signing-cell
architecture started at v1.4). Fixes the cold-start slowness at the root.

### Changed
- **Vault bundles only signing DNA v1.4.** The 4 older `.happ` files
  (v1.0 / v1.1 / v1.2 / v1.3) are removed from the resource bundle.
  Vault no longer installs them on first launch.
- **Signature lookup queries only v1.4.** The cold-start round used to
  query 5 cells in parallel and wait on the slowest — `get_links` on
  the empty older cells hit kitsune2's request timeout, blocking the
  whole round for minutes. Now: one cell, one query.
- A Vault upgrading from an earlier build keeps the four orphaned older
  cells in its conductor; they're ignored by the new code path.

### Effect
- Faster startup (no historical install — ~7 s saved on first launch).
- Cold-start signature load on a returning agent's new device should
  now complete in a single round.
- Installer is ~8 MB smaller.

## [0.6.0-beta6] — 2026-05-24

Sixth 0.6.1 / Iroh beta. Fixes two cases where signatures appeared,
then later dropped to fewer or zero after a lock + unlock.

### Fixed
- **Cell-disabled retry budget bumped 18 s → 45 s on unlock.** On some
  machines (Windows in particular) cells took ~21 s to come ready after
  the conductor restarted, just past the previous 18 s budget. After
  `ensure_apps_enabled` gave up, every signing-DNA auth-creds call
  returned `CellDisabled` and the round blanked to zero. 15 attempts
  × 3 s covers the observed slow path with headroom.
- **Refresh rounds no longer downgrade the signatures cache.** A round
  that returned fewer signatures than the cache (linked-agent query
  timed out, the user locked mid-round, the CellDisabled race fired)
  used to overwrite the cache with the shorter list. It now merges
  by `action_hash`: the new round's data wins for sigs both contain,
  cached sigs that the round missed are preserved. Empty results don't
  touch the cache at all.

## [0.6.0-beta5] — 2026-05-23

Fifth 0.6.1 / Iroh beta. Follow-up to beta4 — addresses the actual
limiting factor in cold-start signature loads and adds a deliberate
retry.

### Fixed
- **Conductor's p2p request timeout bumped 60 s → 240 s** in the
  generated conductor config. The beta4 log showed signing zome calls
  failing with `get_links response channel dropped: likely response
  timeout` long before the WebSocket budget was exhausted — that's
  kitsune2's own 60 s `request_timeout_s` (the default) firing inside
  the conductor. 240 s lets a cold-start `get_links` complete before
  the conductor aborts it, so most fresh installs of a returning agent
  see signatures land on the first round instead of needing a retry.
- **Deliberate retry on slow-empty rounds.** Up to one back-to-back
  retry when the first round returned empty after a long wait — the
  DHT is materially warmer by then, so the second round usually has
  data. Bounded so we don't loop indefinitely.

## [0.6.0-beta4] — 2026-05-23

Fourth 0.6.1 / Iroh beta. UX fixes for "log in on a new device" — when a
returning agent (same recovery phrase) installs Vault fresh and the local
cell starts empty, the signing zome's `get_links` / `get` calls wait for
Iroh peers + DHT data to gossip in. The first launch can take minutes,
and the previous betas misreported the wait as "0 — Sign your first file"
once an early round timed out silently.

### Fixed
- **Signatures now load on a fresh install of a returning agent.** The
  Holochain WebSocket request timeout for signature fetch + sign / revoke
  / amend paths is bumped from 60 s to 300 s, comfortably covering
  cold-start DHT warmup.
- **No more misleading "Sign your first file" during cold-start.** The
  dashboard keeps "Syncing from the network…" showing while rounds are
  still completing slowly; only flips when a round genuinely returns
  empty quickly (truly-empty user) or when signatures arrive.
- More informative Sign It loading messages through the 75 s – 240 s
  range for long cold-starts.

## [0.6.0-beta2] — 2026-05-22

Second 0.6.1 / Iroh beta. Windows Sign It is now enabled, plus two
refinements spotted during beta1 testing.

### Added
- **Sign It is now available on Windows.** Holochain 0.6.1 fixes the
  upstream WASM-compile crash that gated Sign It on Windows since v0.5.2.
  All three DNAs (private, identity, signing) now install cleanly on
  Windows on the first launch, and historical signatures load alongside
  Linux + macOS.
- **Recent Activity on the Overview now includes signatures.** One
  unified feed across the top 5 of signatures, app backups, and
  connected-app links, sorted by time.

### Fixed
- **Edit Thumbnail button now shows on a freshly-signed entry** without
  requiring a refresh.

## [0.6.0-beta1] — 2026-05-22

The Holochain 0.6.1 / Iroh networking release. No feature changes — this is
the transport upgrade that keeps Vault in sync with the Flowsta network now
that the production conductors run Holochain 0.6.1.

### Changed
- **Holochain conductor upgraded to 0.6.1.** The peer-to-peer transport moves
  from WebRTC to Iroh (kitsune2 0.4.1). Existing vaults upgrade in place on
  first launch — no migration, your data is read as-is.
- Bundled conductor binary is now Holochain 0.6.1; `holochain_client` 0.8.1.
  lair-keystore is unchanged (0.6.3).

### Added
- **Update banner.** If the Flowsta network reports your Vault is below the
  minimum supported version, Vault shows a banner with an update link. The
  vault stays fully usable and your local data is always accessible — but you
  won't sync with the network until you update.

### Notes
- Pre-0.6.0 Vaults use the older WebRTC transport and can no longer gossip
  with the upgraded network. Updating to this build restores sync.

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
