# Changelog

All notable changes to Flowsta Vault are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.2-rc1] — 2026-05-08

Release candidate consolidating the v0.5.2 work. No code changes
relative to beta12 — promoting that build for final-stage verification.

Highlights since v0.5.1:

### Reliability infrastructure (new)
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

## [0.5.2-beta12] — 2026-05-07

### Skip historical signing-DNA backfill on Windows

The historical signing-DNA backfill introduced in beta11 is now gated
to Linux + macOS. Sign It is already UI-gated on Windows in this
release, so historical signatures aren't surfaced there — the backfill
runs only on platforms where it's relevant.

Linux + macOS behaviour is unchanged: a fresh install pulls in all
five signing DNA versions (v1.0–v1.4) so the user's full signature
history is visible end-to-end.

The Windows gate is scheduled to be lifted in a future release once
the platform-side issues are fully resolved.

## [0.5.2-beta11] — 2026-05-07

### Backfill historical signing-DNA versions on every install

Each Sign It signature lives on the signing DNA that was current at
sign-time, and the `get_my_signatures` zome only returns entries from
the cell it's called against. Until now, a fresh install only got the
current signing DNA (v1.4) — historical signatures on v1.0 / v1.1 / v1.2
/ v1.3 were invisible on any new device.

beta11 bundles all five signing-DNA versions in the installer
(`bundle.resources` extended) and adds an `install_historical_signing_dnas`
pass at the end of `install_dnas` that installs + enables any of the
historical versions that aren't already present. Best-effort — a
per-version failure logs a warning and moves on, the unlock continues.

End result: a fresh install on any platform shows the user's full
signature history as soon as DHT gossip catches up.

### Sign It on Windows: friendly placeholder + dashboard tile gate

The Windows Sign It path isn't yet reliable in this build (signing-DNA
admin calls trigger a conductor crash that the runtime watchdog
absorbs but can't durably recover from). Rather than show a broken
list, beta11 replaces the Sign It page on Windows with:

> **Signing files from Windows is coming soon.** Until then, sign at
> flowsta.com or use Flowsta Vault on Linux / macOS — your signatures
> will appear here automatically.

A clear "Open flowsta.com" button takes the user to the web Sign It.

The Overview dashboard's Signatures tile shows "—" with the same
friendly subtitle on Windows, and the layout-owned background fetch
(`refreshSignatures` on conductor-ready and on `profile-synced`) is
skipped on Windows so the watchdog doesn't fire in a tight loop.

Linux / macOS users see no behaviour change — full Sign It UI, full
sig list, full create / revoke / thumbnail flow.

### File-explorer right-click label

Renamed *"Sign with Flowsta Vault"* → *"Sign It with Flowsta Vault"*
on Linux (`flowsta-vault-sign.desktop`) and Windows (NSIS installer
hook). macOS uses the OS's generic "Open With" menu and shows the
product name there, so no change needed.

## [0.5.2-beta10] — 2026-05-07

### Runtime conductor watchdog — recovers from post-startup crashes

beta9 confirmed Linux signatures back in working order, but Windows
testing revealed a third holochain.exe crash class: the conductor can
crash *after* `start_holochain` has returned. The startup auto-restart
(beta4) only covers crashes during DNA install; once we report
"conductor ready" and the vault enters its normal operating loop, a
later crash in the Holochain conductor leaves nothing to catch it. The
user sees a healthy-looking vault that silently returns 0 signatures
because every admin call hits a closed (10054) or refused (10061)
socket.

beta10 adds a **runtime watchdog**:

- The Lair-keystore passphrase is now cached for the duration of an
  unlocked session in a `sodoken::LockedArray` (memory-locked pages,
  zeroed on drop). This lets us restart the conductor without
  re-prompting. The buffer is cleared on lock and on app exit.
- A new `ensure_conductor_alive` helper checks the conductor process
  via `Child::try_wait()`. If it has exited, the helper kills any
  leftover lair process, runs the full `start_holochain` flow again
  with the cached credentials, and replaces the stale handle in
  AppState.
- Concurrent watchdog calls are serialised by a `tokio::sync::Mutex` so
  two simultaneously-failing commands don't both spawn a fresh
  conductor.
- `get_my_signatures` detects WS-unreachable errors (closed / refused)
  and runs the watchdog before retrying once. The frontend's existing
  layout-owned signature fetch is unchanged — recovery happens entirely
  inside the backend command.

This is a foundational reliability feature, not just a Holochain-bug
patch. The same mechanism will catch any future crash class, support
seamless conductor binary upgrades, and recover from runtime hangs or
resource exhaustion without forcing the user back through unlock.

The terminal-flash issue on Windows (windows appear-then-disappear) is
unchanged in beta10 and is the next target — beta11 will replace the
post-spawn `ShowWindow(SW_HIDE)` polling with `STARTUPINFOW.wShowWindow
= SW_HIDE` set at process-creation time, eliminating the flash
entirely.

## [0.5.2-beta9] — 2026-05-07

### Fix beta8 regression: 0 signatures returned on Linux + Windows

beta8 shrunk `ensure_apps_enabled`'s retry budget from 6 × 3 s = 18 s
down to 3 × 1 s = 3 s with the goal of holding the admin WebSocket open
for less time on Windows. The reasoning was sound *for Windows* — the
conductor's WS server can reset long-running admin connections — but it
broke signatures retrieval on **all** platforms.

The chain of events:

1. Conductor reports apps Enabled, but the cells take a few seconds to
   fully initialise after that (transient `CellDisabled` state).
2. `ensure_apps_enabled` calls `authorize_signing_credentials` to verify
   readiness. With the old 18 s budget, it'd retry through the
   `CellDisabled` window — typically succeeding by attempt 2 or 3.
3. With the 3 s budget, all 3 attempts can fail before cells come up,
   and the function bails *silently* (`log::warn!` then return).
4. The downstream `connect_signing_app_ws` then calls the same
   `authorize_signing_credentials` and **still sees** `CellDisabled` —
   it returns `None`, and the per-version sig query returns
   `Vec::new()`.
5. End result: `get_my_signatures` succeeds with an empty list. The
   retry wrapper added in beta8 only fires on WebSocket errors, not on
   empty-but-Ok results, so the user sees 0 signatures.

beta9 reverts the retry budget to the 6 × 3 s pattern that worked on
0.5.1. Windows safety on the long wait is now provided by the outer
`start_holochain` auto-restart (beta4) and the `get_my_signatures`
retry-once wrapper (beta8) — both of which catch the WS-reset case
without needing this function to bail early.

No other changes; this is a focused regression fix.

## [0.5.2-beta8] — 2026-05-07

### Hide conhost.exe terminals + recover signatures fetch from WS resets

beta7 closed the timing race for any window the OS attributed to our
spawned PID directly. The diagnostic logging revealed that on this
machine, what we were finding was the **PseudoConsoleWindow** (an
invisible-by-design ConPTY infrastructure window) — not the visible
terminal. The visible terminal is created by `conhost.exe`, a separate
process whose **parent** is our spawned binary.

beta8 extends `windows_hide` to handle that:

- Each poll iteration also takes a Toolhelp32 snapshot of every
  process's parent PID and enumerates windows whose class matches a
  known console host class (`ConsoleWindowClass`, `OpenConsoleWindow`,
  `PseudoConsoleWindow`, `CASCADIA_HOSTING_WINDOW_CLASS`). Any whose
  owner-process's parent is our spawned PID get hidden.
- The diagnostic log now distinguishes "first direct-match class" from
  "first conhost-child match class" so the next test makes it obvious
  which path is finding the visible terminal.

Linux / macOS unchanged — they don't allocate consoles for sidecar
processes the same way.

### Signatures fetch survives a WebSocket reset mid-call

User reports show `get_my_signatures` returning 0 on Windows when the
conductor's WS server resets the long-running admin connection during
the call (the same WS-server quirk we work around in the install path).
The frontend then displays an empty list instead of an error.

beta8:

- Wraps the `get_my_signatures` Tauri command in a retry-once-on-WS-
  error pattern that mirrors `install_app_resilient` /
  `enable_app_resilient`. On a Websocket / ConnectionReset / closed-
  connection error, sleep 1 s and run the whole fetch again with fresh
  admin + app WebSockets.
- Shrinks `ensure_apps_enabled`'s retry budget from 6 × 3 s to
  3 × 1 s. Plenty for the typical "cells just came online" case, and
  the shorter window means the admin WS is held open for less time
  before either succeeding or returning, reducing the chance of being
  caught by a WS reset.

The frontend layout-owned background fetch on conductor-ready is
unchanged — signatures still load automatically when the vault unlocks
regardless of which page you're on. The retry happens transparently
inside the backend command.

## [0.5.2-beta7] — 2026-05-07

### Stop the hide thread bailing out before terminal windows appear

beta6 hid lair-keystore reliably but the holochain conductor's terminal
still flashed (and sometimes stuck around) on Windows. The diagnostic
logs showed the hide thread exiting too early: it would find a window
owned by the spawned PID with `IsWindowVisible == 0` after a few polls,
log *"found 1 window(s) but none visible — not hiding"*, and quit.
Conhost then toggled `WS_VISIBLE` on milliseconds later — too late for
us to catch.

The early-exit on *"found but invisible"* assumed the child was
deliberately keeping a hidden IPC window we shouldn't flap. That was
wrong for our case. The fix is to keep polling for the full budget and
call `ShowWindow(SW_HIDE)` on every match every iteration, regardless
of current visibility. `SW_HIDE` is idempotent on already-hidden
windows, so the worst case is a 50 ms visibility flicker between
conhost toggling the window on and our next poll catching it.

The hide thread now also:

- Polls for **3 s total** (was 2 s) at **50 ms intervals** — 60 attempts
  per spawned process, more than enough headroom for slow Windows
  startups.
- Logs the **window class name** on the first match per pid. Lets us
  confirm we're actually finding the `ConsoleWindowClass` window vs.
  some unrelated internal window. If beta7 logs show we're matching a
  non-console class and the real terminal still escapes, beta8 will add
  conhost-parent tracking — find `ConsoleWindowClass` windows whose
  conhost.exe parent matches our spawned PID.
- Reports a summary at exit: total iterations, total hide calls, and
  how many of those calls were on a previously-visible window (the
  metric that tells us the polling is doing useful work).

Linux / macOS unchanged.

## [0.5.2-beta6] — 2026-05-06

### Hide both sidecar terminals on Windows; soften the recovery message

beta5's first-install captured the conductor's exit status for the first
time: `0xc0000005` (Windows `STATUS_ACCESS_VIOLATION`) — `holochain.exe`
genuinely crashes during signing DNA's first-time WASM compile, same
crash class as v0.5.0. With the start_holochain auto-restart (beta4) and
the fast bail-on-process-exit (beta5) catching this transparently, the
visible-terminal workaround is no longer load-bearing.

beta6:

- Re-enables `spawn_hidden()` for `holochain.exe` (was disabled in
  v0.5.2-rc2 on the theory that hiding caused the crash). beta1's
  diagnostic logging and beta5's exit-code capture proved the crash
  happens regardless of window state — it's an upstream holochain bug,
  not something the vault's spawn flags can change. Both sidecar
  terminals (`lair-keystore.exe` and `holochain.exe`) are now hidden on
  Windows. Linux / macOS unchanged.
- Replaces the auto-restart status message *"First-run setup needs a
  quick restart..."* with *"Finishing first-time setup..."* so the
  brief recovery feels like progression, not a fault recovery.

The upstream `holochain.exe` crash on first signing-DNA install will be
filed with the holochain team. The vault's auto-restart is a clean
work-around in the meantime; users see a single ~30 s "Initializing..."
on a clean Windows install and then the vault is ready.

## [0.5.2-beta5] — 2026-05-06

### Bail out of inner retry the moment the conductor process exits

beta4 added the outer auto-restart and it works. But the inner WS-recovery
loop was still burning ~35 s waiting on a port that nothing was listening
on, before handing off to the outer restart. The Windows symptom is
distinctive: once `holochain.exe` exits, every reconnect attempt comes
back with `os error 10061` (connection refused) — there's no point
hammering it.

`install_app_resilient` and `enable_app_resilient` now take a handle to
the conductor's child process and call `Child::try_wait()` on every
recovery iteration. The instant the OS reports the process has exited,
the helpers return an error so the outer `start_holochain` retry can
spawn a fresh conductor immediately.

Cross-platform: macOS / Linux never have the conductor exit during DNA
install, so the early-bail check is a no-op there. The path is
unchanged for those platforms.

End-to-end on Windows: first-install + auto-recovery should now complete
in ~10 s instead of ~70 s, with the same eventual outcome (working vault
on the first launch).

## [0.5.2-beta4] — 2026-05-06

### Auto-restart the conductor on first-install hiccups

beta3 added retry+reconnect for `install_app` and `enable_app`, but the
new logs revealed the next layer of the problem: on Windows, the
conductor process itself can exit during identity DNA's first-time
setup. Once `holochain.exe` is gone, no amount of WS reconnecting will
help — every reconnect attempt comes back with `os error 10061`
(connection refused) because there's nothing listening on the admin
port. The vault was sitting in its 120 s recovery loop watching a dead
process before bailing out with `HC Error`.

Users were already working around this by hand: lock the vault → unlock.
That kills the (already-dead) conductor and starts a fresh one, which
warm-starts against the cached WASM and registered-but-disabled identity
DNA. Total recovery: <2 s of actual conductor work.

beta4 automates that workaround:

- `start_holochain` now wraps the full startup-and-DNA-install flow in a
  retry-once pattern. If the first attempt errors for any reason, vault
  pauses 2 s for OS resources to release and runs the whole flow again
  on a fresh conductor process. The frontend gets a transient
  *"First-run setup needs a quick restart..."* status so the user sees
  visible progress instead of an HC Error.
- `enable_app_resilient` and `install_app_resilient` shrink their
  per-call recovery budget from 120 s to 30 s. 30 s is plenty for a
  healthy conductor's slow WASM compile; if the conductor has died, we
  hand off to the outer restart sooner instead of burning two minutes
  watching a closed port.

End-to-end behaviour: the user sees a slightly longer "Initializing..."
on a clean Windows install (the cost of the auto-restart), but no HC
Error and no manual lock+unlock dance.

holochain.exe terminal is still visible on Windows; will be addressed in
the next beta once first-install is solid.

## [0.5.2-beta3] — 2026-05-06

### Make `install_app` resilient too

beta2 confirmed Bug 2 was fixed (the normalization pass made lock+unlock
recovery succeed in 1.8 s, vs. needing two retries before). It also
showed Bug 1 has a second face: the same WS-reset-during-long-WASM-compile
hits **`install_app(identity)`** on a fresh install, not just
`enable_app(identity)`. Beta2 wrapped only the latter, so the first
install still failed and the user had to lock+unlock to recover.

beta3 adds an `install_app_resilient` helper that mirrors the existing
`enable_app_resilient`: on a WS error, reconnect, poll `list_apps` for
the target app, and either accept already-registered (the conductor
completed the install server-side, only the response was lost) or
retry `install_app` on a fresh connection. The retry is fast because
the conductor caches the compiled WASM even when the response is lost.

All three DNA install blocks (private / identity / signing) now route
through `install_app_resilient`, then `enable_app_resilient`, so a WS
reset at either step is recoverable inside the same vault session — the
user shouldn't need to lock and unlock to get past the first install.

holochain.exe terminal still visible on Windows; will be addressed in
the next beta once first-install is rock solid.

## [0.5.2-beta2] — 2026-05-06

### Fix the Windows first-install failure

beta1's diagnostic logging pinned down two distinct bugs masquerading as a
single "HC Error". Neither involves holochain.exe crashing — the conductor
stays alive throughout. holochain.exe's terminal stays visible on Windows
in this build; the next beta will revisit hiding it now that we have a
working baseline.

**Bug 1 — `enable_app(identity)` WebSocket reset on first install.**
The conductor's WS server forcibly closes long-running admin requests
(Windows error 10054 / `Websocket closed: ConnectionClosed`) while the
identity hApp's ~3.9 MB WASM is being compiled for the first time. The
work usually completes server-side; only the response is lost. Vault now
wraps every `enable_app` call in `enable_app_resilient` — on a WS error
it reconnects, polls `list_apps(Enabled)` for the target app, and either
treats already-Enabled as success or retries `enable_app` on the fresh
connection. Total recovery budget is 120 s, which is plenty for the
worst-case first-time WASM compile we've measured.

**Bug 2 — partially-installed apps left in `Disabled(NeverStarted)` on
retry.** When Bug 1 dropped the connection mid-enable, the identity app
was registered in the conductor's state DB but never marked Enabled. The
next vault unlock then walked the install path, saw the existing
identity, marked it `installed`, and skipped past it — but never
explicitly re-enabled the disabled cell. DNA verification then failed
with `private=true, identity=false`. Vault now runs a normalization pass
that calls `enable_app_resilient` on every known-target-and-keymatched
existing app before deciding what's missing. enable_app is safe to call
on an already-Enabled app, so the pass is a no-op when state is
healthy.

## [0.5.2-beta1] — 2026-05-06

### Diagnostic build for the Windows first-install crash

This is a **diagnostic-only** pre-release. Behaviour is the same as v0.5.2 (lair
hidden, holochain visible) but with verbose logging added throughout the
Holochain startup path. The goal is to capture timing and lifecycle events
during the Windows first-install failure so we can pin down the root cause and
ship a clean v0.5.2 with both terminals hidden and no crashes.

**What's new in the log:**
- `[hide:<pid>]` — lifecycle of the post-spawn `ShowWindow(SW_HIDE)` thread on
  Windows: when it starts, every poll iteration that finds a top-level
  window for the spawned pid, the HWND we hide, and how long the whole hunt
  took.
- `[lair:init]` / `[lair:server]` — spawn timing for the lair-keystore init
  and server processes.
- `[conductor:<pid>]` — spawn time for `holochain.exe`, and a liveness check
  500ms after spawn.
- `[dna:private|identity|signing]` — per-DNA install + enable timing, plus
  the `.happ` file size we're feeding the conductor.
- A `[conductor]` summary after the DNA install sequence reports whether the
  conductor process is still alive and the size of its stdout/stderr log
  files. Critical for the Windows fault: if `holochain.exe` died mid-install,
  this is the line that pins down which DNA was being processed.

The log is written to the standard Tauri app-log directory; the path is
printed on every startup (`Log dir: ...`) so testers can find it without
guessing.

No behaviour changes vs v0.5.2 are included. Once we have a reproducible
log capture from a tester, we'll cut beta2 with a targeted fix.

## [0.5.2] — 2026-05-05

### Hide the lair-keystore terminal window on Windows

v0.5.0 tried to hide both sidecar terminals (`lair-keystore.exe` and
`holochain.exe`) via `CREATE_NO_WINDOW`. That broke fresh installs because
the flag also prevents Windows from allocating a console handle, and
`holochain.exe` then crashed in `MSVCP140.dll` during signing-DNA WASM
compilation. v0.5.1 reverted to leave both terminals visible.

v0.5.2 testing showed the crash is specific to `holochain.exe` and
reproduces with **any** mechanism that hides its console window —
post-spawn `ShowWindow(SW_HIDE)` reproduces the same `0xc0000005`
access violation. The root cause is upstream (holochain or wasmer's
WASM-compilation path on Windows requires a visible console for some
stdio operation we haven't pinned down). `lair-keystore.exe` is fine
with hidden consoles.

The compromise: lair-keystore is now spawned with a hidden window via a
new `Command::spawn_hidden` extension that calls `EnumWindows` +
`ShowWindow(SW_HIDE)` post-spawn (so the console handle is allocated
normally, only the window is hidden). The holochain terminal stays
visible on Windows for now. Half the previous noise, no crashes. Linux
and macOS are unchanged.

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
