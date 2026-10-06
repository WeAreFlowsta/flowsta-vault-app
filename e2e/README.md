# UI tests: the real app, driven

These tests drive the real Flowsta Vault window through an embedded
WebDriver server (`tauri-plugin-wdio-webdriver`, compiled in only with the
`e2e` cargo feature; no release build carries it -
`scripts/check-no-e2e-feature.mjs` proves that on every build).

```bash
npm ci                 # WebdriverIO and the Tauri service come as dev deps
npm run e2e:build      # the staging test build with the e2e feature
npm run e2e            # fresh data folder: first launch
```

Screenshots land in `e2e/shots/` (one per step, plus one per test marked
`ok_` or `FAIL_`). The app runs on a scratch data folder under
`e2e/profile/` (wiped per run), against staging, in a session bus of its
own; the person's own Vault is never touched and may stay open.

Linux desktop (Wayland or X11): `sudo apt install xdotool`. The window must
be ACTIVE or the webview produces no frames; `wdio.conf.ts` activates it
before every test, so a run takes the foreground while it lasts. A run
refuses to start on a locked screen.

A full run is about 50 minutes. Most of it is the conductor's cold start:
after a restart, an identity whose data has grown takes minutes before its
cells answer (the DHT model is rebuilt per cell at join), and every spec
file restarts the app. Steps that follow a restart wait `COLD_START_MS`
(`specs/_helpers.ts`) and print `[timed] ...: Ns`; they nudge the page while
they wait, as a person would, or the Vault locks itself after 15 minutes.

Looking into something a run left behind:

```bash
VAULT_E2E_KEEP_PROFILE=1 RUST_LOG=warn,holochain=info node e2e/run.mjs probe
```

reopens the first identity without wiping the folder (`VAULT_E2E_IDENTITY`
picks another, `VAULT_E2E_PROBE_WAIT` the seconds to watch). Each instance's
app log is `e2e/profile/<a|b>/xdg/com.flowsta.vault/logs/Flowsta Vault.log`
(the launcher points the XDG dirs into the profile, so neither the log nor
the webview's localStorage is shared with the installed Vault). The
conductor's own log is `e2e/profile/<a|b>/identities/<id>/conductor/holochain-stderr.log`;
the app writes it at `warn` unless `RUST_LOG` says otherwise.

## Writing a spec

- Select by `data-testid`, never by copy.
- A second device is another instance driven through the dev endpoints
  (`POST /dev/devices`), not a second window.
- Nothing leaves the scratch data folder.
- A wait that may span a conductor restart uses `waitAwake` with
  `COLD_START_MS`, inside `timed(...)` so the run prints what it took.
