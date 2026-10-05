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

## Writing a spec

- Select by `data-testid`, never by copy.
- A second device is another instance driven through the dev endpoints
  (`POST /dev/devices`), not a second window.
- Nothing leaves the scratch data folder.
