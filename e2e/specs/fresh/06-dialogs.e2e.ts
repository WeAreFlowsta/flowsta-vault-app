// Approval dialogs, seen for real (build-docs VAULT_CONNECTION_UX.md fixes
// 5, 6 and 15). The test build answers dialogs by itself; the debug-only
// `x-flowsta-test-dialog: 1` header makes a request show its real dialog.
//   1. Two requests at once: one dialog on screen; the second shows when the
//      first is answered.
//   2. A sign-in sent while the Vault is locked shows its dialog after unlock.
//   3. A remembered desktop app signs silently only with its link key.
//   4. The same sign-in sent twice at once (a page that started twice): one
//      dialog, one answer, both requests get it (Windows, 2026-10-16).
//   5. A website's and a desktop app's connect dialogs; a signature asked
//      for straight after connecting shows its own dialog.
//   6. Publishing a release: the dialog lists every file, the Holochain
//      programs and the other downloads the version needs (its `parts`),
//      each with its hash, before anything is signed.
import { randomBytes } from "node:crypto";
import { byId, click, fill, PASSWORD, PORT_A, devOp, vault } from "../_helpers";

const FIXTURE_CLIENT = "flowsta_app_2f0660aa9c7afdda85e8e8fc88e59cbcce79921cdecf9c81a2cbba8e34420a9b"; // staging fixture app
const KEY_CLIENT = "dialog_key_app";
const KEY_ORIGIN = "yoai://dialog-key";
const LINK_KEY = "uhCAk" + randomBytes(36).toString("base64url").slice(0, 48);

const ipc = (path: string, origin: string, body: unknown, showDialog = true) =>
  fetch(`http://127.0.0.1:${PORT_A}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin, ...(showDialog ? { "x-flowsta-test-dialog": "1" } : {}) },
    body: JSON.stringify(body),
  }).then(async (r) => ({ status: r.status, data: (await r.json().catch(() => null)) as any }));

const signIn = (origin: string, extra: Record<string, unknown> = {}, showDialog = true) =>
  ipc("/authenticate", origin, {
    app_name: "Dialog test",
    challenge: Buffer.from(`dialog-test-${randomBytes(8).toString("hex")}`, "utf8").toString("base64"),
    reason: "Sign in to the dialog test",
    ...extra,
  }, showDialog);

const shown = async (id: string) => (await byId(id)).isDisplayed().catch(() => false);

async function ensureUnlocked() {
  const status = (await vault(PORT_A, "/status")).data || {};
  if (status.unlocked) return;
  await (await byId("unlock-password")).waitForDisplayed({ timeout: 90_000 });
  const row = await $('[data-testid="identity-row"]');
  if (await row.isExisting()) await row.click();
  await fill('[data-testid="unlock-password"]', PASSWORD);
  await click("unlock-submit");
  await (await byId("devices-chip")).waitForDisplayed({ timeout: 300_000 });
}

describe("approval dialogs", () => {
  before(async function () {
    this.timeout(400_000);
    await ensureUnlocked();
  });

  it("shows one request at a time; the next appears when the first is answered", async function () {
    this.timeout(180_000);
    const link = ipc("/link-identity", "yoai://dialog-link", {
      app_name: "Dialog link test",
      client_id: FIXTURE_CLIENT,
      app_agent_pub_key: "uhCAk" + randomBytes(36).toString("base64url").slice(0, 48),
    });
    await browser.waitUntil(() => shown("link-dialog"), { timeout: 30_000, timeoutMsg: "the link dialog never showed" });
    const auth = signIn("yoai://dialog-auth");
    // The sign-in is pending behind the link dialog, not on top of it.
    await browser.pause(3_000);
    expect(await shown("link-dialog")).toBe(true);
    expect(await shown("auth-dialog")).toBe(false);
    console.log("e2e: one dialog on screen with two requests pending");
    await click("link-deny");
    await browser.waitUntil(() => shown("auth-dialog"), { timeout: 15_000, timeoutMsg: "the second request never showed after the first was answered" });
    expect(await shown("link-dialog")).toBe(false);
    await click("auth-deny");
    const [l, a] = await Promise.all([link, auth]);
    console.log(`e2e: queue answered: link ${l.status}, sign-in ${a.status}`);
    expect(l.status).toBe(403);
    expect(a.status).toBe(403);
  });

  it("the same sign-in sent twice at once takes one answer", async function () {
    this.timeout(180_000);
    const origin = "https://dialog-twice.example";
    const first = signIn(origin);
    await browser.waitUntil(() => shown("auth-dialog"), { timeout: 30_000, timeoutMsg: "the first sign-in showed no dialog" });
    const second = signIn(origin);
    // The second must not knock the first off: it waits on the same dialog.
    await browser.pause(2_000);
    expect(await shown("auth-dialog")).toBe(true);
    await click("auth-allow");
    const [a, b] = await Promise.all([first, second]);
    console.log(`e2e: twice at once -> ${a.status}, ${b.status}`);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect(typeof a.data?.signature).toBe("string");
    expect(typeof b.data?.signature).toBe("string");
    await browser.pause(1_000);
    expect(await shown("auth-dialog")).toBe(false);
  });

  it("a sign-in sent while locked shows its dialog after unlock", async function () {
    this.timeout(400_000);
    await click("lock-vault");
    await (await byId("unlock-password")).waitForDisplayed({ timeout: 60_000 });
    const pending = signIn("yoai://dialog-locked");
    await browser.pause(2_000);
    const row = await $('[data-testid="identity-row"]');
    if (await row.isExisting()) await row.click();
    await fill('[data-testid="unlock-password"]', PASSWORD);
    await click("unlock-submit");
    await browser.waitUntil(() => shown("auth-dialog"), { timeout: 120_000, timeoutMsg: "the sign-in sent while locked never showed after unlock" });
    console.log("e2e: sign-in sent while locked showed after unlock");
    await click("auth-allow");
    const r = await pending;
    console.log(`e2e: locked sign-in -> ${r.status}`);
    expect(r.status).toBe(200);
    await (await byId("devices-chip")).waitForDisplayed({ timeout: 300_000 });
  });

  it("a remembered desktop app signs silently only with its link key", async function () {
    this.timeout(180_000);
    const linked = await devOp(PORT_A, { op: "connect", client_id: KEY_CLIENT, app_name: "Dialog key test", origin: KEY_ORIGIN, app_agent_pub_key: LINK_KEY });
    expect(linked.connected).toBe(true);
    try {
      // Remember the app: approve once with the remember box ticked.
      const first = signIn(KEY_ORIGIN, { app_agent_pub_key: LINK_KEY });
      await browser.waitUntil(() => shown("auth-dialog"), { timeout: 30_000, timeoutMsg: "the first sign-in showed no dialog" });
      await (await byId("auth-remember")).click();
      await click("auth-allow");
      expect((await first).status).toBe(200);

      // Remembered, but no link key: the dialog shows instead of a silent signature.
      const noKey = signIn(KEY_ORIGIN);
      await browser.waitUntil(() => shown("auth-dialog"), { timeout: 30_000, timeoutMsg: "a remembered app WITHOUT its key was signed silently" });
      console.log("e2e: remembered app without its key -> dialog");
      await click("auth-deny");
      expect((await noKey).status).toBe(403);

      // Remembered, with the key: signed with no dialog.
      const withKey = await signIn(KEY_ORIGIN, { app_agent_pub_key: LINK_KEY });
      console.log(`e2e: remembered app with its key -> ${withKey.status}`);
      expect(withKey.status).toBe(200);
      expect(typeof withKey.data?.signature).toBe("string");
      expect(await shown("auth-dialog")).toBe(false);

      // A wrong key is no key.
      const wrongKey = signIn(KEY_ORIGIN, { app_agent_pub_key: LINK_KEY.slice(0, -2) + "zz" });
      await browser.waitUntil(() => shown("auth-dialog"), { timeout: 30_000, timeoutMsg: "a remembered app with the WRONG key was signed silently" });
      await click("auth-deny");
      expect((await wrongKey).status).toBe(403);
      console.log("e2e: wrong key -> dialog");
    } finally {
      await devOp(PORT_A, { op: "disconnect", client_id: KEY_CLIENT }).catch(() => null);
    }
  });

  it("names a website by its address, and says when the app is already connected from somewhere else", async function () {
    this.timeout(180_000);
    const text = async (id: string) => ((await (await byId(id)).getText().catch(() => "")) || "").replace(/\s+/g, " ").trim();
    // A desktop app: its verified name leads, and its made-up name is not shown.
    const desktop = ipc("/link-identity", "yoai://dialog-desktop", {
      app_name: "A name the caller made up",
      client_id: FIXTURE_CLIENT,
      app_agent_pub_key: "uhCAk" + randomBytes(36).toString("base64url").slice(0, 48),
    });
    await browser.waitUntil(() => shown("link-dialog"), { timeout: 30_000, timeoutMsg: "the link dialog never showed" });
    const desktopTitle = await text("link-title");
    console.log(`e2e: a desktop app's link dialog says: ${desktopTitle}`);
    expect(desktopTitle).toMatch(/^Connect .+\?$/);
    expect(desktopTitle).not.toContain("A name the caller made up");
    expect(await shown("link-elsewhere-warning")).toBe(false);
    await click("link-allow");
    const linked = await desktop;
    expect(linked.status).toBe(200);
    expect(typeof linked.data?.link_token).toBe("string");
    // A signature asked for straight after connecting still shows its own
    // dialog: connecting is not a yes to signing.
    const sign = (bytes: string) => ipc("/sign", "yoai://dialog-desktop", {
      type: "bytes", bytes: Buffer.from(bytes, "utf8").toString("base64"), reason: "dialog test",
      link_token: linked.data.link_token, client_id: FIXTURE_CLIENT,
    });
    const refused = sign("dialog test payload one");
    await browser.waitUntil(() => shown("raw-sign-dialog"), { timeout: 30_000, timeoutMsg: "a signature asked for straight after connecting showed no dialog" });
    await click("raw-sign-deny");
    const no = await refused;
    console.log(`e2e: a signature denied straight after connecting: ${no.status} ${no.data?.error}`);
    expect(no.status).toBe(403);
    expect(no.data?.error).toBe("user_denied");
    const allowed = sign("dialog test payload two");
    await browser.waitUntil(() => shown("raw-sign-dialog"), { timeout: 30_000, timeoutMsg: "the second signing dialog never showed" });
    await click("raw-sign-approve");
    const yes = await allowed;
    expect(yes.status).toBe(200);
    expect(typeof yes.data?.signature).toBe("string");
    // A website asking to connect as the same app: its address leads, and
    // the dialog says the app is already connected from elsewhere.
    const site = ipc("/link-identity", "https://dialog-site.example", {
      app_name: "Dialog link test",
      client_id: FIXTURE_CLIENT,
      app_agent_pub_key: "uhCAk" + randomBytes(36).toString("base64url").slice(0, 48),
    });
    await browser.waitUntil(() => shown("link-dialog"), { timeout: 30_000, timeoutMsg: "the second link dialog never showed" });
    const siteTitle = await text("link-title");
    const warning = await text("link-elsewhere-warning");
    console.log(`e2e: a website's link dialog says: ${siteTitle} | ${warning}`);
    expect(siteTitle).toMatch(/^dialog-site\.example wants to connect as /);
    expect(warning).toContain("is already connected from yoai://dialog-desktop");
    await click("link-deny");
    expect((await site).status).toBe(403);
  });
  it("a release to publish shows its files and the other downloads it needs before it is signed", async function () {
    this.timeout(180_000);
    await ensureUnlocked();
    const RELEASE_CLIENT = "dialog_release_tool";
    const RELEASE_ORIGIN = "yoai://dialog-release";
    const sha = (c: string) => c.repeat(64);
    const manifest = {
      v: 1, app: "com.example.dialogtest", channel: "beta", sequence: 7,
      issued_at: "2026-11-19T00:00:00Z", version: "9.9.9-beta.1", from_version: "9.9.8",
      notes_url: "https://example.com/notes",
      holochain: { lines: ["holochain-0.7"], changes_line: false },
      rollout: { percent: 100 },
      files: [
        { platform: "darwin-aarch64", kind: "app-tarball", name: "Dialog.Test_aarch64.app.tar.gz", url: "https://example.com/a.tar.gz", size: 123456789, sha256: sha("a") },
        { platform: "windows-x86_64", kind: "nsis", name: "Dialog.Test_9.9.9_x64-setup.exe", url: "https://example.com/b.exe", size: 65432100, sha256: sha("b") },
      ],
      kit: [{ line: "holochain-0.7", target: "x86_64-pc-windows-msvc", sidecar: "dialogtest-holochain-07", sha256: sha("c") }],
      parts: [
        { name: "nvidia-engine", target: "x86_64-pc-windows-msvc", version: "b12359", size: 790346417, sha256: sha("d") },
        { name: "projects-helper", target: "linux-x86_64", version: "0.4.3", size: 73031195, sha256: sha("e") },
      ],
    };
    const ask = () => ipc("/sign-release-manifest", RELEASE_ORIGIN, { manifest });
    const linked = await devOp(PORT_A, { op: "connect", client_id: RELEASE_CLIENT, app_name: "Dialog release tool", origin: RELEASE_ORIGIN });
    expect(linked.connected).toBe(true);
    try {
      // Denied: nothing is signed.
      const denied = ask();
      await browser.waitUntil(() => shown("release-manifest-dialog"), { timeout: 30_000, timeoutMsg: "a release to publish showed no dialog" });
      const dialog = (await (await byId("release-manifest-dialog")).getText()).replace(/\s+/g, " ");
      // Who asks, what for, and which release.
      expect(dialog).toContain("Publish a release");
      expect(dialog).toContain("Dialog release tool asks you to sign");
      expect(dialog).toContain("com.example.dialogtest");
      expect(dialog).toContain("9.9.9-beta.1 (from 9.9.8 or later)");
      expect(dialog).toContain("beta #7");
      expect(dialog).toContain("100% of installs");
      // Every file, with its platform, size and the start of its hash.
      expect(dialog).toContain("Dialog.Test_aarch64.app.tar.gz");
      expect(dialog).toMatch(/darwin-aarch64 · app-tarball · 117\.7 MB · a{12}/);
      expect(dialog).toContain("Dialog.Test_9.9.9_x64-setup.exe");
      expect(dialog).toMatch(/windows-x86_64 · nsis · 62\.4 MB · b{12}/);
      // The Holochain programs it carries.
      expect(dialog).toMatch(/dialogtest-holochain-07 · x86_64-pc-windows-msvc · c{12}/);
      // The other downloads the version needs: each part, its version, target, size and hash.
      const parts = (await (await byId("release-sign-parts")).getText()).replace(/\s+/g, " ");
      expect(parts).toContain("Other downloads this version needs");
      expect(parts).toMatch(/nvidia-engine b12359 · x86_64-pc-windows-msvc · 753\.7 MB · d{12}/);
      expect(parts).toMatch(/projects-helper 0\.4\.3 · linux-x86_64 · 69\.6 MB · e{12}/);
      // The statement that is signed, and the caution.
      expect(dialog).toMatch(/flowsta-release-manifest:v1:com\.example\.dialogtest:beta:7:[0-9a-f]{64}/);
      expect(dialog).toContain("Approve only if the app, version, channel and file hashes match");
      await browser.saveScreenshot(`${process.cwd()}/e2e/shots/release-sign-dialog.png`);
      await click("release-sign-deny");
      const no = await denied;
      expect(no.status).toBe(403);
      expect(no.data?.error).toBe("user_denied");
      expect(await shown("release-manifest-dialog")).toBe(false);

      // Approved: signed, and the statement is the one the dialog showed.
      const approved = ask();
      await browser.waitUntil(() => shown("release-manifest-dialog"), { timeout: 30_000, timeoutMsg: "the second request showed no dialog" });
      // The list is longer than its box: signing waits until its end has been in view.
      const approve = await byId("release-sign-approve");
      expect(await approve.isEnabled()).toBe(false);
      expect(await (await byId("release-sign-scroll-first")).getText()).toContain("Scroll to its end to sign");
      await browser.execute(() => { const el = document.querySelector('[data-testid="release-sign-details"]')!; el.scrollTop = el.scrollHeight; el.dispatchEvent(new Event("scroll")); });
      await browser.waitUntil(() => approve.isEnabled(), { timeout: 10_000, timeoutMsg: "Sign and publish stayed off after the list was read to its end" });
      expect(await shown("release-sign-scroll-first")).toBe(false);
      await browser.saveScreenshot(`${process.cwd()}/e2e/shots/release-sign-dialog-end.png`);
      const shownStatement = /flowsta-release-manifest:v1:[\w.]+:\w+:\d+:[0-9a-f]{64}/.exec(await (await byId("release-manifest-dialog")).getText())?.[0];
      await click("release-sign-approve");
      const yes = await approved;
      expect(yes.status).toBe(200);
      expect(typeof yes.data?.signature).toBe("string");
      expect(yes.data?.statement).toBe(shownStatement);

      // A part named with words that could not be a file name is refused before any dialog.
      const bad = await ipc("/sign-release-manifest", RELEASE_ORIGIN, { manifest: { ...manifest, parts: [{ ...manifest.parts[0], version: "../b1" }] } });
      expect(bad.status).toBe(400);
      expect(bad.data?.error).toBe("bad_manifest");
      expect(await shown("release-manifest-dialog")).toBe(false);
      // And a caller that is not a connected app is refused too.
      const stranger = await ipc("/sign-release-manifest", "https://never-connected.example", { manifest });
      expect(stranger.status).toBe(403);
      expect(stranger.data?.error).toBe("not_linked");
    } finally {
      await devOp(PORT_A, { op: "disconnect", client_id: RELEASE_CLIENT }).catch(() => null);
    }
  });
});
