// Approval dialogs, seen for real (build-docs VAULT_CONNECTION_UX.md fixes
// 5, 6 and 15). The test build answers dialogs by itself; the debug-only
// `x-flowsta-test-dialog: 1` header makes a request show its real dialog.
//   1. Two requests at once: one dialog on screen; the second shows when the
//      first is answered.
//   2. A sign-in sent while the Vault is locked shows its dialog after unlock.
//   3. A remembered desktop app signs silently only with its link key.
//   4. The same sign-in sent twice at once (a page that started twice): one
//      dialog, one answer, both requests get it (Windows, 2026-10-16).
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
});
