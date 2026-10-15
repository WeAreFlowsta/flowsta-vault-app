// The desktop-to-web hand-off (build-docs VAULT_CONNECTION_UX.md §4): a LINKED
// app may have the web-login challenge for its own client, or its companion
// web client, signed - so its web app opens signed in and the browser never
// has to reach this Vault. Any other client, or an unlinked origin, is
// refused as before. Driven over the IPC with the dev link op; the dev build
// resolves dialogs headlessly, so this leg proves the gate, not the dialog.
import { byId, click, fill, PASSWORD, PORT_A, devOp, vault } from "../_helpers";

const DESKTOP = "handoff_desktop_app";
const WEB = "handoff_web_app";
const ORIGIN = "yoai://handoff-test";

const authenticate = async (origin: string, challengeText: string) => {
  const resp = await fetch(`http://127.0.0.1:${PORT_A}/authenticate`, {
    method: "POST",
    headers: { "content-type": "application/json", origin },
    body: JSON.stringify({
      app_name: "Hand-off test",
      challenge: Buffer.from(challengeText, "utf8").toString("base64"),
      reason: "Sign in to the web app",
      client_id: DESKTOP,
      scopes: [],
    }),
  });
  return { status: resp.status, data: (await resp.json().catch(() => null)) as any };
};

describe("the desktop-to-web hand-off", () => {
  it("signs the web-login challenge for a linked app's companion client, and for nothing else", async function () {
    this.timeout(300_000);
    // An unlocked Vault: whatever 03 left on screen, unlock the first identity.
    const status = (await vault(PORT_A, "/status")).data || {};
    if (!status.unlocked) {
      await (await byId("unlock-password")).waitForDisplayed({ timeout: 90_000 });
      const row = await $('[data-testid="identity-row"]');
      if (await row.isExisting()) await row.click();
      await fill('[data-testid="unlock-password"]', PASSWORD);
      await click("unlock-submit");
      await (await byId("devices-chip")).waitForDisplayed({ timeout: 300_000 });
    }
    const linked = await devOp(PORT_A, { op: "connect", client_id: DESKTOP, app_name: "Hand-off test", origin: ORIGIN, companion_client_id: WEB });
    console.log(`e2e: linked ${JSON.stringify(linked)}`);
    expect(linked.connected).toBe(true);
    try {
      const own = await authenticate(ORIGIN, `flowsta-auth-challenge:v1:n0nce+AbC=:${WEB}`);
      console.log(`e2e: companion client -> ${own.status} ${JSON.stringify(own.data).slice(0, 160)}`);
      expect(own.status).toBe(200);
      expect(typeof own.data?.signature).toBe("string");
      expect(own.data.signature.length).toBeGreaterThan(40);

      const self = await authenticate(ORIGIN, `flowsta-auth-challenge:v1:n0nce:${DESKTOP}`);
      console.log(`e2e: own client -> ${self.status}`);
      expect(self.status).toBe(200);

      const other = await authenticate(ORIGIN, "flowsta-auth-challenge:v1:n0nce:someone_elses_app");
      console.log(`e2e: another app's client -> ${other.status} ${other.data?.error}`);
      expect(other.status).toBe(400);
      expect(other.data?.error).toBe("reserved_prefix");

      const stranger = await authenticate("yoai://not-linked", `flowsta-auth-challenge:v1:n0nce:${WEB}`);
      console.log(`e2e: unlinked origin -> ${stranger.status} ${stranger.data?.error}`);
      expect(stranger.status).toBe(400);
      expect(stranger.data?.error).toBe("reserved_prefix");

      const plain = await authenticate(ORIGIN, "a-plain-random-challenge-for-the-apps-own-proxy");
      console.log(`e2e: plain challenge -> ${plain.status}`);
      expect(plain.status).toBe(200);
    } finally {
      await devOp(PORT_A, { op: "disconnect", client_id: DESKTOP });
    }
  });
});
