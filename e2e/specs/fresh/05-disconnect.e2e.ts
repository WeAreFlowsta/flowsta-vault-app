// Disconnect asks once, in place (build-docs VAULT_CONNECTION_UX.md fix 10):
// the Connections row says what happens and offers Cancel / Disconnect; no
// browser confirm(). Cancel keeps the app; Disconnect removes it.
import { byId, click, fill, PASSWORD, PORT_A, devOp, vault } from "../_helpers";

const CLIENT = "disconnect_test_app";
const APP_NAME = "Disconnect test";

describe("Connections: Disconnect asks in place", () => {
  it("shows the ask, Cancel keeps the app, Disconnect removes it", async function () {
    this.timeout(300_000);
    const status = (await vault(PORT_A, "/status")).data || {};
    if (!status.unlocked) {
      await (await byId("unlock-password")).waitForDisplayed({ timeout: 90_000 });
      const row = await $('[data-testid="identity-row"]');
      if (await row.isExisting()) await row.click();
      await fill('[data-testid="unlock-password"]', PASSWORD);
      await click("unlock-submit");
      await (await byId("devices-chip")).waitForDisplayed({ timeout: 300_000 });
    }
    const linked = await devOp(PORT_A, { op: "connect", client_id: CLIENT, app_name: APP_NAME, origin: "yoai://disconnect-test" });
    expect(linked.connected).toBe(true);
    try {
      const link = await $('a[href="/identities/"]');
      await link.waitForDisplayed({ timeout: 30_000 });
      await link.click();
      await browser.waitUntil(async () => (await browser.execute(() => location.pathname)) === "/identities/", { timeout: 30_000 });
      const card = await $(`[data-testid="linked-app"][data-app-name="${APP_NAME}"]`);
      await card.waitForDisplayed({ timeout: 60_000 });
      await (await card.$('[data-testid="disconnect-app"]')).click();
      const ask = await card.$('[data-testid="disconnect-confirm"]');
      await ask.waitForDisplayed({ timeout: 10_000 });
      expect(await ask.getText()).toContain(`Disconnect ${APP_NAME}? It is signed out on every device.`);
      await (await card.$('[data-testid="disconnect-app-cancel"]')).click();
      await browser.waitUntil(async () => !(await (await card.$('[data-testid="disconnect-confirm"]')).isExisting()), { timeout: 10_000 });
      expect(await card.isDisplayed()).toBe(true);
      console.log("e2e: disconnect ask shown; Cancel kept the app");
      await (await card.$('[data-testid="disconnect-app"]')).click();
      await (await card.$('[data-testid="disconnect-app-confirm"]')).waitForDisplayed({ timeout: 10_000 });
      await (await card.$('[data-testid="disconnect-app-confirm"]')).click();
      await browser.waitUntil(async () => !(await (await $(`[data-testid="linked-app"][data-app-name="${APP_NAME}"]`)).isExisting()), { timeout: 30_000, timeoutMsg: "the app is still listed after Disconnect" });
      console.log("e2e: Disconnect removed the app");
    } finally {
      await devOp(PORT_A, { op: "disconnect", client_id: CLIENT }).catch(() => null);
    }
  });
});
