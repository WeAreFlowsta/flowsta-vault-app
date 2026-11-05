// The update panel and the message stack (Restart to update),
// shown without a real update: the spec sends the events the updater sends
// ("update-ready", then each "update-stage") and saves a screenshot of each
// step for a person to look at. "failed" is set by the button when the install
// does not happen; sending it as a stage shows the same panel. The button is
// never pressed, so nothing installs.
import { byId, click, fill, PASSWORD, PORT_A, shot, vault } from "../_helpers";

const emit = (event: string, payload: unknown) =>
  browser.execute(
    (e: string, p: unknown) => (window as any).__TAURI_INTERNALS__.invoke("plugin:event|emit", { event: e, payload: p }),
    event,
    payload,
  );

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

describe("the update panel", () => {
  before(async function () {
    this.timeout(400_000);
    await ensureUnlocked();
  });

  it("shows each step of Restart to update in the message stack", async () => {
    await emit("update-ready", {
      version: "1.8.0-beta5",
      notes_url: "https://github.com/WeAreFlowsta/flowsta-vault-app/releases",
      changes_line: false,
      asks_password: true,
    });
    const button = await byId("update-button");
    await button.waitForDisplayed({ timeout: 10_000 });
    expect(await button.getAttribute("title")).toContain("then closes and opens the Vault again");
    await shot("update-ready");
    for (const stage of ["password", "installing", "restarting", "failed"]) {
      await emit("update-stage", stage);
      await (await byId("update-panel")).waitForDisplayed({ timeout: 10_000 });
      await browser.pause(500);
      await shot(`update-${stage}`);
    }
  });
});
