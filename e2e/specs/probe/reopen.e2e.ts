// Diagnostic, not a gate: reopen an identity the fresh run left behind and
// watch whether its cells come up. Run with VAULT_E2E_KEEP_PROFILE=1.
import { byId, click, fill, PASSWORD, shot, visibleText } from "../_helpers";

const NAME = process.env.VAULT_E2E_IDENTITY || "UI Journey";
const WAIT_S = Number(process.env.VAULT_E2E_PROBE_WAIT || 240);

describe("probe: reopen an identity", () => {
  it(`unlocks ${NAME} and waits ${WAIT_S}s for its devices`, async () => {
    await (await byId("unlock-password")).waitForDisplayed({ timeout: 90_000 });
    const row = await $(`[data-testid="identity-row"][data-name="${NAME}"]`);
    await row.waitForDisplayed({ timeout: 30_000 });
    await row.click();
    await fill('[data-testid="unlock-password"]', PASSWORD);
    await click("unlock-submit");
    const chip = await byId("devices-chip");
    await chip.waitForDisplayed({ timeout: 300_000 });
    const t0 = Date.now();
    let last = "";
    while (Date.now() - t0 < WAIT_S * 1000) {
      const now = await chip.getText();
      if (now !== last) { console.log(`[probe] +${Math.round((Date.now() - t0) / 1000)}s chip: ${now}`); last = now; }
      await browser.pause(5_000);
    }
    await shot("probe-end");
    console.log(`[probe] end: ${(await visibleText()).slice(0, 300)}`);
  });
});
