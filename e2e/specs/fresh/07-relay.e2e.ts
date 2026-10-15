// A sign-in handed over from a browser (Safari, Brave, a phone) through
// flowsta://relay/v1?code=: the Vault, already open and unlocked, must show
// the approval for it at once - never just come forward with nothing to act
// on (Eric's Mac, 2026-10-15: the Vault covered the page that showed the
// code, and nothing in the Vault said a sign-in was waiting).
import { byId, click, fill, PASSWORD, PORT_A, devOp, vault } from "../_helpers";

const API = "https://auth-api-staging.flowsta.com";
const shown = async (id: string) => (await byId(id)).isDisplayed().catch(() => false);

async function startRelay() {
  const r = await fetch(`${API}/auth/relay/start`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  const d = (await r.json()) as any;
  expect(typeof d.user_code).toBe("string");
  return d as { user_code: string; relay_id?: string; poll_token?: string };
}

describe("relay sign-in by deep link", () => {
  before(async function () {
    this.timeout(400_000);
    const status = (await vault(PORT_A, "/status")).data || {};
    if (!status.unlocked) {
      await (await byId("unlock-password")).waitForDisplayed({ timeout: 90_000 });
      const row = await $('[data-testid="identity-row"]');
      if (await row.isExisting()) await row.click();
      await fill('[data-testid="unlock-password"]', PASSWORD);
      await click("unlock-submit");
      await (await byId("devices-chip")).waitForDisplayed({ timeout: 300_000 });
    }
  });

  it("an open, unlocked Vault shows the approval when the link arrives", async function () {
    this.timeout(120_000);
    const relay = await startRelay();
    const code = relay.user_code.replace(/[^A-Za-z]/g, "");
    console.log(`e2e: relay started, code ${relay.user_code}`);
    await devOp(PORT_A, { op: "open_url", url: `flowsta://relay/v1?code=${code}` });
    await browser.waitUntil(async () => (await shown("relay-dialog")) || (await shown("relay-code-modal")), {
      timeout: 30_000,
      timeoutMsg: "the Vault received the relay link and showed nothing to act on",
    });
    expect(await shown("relay-code-modal")).toBe(false);
    console.log("e2e: relay approval shown from the deep link");
    await click("relay-deny");
    await browser.waitUntil(async () => !(await shown("relay-dialog")), { timeout: 15_000 });
  });

  it("a second link while the first is unanswered still shows one approval", async function () {
    this.timeout(120_000);
    const first = await startRelay();
    await devOp(PORT_A, { op: "open_url", url: `flowsta://relay/v1?code=${first.user_code.replace(/[^A-Za-z]/g, "")}` });
    await browser.waitUntil(() => shown("relay-dialog"), { timeout: 30_000, timeoutMsg: "first relay link showed nothing" });
    const second = await startRelay();
    await devOp(PORT_A, { op: "open_url", url: `flowsta://relay/v1?code=${second.user_code.replace(/[^A-Za-z]/g, "")}` });
    await browser.pause(5_000);
    expect(await shown("relay-dialog")).toBe(true);
    await click("relay-deny");
    console.log("e2e: second link while the first was open handled");
  });

  it("a link that arrives while locked shows its approval after unlock", async function () {
    this.timeout(400_000);
    await click("lock-vault");
    await (await byId("unlock-password")).waitForDisplayed({ timeout: 60_000 });
    const relay = await startRelay();
    await devOp(PORT_A, { op: "open_url", url: `flowsta://relay/v1?code=${relay.user_code.replace(/[^A-Za-z]/g, "")}` });
    await browser.pause(2_000);
    const row = await $('[data-testid="identity-row"]');
    if (await row.isExisting()) await row.click();
    await fill('[data-testid="unlock-password"]', PASSWORD);
    await click("unlock-submit");
    await browser.waitUntil(() => shown("relay-dialog"), { timeout: 180_000, timeoutMsg: "a relay link that arrived while locked showed nothing after unlock" });
    console.log("e2e: relay link from while locked shown after unlock");
    await click("relay-deny");
    await (await byId("devices-chip")).waitForDisplayed({ timeout: 300_000 });
  });
});
