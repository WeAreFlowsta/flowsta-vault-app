// An install that runs as the identity's own key while another install does
// too (both set up from the phrase before a device had a key of its own):
// the Overview says the two are not syncing and offers to set this one up.
// The notice is shown here through the harness door (the real signal needs
// two installs and a quarter hour: `scripts/matrix-same-key.sh`); the
// button then does the real thing to the identity made in 01, whose first
// device runs as the identity's key.
import { byId, click, copyProblems, devOp, fill, PASSWORD, PORT_A, shot, COLD_START_MS, timed, waitAwake } from "../_helpers";

const problems: string[] = [];
const note = async (where: string) => { problems.push(...(await copyProblems(where))); };

describe("two installs on one key", () => {
  after(async () => { await devOp(PORT_A, { op: "same-key", force: false, told: false }); });

  it("the Vault unlocks and says nothing while no other install is seen", async () => {
    await (await byId("unlock-password")).waitForDisplayed({ timeout: 90_000 });
    await fill('[data-testid="unlock-password"]', PASSWORD);
    await click("unlock-submit");
    await (await byId("devices-chip")).waitForDisplayed({ timeout: 120_000 });
    expect(await (await byId("same-key-callout")).isExisting()).toBe(false);
  });

  let ownBefore: unknown;
  it("another install seen on this key: the Overview says so, with one thing to do", async () => {
    ownBefore = (await devOp(PORT_A, { op: "status" })).own_conductor_key;
    await devOp(PORT_A, { op: "same-key", force: true });
    // The page asks every half minute.
    await (await byId("same-key-callout")).waitForDisplayed({ timeout: 60_000 });
    await (await byId("same-key-go")).waitForDisplayed({ timeout: 10_000 });
    await shot("k-not-syncing");
    await note("same-key notice");
    expect(await (await byId("same-key-phrase")).isExisting()).toBe(false);
  });

  it("told by the other install instead: the notice asks for the same step in its own words", async () => {
    await devOp(PORT_A, { op: "same-key", force: false, told: true });
    await (await byId("same-key-second")).waitForDisplayed({ timeout: 60_000 });
    await shot("k-one-more-step");
    await note("same-key second install");
    await devOp(PORT_A, { op: "same-key", force: true, told: false });
    await browser.waitUntil(async () => !(await (await byId("same-key-second")).isExisting()), { timeout: 60_000 });
  });

  it("the button sets this device up, says it is working, and then says it is done", async function () {
    if (ownBefore !== false) {
      // An earlier spec already gave this install a key of its own.
      this.skip();
    }
    // Its cells must answer first (this file restarted the app).
    await timed("cells answer", () => waitAwake(async () => (await devOp(PORT_A, { op: "notes" })).notes !== undefined, { timeout: COLD_START_MS, interval: 10_000 }));
    await click("same-key-go");
    await (await byId("same-key-busy")).waitForDisplayed({ timeout: 15_000 });
    await shot("k-working");
    await note("same-key working");
    await timed("this device is set up to sync", () => waitAwake(async () => (await byId("same-key-done")).isDisplayed(), { timeout: COLD_START_MS, interval: 5_000 }));
    await shot("k-done");
    await note("same-key done");
    expect(await (await byId("same-key-note")).isExisting()).toBe(false);
    expect(await (await byId("same-key-callout")).isExisting()).toBe(false);
    expect((await devOp(PORT_A, { op: "status" })).own_conductor_key).toBe(true);
  });

  it("the wording holds", () => {
    expect(problems).toEqual([]);
  });
});
