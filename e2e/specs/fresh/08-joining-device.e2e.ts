// The identity made in 01, restored from its phrase on a second device - and
// this time the SECOND device's own window is watched (its e2e build serves
// WebDriver too). What a person sees on a device restored from the phrase:
// the one question only they can answer (is this identity on another device
// you still have?), then a card that says only what this device knows
// (looking, the device the things are on, or progress), gone as soon as the
// device holds what the other one said it holds, and no question about the
// email, which comes over with the profile. Both 10-27 findings lived here
// (a card that never left; a card that stayed ten minutes after the bars
// were full), and the 11-18 one: ten quiet minutes ended setup and the
// device said it had everything.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { activateSecondWindow, API, byId, click, copyProblemsIn, fill, PASSWORD, PHRASE_FILE, PORT_A, PORT_B, secondWindow, shot, startSecondDevice, stopSecondDevice, vault, COLD_START_MS, timed } from "../_helpers";
import { SHOTS } from "../../wdio.conf";

const problems: string[] = [];
let b: WebdriverIO.Browser | null = null;
let bShot = 0;
const textOfB = async () => (await b!.execute(() => document.body.innerText)) as string;
const noteB = async (where: string) => { problems.push(...copyProblemsIn(await textOfB(), where)); };
const shotB = (name: string) => b!.saveScreenshot(resolve(SHOTS, `b-${String(++bShot).padStart(2, "0")}-${name}.png`));
const existsOnB = async (id: string) => (await b!.$(`[data-testid="${id}"]`)).isExisting();
const nudgeB = () => b!.execute(() => { document.dispatchEvent(new MouseEvent("mousemove", { bubbles: true })); });
const setupOf = async (port: number) => ((await vault(port, "/dev/status")).data?.setup || {}) as { joined?: boolean; pending?: boolean };

describe("the device being added, in its own window", () => {
  after(async () => { try { await b?.deleteSession(); } catch { /* gone */ } stopSecondDevice(); });

  it("the first device opens locked and the password unlocks it", async () => {
    await (await byId("unlock-password")).waitForDisplayed({ timeout: 90_000 });
    await fill('[data-testid="unlock-password"]', PASSWORD);
    await click("unlock-submit");
    await (await byId("devices-chip")).waitForDisplayed({ timeout: 120_000 });
    const setup = await setupOf(PORT_A);
    expect(setup.joined).toBe(false);
    expect(setup.pending).toBe(false);
    expect(await (await byId("setup-card")).isExisting()).toBe(false);
  });

  it("a second device restores the identity from its phrase", async () => {
    const phrase = readFileSync(PHRASE_FILE, "utf8").trim();
    expect(phrase.split(/\s+/).length).toBe(24);
    await startSecondDevice(resolve(import.meta.dirname ?? ".", "..", "..", "profile", "c"));
    const restored = await vault(PORT_B, "/dev/setup-identity", { api_url: API, password: PASSWORD, phrase, restore: true });
    expect(restored.status).toBe(200);
    expect(restored.data?.restored).toBe(true);
    // Being set up from the first moment: the card's rule.
    expect(await setupOf(PORT_B)).toEqual({ joined: true, pending: true });
  });

  it("its window asks whether the identity is on another device, and Yes starts the wait", async () => {
    b = await secondWindow();
    activateSecondWindow();
    // The window was opened on the welcome screen before the restore; the
    // identity is unlocked now, so the front page is the Overview (or the
    // unlock screen, if the window had locked itself meanwhile).
    await b.execute(() => location.assign("/"));
    await b.waitUntil(async () => (await existsOnB("setup-card")) || (await existsOnB("unlock-password")), { timeout: 120_000, timeoutMsg: "the second device's window showed neither the card nor the unlock screen" });
    if (await existsOnB("unlock-password")) {
      await (await b.$('[data-testid="unlock-password"]')).setValue(PASSWORD);
      await (await b.$('[data-testid="unlock-submit"]')).click();
      await (await b.$('[data-testid="setup-card"]')).waitForDisplayed({ timeout: 120_000 });
    }
    // The restore went through the test door, so the wizard's question was
    // not answered: the Overview asks it, once.
    await b.waitUntil(async () => existsOnB("other-device-yes"), { timeout: 60_000, timeoutMsg: "the card did not ask whether the identity is on another device" });
    await shotB("asks");
    const asks = await (await b.$('[data-testid="setup-card"]')).getText();
    expect(asks).toMatch(/Do you have Flowsta Vault on another device with this identity\?/);
    expect(asks).toMatch(/Not sure\? Choose Yes\./);
    expect(await existsOnB("continue-without")).toBe(false);
    expect(await existsOnB("email-callout")).toBe(false);
    await noteB("the question");
    await (await b.$('[data-testid="other-device-yes"]')).click();
    await b.waitUntil(async () => !(await existsOnB("other-device-yes")), { timeout: 30_000, timeoutMsg: "the question stayed after Yes" });
    // The card's title follows a moment after its body (its own redraw).
    await b.waitUntil(async () => !(await existsOnB("setup-card")) || !/Do you have Flowsta Vault on another device/.test(await (await b!.$('[data-testid="setup-card"]')).getText()), { timeout: 15_000, timeoutMsg: "the card kept the question as its title after Yes" });
    // Still being set up, by the person's word: no timer ends it.
    expect(await setupOf(PORT_B)).toEqual({ joined: true, pending: true });
    if (await existsOnB("setup-card")) {
      const card = await (await b.$('[data-testid="setup-card"]')).getText();
      expect(card).toMatch(/Looking for your other devices|Your things are on |Your private data is on its way/);
      expect(card).not.toMatch(/No other device has answered|Nothing to do|can stay locked/);
    }
    await shotB("after-yes");
    expect(await existsOnB("email-callout")).toBe(false);
    await noteB("after yes");
  });

  it("while it waits, the other device is named as online or its progress shows - never as offline", async () => {
    // The suite's own hook brings the FIRST window up before each test; this
    // one draws only while it is active.
    activateSecondWindow();
    // A few looks over the first minute: whatever the card shows, it must
    // never read as if the first device were offline or unreachable.
    const deadline = Date.now() + 90_000;
    let sawProgress = false;
    while (Date.now() < deadline) {
      if (!(await existsOnB("setup-card"))) break; // already done - fine
      const card = await (await b!.$('[data-testid="setup-card"]')).getText();
      expect(card).not.toMatch(/Waiting for|a moment ago|offline|unreachable|No other device has answered|Nothing to do/);
      expect(card).toMatch(/Looking for your other devices|Your things are on |Your private data is on its way/);
      if (await existsOnB("setup-progress")) {
        sawProgress = true;
        const progress = await (await b!.$('[data-testid="setup-progress"]')).getText();
        expect(progress).toMatch(/Records|App backups/);
      }
      await nudgeB();
      await b!.pause(5_000);
    }
    if (sawProgress) await shotB("progress");
    await noteB("while waiting");
  });

  it("the card leaves as soon as the device has everything, and the email came with the profile", async () => {
    activateSecondWindow();
    // The round writes its marker once the other device's records are
    // matched (its profile record counted in). The card follows within a
    // poll (30 s) or at once on the event.
    await timed("the second device has everything", async () =>
      b!.waitUntil(async () => { await nudgeB(); return (await setupOf(PORT_B)).pending === false; }, { timeout: COLD_START_MS, interval: 5_000, timeoutMsg: "the second device never finished being set up" }));
    await b!.waitUntil(async () => !(await existsOnB("setup-card")), { timeout: 60_000, interval: 2_000, timeoutMsg: "the device has everything but the card is still up" });
    await shotB("card-gone");
    // The first device holds the email (the wizard asked for it) and wrote
    // the identity's profile record; this device applied it before it said
    // it has everything, so nothing asks for the email now or a minute on.
    expect(await existsOnB("email-callout")).toBe(false);
    await b!.pause(45_000);
    expect(await existsOnB("email-callout")).toBe(false);
    expect(await existsOnB("setup-card")).toBe(false);
    const st = await vault(PORT_B, "/status");
    expect(st.data?.unlocked).toBe(true);
    await shotB("settled");
    await noteB("settled");
  });

  it("the first device never showed the card", async () => {
    expect(await setupOf(PORT_A)).toEqual({ joined: false, pending: false });
    expect(await (await byId("setup-card")).isExisting()).toBe(false);
    await shot("first-device-after-join");
  });

  it("no screen showed wording the app must never show", async () => {
    expect(problems).toEqual([]);
  });
});
