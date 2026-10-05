// The identity made in 01, on two devices. The window is the device the
// person already has; the new device is a second copy of the app with no
// window in front, driven through the harness doors. What is checked is
// what the person SEES on the first device while the second one joins,
// signs, and while this one locks.
import { resolve } from "node:path";
import { byId, click, copyProblems, devOp, fill, PASSWORD, PORT_A, PORT_B, randomHash, shot, signOn, startSecondDevice, stillBusy, stopSecondDevice, vault, visibleText } from "../_helpers";

const problems: string[] = [];
const note = async (where: string) => { problems.push(...(await copyProblems(where))); };
const chipText = async () => (await byId("devices-chip")).getText();
const goto = async (href: string) => {
  const link = await $(`a[href="${href}"]`);
  await link.waitForDisplayed({ timeout: 30_000 });
  await link.click();
  await browser.waitUntil(async () => (await browser.execute(() => location.pathname)) === href, { timeout: 30_000 });
};

describe("a second device", () => {
  after(() => stopSecondDevice());

  it("the Vault opens locked and the password unlocks it", async () => {
    await (await byId("unlock-password")).waitForDisplayed({ timeout: 90_000 });
    await shot("d-locked");
    await note("unlock screen");
    await fill('[data-testid="unlock-password"]', PASSWORD);
    await click("unlock-submit");
    await (await byId("devices-chip")).waitForDisplayed({ timeout: 120_000 });
    expect(await chipText()).toBe("1 device");
  });

  let code = "";
  it("the new device shows a code", async () => {
    await startSecondDevice(resolve(import.meta.dirname ?? ".", "..", "..", "profile", "b"));
    code = (await devOp(PORT_B, { op: "pair-begin", password: PASSWORD })).code || "";
    expect(code).toMatch(/^[A-Z]{4}-[A-Z]{4}-[A-Z]{4}$/);
  });

  it("typing the code here names the new device and asks before adding it", async () => {
    await click("devices-chip");
    await click("device-add");
    await shot("d-add-a-device");
    await note("add a device");
    await fill('[data-testid="device-code"]', code);
    await click("device-code-submit");
    await (await byId("device-approve")).waitForDisplayed({ timeout: 90_000 });
    await shot("d-approve");
    await note("approve dialog");
  });

  it("after approving, this device says what is happening until there are two", async () => {
    await click("device-approve");
    // Between the approval and the new device's first record, the page must
    // say it is waiting - never look finished and never look broken.
    await browser.pause(4_000);
    await shot("d-just-approved");
    await note("just approved");
    await browser.waitUntil(async () => (await chipText()) === "2 devices", { timeout: 420_000, interval: 5_000, timeoutMsg: `never reached 2 devices; the chip says "${await chipText()}"` });
    await shot("d-two-devices");
    await browser.waitUntil(async () => !/Waiting for .* to start/.test(await visibleText()), { timeout: 120_000, timeoutMsg: 'still says "Waiting for ... to start" although both devices are listed' });
    await note("two devices");
    // The new device learns of this one a little after this one learns of it.
    await browser.waitUntil(async () => ((await devOp(PORT_B, { op: "list" })).devices || []).length === 2, { timeout: 240_000, interval: 5_000, timeoutMsg: "the new device never listed both devices" });
  });

  const hashHere = randomHash();
  const hashThere = randomHash();
  it("a file signed on either device is counted and listed here, and nothing else is", async () => {
    // Signing here raises the real approval dialog in this window: approve it there.
    const signing = signOn(PORT_A, hashHere);
    const approve = await byId("sign-approve");
    await approve.waitForDisplayed({ timeout: 60_000 });
    await shot("d-sign-dialog");
    await note("sign dialog");
    await approve.click();
    const here = await signing;
    expect(here.stage).toBe("done");
    await approve.waitForDisplayed({ timeout: 30_000, reverse: true, timeoutMsg: "the sign dialog stayed on screen after it was answered" });
    const there = await signOn(PORT_B, hashThere);
    expect(there.stage).toBe("done");
    await goto("/");
    const count = await byId("signatures-count");
    await browser.waitUntil(async () => (await count.getAttribute("data-loaded")) === "1" && (await count.getText()).trim() === "2", {
      timeout: 420_000, interval: 5_000,
      timeoutMsg: `the Overview never showed 2 signatures; it shows "${await count.getText()}"`,
    });
    await shot("d-overview-two-signatures");
    await note("overview with signatures");
    await goto("/sign-it/");
    await browser.waitUntil(async () => (await $$('[data-testid="signature-row"]')).length === 2, { timeout: 180_000, interval: 3_000, timeoutMsg: "Sign It never listed exactly two signatures" });
    const hashes: string[] = await browser.execute(() => [...document.querySelectorAll('[data-testid="signature-row"]')].map((e) => (e as HTMLElement).dataset.fileHash || ""));
    expect(hashes.sort()).toEqual([hashHere, hashThere].sort());
    await shot("d-sign-it-two-signatures");
    await note("sign it with signatures");
  });

  it("locking says it is still syncing, and unlocking comes straight back", async () => {
    await click("lock-vault");
    await (await byId("unlock-password")).waitForDisplayed({ timeout: 60_000 });
    await browser.waitUntil(async () => /still syncing/i.test(await visibleText()), { timeout: 30_000, timeoutMsg: "the lock screen does not say the Vault is still syncing" });
    await shot("d-locked-still-syncing");
    await note("locked, still syncing");
    const lockedStatus = await devOp(PORT_A, { op: "status" });
    expect(lockedStatus.unlocked).toBe(false);
    expect(lockedStatus.syncing_while_locked).toBe(true);
    await fill('[data-testid="unlock-password"]', PASSWORD);
    await click("unlock-submit");
    const chip = await byId("devices-chip");
    await chip.waitForDisplayed({ timeout: 60_000 });
    await shot("d-unlocked-first-paint");
    await browser.waitUntil(async () => (await chipText()) === "2 devices", { timeout: 120_000, timeoutMsg: `after unlocking the chip says "${await chipText()}"` });
    await browser.waitUntil(async () => { const s = await stillBusy(); return s.spinning === 0 && s.words.length === 0; }, { timeout: 180_000, interval: 3_000, timeoutMsg: `still busy after unlock: ${JSON.stringify(await stillBusy())}` });
    await shot("d-unlocked-settled");
    await note("after unlock");
  });

  it("no screen showed wording the app must never show", async () => {
    if (problems.length) console.log("WORDING PROBLEMS:\n  " + [...new Set(problems)].join("\n  "));
    expect([...new Set(problems)]).toEqual([]);
  });
});
