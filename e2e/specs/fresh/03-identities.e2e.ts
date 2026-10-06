// Two identities in one Vault. The first (made in 01, on two devices, with
// two signatures) and a second made here. Whatever one holds, the other
// must never show: not its signatures, not its devices, not its name.
import { byId, click, COLD_START_MS, copyProblems, createIdentityInWizard, fill, PASSWORD, shot, timed, visibleText, waitAwake } from "../_helpers";

const problems: string[] = [];
const note = async (where: string) => { problems.push(...(await copyProblems(where))); };
const goto = async (href: string) => {
  const link = await $(`a[href="${href}"]`);
  await link.waitForDisplayed({ timeout: 30_000 });
  await link.click();
  await browser.waitUntil(async () => (await browser.execute(() => location.pathname)) === href, { timeout: 30_000 });
};
const signatureCount = async () => {
  const count = await byId("signatures-count");
  await count.waitForDisplayed({ timeout: 60_000 });
  await timed("signature count settled", () =>
    waitAwake(async () => (await count.getAttribute("data-loaded")) === "1", { timeout: COLD_START_MS, interval: 3_000, timeoutMsg: "the signature count never finished loading" }));
  return (await count.getText()).trim();
};
const signatureRows = async () => (await $$('[data-testid="signature-row"]')).length;
/** From the lock screen: choose an identity by its name and unlock it. */
const unlockAs = async (name: string) => {
  await (await byId("unlock-password")).waitForDisplayed({ timeout: 90_000 });
  const row = await $(`[data-testid="identity-row"][data-name="${name}"]`);
  await row.waitForDisplayed({ timeout: 30_000 });
  await row.click();
  await fill('[data-testid="unlock-password"]', PASSWORD);
  await click("unlock-submit");
  await (await byId("devices-chip")).waitForDisplayed({ timeout: 300_000 });
};
/** What the second identity must look like, now and half a minute from now. */
const expectEmptySecond = async (where: string) => {
  await goto("/");
  expect(await signatureCount()).toBe("0");
  expect(await (await byId("devices-chip")).getText()).toBe("1 device");
  await shot(`i-${where}-overview`);
  await note(`${where} overview`);
  await goto("/sign-it/");
  await browser.pause(30_000); // late arrivals are the failure this looks for
  expect(await signatureRows()).toBe(0);
  await shot(`i-${where}-sign-it`);
  await goto("/");
  expect(await signatureCount()).toBe("0");
  await click("devices-chip");
  await browser.waitUntil(async () => (await visibleText()).includes("This device"), { timeout: 120_000, timeoutMsg: "the Devices tab never listed this device" });
  expect(await visibleText()).not.toMatch(/Up to date|Has everything up to|Not seen since|Waiting for/);
  await shot(`i-${where}-devices`);
};

describe("two identities in one Vault", () => {
  it("a second identity is made from the lock screen", async () => {
    await (await byId("unlock-password")).waitForDisplayed({ timeout: 90_000 });
    await shot("i-locked");
    await click("identity-add");
    await (await byId("wizard-welcome")).waitForDisplayed({ timeout: 60_000 });
    await note("add another identity");
    await createIdentityInWizard("UI Second", `ui-second-${Date.now()}@example.com`);
    await click("wizard-finish");
    await (await byId("devices-chip")).waitForDisplayed({ timeout: 120_000 });
  });

  it("the second identity shows none of the first's signatures or devices", async () => {
    expect(await visibleText()).toContain("UI Second");
    await expectEmptySecond("second-new");
  });

  it("switching back, the first identity shows its own two signatures and two devices", async () => {
    await click("lock-vault");
    await unlockAs("UI Journey");
    await goto("/");
    expect(await visibleText()).toContain("UI Journey");
    expect(await (await byId("devices-chip")).getText()).toBe("2 devices");
    await shot("i-first-first-paint");
    expect(await signatureCount()).toBe("2");
    await goto("/sign-it/");
    await waitAwake(async () => (await signatureRows()) === 2, { timeout: COLD_START_MS, interval: 3_000, timeoutMsg: "the first identity's Sign It never listed its two signatures" });
    await shot("i-first-sign-it");
    await note("first identity after switching back");
  });

  it("switching again, the second identity still shows none of them", async () => {
    await click("lock-vault");
    await unlockAs("UI Second");
    expect(await visibleText()).toContain("UI Second");
    await expectEmptySecond("second-again");
  });

  it("no screen showed wording the app must never show", async () => {
    if (problems.length) console.log("WORDING PROBLEMS:\n  " + [...new Set(problems)].join("\n  "));
    expect([...new Set(problems)]).toEqual([]);
  });
});
