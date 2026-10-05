// One person's first hour, through the real window: a fresh Vault, a new
// identity made in the wizard, then every page looked at for things that
// are stuck, asked twice, or worded wrongly. A picture is kept of each step.
import { byId, click, copyProblems, fill, PASSWORD, shot, stillBusy, visibleText } from "../_helpers";

const email = `ui-journey-${Date.now()}@example.com`;
const password = PASSWORD;
const problems: string[] = [];
const note = async (where: string) => { problems.push(...(await copyProblems(where))); };

describe("a new identity", () => {
  it("a fresh Vault opens on the welcome screen", async () => {
    await (await byId("wizard-welcome")).waitForDisplayed({ timeout: 90_000 });
    await shot("welcome");
    await note("welcome");
  });

  it("the details form takes an email, a name and a password", async () => {
    await click("wizard-create");
    await fill('[data-testid="create-email"]', email);
    await fill('[data-testid="create-email2"]', email);
    await fill('[data-testid="create-name"]', "UI Journey");
    await fill('[data-testid="create-password"]', password);
    await fill('[data-testid="create-password2"]', password);
    await shot("details");
    await note("details");
    await click("create-continue");
  });

  let words: string[] = [];
  it("shows a 24-word recovery phrase", async () => {
    await browser.waitUntil(async () => (await $$('[data-testid="phrase-word"]')).length === 24, { timeout: 60_000, timeoutMsg: "the phrase never appeared" });
    words = await browser.execute(() => [...document.querySelectorAll('[data-testid="phrase-word"]')].map((e) => (e as HTMLElement).innerText.trim()));
    expect(words.length).toBe(24);
    expect(words.every((w) => /^[a-z]+$/.test(w))).toBe(true);
    await note("phrase");
    // No picture here: the phrase is a secret even for a test identity.
  });

  it("checks the phrase was written down, then creates the identity", async () => {
    await click("phrase-saved");
    await browser.waitUntil(async () => (await $$('[data-testid="verify-word"]')).length > 0, { timeout: 30_000 });
    const asked: number[] = await browser.execute(() => [...document.querySelectorAll('[data-testid="verify-word"]')].map((e) => Number((e as HTMLElement).dataset.word)));
    for (const i of asked) await fill(`[data-testid="verify-word"][data-word="${i}"]`, words[i]);
    await shot("phrase-check");
    await note("phrase check");
    await click("create-finish");
    const done = await byId("wizard-done");
    // While it works, the screen must say what it is doing.
    await browser.waitUntil(async () => (await done.isDisplayed()) || (await visibleText()).length > 40, { timeout: 30_000 });
    await shot("creating");
    await note("creating");
    await done.waitForDisplayed({ timeout: 300_000, timeoutMsg: "the identity was not ready within 5 minutes" });
    await shot("ready");
    await note("ready");
  });

  it("lands on the Overview with one device and nothing stuck", async () => {
    await click("wizard-finish");
    const chip = await byId("devices-chip");
    await chip.waitForDisplayed({ timeout: 60_000 });
    await shot("overview-first-paint");
    expect(await chip.getText()).toBe("1 device");
    // Give the page its settling time, then nothing may still be spinning.
    await browser.waitUntil(async () => { const b = await stillBusy(); return b.spinning === 0 && b.words.length === 0; }, {
      timeout: 240_000, interval: 3_000,
      timeoutMsg: `still busy after 4 minutes: ${JSON.stringify(await stillBusy())}`,
    });
    await shot("overview-settled");
    await note("overview");
    const text = await visibleText();
    expect(text).toContain("UI Journey");
  });
});

describe("every page", () => {
  const pages: [string, string][] = [["sign-it", "/sign-it/"], ["connections", "/identities/"], ["your-data", "/your-data/"], ["activity", "/activity/"], ["settings", "/settings/"], ["overview", "/"]];
  for (const [name, href] of pages) {
    it(`${name}: opens, settles, and reads right`, async () => {
      const link = await $(`a[href="${href}"]`);
      await link.waitForDisplayed({ timeout: 30_000 });
      await link.click();
      await browser.waitUntil(async () => (await browser.execute(() => location.pathname)) === href, { timeout: 30_000, timeoutMsg: `never reached ${href}` });
      await shot(`${name}-first-paint`);
      await browser.waitUntil(async () => { const b = await stillBusy(); return b.spinning === 0 && b.words.length === 0; }, {
        timeout: 180_000, interval: 3_000,
        timeoutMsg: `${name} still busy after 3 minutes: ${JSON.stringify(await stillBusy())}`,
      });
      await shot(`${name}-settled`);
      await note(name);
      // The window must never offer the wizard to someone who has an identity.
      expect(await (await byId("wizard-welcome")).isExisting()).toBe(false);
    });
  }

  it("the Devices tab lists this device", async () => {
    await click("devices-chip");
    await browser.waitUntil(async () => (await visibleText()).includes("This device"), { timeout: 60_000, timeoutMsg: "the Devices tab never listed this device" });
    await shot("devices-tab");
    await note("devices tab");
    expect(await visibleText()).not.toMatch(/Waiting for .* to start/);
  });
});

describe("wording", () => {
  it("no screen showed wording the app must never show", async () => {
    if (problems.length) console.log("WORDING PROBLEMS:\n  " + [...new Set(problems)].join("\n  "));
    expect([...new Set(problems)]).toEqual([]);
  });
});
