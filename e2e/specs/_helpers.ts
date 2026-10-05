// Shared helpers for the UI specs.
import { resolve } from "node:path";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { SHOTS } from "../wdio.conf";

let step = 0;
/** A numbered picture of the window as it is now. */
export const shot = (name: string) => browser.saveScreenshot(resolve(SHOTS, `${String(++step).padStart(2, "0")}-${name}.png`));

export const byId = (id: string) => $(`[data-testid="${id}"]`);

/** Type into an input the way a person's typing reaches the page: set the
 *  value and send the input event the front end listens for. */
export async function fill(selector: string, text: string) {
  const el = await $(selector);
  await el.waitForDisplayed({ timeout: 30_000 });
  await browser.execute((sel: string, t: string) => {
    const input = document.querySelector(sel) as HTMLInputElement;
    const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), "value")?.set;
    input.focus();
    setter ? setter.call(input, t) : (input.value = t);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }, selector, text);
}

export async function click(id: string, timeout = 30_000) {
  const el = await byId(id);
  await el.waitForDisplayed({ timeout });
  await el.waitForEnabled({ timeout });
  await el.click();
}

/** Everything a person can read in the window right now. */
export const visibleText = () => browser.execute(() => document.body.innerText);

/** Wording the app must never show (the list grows with what testing finds). */
const BANNED: [RegExp, string][] = [
  [/\bcomputer\b/i, 'says "computer" (the word is "device")'],
  [/\bhandle\b/i, 'says "handle" (the word is "username")'],
  [/web sign-in/i, 'says "web sign-in"'],
  [/—/, "has an em dash"],
  [/\b1 devices\b/, 'says "1 devices"'],
  [/\b[a-z]+(?:_[a-z]+){1,}\b(?: \[\d{3}\])?/, "shows a raw code"],
  [/\[\d{3}\]/, "shows an HTTP status"],
  [/undefined|NaN|\[object Object\]/, "shows a programming leftover"],
];

/** The wording problems on the screen as it is now, each with where it was seen. */
export async function copyProblems(where: string): Promise<string[]> {
  const text = await visibleText();
  return BANNED.filter(([re]) => re.test(text)).map(([re, what]) => `${where}: ${what}: "${(text.match(re) || [""])[0]}"`);
}

/** Anything still spinning or still saying it is loading. */
export const stillBusy = () =>
  browser.execute(() => {
    const spinning = [...document.querySelectorAll(".animate-spin")].filter((e) => (e as HTMLElement).offsetParent !== null).length;
    const words = (document.body.innerText.match(/\b(Loading|Syncing|Starting|Preparing|One moment)[^\n]{0,60}/g) || []);
    return { spinning, words };
  });

// ── A second device, and the doors the harness uses without a window ──


/** The test identity's Vault password (the same in every spec of a run). */
export const PASSWORD = "Ui-journey-password-1!";
const ORIGIN = "https://ourtest.flowsta.com";
/** The window's Vault answers on the first port; a second device on the next. */
export const PORT_A = 27777;
export const PORT_B = 27778;
const TINY_PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';

export async function vault(port: number, path: string, body?: unknown) {
  const resp = await fetch(`http://127.0.0.1:${port}${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json", origin: ORIGIN },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: resp.status, data: (await resp.json().catch(() => null)) as any };
}
export const devOp = async (port: number, body: Record<string, unknown>) => (await vault(port, "/dev/devices", body)).data || {};

export const randomHash = () => randomBytes(32).toString("hex");

/** Sign a file the way a Flowsta page asks for it; returns the finished job. */
export async function signOn(port: number, fileHash: string) {
  const sub = await vault(port, "/sign-document", { file_hash: fileHash, label: "ui-test.txt", app_name: "UI tests", comment: "automated UI run", thumbnail: TINY_PNG, commit: true, job: true });
  if (sub.status !== 200 || !sub.data?.job_id) return { stage: "failed", error: `${sub.status} ${JSON.stringify(sub.data)}` };
  const deadline = Date.now() + 300_000;
  let last: any = {};
  while (Date.now() < deadline) {
    last = (await vault(port, `/op-status/${sub.data.job_id}`)).data || {};
    if (last.stage === "done" || last.stage === "failed") break;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return last;
}

let second: ChildProcess | null = null;
/** Start a second copy of the test build on its own data folder: device B. */
export async function startSecondDevice(dataDir: string) {
  second = spawn(resolve(import.meta.dirname ?? ".", "..", "launch-app.sh"), [], {
    env: { ...process.env, VAULT_E2E_DATA_DIR: dataDir, TAURI_WEBDRIVER_PORT: "4470" },
    stdio: "ignore",
    detached: true,
  });
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    const st = await vault(PORT_B, "/status").catch(() => null);
    if (st?.status === 200) return;
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error("the second device never answered on its port");
}
/** Stop device B: every copy of the test build that listens on B's port. */
export function stopSecondDevice() {
  try {
    const out = execFileSync("ss", ["-ltnpH", "sport", "=", `:${PORT_B}`], { encoding: "utf8" });
    for (const m of out.matchAll(/pid=(\d+)/g)) {
      const pid = Number(m[1]);
      try { process.kill(pid, "SIGTERM"); } catch { /* gone */ }
      execFileSync("sleep", ["3"]);
      try { process.kill(pid, 0); process.kill(pid, "SIGKILL"); } catch { /* it left */ }
    }
  } catch { /* nothing listening */ }
  second = null;
}
