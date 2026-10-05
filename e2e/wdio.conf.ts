// WebdriverIO against the REAL app (see e2e/README.md).
// `npm run e2e:build` builds the app with the `e2e` cargo feature (the
// embedded WebDriver server, never in a release build) against staging;
// `npm run e2e` wipes the scratch data folder and runs the specs.
// Screenshots land in e2e/shots.
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { SevereServiceError } from "webdriverio";

const here = resolve(import.meta.dirname ?? ".");
export const SHOTS = resolve(here, "shots");
const PROFILE = resolve(here, "profile");
const launcher = resolve(here, "launch-app.sh");

/**
 * The service ends the app between spec files but not its sidecars (the key
 * store and the conductor). Stop, by pid, every sidecar of the test build
 * whose parent is not a live test app.
 */
function reapSidecars() {
  if (process.platform === "win32") return;
  try {
    const bin = resolve(here, "..", "src-tauri", "binaries") + "/";
    const appBin = resolve(here, "..", "src-tauri", "target", "debug", "flowsta-vault");
    const rows = execFileSync("ps", ["-eo", "pid=,ppid=,args="], { encoding: "utf8" }).split("\n");
    const parsed = rows.map((r) => r.trim().match(/^(\d+)\s+(\d+)\s+(.*)$/)).filter(Boolean) as RegExpMatchArray[];
    const liveApps = new Set(parsed.filter((m) => m[3] === appBin || m[3].startsWith(appBin + " ")).map((m) => m[1]));
    for (const m of parsed) {
      const [, pid, ppid, args] = m;
      if (args.startsWith(bin) && !liveApps.has(ppid)) {
        try { process.kill(Number(pid), "SIGTERM"); console.log(`e2e: stopped a leftover sidecar ${pid}`); } catch { /* gone */ }
      }
    }
  } catch (e) {
    console.warn("e2e: sidecar check skipped:", (e as Error).message);
  }
}

/**
 * The launcher starts the app inside a session bus of its own, so ending the
 * launcher does not end the app. Stop, by pid, every running copy of the
 * TEST build (never an installed Vault: that is a different program) before
 * a run and after each session, or the next session drives the last one's
 * window.
 */
function stopTestApps() {
  if (process.platform === "win32") return;
  try {
    const appBin = resolve(here, "..", "src-tauri", "target", "debug", "flowsta-vault");
    const rows = execFileSync("ps", ["-eo", "pid=,args="], { encoding: "utf8" }).split("\n");
    for (const row of rows) {
      const m = row.trim().match(/^(\d+)\s+(.*)$/);
      if (m && (m[2] === appBin || m[2].startsWith(appBin + " "))) {
        const pid = Number(m[1]);
        try { process.kill(pid, "SIGTERM"); } catch { /* gone */ }
        execFileSync("sleep", ["3"]);
        // The test build does not always leave on the polite signal.
        try { process.kill(pid, 0); process.kill(pid, "SIGKILL"); } catch { /* it left */ }
        console.log(`e2e: stopped a running test app ${pid}`);
      }
    }
  } catch (e) {
    console.warn("e2e: test app check skipped:", (e as Error).message);
  }
}

/**
 * The window must be ACTIVE on the desktop, or the compositor withholds
 * frame callbacks: the webview then produces no frames and Qwik's visible
 * tasks never run. xdotool's activation is honored where the app's own
 * set_focus is not. Linux desktop only.
 */
function activateWindow() {
  if (process.platform !== "linux" || !process.env.DISPLAY) return;
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    try {
      const ids = execFileSync("xdotool", ["search", "--onlyvisible", "--name", "^Flowsta Vault$"], { encoding: "utf8", timeout: 5_000 }).trim().split("\n").filter(Boolean);
      if (ids.length) {
        execFileSync("xdotool", ["windowactivate", "--sync", ids[ids.length - 1]], { timeout: 10_000, stdio: "ignore" });
        return;
      }
    } catch { /* not mapped yet */ }
    execFileSync("sleep", ["1"]);
  }
  console.warn("e2e: could not activate the app window (no visible 'Flowsta Vault' window in 60 s)");
}

/** A locked screen gives the app no frames either: refuse to start on one,
 *  and hold off the idle lock while the run lasts. GNOME only. */
let idleInhibitor: ChildProcess | null = null;

function screenLocked(): boolean {
  if (process.platform !== "linux") return false;
  try {
    const out = execFileSync("gdbus", ["call", "--session", "--dest", "org.gnome.ScreenSaver", "--object-path", "/org/gnome/ScreenSaver", "--method", "org.gnome.ScreenSaver.GetActive"], { encoding: "utf8", timeout: 5_000 });
    return out.includes("true");
  } catch {
    return false;
  }
}

function holdIdleLock() {
  if (process.platform !== "linux") return;
  try {
    idleInhibitor = spawn("gnome-session-inhibit", ["--inhibit", "idle", "--reason", "Flowsta Vault UI tests", "sleep", "infinity"], { stdio: "ignore" });
    idleInhibitor.on("error", () => { idleInhibitor = null; });
  } catch { /* not GNOME */ }
}

export const config: WebdriverIO.Config = {
  runner: "local",
  specs: [`./specs/${process.env.VAULT_E2E_MODE || "fresh"}/**/*.e2e.ts`],
  maxInstances: 1,
  capabilities: [
    {
      browserName: "tauri",
      "tauri:options": { application: launcher },
    },
  ],
  services: [
    [
      "@wdio/tauri-service",
      {
        driverProvider: "embedded",
        appBinaryPath: launcher,
        captureBackendLogs: true,
        captureFrontendLogs: true,
        startTimeout: 120_000,
      },
    ],
  ],
  framework: "mocha",
  // A first start installs the networks; joining waits on another device.
  mochaOpts: { ui: "bdd", timeout: 600_000, bail: true },
  reporters: ["spec"],
  logLevel: "warn",
  waitforTimeout: 30_000,
  onPrepare() {
    if (screenLocked()) throw new SevereServiceError("e2e: the screen is locked - the app gets no frames while it is. Unlock it and run again.");
    holdIdleLock();
    stopTestApps();
    reapSidecars();
    rmSync(PROFILE, { recursive: true, force: true });
    rmSync(SHOTS, { recursive: true, force: true });
    mkdirSync(SHOTS, { recursive: true });
  },
  before: async function () {
    activateWindow();
  },
  beforeTest: async function () {
    activateWindow();
  },
  onComplete() {
    idleInhibitor?.kill();
  },
  afterSession() {
    stopTestApps();
    reapSidecars();
  },
  afterTest: async function (test, _context, { passed }) {
    // One picture of where it ended, pass or fail.
    const name = `${test.parent} - ${test.title}`.replace(/[^a-z0-9]+/gi, "_").slice(0, 80);
    await browser.saveScreenshot(resolve(SHOTS, `${passed ? "ok" : "FAIL"}_${name}.png`));
  },
};
