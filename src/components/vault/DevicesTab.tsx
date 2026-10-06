/**
 * Settings → Devices: the devices of this identity, adding one with a code
 * shown on the new device, and removing one.
 */
import { component$, useSignal, useVisibleTask$, $ } from "@builder.io/qwik";
import { invoke } from "@tauri-apps/api/core";
import { GlassButton } from "~/components/common/GlassButton";
import { PillButton } from "~/components/ui/PillButton";

declare const __API_URL__: string;

export interface DeviceRow {
  install_id: string;
  name: string;
  platform: string;
  added_at: number;
  state: "this_device" | "this_device_setting_up" | "up_to_date" | "last_synced" | "not_seen_since" | "needs_update" | "removed";
  at?: number;
}

interface Standing {
  device: "unknown" | "registered" | "needs_confirming";
  enrollment: "none" | "waiting" | "in_force" | null;
}

interface NewDevice {
  name: string;
  platform: string;
  install_id: string;
}

const PLATFORM_NAMES: Record<string, string> = { windows: "Windows", macos: "Mac", linux: "Linux" };

function dayAndTime(ms: number): string {
  return new Date(ms).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
}

function day(ms: number): string {
  return new Date(ms).toLocaleDateString(undefined, { day: "numeric", month: "long" });
}

/** A device that said what it holds this recently is catching up, not behind. */
export const RECENT_MS = 10 * 60 * 1000;
export const isCatchingUp = (d: DeviceRow, now = Date.now()) => d.state === "last_synced" && now - (d.at ?? 0) <= RECENT_MS;

/** How current a device is, in plain words. */
export function deviceLine(d: DeviceRow): string {
  switch (d.state) {
    case "this_device": return "This device";
    case "this_device_setting_up": return "This device - being set up";
    case "up_to_date": return d.at ? `Up to date - last seen ${dayAndTime(d.at)}` : "Up to date";
    case "last_synced": return isCatchingUp(d) ? "Syncing a recent change" : `Has everything up to ${dayAndTime(d.at ?? 0)}`;
    case "not_seen_since": return `Not seen since ${day(d.at ?? 0)}`;
    case "needs_update": return "Needs the Vault update to sync";
    case "removed": return "Removed";
  }
}

function claimError(e: unknown): string {
  const msg = String(e);
  if (msg.includes("invalid_code")) return "That doesn't look like a code. It has three groups of four letters.";
  if (msg.includes("code_not_found") || msg.includes("already_claimed") || msg.includes("pair_timeout"))
    return "That code wasn't found. Get a new one on the new device.";
  if (msg.includes("code_mismatch") || msg.includes("pair_closed")) return "That code didn't match. Get a new one on the new device.";
  if (msg.includes("needs_phrase_once")) return "Enter your recovery phrase once (above), then add the device.";
  if (msg.includes("api_unreachable")) return "Couldn't reach Flowsta. Check your connection, or use your recovery phrase on the new device.";
  return "That didn't work. Get a new code on the new device.";
}

export const DevicesTab = component$(() => {
  const devices = useSignal<DeviceRow[] | null>(null);
  const checking = useSignal(false);
  // False on an identity set up before 1.6.0 until the phrase is typed once.
  const handoverReady = useSignal(true);
  const adding = useSignal(false);
  const code = useSignal("");
  const busy = useSignal(false);
  const error = useSignal("");
  const asking = useSignal<NewDevice | null>(null);
  const added = useSignal("");
  // The install id of the device just approved here, until it is listed.
  const addedInstall = useSignal("");
  const removing = useSignal<DeviceRow | null>(null);
  // How the account sees this device, and the one-time recovery phrase step.
  const standing = useSignal<Standing>({ device: "unknown", enrollment: null });
  const phraseOpen = useSignal(false);
  const phrase = useSignal("");
  const phraseError = useSignal("");
  const phraseDone = useSignal("");
  // Confirming this device from another one: the code to type there.
  const confirmCode = useSignal("");
  const confirmWaiting = useSignal(false);

  const confirmWithDevice = $(async () => {
    phraseError.value = "";
    busy.value = true;
    try {
      const { listen } = await import("@tauri-apps/api/event");
      const unlisten = await listen<{ state: string; reason?: string }>("pair-status", (ev) => {
        if (ev.payload.state === "waiting_for_approval") {
          confirmWaiting.value = true;
          return;
        }
        unlisten();
        confirmCode.value = "";
        confirmWaiting.value = false;
        if (ev.payload.state === "done") {
          phraseDone.value = "Done. This device is confirmed.";
          load();
        } else {
          error.value = claimError(ev.payload.reason || "");
        }
      });
      confirmCode.value = await invoke<string>("pair_confirm_begin", { apiUrl: __API_URL__ });
    } catch (e) {
      error.value = claimError(e);
    } finally {
      busy.value = false;
    }
  });

  const load = $(async () => {
    try {
      devices.value = await invoke<DeviceRow[]>("devices_list");
      // The chip shows the same list at the same moment.
      window.dispatchEvent(new CustomEvent("devices-listed", { detail: devices.value }));
      // The device approved here has started: the waiting line goes.
      if (addedInstall.value && devices.value.some((d) => d.install_id === addedInstall.value && d.state !== "removed")) {
        const name = devices.value.find((d) => d.install_id === addedInstall.value)?.name || "The new device";
        addedInstall.value = "";
        added.value = `${name} has started and is one of your devices.`;
        setTimeout(() => { added.value = ""; }, 8_000);
      }
    } catch {
      // The cells are still starting (minutes after opening): say so
      // rather than spin as if the list were a moment away.
      checking.value = true;
    }
    try {
      standing.value = await invoke<Standing>("device_standing");
    } catch { /* locked */ }
    try {
      handoverReady.value = await invoke<boolean>("can_hand_over");
    } catch { /* locked */ }
  });

  const submitPhrase = $(async () => {
    phraseError.value = "";
    busy.value = true;
    try {
      const done = await invoke<{ keys_added: boolean; standing: Standing }>("use_recovery_phrase_once", {
        apiUrl: __API_URL__,
        mnemonic: phrase.value,
      });
      standing.value = done.standing;
      handoverReady.value = true;
      phrase.value = "";
      phraseOpen.value = false;
      phraseDone.value =
        done.standing.enrollment === "waiting"
          ? "Done."
          : "Done. Only you can add devices now.";
    } catch (e) {
      phraseError.value = String(e);
    } finally {
      busy.value = false;
    }
  });
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ cleanup }) => {
    load();
    const id = setInterval(load, 5_000);
    cleanup(() => clearInterval(id));
  });

  const submitCode = $(async () => {
    error.value = "";
    added.value = "";
    busy.value = true;
    try {
      asking.value = await invoke<NewDevice>("pair_claim", { apiUrl: __API_URL__, code: code.value });
    } catch (e) {
      error.value = claimError(e);
      // This device was set up before it kept the keys a new device needs:
      // the phrase fills them in.
      if (String(e).includes("needs_phrase_once")) phraseOpen.value = true;
    } finally {
      busy.value = false;
    }
  });

  const approve = $(async () => {
    const device = asking.value;
    busy.value = true;
    try {
      await invoke("pair_approve");
      window.dispatchEvent(new Event("devices-changed-here"));
      added.value = device ? `Waiting for ${device.name} to start...` : "";
      addedInstall.value = device?.install_id || "";
      adding.value = false;
      code.value = "";
    } catch (e) {
      error.value = claimError(e);
    } finally {
      asking.value = null;
      busy.value = false;
      load();
    }
  });

  const decline = $(async () => {
    asking.value = null;
    await invoke("pair_decline").catch(() => {});
  });

  const remove = $(async () => {
    const device = removing.value;
    if (!device) return;
    busy.value = true;
    error.value = "";
    try {
      await invoke("device_remove", { apiUrl: __API_URL__, installId: device.install_id });
      window.dispatchEvent(new Event("devices-changed-here"));
    } catch (e) {
      error.value = String(e).includes("api_unreachable")
        ? "Couldn't reach Flowsta. Removing a device needs a connection."
        : "That device could not be removed. Try again.";
    } finally {
      removing.value = null;
      busy.value = false;
      load();
    }
  });

  // The 24 words, used once: shown under "Who can add devices" and, on a
  // device the account wants confirmed, in place of the code.
  const phraseForm = (
    <>
            <p class="mb-3 text-sm text-gray-300">Your 24 words are used now and not kept.</p>
            <textarea
              class="mb-3 w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400 resize-none"
              rows={3}
              placeholder="word1 word2 word3 ... word24"
              value={phrase.value}
              onInput$={(e) => { phrase.value = (e.target as HTMLTextAreaElement).value; phraseError.value = ""; }}
            />
            {phraseError.value && <p class="mb-3 text-sm text-red-400">{phraseError.value}</p>}
            <div class="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <GlassButton variant="secondary" disabled={busy.value} onClick$={() => { phraseOpen.value = false; phrase.value = ""; phraseError.value = ""; }}>Cancel</GlassButton>
              <GlassButton disabled={busy.value || !phrase.value.trim()} onClick$={submitPhrase}>{busy.value ? "Checking..." : "Confirm"}</GlassButton>
            </div>
    </>
  );

  return (
    <div class="space-y-6">
      <div class="rounded-lg border border-gray-700 bg-[#15203a] p-6">
        <div class="mb-4 flex items-center justify-between gap-4">
          <h3 class="text-lg font-semibold text-white">Your devices</h3>
          {!adding.value && (
            <GlassButton testId="device-add" onClick$={() => { adding.value = true; error.value = ""; added.value = ""; }}>Add a device</GlassButton>
          )}
        </div>

        {adding.value && (
          <div class="mb-5 rounded-lg border border-gray-700 bg-gray-900/40 p-4">
            <h4 class="mb-2 text-sm font-semibold text-white">Add a device</h4>
            {!handoverReady.value && (
              <div class="mb-4 rounded-md border border-amber-400/30 bg-amber-400/5 p-3" data-testid="phrase-first">
                <p class="mb-2 text-sm text-gray-200">
                  First, your recovery phrase - once. This identity was made before devices could be added, and the phrase fills in what a new device needs.
                </p>
                {phraseForm}
              </div>
            )}
            <ol class="mb-3 list-decimal space-y-1 pl-5 text-sm text-gray-300">
              <li>On the new device, open Flowsta Vault and choose "I already have an identity", then "Use another device".</li>
              <li>It shows a code. Type it here and approve.</li>
            </ol>
            <input
              class="mb-3 w-full max-w-xs rounded-md border border-gray-600 bg-gray-900 px-4 py-2 font-mono text-lg uppercase tracking-widest text-white placeholder-gray-600 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
              placeholder="XXXX-XXXX-XXXX"
              data-testid="device-code"
              maxLength={20}
              value={code.value}
              onInput$={(e) => { code.value = (e.target as HTMLInputElement).value; error.value = ""; }}
            />
            <div class="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <GlassButton variant="secondary" onClick$={() => { adding.value = false; code.value = ""; error.value = ""; }}>Cancel</GlassButton>
              <GlassButton testId="device-code-submit" disabled={busy.value || !handoverReady.value || code.value.replace(/[^a-zA-Z]/g, "").length !== 12} onClick$={submitCode}>
                {busy.value ? "Checking..." : "Continue"}
              </GlassButton>
            </div>
            <p class="mt-3 text-xs text-gray-500">Without this device to hand, the new device can use your recovery phrase instead.</p>
          </div>
        )}

        {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}
        {added.value && (
          <p class="mb-4 flex items-center gap-2 text-sm text-sky-300">
            {addedInstall.value && (
              <svg class="h-4 w-4 shrink-0 animate-spin" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
              </svg>
            )}
            <span>{added.value}</span>
          </p>
        )}
        {phraseDone.value && <p class="mb-4 text-sm text-sky-300">{phraseDone.value}</p>}

        {/* The account does not count this device yet: one question fixes it. */}
        {standing.value.device === "needs_confirming" && !phraseOpen.value && (
          <div class="mb-5 rounded-lg border border-amber-700/60 bg-amber-950/30 p-4">
            <p class="mb-1 text-sm font-semibold text-amber-200">Confirm this device</p>
            {confirmCode.value ? (
              <>
                <p class="mb-2 text-sm text-gray-300">
                  Type this code on your other device: Settings, Devices, Add a device.
                </p>
                <p class="mb-2 select-all rounded-lg bg-gray-900 py-3 text-center font-mono text-2xl tracking-widest text-white">{confirmCode.value}</p>
                <p class="text-xs text-sky-300">{confirmWaiting.value ? "Now choose Add device there." : "Waiting for your other device..."}</p>
              </>
            ) : (
              <>
                <p class="mb-3 text-sm text-gray-300">Your account does not count this device yet. Confirm it once:</p>
                <div class="flex flex-col gap-2 sm:flex-row">
                  <GlassButton disabled={busy.value} onClick$={() => { phraseOpen.value = true; phraseError.value = ""; }}>Use my recovery phrase</GlassButton>
                  <GlassButton variant="secondary" disabled={busy.value} onClick$={confirmWithDevice}>Use another device</GlassButton>
                </div>
              </>
            )}
          </div>
        )}
        {phraseOpen.value && standing.value.device === "needs_confirming" && (
          <div class="mb-5 rounded-lg border border-gray-700 bg-gray-900/40 p-4">
            {phraseForm}
          </div>
        )}

        {devices.value === null ? (
          <p class="flex items-center gap-2 text-sm text-gray-400">
            <svg class="h-4 w-4 shrink-0 animate-spin" fill="none" viewBox="0 0 24 24" aria-hidden="true">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
            </svg>
            <span>{checking.value ? "Checking your devices - this takes a few minutes after opening." : "Loading your devices..."}</span>
          </p>
        ) : devices.value.length === 0 ? (
          <p class="text-sm text-gray-400">This device appears here once its network has started.</p>
        ) : (
          <ul class="divide-y divide-gray-700/70">
            {devices.value.map((d) => (
              <li key={d.install_id} class="flex items-center justify-between gap-4 py-3">
                <div class="min-w-0">
                  <p class={["truncate text-sm font-medium", d.state === "removed" ? "text-gray-500" : "text-white"].join(" ")}>
                    {d.name}
                    <span class="ml-2 text-xs font-normal text-gray-500">{PLATFORM_NAMES[d.platform] || d.platform}</span>
                  </p>
                  <p class={["text-xs", d.state === "up_to_date" || d.state === "this_device" ? "text-green-400" : d.state === "removed" || d.state === "this_device_setting_up" || isCatchingUp(d) ? "text-gray-400" : "text-amber-300"].join(" ")}>
                    {deviceLine(d)}
                  </p>
                </div>
                {d.state !== "this_device" && d.state !== "this_device_setting_up" && d.state !== "removed" && (
                  <PillButton accent="red" onClick$={() => { removing.value = d; error.value = ""; }}>Remove</PillButton>
                )}
              </li>
            ))}
          </ul>
        )}

        {standing.value.device === "registered" && standing.value.enrollment === "none" && !(adding.value && !handoverReady.value) && (
          <div class="mt-6 rounded-lg border border-gray-700 bg-gray-900/40 p-4" data-testid="who-can-add">
            <h4 class="mb-2 text-sm font-semibold text-white">Who can add devices</h4>
            <p class="mb-2 text-sm text-gray-300">
              Today: anyone with your Vault password on one of your devices, or an export of it.
            </p>
            <p class="mb-3 text-sm text-gray-300">
              Enter your recovery phrase once and adding a device will need the phrase, or your approval on a device you already have. It takes effect in 7 days.
            </p>
            {phraseOpen.value ? (
              <div>{phraseForm}</div>
            ) : (
              <GlassButton variant="secondary" disabled={busy.value} onClick$={() => { phraseOpen.value = true; phraseError.value = ""; }}>Enter recovery phrase</GlassButton>
            )}
          </div>
        )}
        {standing.value.device === "registered" && standing.value.enrollment === "waiting" && (
          <p class="mt-6 text-sm text-gray-400" data-testid="who-can-add">
            From 7 days after you entered your recovery phrase, adding a device needs the phrase or your approval on a device you already have.
          </p>
        )}

        <p class="mt-5 text-xs text-gray-500">
          Your private data goes to every one of your devices. Your devices keep syncing while this Vault is locked. Unlock to approve anything.
        </p>
      </div>

      {asking.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div class="mx-4 w-full max-w-md rounded-lg border border-gray-700 bg-gray-800 p-6">
            <h3 class="mb-2 text-lg font-semibold text-white">
              Add {asking.value.name} ({PLATFORM_NAMES[asking.value.platform] || asking.value.platform}) as one of your devices?
            </h3>
            <p class="mb-6 text-sm text-gray-300">
              It will be able to sign in and approve as you, and will keep a copy of your private data.
            </p>
            <div class="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <GlassButton variant="secondary" disabled={busy.value} onClick$={decline}>Cancel</GlassButton>
              <GlassButton testId="device-approve" disabled={busy.value} onClick$={approve}>{busy.value ? "Adding..." : "Add device"}</GlassButton>
            </div>
          </div>
        </div>
      )}

      {removing.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div class="mx-4 w-full max-w-md rounded-lg border border-gray-700 bg-gray-800 p-6">
            <h3 class="mb-2 text-lg font-semibold text-white">Remove {removing.value.name}?</h3>
            <p class="mb-6 text-sm text-gray-300">
              This device will no longer sign in or approve as you, and it stops syncing. Anything already on it stays there.
            </p>
            <div class="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <GlassButton variant="secondary" disabled={busy.value} onClick$={() => { removing.value = null; }}>Cancel</GlassButton>
              <GlassButton variant="danger" disabled={busy.value} onClick$={remove}>{busy.value ? "Removing..." : "Remove device"}</GlassButton>
            </div>
          </div>
        </div>
      )}
    </div>
  );
});
