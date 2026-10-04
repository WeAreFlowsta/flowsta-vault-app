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
  state: "this_device" | "up_to_date" | "last_synced" | "not_seen_since" | "needs_update" | "removed";
  at?: number;
}

interface NewDevice {
  name: string;
  platform: string;
}

const PLATFORM_NAMES: Record<string, string> = { windows: "Windows", macos: "Mac", linux: "Linux" };

function dayAndTime(ms: number): string {
  return new Date(ms).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
}

function day(ms: number): string {
  return new Date(ms).toLocaleDateString(undefined, { day: "numeric", month: "long" });
}

/** How current a device is, in plain words. */
export function deviceLine(d: DeviceRow): string {
  switch (d.state) {
    case "this_device": return "This device";
    case "up_to_date": return "Up to date";
    case "last_synced": return `Has everything up to ${dayAndTime(d.at ?? 0)}`;
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
  if (msg.includes("needs_phrase_once")) return "Enter your recovery phrase on this device once, then add the device.";
  if (msg.includes("api_unreachable")) return "Couldn't reach Flowsta. Check your connection, or use your recovery phrase on the new device.";
  return "That didn't work. Get a new code on the new device.";
}

export const DevicesTab = component$(() => {
  const devices = useSignal<DeviceRow[] | null>(null);
  const adding = useSignal(false);
  const code = useSignal("");
  const busy = useSignal(false);
  const error = useSignal("");
  const asking = useSignal<NewDevice | null>(null);
  const added = useSignal("");
  const removing = useSignal<DeviceRow | null>(null);

  const load = $(async () => {
    try {
      devices.value = await invoke<DeviceRow[]>("devices_list");
    } catch {
      /* the network is still starting: the list fills in on the next pass */
    }
  });
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ cleanup }) => {
    load();
    const id = setInterval(load, 10_000);
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
    } finally {
      busy.value = false;
    }
  });

  const approve = $(async () => {
    const device = asking.value;
    busy.value = true;
    try {
      await invoke("pair_approve");
      added.value = device ? `${device.name} is being added. It appears here once it has started.` : "";
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

  return (
    <div class="space-y-6">
      <div class="rounded-lg border border-gray-700 bg-[#15203a] p-6">
        <div class="mb-4 flex items-center justify-between gap-4">
          <h3 class="text-lg font-semibold text-white">Your devices</h3>
          {!adding.value && (
            <GlassButton onClick$={() => { adding.value = true; error.value = ""; added.value = ""; }}>Add a device</GlassButton>
          )}
        </div>

        {adding.value && (
          <div class="mb-5 rounded-lg border border-gray-700 bg-gray-900/40 p-4">
            <p class="mb-3 text-sm text-gray-300">
              On the new device, open Flowsta Vault and choose "I already have an identity", then "Use another device". Type the code it shows.
            </p>
            <input
              class="mb-3 w-full max-w-xs rounded-md border border-gray-600 bg-gray-900 px-4 py-2 font-mono text-lg uppercase tracking-widest text-white placeholder-gray-600 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
              placeholder="XXXX-XXXX-XXXX"
              maxLength={20}
              value={code.value}
              onInput$={(e) => { code.value = (e.target as HTMLInputElement).value; error.value = ""; }}
            />
            <div class="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <GlassButton variant="secondary" onClick$={() => { adding.value = false; code.value = ""; error.value = ""; }}>Cancel</GlassButton>
              <GlassButton disabled={busy.value || code.value.replace(/[^a-zA-Z]/g, "").length !== 12} onClick$={submitCode}>
                {busy.value ? "Checking..." : "Continue"}
              </GlassButton>
            </div>
            <p class="mt-3 text-xs text-gray-500">No other device to hand? Use your recovery phrase on the new device instead.</p>
          </div>
        )}

        {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}
        {added.value && <p class="mb-4 text-sm text-sky-300">{added.value}</p>}

        {devices.value === null ? (
          <p class="text-sm text-gray-400">Loading your devices...</p>
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
                  <p class={["text-xs", d.state === "up_to_date" || d.state === "this_device" ? "text-green-400" : d.state === "removed" ? "text-gray-500" : "text-amber-300"].join(" ")}>
                    {deviceLine(d)}
                  </p>
                </div>
                {d.state !== "this_device" && d.state !== "removed" && (
                  <PillButton accent="red" onClick$={() => { removing.value = d; error.value = ""; }}>Remove</PillButton>
                )}
              </li>
            ))}
          </ul>
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
              <GlassButton disabled={busy.value} onClick$={approve}>{busy.value ? "Adding..." : "Add device"}</GlassButton>
            </div>
          </div>
        </div>
      )}

      {removing.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div class="mx-4 w-full max-w-md rounded-lg border border-gray-700 bg-gray-800 p-6">
            <h3 class="mb-2 text-lg font-semibold text-white">Remove {removing.value.name}?</h3>
            <p class="mb-6 text-sm text-gray-300">
              It can no longer sign in or approve as you, and it stops syncing. What it already holds stays on it.
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
