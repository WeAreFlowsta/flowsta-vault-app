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
  state: "this_device" | "this_device_setting_up" | "up_to_date" | "setting_up" | "last_synced" | "not_seen_since" | "needs_update" | "removed";
  /** The later of the device's own record time and when this Vault last heard it directly (ms). */
  at?: number;
  /** When the device last wrote its own record (ms). */
  record_at?: number;
  /** When this Vault last heard it directly this session (ms), if it has. */
  heard_at?: number;
}

/** What a device holds (devices_progress): its private records and the
 *  other devices' backups it should keep, with how much is still to come. */
export interface Holds {
  records: number;
  backups_wanted: number;
  backups_pending: number;
  setting_up: boolean;
}
/** Where this identity's records are (move_status): the line they are on,
 *  and what the move to the 0.7 line carried and when, once it has. */
export interface MoveStatus {
  moved: boolean;
  marker: { moved_at_ms: number; private_records: number; signatures: number; revocations: number; thumbnails: number; born?: boolean; restored?: boolean; web_era_carried?: boolean; web_era_signatures?: number } | null;
  running: boolean;
  last_pass: { private_06: number; private_present: number; private_written: number; signatures_06: number; signatures_carried: number; error: string | null; skipped: string | null } | null;
  line: "V06" | "V07";
}

/** One line while a move is running or stuck; nothing once it is done (the
 *  move is an event: the Activity page carries it, with the counts). */
export function moveNote(m: MoveStatus | null): string {
  if (!m) return "";
  // An identity created on 1.7.0 or later was never anywhere else, and one
  // restored or added on this version had nothing here to move: nothing to say.
  if (m.marker?.born || m.marker?.restored) return "";
  if (m.moved) return "";
  if (m.running || (m.last_pass && !m.last_pass.error && !m.last_pass.skipped)) {
    const p = m.last_pass;
    const done = p ? p.private_present + p.private_written : 0;
    return p && p.private_06 > 0 ? `Syncing your Vault to the new network: ${Math.min(done, p.private_06).toLocaleString()} of ${p.private_06.toLocaleString()} records so far. Nothing to do.` : "Syncing your Vault to the new network. Nothing to do.";
  }
  if (m.last_pass?.error) return "Your Vault has not synced to the new network yet. It tries again every minute, nothing to do.";
  return "";
}

export interface DevicesProgress {
  setting_up: boolean;
  mine: Holds;
  siblings: { install_id: string; holds: Holds; at: number }[];
  /** Backups this device is still getting, by the device that holds them. */
  fetching?: { install_id: string; backups: number; bytes: number }[];
}

export function sizeText(bytes: number): string {
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${Math.round(bytes / 1e6)} MB`;
  return `${Math.max(1, Math.round(bytes / 1e3))} KB`;
}

/** How far a device being set up has got, in plain words: its records
 *  against `target` (what the device showing it holds) and the backups it
 *  is fetching. Empty when there is nothing to count yet. */
export function progressText(h: Holds, target: number): string {
  const parts: string[] = [];
  if (target > 0) parts.push(`${Math.min(h.records, target).toLocaleString()} of ${target.toLocaleString()} records`);
  if (h.backups_wanted > 0) parts.push(`${sizeText(h.backups_wanted - h.backups_pending)} of ${sizeText(h.backups_wanted)} of app backups`);
  return parts.join(" · ");
}

/** What this device is still getting from the others, in plain words:
 *  "Getting 1 backup from Erics-MacBook-Air (58 KB)". Empty when nothing is. */
export function gettingText(fetching: DevicesProgress["fetching"], names: Record<string, string>): string {
  const parts = (fetching ?? [])
    .filter((f) => f.backups > 0)
    .map((f) => `${f.backups.toLocaleString()} backup${f.backups === 1 ? "" : "s"} from ${names[f.install_id] || "another device"} (${sizeText(f.bytes)})`);
  if (parts.length === 0) return "";
  const list = parts.length === 1 ? parts[0] : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
  return `Getting ${list}`;
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

/** "heard just now" / "heard 3 min ago" when this Vault heard the device
 *  directly after its record was written: the time on the row is the hello,
 *  and the line says the record is older (10-26: a day-old record read as
 *  "last heard from Oct 25" of a device online right then). */
function heardNote(d: DeviceRow, now = Date.now()): string {
  if (!d.heard_at || !d.record_at || d.heard_at <= d.record_at + 60_000) return "";
  const mins = Math.floor((now - d.heard_at) / 60_000);
  const ago = mins < 1 ? "just now" : mins < 60 ? `${mins} min ago` : `${Math.floor(mins / 60)} h ago`;
  return ` - heard ${ago}, its record is from ${dayAndTime(d.record_at)}`;
}

/** How current a device is, in plain words. */
export function deviceLine(d: DeviceRow): string {
  switch (d.state) {
    case "this_device": return "This device";
    case "this_device_setting_up": return "This device - being set up";
    case "up_to_date": return d.at ? (heardNote(d) ? `Up to date${heardNote(d)}` : `Up to date - last seen ${dayAndTime(d.at)}`) : "Up to date";
    case "setting_up": return "Receiving your private data";
    // Its newest record is older than this device's: it is behind. (It said
    // "Has everything up to <when it last checked in>" - the opposite.) A
    // recent one is catching up with this device, which it names (10-18:
    // "Syncing a recent change" read as this device fetching from it).
    case "last_synced": return isCatchingUp(d) ? "Catching up with a change made here" : heardNote(d) ? `Not up to date${heardNote(d)}` : `Not up to date - last heard from ${dayAndTime(d.at ?? 0)}`;
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
  // Renaming this device (the record's name, shown on every device).
  const renaming = useSignal(false);
  const renameValue = useSignal("");
  const renameError = useSignal("");
  // A device this one knows has not been heard from yet this session (the
  // first quarter hour after unlock): the list is not confirmed yet.
  const reaching = useSignal(false);
  // How far a device being set up has got (its own word, sent directly).
  const progress = useSignal<DevicesProgress | null>(null);
  /** Where this identity's records are, and what the move carried. */
  const moveStatus = useSignal<MoveStatus | null>(null);
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
      moveStatus.value = await invoke<MoveStatus>("move_status").catch(() => null);
      reaching.value = await invoke<boolean>("devices_checking").catch(() => false);
      progress.value = await invoke<DevicesProgress>("devices_progress").catch(() => null);
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
        {moveNote(moveStatus.value) && (
          <p class="-mt-2 mb-4 text-xs text-gray-400" data-testid="move-note">{moveNote(moveStatus.value)}</p>
        )}

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
                  {d.state === "this_device" && renaming.value ? (
                    <form
                      preventdefault:submit
                      class="flex flex-wrap items-center gap-2"
                      onSubmit$={async () => {
                        try {
                          renameError.value = "";
                          await invoke("rename_this_device", { name: renameValue.value });
                          renaming.value = false;
                          devices.value = await invoke<DeviceRow[]>("devices_list").catch(() => devices.value);
                        } catch (e) {
                          renameError.value = String(e).replace(/^Error:\s*/, "");
                        }
                      }}
                    >
                      <input
                        type="text"
                        maxLength={40}
                        value={renameValue.value}
                        onInput$={(_, el) => (renameValue.value = el.value)}
                        class="w-48 rounded-md border border-gray-600 bg-gray-900 px-2 py-1 text-sm text-white"
                        aria-label="Device name"
                        data-testid="device-rename-input"
                      />
                      <PillButton type="submit" variant="primary">Save</PillButton>
                      <PillButton type="button" onClick$={() => { renaming.value = false; renameError.value = ""; }}>Cancel</PillButton>
                      {renameError.value && <span class="text-xs text-amber-300">{renameError.value}</span>}
                    </form>
                  ) : (
                    <p class={["truncate text-sm font-medium", d.state === "removed" ? "text-gray-500" : "text-white"].join(" ")}>
                      {d.name}
                      <span class="ml-2 text-xs font-normal text-gray-500">{PLATFORM_NAMES[d.platform] || d.platform}</span>
                      {d.state === "this_device" && (
                        <button
                          type="button"
                          class="ml-2 text-xs font-normal text-sky-300 hover:underline"
                          data-testid="device-rename"
                          onClick$={() => { renameValue.value = d.name; renaming.value = true; }}
                        >
                          Rename
                        </button>
                      )}
                    </p>
                  )}
                  <p class={["text-xs", d.state === "up_to_date" || d.state === "this_device" ? "text-green-400" : d.state === "removed" || d.state === "this_device_setting_up" || isCatchingUp(d) ? "text-gray-400" : "text-amber-300"].join(" ")}>
                    {deviceLine(d)}
                  </p>
                  {(d.state === "this_device" || d.state === "this_device_setting_up") && (() => {
                    const names = Object.fromEntries((devices.value ?? []).map((x) => [x.install_id, x.name]));
                    const text = gettingText(progress.value?.fetching, names);
                    return text ? <p class="text-xs text-gray-400" data-testid="device-getting">{text}</p> : null;
                  })()}
                  {d.state === "setting_up" && (() => {
                    const p = progress.value;
                    const theirs = p?.siblings.find((s) => s.install_id === d.install_id)?.holds;
                    const text = theirs && p ? progressText(theirs, p.mine.records) : "";
                    return text ? <p class="text-xs text-gray-400" data-testid="device-progress">{text}</p> : null;
                  })()}
                </div>
                {d.state !== "this_device" && d.state !== "this_device_setting_up" && d.state !== "removed" && (
                  <PillButton accent="red" onClick$={() => { removing.value = d; error.value = ""; }}>Remove</PillButton>
                )}
              </li>
            ))}
          </ul>
        )}
        {devices.value !== null && devices.value.length > 0 && reaching.value && (
          <p class="mt-2 flex items-center gap-2 text-xs text-gray-400" data-testid="devices-reaching">
            <svg class="h-3.5 w-3.5 shrink-0 animate-spin" fill="none" viewBox="0 0 24 24" aria-hidden="true">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
            </svg>
            <span>Checking with your other devices...</span>
          </p>
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
