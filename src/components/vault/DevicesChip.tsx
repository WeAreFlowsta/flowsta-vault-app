/**
 * The identity's devices at a glance, beside the network chips: how many
 * there are and whether they hold the same things. A click opens
 * Settings → Devices.
 */
import { component$, useSignal, useVisibleTask$ } from "@builder.io/qwik";
import { useNavigate } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import type { DeviceRow, DevicesProgress } from "~/components/vault/DevicesTab";
import { chip, knownDevices, type OtherDevice, type RowColor } from "~/lib/device-rules";

const DOT: Record<RowColor, string> = { green: "bg-green-400", grey: "bg-gray-500", amber: "bg-amber-400" };

/** What the chip needs beside the list: whether this device joined an
 *  identity that existed, and the person's answer about another device. */
export interface ChipFacts { joined: boolean; answer: OtherDevice }

export const DevicesChip = component$<{ ready: boolean }>((props) => {
  const nav = useNavigate();
  const devices = useSignal<DeviceRow[] | null>(null);
  const progress = useSignal<DevicesProgress | null>(null);
  const facts = useSignal<ChipFacts>({ joined: false, answer: null });
  // What this device already knew before the network came up.
  const known = useSignal(1);

  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ cleanup }) => {
    const load = async () => {
      try {
        devices.value = await invoke<DeviceRow[]>("devices_list");
        progress.value = await invoke<DevicesProgress>("devices_progress").catch(() => null);
        const id = await invoke<{ joined_existing?: boolean; has_other_device?: boolean | null } | null>("get_identity").catch(() => null);
        facts.value = { joined: !!id?.joined_existing, answer: id?.has_other_device == null ? null : id.has_other_device ? "yes" : "no" };
      } catch {
        /* locked, or the network is still starting */
      }
    };
    invoke<number>("devices_known_count").then((n) => { known.value = n; }).catch(() => {});
    load();
    const id = setInterval(load, 30_000);
    // A change made on this device (remove, approve) or heard from another.
    window.addEventListener("devices-changed-here", load);
    // The Devices tab just loaded the list: show the same one now.
    const listed = (e: Event) => { devices.value = (e as CustomEvent<DeviceRow[]>).detail; };
    window.addEventListener("devices-listed", listed);
    let unlisten: (() => void) | null = null;
    import("@tauri-apps/api/event").then(({ listen }) => listen("devices-changed", load).then((u) => { unlisten = u; })).catch(() => {});
    cleanup(() => {
      clearInterval(id);
      window.removeEventListener("devices-changed-here", load);
      window.removeEventListener("devices-listed", listed);
      if (unlisten) unlisten();
    });
  });

  // Drawn from the start, so the panel never changes shape. Until the list
  // answers, the count is the one this device last saw, in grey; "1 device"
  // is said only when it is known (the rules in ~/lib/device-rules).
  const list = devices.value;
  const view = list && list.length > 0
    ? chip({
        joined: facts.value.joined,
        answer: facts.value.answer,
        listRead: true,
        settingUp: list.some((d) => d.state === "this_device_setting_up"),
        others: knownDevices(list, progress.value?.siblings ?? []),
        mine: progress.value?.mine.records ?? 0,
        now: Date.now(),
      })
    : known.value > 1
      ? { label: `${known.value} devices`, color: "grey" as RowColor, title: "Checking your devices" }
      : chip({ joined: facts.value.joined, answer: facts.value.answer, listRead: false, settingUp: true, others: [], mine: 0, now: Date.now() });
  const summary = { label: view.label, color: DOT[view.color], title: view.title };
  // Shown from the first paint ("1 device", grey) and filled in later.
  void props.ready;
  return (
    <button
      type="button"
      class="flex shrink-0 items-center gap-2 text-left"
      title={summary.title}
      data-testid="devices-chip"
      onClick$={async () => {
        try { sessionStorage.setItem("settings-tab", "devices"); } catch { /* no storage */ }
        window.dispatchEvent(new Event("open-devices-tab"));
        await nav("/settings/");
      }}
    >
      <span class={`h-2.5 w-2.5 shrink-0 rounded-full ${summary.color}`} />
      <span class="text-xs text-gray-400 hover:text-gray-200">{summary.label}</span>
    </button>
  );
});
