/**
 * The identity's devices at a glance, beside the network chips: how many
 * there are and whether they hold the same things. A click opens
 * Settings → Devices.
 */
import { component$, useSignal, useVisibleTask$ } from "@builder.io/qwik";
import { useNavigate } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { deviceLine } from "~/components/vault/DevicesTab";

type Row = Parameters<typeof deviceLine>[0];

/** The chip's text, colour and tooltip for a list of devices. */
export function devicesSummary(devices: Row[]): { label: string; color: string; title: string } {
  const live = devices.filter((d) => d.state !== "removed");
  const others = live.filter((d) => d.state !== "this_device");
  if (others.length === 0) {
    return { label: "1 device", color: "bg-gray-500", title: "Only on this device" };
  }
  const behind = others.some((d) => d.state !== "up_to_date");
  return {
    label: `${live.length} devices`,
    color: behind ? "bg-amber-400" : "bg-green-400",
    title: others.map((d) => `${d.name} - ${deviceLine(d).toLowerCase()}`).join("\n"),
  };
}

export const DevicesChip = component$(() => {
  const nav = useNavigate();
  const devices = useSignal<Row[] | null>(null);

  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ cleanup }) => {
    const load = async () => {
      try {
        devices.value = await invoke<Row[]>("devices_list");
      } catch {
        /* locked, or the network is still starting */
      }
    };
    load();
    const id = setInterval(load, 30_000);
    cleanup(() => clearInterval(id));
  });

  if (!devices.value || devices.value.length === 0) return null;
  const summary = devicesSummary(devices.value);
  return (
    <button
      type="button"
      class="mb-3 flex items-center gap-2 text-left"
      title={summary.title}
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
