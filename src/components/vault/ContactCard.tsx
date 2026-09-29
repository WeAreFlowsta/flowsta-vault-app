/**
 * ContactCard - "Let people contact me through Flowsta". Off by default.
 * Lives in Settings (the Overview keeps its space); the public profile
 * page offers "Turn on" to the owner while it is off. The page shows a
 * Contact button only when this is on AND Flowsta holds an address it can
 * relay to (an email grant to flowsta.com); the relay never reveals the
 * address. Device-hosted identities only (the setting lives on the account).
 */
import { component$, useSignal, useVisibleTask$, $ } from "@builder.io/qwik";
import { invoke } from "@tauri-apps/api/core";

declare const __API_URL__: string;

export const ContactCard = component$(() => {
  const enabled = useSignal(false);
  const deliverable = useSignal(true);
  const busy = useSignal(false);
  const loaded = useSignal(false);
  const note = useSignal("");

  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async () => {
    try {
      const p = await invoke<{ enabled: boolean; deliverable: boolean }>("get_contact_preference", { apiUrl: __API_URL__ });
      enabled.value = p.enabled;
      deliverable.value = p.deliverable;
    } catch { /* offline - the card stays quiet */ }
    finally { loaded.value = true; }
  });

  const toggle = $(async () => {
    if (busy.value) return;
    busy.value = true;
    note.value = "";
    try {
      const p = await invoke<{ enabled: boolean; deliverable: boolean }>("set_contact_preference", {
        apiUrl: __API_URL__,
        enabled: !enabled.value,
      });
      enabled.value = p.enabled;
      deliverable.value = p.deliverable;
    } catch (e) {
      note.value = `${e}`;
    } finally {
      busy.value = false;
    }
  });

  const off = busy.value || !loaded.value || (!enabled.value && !deliverable.value);
  return (
    <div class="rounded-lg border border-gray-700 bg-[#15203a] p-6">
      <div class="flex items-start justify-between gap-4">
        <div class="min-w-0">
          <h3 class="text-lg font-semibold text-white">Messages through your page</h3>
          <p class="mt-1 text-sm text-gray-400">
            Let people write to you from your profile page. Messages reach you by email; your address is never shown to them.
          </p>
          {!deliverable.value && (
            <p class="mt-2 text-xs text-gray-400">
              Share your email with flowsta.com first so messages have somewhere to go.
            </p>
          )}
          {note.value && <p class="mt-2 text-xs text-red-400">{note.value}</p>}
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={enabled.value}
          aria-label="Let people contact me through Flowsta"
          disabled={off}
          onClick$={toggle}
          class={{
            "relative mt-1 inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full p-0 transition-colors": true,
            "bg-amber-500": enabled.value,
            "bg-gray-600": !enabled.value,
            "opacity-60": off,
          }}
        >
          <span
            class={{
              "inline-block h-4 w-4 transform rounded-full bg-white transition-transform": true,
              "translate-x-6": enabled.value,
              "translate-x-1": !enabled.value,
            }}
          />
        </button>
      </div>
    </div>
  );
});
