import { component$, useSignal, $, type QRL, type Signal } from "@builder.io/qwik";
import { invoke } from "@tauri-apps/api/core";
import { GlassButton } from "~/components/common/GlassButton";

/**
 * Revoke confirmation modal. Shared between the recent-signatures list
 * on the sign-it page and the all-signatures page so adding new
 * per-signature actions (Amend, etc.) keeps the two surfaces in sync.
 *
 * Parent owns the `target` signal (which signature is being revoked /
 * null when closed). Internal state — reason, in-flight flag, error —
 * lives in the modal because it's modal-scoped. On success, calls
 * onRevoked$ so the parent can update its local signature list.
 *
 * Talks to the local conductor via the `revoke_signature` Tauri command
 * (no API round-trip).
 */

interface Props {
  target: Signal<any | null>;
  onRevoked$: QRL<(actionHash: string, reason: string | null) => void>;
}

export default component$<Props>(({ target, onRevoked$ }) => {
  const reason = useSignal("");
  const submitting = useSignal(false);
  const error = useSignal("");

  const close = $(() => {
    target.value = null;
    reason.value = "";
    error.value = "";
  });

  const handleRevoke = $(async () => {
    if (!target.value?.action_hash) return;
    submitting.value = true;
    error.value = "";
    try {
      await invoke("revoke_signature", {
        actionHashHex: target.value.action_hash,
        reason: reason.value || null,
      });
      await onRevoked$(target.value.action_hash, reason.value || null);
      target.value = null;
      reason.value = "";
    } catch (e: any) {
      error.value = (typeof e === "string" ? e : e.message) || "Revocation failed";
    } finally {
      submitting.value = false;
    }
  });

  if (!target.value) return null;
  return (
    <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div class="mx-4 w-full max-w-sm rounded-xl border border-gray-600 bg-gray-800 p-6 shadow-2xl">
        <h3 class="mb-2 text-base font-semibold text-white">Revoke Signature</h3>
        <p class="mb-4 text-xs text-gray-400">
          This will publicly mark this signature as revoked. The original record stays on the DHT but verifiers will see it as revoked.
        </p>
        <div class="mb-4 rounded-lg border border-gray-700 bg-gray-900 p-3">
          <p class="truncate text-xs font-mono text-gray-400">
            {target.value.file_hash?.slice(0, 24)}...
          </p>
        </div>
        <div class="mb-4">
          <label class="mb-1 block text-xs text-gray-500">Reason (optional)</label>
          <input
            type="text"
            maxLength={280}
            placeholder="e.g. Replaced with updated version"
            class="w-full rounded-md border border-gray-600 bg-gray-900 px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:border-amber-400 focus:outline-none"
            style={{ colorScheme: "dark" }}
            value={reason.value}
            onInput$={(e) => { reason.value = (e.target as HTMLInputElement).value; }}
          />
        </div>
        {error.value && (
          <div class="mb-3 rounded-lg border border-red-800/50 bg-red-900/20 p-2">
            <p class="text-xs text-red-400">{error.value}</p>
          </div>
        )}
        <div class="flex gap-3">
          <GlassButton variant="secondary" class="flex-1" onClick$={close}>Cancel</GlassButton>
          <GlassButton
            variant="danger"
            class="flex-1"
            disabled={submitting.value}
            onClick$={handleRevoke}
          >
            {submitting.value ? "Revoking..." : "Revoke"}
          </GlassButton>
        </div>
      </div>
    </div>
  );
});
