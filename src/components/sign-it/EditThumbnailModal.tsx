import { component$, useSignal, $, type QRL, type Signal } from "@builder.io/qwik";
import { invoke } from "@tauri-apps/api/core";
import { GlassButton } from "~/components/common/GlassButton";
import ImageCropper from "~/components/sign-it/ImageCropper";

/**
 * Edit-thumbnail modal. Shared between the dashboard recent-signatures
 * list (sign-it/index.tsx) and the all-signatures page
 * (sign-it/signatures/index.tsx) so adding new per-signature actions
 * (Amend, etc.) keeps the two surfaces in sync.
 *
 * Parent owns the `target` signal (which signature is being edited /
 * null when closed). Internal state — picked image, cropped canvas,
 * saving flag, error message — lives in the modal because it's
 * modal-scoped.
 *
 * On success, calls onSaved$(action_hash, thumbnail) so the parent can
 * update its local signature list without a full refetch.
 *
 * Mirrors Website/src/components/sign-it/EditThumbnailModal.tsx (uses
 * the local conductor via Tauri invoke instead of the API).
 */

interface Props {
  target: Signal<any | null>;
  onSaved$: QRL<(actionHash: string, thumbnail: string) => void>;
}

export default component$<Props>(({ target, onSaved$ }) => {
  const image = useSignal<string | null>(null);
  const canvas = useSignal<HTMLCanvasElement | null>(null);
  const saving = useSignal(false);
  // Holds the in-flight publish so closing the modal doesn't cancel it.
  const backgroundSave = useSignal<any>(null);
  const error = useSignal("");

  const reset = $(() => {
    target.value = null;
    image.value = null;
    canvas.value = null;
    error.value = "";
  });

  // A real <input type=file> behind a <label>: the picker opens natively on
  // the first click. (A programmatic input.click() fires only after the
  // lazy-loaded handler arrives — outside the click's user-gesture window —
  // so the webview swallowed the first attempt.)
  const handleFileChosen = $((_: Event, el: HTMLInputElement) => {
    const file = el.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      image.value = e.target?.result as string;
    };
    reader.readAsDataURL(file);
    el.value = "";
  });

  const handleSave = $(async () => {
    if (!target.value?.action_hash) return;
    if (!canvas.value) {
      error.value = "Pick an image first.";
      return;
    }
    saving.value = true;
    error.value = "";
    try {
      const thumbnail = canvas.value.toDataURL("image/jpeg", 0.7);
      if (thumbnail.length > 15000) {
        error.value = "Thumbnail too large. Try a simpler image.";
        saving.value = false;
        return;
      }
      const actionHash = target.value.action_hash;
      // The save publishes to the signing network — on a fresh vault the
      // network walk can take a minute or two. If the user closes the
      // modal meanwhile, the publish keeps going and the list updates
      // when it lands.
      const pending = invoke("set_thumbnail", {
        actionHashHex: actionHash,
        thumbnail,
      }).then(
        async () => {
          await onSaved$(actionHash, thumbnail);
          return null;
        },
        (e: any) => (typeof e === "string" ? e : e?.message) || "Failed to save thumbnail",
      );
      backgroundSave.value = pending as any;
      const failure = await pending;
      if (failure) {
        error.value = failure;
      } else if (target.value?.action_hash === actionHash) {
        target.value = null;
        image.value = null;
        canvas.value = null;
      }
    } catch (e: any) {
      console.error("Thumbnail save error:", e);
      error.value = (typeof e === "string" ? e : e.message) || "Failed to save thumbnail";
    } finally {
      saving.value = false;
    }
  });

  if (!target.value) return null;
  return (
    <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div class="mx-4 w-full max-w-md rounded-xl border border-gray-600 bg-gray-800 p-6 shadow-2xl">
        <h3 class="mb-4 text-base font-semibold text-white">Edit Thumbnail</h3>

        {!image.value ? (
          <label
            for="thumbnail-file-input"
            class="flex flex-col items-center justify-center rounded-lg border-2 border-dashed border-gray-600 p-10 transition-colors cursor-pointer hover:border-gray-500"
          >
            <input
              id="thumbnail-file-input"
              type="file"
              accept="image/*"
              class="hidden"
              onChange$={handleFileChosen}
            />
            <svg class="mb-3 h-10 w-10 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={1.5}>
              <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 15.75l5.159-5.159a2.25 2.25 0 013.182 0l5.159 5.159m-1.5-1.5l1.409-1.409a2.25 2.25 0 013.182 0l2.909 2.909M3.75 21h16.5A2.25 2.25 0 0022.5 18.75V5.25A2.25 2.25 0 0020.25 3H3.75A2.25 2.25 0 001.5 5.25v13.5A2.25 2.25 0 003.75 21z" />
            </svg>
            <p class="text-sm text-gray-400">Click to choose a thumbnail image</p>
          </label>
        ) : (
          <div>
            <ImageCropper
              imageSrc={image.value}
              cropShape="square"
              outputSize={128}
              onCropComplete$={(c) => { canvas.value = c; }}
            />
            <button
              class="mt-2 text-xs text-amber-500 hover:text-amber-400 transition-colors"
              onClick$={() => { image.value = null; canvas.value = null; }}
            >
              Choose a different image
            </button>
          </div>
        )}

        {error.value && (
          <div class="mt-3 rounded-lg border border-red-800/50 bg-red-900/20 p-2">
            <p class="text-xs text-red-400">{error.value}</p>
          </div>
        )}

        {saving.value && (
          <p class="mt-3 text-xs text-gray-400">
            Publishing to your signing network — on a fresh Vault this can
            take a minute or two. You can close this window; the thumbnail
            appears when it lands.
          </p>
        )}

        <div class="mt-4 flex gap-3">
          <GlassButton
            variant="secondary"
            class="flex-1"
            onClick$={saving.value
              ? $(() => { target.value = null; image.value = null; canvas.value = null; })
              : reset}
          >
            {saving.value ? "Close — keep publishing" : "Cancel"}
          </GlassButton>
          {image.value && (
            <GlassButton
              class="flex-1"
              disabled={saving.value || !canvas.value}
              onClick$={handleSave}
            >
              {saving.value ? "Publishing…" : "Save Thumbnail"}
            </GlassButton>
          )}
        </div>
      </div>
    </div>
  );
});
