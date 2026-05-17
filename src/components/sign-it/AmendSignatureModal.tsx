import { component$, useStore, useSignal, useTask$, $, type QRL, type Signal } from "@builder.io/qwik";
import { invoke } from "@tauri-apps/api/core";
import { GlassButton } from "~/components/common/GlassButton";

/**
 * Amend a signature — creates a new signature with `supersedes` pointing
 * back at the original, replacing it in the user's chain. Both versions
 * stay on the DHT forever (the chain IS the audit trail); the list
 * endpoints hide the old version from default views via the
 * `superseded_by` annotation computed server-side.
 *
 * The form pre-fills with the target signature's metadata so the user
 * is editing-not-restarting. Quota: amendments count as regular signs.
 *
 * Talks to the local conductor via the `sign_file` Tauri command
 * (no API round-trip). The Rust pipeline forwards `supersedes` into the
 * SignatureRecord payload so the DNA stores the chain link.
 */

interface Props {
  target: Signal<any | null>;
  onAmended$: QRL<() => void>;
}

const selectClass =
  "w-full rounded-md border border-gray-600 bg-gray-800 px-3 py-2 text-sm text-gray-200 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400";

export default component$<Props>(({ target, onAmended$ }) => {
  const form = useStore({
    aiGeneration: "",
    license: "",
    commercialLicensing: "",
    aiTraining: "",
    contactPreference: "",
    comment: "",
  });
  const submitting = useSignal(false);
  const error = useSignal("");

  useTask$(({ track }) => {
    const sig = track(() => target.value);
    if (!sig) return;
    // ai_generation + content_rights come back in DNA PascalCase enum form.
    // Lower-case them back to the form's option-value keys.
    const aiMap: Record<string, string> = {
      None: "none",
      Assisted: "assisted",
      Generated: "generated",
    };
    const licenseMap: Record<string, string> = {
      AllRightsReserved: "all-rights-reserved",
      CC0: "cc0",
      CCBY: "cc-by",
      CCBYSA: "cc-by-sa",
      CCBYNC: "cc-by-nc",
      CCBYNCSA: "cc-by-nc-sa",
      MIT: "mit",
      Apache2: "apache-2",
      GPL3: "gpl-3",
    };
    const commercialMap: Record<string, string> = {
      NotAvailable: "not_available",
      OpenToLicensing: "open_to_licensing",
    };
    const aiTrainingMap: Record<string, string> = {
      Allowed: "allowed",
      AllowedWithAttribution: "allowed_with_attribution",
      RequiresLicense: "requires_license",
      NotAllowed: "not_allowed",
    };
    const contactMap: Record<string, string> = {
      NoContact: "no_contact",
      AllowContactRequests: "allow_contact_requests",
    };
    form.aiGeneration = aiMap[sig.ai_generation] || sig.ai_generation || "";
    form.license = licenseMap[sig.content_rights?.license] || sig.content_rights?.license || "";
    form.commercialLicensing = commercialMap[sig.content_rights?.commercial_licensing] || sig.content_rights?.commercial_licensing || "";
    form.aiTraining = aiTrainingMap[sig.content_rights?.ai_training] || sig.content_rights?.ai_training || "";
    form.contactPreference = contactMap[sig.content_rights?.contact_preference] || sig.content_rights?.contact_preference || "";
    form.comment = sig.comment || "";
    error.value = "";
  });

  const close = $(() => {
    target.value = null;
    error.value = "";
  });

  const handleAmend = $(async () => {
    if (!target.value?.action_hash || !target.value?.file_hash) return;
    submitting.value = true;
    error.value = "";
    try {
      const cr: Record<string, string> = {};
      if (form.license) cr.license = form.license;
      if (form.commercialLicensing) cr.commercial_licensing = form.commercialLicensing;
      if (form.aiTraining) cr.ai_training = form.aiTraining;
      if (form.contactPreference) cr.contact_preference = form.contactPreference;
      const contentRights = Object.keys(cr).length > 0 ? cr : null;

      const result = await invoke<any>("sign_file", {
        fileHash: target.value.file_hash,
        intent: target.value.intent || "authorship",
        aiGeneration: form.aiGeneration || null,
        contentRights: contentRights,
        integrityReport: null,
        perceptualHash: target.value.perceptual_hash || null,
        comment: form.comment.trim() || null,
        supersedes: target.value.action_hash,
      });
      // Carry the original thumbnail across to the new chain head.
      // Thumbnails are a separate DHT entry keyed by signature action_hash,
      // so the amended signature would otherwise show the default
      // file-type SVG even when the original had a custom or auto-
      // generated thumbnail. Awaited so the refreshed list shows the
      // thumbnail without a flicker.
      if (target.value.thumbnail && result?.action_hash) {
        try {
          await invoke("set_thumbnail", {
            actionHashHex: result.action_hash,
            thumbnail: target.value.thumbnail,
          });
        } catch (e) {
          // Non-blocking — the amend itself succeeded.
          console.warn("Failed to carry thumbnail to amended signature:", e);
        }
      }
      await onAmended$();
      target.value = null;
    } catch (e: any) {
      error.value = (typeof e === "string" ? e : e.message) || "Amendment failed";
    } finally {
      submitting.value = false;
    }
  });

  if (!target.value) return null;
  return (
    <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm overflow-y-auto py-8">
      <div class="mx-4 w-full max-w-md rounded-xl border border-gray-600 bg-gray-800 p-6 shadow-2xl">
        <h3 class="mb-2 text-base font-semibold text-white">Amend Signature</h3>
        <p class="mb-4 text-xs text-gray-400">
          This creates a new signature replacing your previous one. The original stays permanently on the public DHT — amending doesn't delete history.
        </p>
        <div class="mb-4 rounded-lg border border-gray-700 bg-gray-900 p-3">
          <p class="truncate text-xs font-mono text-gray-400">
            {target.value.file_hash?.slice(0, 24)}...
          </p>
        </div>

        <div class="space-y-3">
          <div>
            <label class="mb-1 block text-xs text-gray-500">AI Generation</label>
            <select style={{ colorScheme: "dark" }} class={selectClass} value={form.aiGeneration}
              onChange$={(e) => { form.aiGeneration = (e.target as HTMLSelectElement).value; }}>
              <option value="">-- Not declared --</option>
              <option value="none">No AI</option>
              <option value="generated">AI Generated</option>
              <option value="assisted">Part AI Generated</option>
            </select>
          </div>
          <div>
            <label class="mb-1 block text-xs text-gray-500">License</label>
            <select style={{ colorScheme: "dark" }} class={selectClass} value={form.license}
              onChange$={(e) => { form.license = (e.target as HTMLSelectElement).value; }}>
              <option value="">-- Not declared --</option>
              <option value="all-rights-reserved">Copyright protected</option>
              <option value="cc0">Public domain (CC0)</option>
              <option value="cc-by">Free to share with credit (CC BY)</option>
              <option value="cc-by-sa">Free to share with credit, same license (CC BY-SA)</option>
              <option value="cc-by-nc">Free for non-commercial use with credit (CC BY-NC)</option>
              <option value="cc-by-nc-sa">Non-commercial, credit, same license (CC BY-NC-SA)</option>
              <option value="mit">MIT License</option>
              <option value="apache-2">Apache 2.0 License</option>
              <option value="gpl-3">GPL 3.0 License</option>
            </select>
          </div>
          <div>
            <label class="mb-1 block text-xs text-gray-500">Commercial Licensing</label>
            <select style={{ colorScheme: "dark" }} class={selectClass} value={form.commercialLicensing}
              onChange$={(e) => {
                form.commercialLicensing = (e.target as HTMLSelectElement).value;
                if ((e.target as HTMLSelectElement).value === "open_to_licensing") form.contactPreference = "allow_contact_requests";
              }}>
              <option value="">-- Not declared --</option>
              <option value="not_available">Not available for licensing</option>
              <option value="open_to_licensing">Open to licensing enquiries</option>
            </select>
          </div>
          <div>
            <label class="mb-1 block text-xs text-gray-500">AI Training</label>
            <select style={{ colorScheme: "dark" }} class={selectClass} value={form.aiTraining}
              onChange$={(e) => {
                form.aiTraining = (e.target as HTMLSelectElement).value;
                if ((e.target as HTMLSelectElement).value === "requires_license") form.contactPreference = "allow_contact_requests";
              }}>
              <option value="">-- Not declared --</option>
              <option value="not_allowed">Do not use to train AI</option>
              <option value="requires_license">Get permission before training AI</option>
              <option value="allowed_with_attribution">Can train AI if they credit me</option>
              <option value="allowed">Anyone can use this to train AI</option>
            </select>
          </div>
          <div>
            <label class="mb-1 block text-xs text-gray-500">Contact Preference</label>
            <select style={{ colorScheme: "dark" }} class={selectClass} value={form.contactPreference}
              onChange$={(e) => { form.contactPreference = (e.target as HTMLSelectElement).value; }}>
              <option value="">-- Not declared --</option>
              <option value="no_contact">Do not contact me</option>
              <option value="allow_contact_requests">Allow contact requests</option>
            </select>
          </div>
          <div>
            <label class="mb-1 flex items-baseline justify-between text-xs text-gray-500">
              <span>Note (optional)</span>
              {form.comment.length > 0 && (
                <span class="text-[10px] text-gray-500">{form.comment.length}/280</span>
              )}
            </label>
            <textarea
              rows={2}
              maxLength={280}
              placeholder="Add a note about this amendment"
              style={{ colorScheme: "dark" }}
              class="w-full rounded-md border border-gray-600 bg-gray-800 px-3 py-2 text-sm text-gray-200 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400 resize-y"
              value={form.comment}
              onInput$={(e) => { form.comment = (e.target as HTMLTextAreaElement).value; }}
            />
          </div>
        </div>

        {error.value && (
          <div class="mt-3 rounded-lg border border-red-800/50 bg-red-900/20 p-2">
            <p class="text-xs text-red-400">{error.value}</p>
          </div>
        )}

        <div class="mt-4 flex gap-3">
          <GlassButton variant="secondary" class="flex-1" onClick$={close}>Cancel</GlassButton>
          <GlassButton
            class="flex-1"
            disabled={submitting.value}
            onClick$={handleAmend}
          >
            {submitting.value ? "Saving..." : "Save Amendment"}
          </GlassButton>
        </div>
      </div>
    </div>
  );
});
