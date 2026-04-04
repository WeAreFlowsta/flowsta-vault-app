import {
  component$,
  useSignal,
  useStore,
  $,
  useVisibleTask$,
} from "@builder.io/qwik";
import { Link } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import { GlassButton } from "~/components/common/GlassButton";

// Shared select styling matching Settings auto-lock dropdown
const selectClass =
  "w-full rounded-md border border-gray-600 bg-gray-800 px-4 py-2.5 text-sm text-gray-200 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400";

interface IntegrityIssue {
  check_type: string;
  severity: string;
  description: string;
}

interface IntegrityReport {
  checks_performed: string[];
  issues_found: IntegrityIssue[];
  checked_at: number;
}

interface SignResult {
  success: boolean;
  file_hash: string;
  signature: string;
  agent_pub_key: string;
  signed_at: number;
  action_hash: string | null;
}

type SigningStep = "idle" | "selected" | "analyzing" | "ready" | "signing" | "done";

export default component$(() => {
  const step = useSignal<SigningStep>("idle");
  const selectedFile = useSignal<string | null>(null);
  const fileName = useSignal("");
  const fileSize = useSignal(0);
  const fileHash = useSignal("");
  const integrityReport = useSignal<IntegrityReport | null>(null);
  const signResult = useSignal<SignResult | null>(null);
  const error = useSignal("");
  const isDragOver = useSignal(false);
  const recentSignatures = useSignal<SignResult[]>([]);

  // Signal to receive file path from Tauri drag-drop (bridges native event → Qwik reactivity)
  const droppedFilePath = useSignal<string | null>(null);

  // Listen for Tauri native drag-and-drop
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ cleanup }) => {
    const unlistenPromise = getCurrentWebview().onDragDropEvent((event) => {
      if (event.payload.type === "enter" || event.payload.type === "over") {
        isDragOver.value = true;
      } else if (event.payload.type === "drop") {
        isDragOver.value = false;
        const paths = (event.payload as any).paths as string[];
        if (paths?.length > 0 && step.value === "idle") {
          droppedFilePath.value = paths[0];
        }
      } else {
        isDragOver.value = false;
      }
    });

    cleanup(() => {
      unlistenPromise.then((fn) => fn());
    });
  });

  // React to dropped file path — inline the processFile logic
  // (QRL functions like processFile aren't available in useVisibleTask$)
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async ({ track }) => {
    const filePath = track(() => droppedFilePath.value);
    if (!filePath) return;
    droppedFilePath.value = null;

    error.value = "";
    selectedFile.value = filePath;
    const parts = filePath.replace(/\\/g, "/").split("/");
    fileName.value = parts[parts.length - 1];
    step.value = "analyzing";

    try {
      const { invoke: inv } = await import("@tauri-apps/api/core");
      const hash = await inv<string>("hash_file", { path: filePath });
      fileHash.value = hash;
      const report = await inv<IntegrityReport>("analyze_file", { path: filePath });
      integrityReport.value = report;
      step.value = "ready";
    } catch (e: any) {
      error.value = `Analysis failed: ${e}`;
      step.value = "idle";
    }
  });

  // Load recent signatures from the signing DNA on mount.
  // Retries a few times since the conductor may still be starting up.
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async () => {
    const { invoke: inv } = await import("@tauri-apps/api/core");
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        const sigs = await inv<any[]>("get_my_signatures");
        if (Array.isArray(sigs) && sigs.length > 0) {
          recentSignatures.value = sigs;
          return;
        }
      } catch (e) {
        // Conductor may not be ready yet
      }
      // Wait before retrying (3s, 5s, 8s, 12s, 15s)
      await new Promise((r) => setTimeout(r, (attempt + 1) * 2000 + 1000));
    }
  });

  // Metadata form
  const metadata = useStore({
    intent: "authorship",
    aiGeneration: "none",
    license: "all-rights-reserved",
    commercialLicensing: "not_available",
    aiTraining: "not_allowed",
    contactPreference: "no_contact",
  });

  const processFile = $(async (filePath: string) => {
    error.value = "";
    selectedFile.value = filePath;

    // Extract filename from path
    const parts = filePath.replace(/\\/g, "/").split("/");
    fileName.value = parts[parts.length - 1];

    step.value = "analyzing";

    try {
      // Hash the file
      const hash = await invoke<string>("hash_file", { path: filePath });
      fileHash.value = hash;

      // Run integrity checks
      const report = await invoke<IntegrityReport>("analyze_file", {
        path: filePath,
      });
      integrityReport.value = report;

      step.value = "ready";
    } catch (e) {
      error.value = `Analysis failed: ${e}`;
      step.value = "idle";
    }
  });

  const handleFilePick = $(async () => {
    const selected = await open({
      multiple: false,
      title: "Select a file to sign",
    });
    if (selected) {
      await processFile(selected as string);
    }
  });

  const handleSign = $(async () => {
    if (!fileHash.value) return;

    step.value = "signing";
    error.value = "";

    try {
      const contentRights = {
        license: metadata.license,
        commercial_licensing: metadata.commercialLicensing,
        ai_training: metadata.aiTraining,
        contact_preference: metadata.contactPreference,
      };

      const result = await invoke<SignResult>("sign_file", {
        fileHash: fileHash.value,
        intent: metadata.intent,
        aiGeneration: metadata.aiGeneration,
        contentRights: contentRights,
        integrityReport: integrityReport.value || null,
      });

      signResult.value = result;
      step.value = "done";

      // Add to recent signatures (prepend)
      recentSignatures.value = [result, ...recentSignatures.value.slice(0, 9)];
    } catch (e) {
      error.value = `Signing failed: ${e}`;
      step.value = "ready";
    }
  });

  const resetForm = $(() => {
    step.value = "idle";
    selectedFile.value = null;
    fileName.value = "";
    fileSize.value = 0;
    fileHash.value = "";
    integrityReport.value = null;
    signResult.value = null;
    error.value = "";
  });

  return (
    <div>
      <h1 class="mb-6 text-2xl font-bold text-white">Sign It</h1>

      {/* ── Sign a File section ────────────────────────────────── */}
      <div class="mb-6 rounded-lg border border-gray-700 bg-gray-900 p-6">
        <h3 class="mb-4 text-sm font-semibold uppercase tracking-wider text-gray-500">
          Sign a File
        </h3>

        {step.value === "idle" && (
          <div>
            {/* Drag and drop zone — visual only, actual drop handled by Tauri events */}
            <div
              class={[
                "relative flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-8 transition-colors cursor-pointer",
                isDragOver.value
                  ? "border-amber-400 bg-amber-500/10"
                  : "border-gray-600 hover:border-gray-500 hover:bg-gray-800/50",
              ].join(" ")}
              onClick$={handleFilePick}
            >
              <svg
                class="mb-3 h-10 w-10 text-gray-500"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                stroke-width={1.5}
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  d="M12 16.5V9.75m0 0l3 3m-3-3l-3 3M6.75 19.5a4.5 4.5 0 01-1.41-8.775 5.25 5.25 0 0110.338-2.32 3 3 0 013.438 3.168A3.75 3.75 0 0118 19.5H6.75z"
                />
              </svg>
              <p class="mb-1 text-sm text-gray-300">
                Drag and drop a file here
              </p>
              <p class="text-xs text-gray-500">or click to select a file</p>
            </div>

            {/* File picker button (alternative) */}
            <div class="mt-3 flex justify-center">
              <GlassButton variant="secondary" onClick$={handleFilePick}>
                Choose File
              </GlassButton>
            </div>
          </div>
        )}

        {step.value === "analyzing" && (
          <div class="flex flex-col items-center py-8">
            <div class="mb-3 h-8 w-8 animate-spin rounded-full border-2 border-amber-400 border-t-transparent" />
            <p class="text-sm text-gray-300">
              Analyzing <span class="font-medium text-white">{fileName.value}</span>...
            </p>
          </div>
        )}

        {(step.value === "ready" || step.value === "signing") && (
          <div>
            {/* File info */}
            <div class="mb-4 rounded-lg border border-gray-700 bg-gray-800 p-4">
              <div class="flex items-center gap-3">
                <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-amber-500/20">
                  <svg class="h-5 w-5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={1.5}>
                    <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                  </svg>
                </div>
                <div class="min-w-0 flex-1">
                  <p class="truncate text-sm font-medium text-white">{fileName.value}</p>
                  <p class="truncate text-xs font-mono text-gray-500">{fileHash.value}</p>
                </div>
                <button
                  class="text-xs text-gray-500 hover:text-gray-300"
                  onClick$={resetForm}
                >
                  Change
                </button>
              </div>
            </div>

            {/* Integrity report */}
            {integrityReport.value && (
              <div class="mb-4 rounded-lg border border-gray-700 bg-gray-800 p-4">
                <h4 class="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
                  Integrity Check
                </h4>
                {integrityReport.value.issues_found.length === 0 ? (
                  <div class="flex items-center gap-2">
                    <span class="h-2 w-2 rounded-full bg-green-400" />
                    <span class="text-sm text-green-400">
                      {integrityReport.value.checks_performed.length} checks passed — no issues found
                    </span>
                  </div>
                ) : (
                  <div class="space-y-2">
                    {integrityReport.value.issues_found.map((issue, i) => (
                      <div key={i} class="flex items-start gap-2">
                        <span
                          class={[
                            "mt-1 h-2 w-2 shrink-0 rounded-full",
                            issue.severity === "Critical"
                              ? "bg-red-400"
                              : issue.severity === "Warning"
                                ? "bg-yellow-400"
                                : "bg-blue-400",
                          ].join(" ")}
                        />
                        <span class="text-xs text-gray-300">{issue.description}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Metadata form */}
            <div class="mb-4 space-y-3">
              <div class="grid grid-cols-2 gap-3">
                <div>
                  <label class="mb-1 block text-xs text-gray-500">Intent</label>
                  <select
                    style={{ colorScheme: "dark" }}
                    class={selectClass}
                    value={metadata.intent}
                    onChange$={(e) => { metadata.intent = (e.target as HTMLSelectElement).value; }}
                  >
                    <option value="authorship">Authorship</option>
                    <option value="approval">Approval</option>
                    <option value="witness">Witness</option>
                    <option value="receipt">Receipt</option>
                    <option value="agreement">Agreement</option>
                  </select>
                </div>
                <div>
                  <label class="mb-1 block text-xs text-gray-500">AI Generation</label>
                  <select
                    style={{ colorScheme: "dark" }}
                    class={selectClass}
                    value={metadata.aiGeneration}
                    onChange$={(e) => { metadata.aiGeneration = (e.target as HTMLSelectElement).value; }}
                  >
                    <option value="none">No AI</option>
                    <option value="assisted">AI Assisted</option>
                    <option value="generated">AI Generated</option>
                  </select>
                </div>
              </div>

              {/* Content Rights */}
              <details class="rounded-lg border border-gray-700 bg-gray-800">
                <summary class="cursor-pointer px-4 py-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
                  Content Rights
                </summary>
                <div class="space-y-3 px-4 pb-4 pt-2">
                  <div>
                    <label class="mb-1 block text-xs text-gray-500">License</label>
                    <select
                      style={{ colorScheme: "dark" }}
                      class={selectClass}
                      value={metadata.license}
                      onChange$={(e) => { metadata.license = (e.target as HTMLSelectElement).value; }}
                    >
                      <option value="all-rights-reserved">All Rights Reserved</option>
                      <option value="cc0">CC0 (Public Domain)</option>
                      <option value="cc-by">CC BY</option>
                      <option value="cc-by-sa">CC BY-SA</option>
                      <option value="cc-by-nc">CC BY-NC</option>
                      <option value="cc-by-nc-sa">CC BY-NC-SA</option>
                      <option value="mit">MIT</option>
                      <option value="apache-2">Apache 2.0</option>
                      <option value="gpl-3">GPL 3.0</option>
                    </select>
                  </div>
                  <div>
                    <label class="mb-1 block text-xs text-gray-500">Commercial Licensing</label>
                    <select
                      style={{ colorScheme: "dark" }}
                      class={selectClass}
                      value={metadata.commercialLicensing}
                      onChange$={(e) => { metadata.commercialLicensing = (e.target as HTMLSelectElement).value; }}
                    >
                      <option value="not_available">Not available</option>
                      <option value="open_to_licensing">Open to licensing</option>
                    </select>
                  </div>
                  <div>
                    <label class="mb-1 block text-xs text-gray-500">AI Training Policy</label>
                    <select
                      style={{ colorScheme: "dark" }}
                      class={selectClass}
                      value={metadata.aiTraining}
                      onChange$={(e) => { metadata.aiTraining = (e.target as HTMLSelectElement).value; }}
                    >
                      <option value="allowed">Allowed</option>
                      <option value="allowed_with_attribution">Allowed with attribution</option>
                      <option value="requires_license">Requires license</option>
                      <option value="not_allowed">Not allowed</option>
                    </select>
                  </div>
                  <div>
                    <label class="mb-1 block text-xs text-gray-500">Contact Preference</label>
                    <select
                      style={{ colorScheme: "dark" }}
                      class={selectClass}
                      value={metadata.contactPreference}
                      onChange$={(e) => { metadata.contactPreference = (e.target as HTMLSelectElement).value; }}
                    >
                      <option value="no_contact">Do not contact</option>
                      <option value="allow_contact_requests">Allow contact requests</option>
                    </select>
                  </div>
                </div>
              </details>
            </div>

            {/* Sign button */}
            <div class="flex gap-3">
              <GlassButton variant="secondary" onClick$={resetForm}>
                Cancel
              </GlassButton>
              <GlassButton
                class="flex-1"
                onClick$={handleSign}
                disabled={step.value === "signing"}
              >
                {step.value === "signing" ? "Signing..." : "Sign File"}
              </GlassButton>
            </div>
          </div>
        )}

        {step.value === "done" && signResult.value && (
          <div>
            <div class="mb-4 flex flex-col items-center py-4">
              <div class="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-green-500/20">
                <svg class="h-6 w-6 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                  <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                </svg>
              </div>
              <p class="text-lg font-semibold text-white">Signed</p>
              <p class="text-xs text-gray-400">{fileName.value}</p>
            </div>

            <div class="mb-4 space-y-3 rounded-lg border border-gray-700 bg-gray-800 p-4">
              <div>
                <div class="mb-1 flex items-center justify-between">
                  <span class="text-xs text-gray-500">File Hash</span>
                  <button
                    class="text-xs text-amber-400 hover:text-amber-300"
                    onClick$={() => navigator.clipboard.writeText(signResult.value!.file_hash)}
                  >
                    Copy
                  </button>
                </div>
                <p class="break-all text-xs font-mono text-gray-300">
                  {signResult.value.file_hash}
                </p>
              </div>
              <div>
                <div class="mb-1 flex items-center justify-between">
                  <span class="text-xs text-gray-500">Agent</span>
                  <button
                    class="text-xs text-amber-400 hover:text-amber-300"
                    onClick$={() => navigator.clipboard.writeText(signResult.value!.agent_pub_key)}
                  >
                    Copy
                  </button>
                </div>
                <p class="break-all text-xs font-mono text-gray-300">
                  {signResult.value.agent_pub_key}
                </p>
              </div>
              {signResult.value.action_hash && (
                <div>
                  <div class="mb-1 flex items-center justify-between">
                    <span class="text-xs text-gray-500">DHT Action</span>
                    <button
                      class="text-xs text-amber-400 hover:text-amber-300"
                      onClick$={() => navigator.clipboard.writeText(signResult.value!.action_hash!)}
                    >
                      Copy
                    </button>
                  </div>
                  <p class="break-all text-xs font-mono text-gray-300">
                    {signResult.value.action_hash}
                  </p>
                </div>
              )}
              {!signResult.value.action_hash && (
                <div class="flex items-center gap-2">
                  <span class="h-2 w-2 rounded-full bg-yellow-400" />
                  <span class="text-xs text-yellow-400">Signed locally — not yet committed to DHT</span>
                </div>
              )}
            </div>

            <GlassButton class="w-full" onClick$={resetForm}>
              Sign Another File
            </GlassButton>
          </div>
        )}

        {error.value && (
          <div class="mt-3 rounded-lg border border-red-800/50 bg-red-900/20 p-3">
            <p class="text-xs text-red-400">{error.value}</p>
          </div>
        )}
      </div>

      {/* ── Recent Signatures section ─────────────────────────── */}
      <div class="rounded-lg border border-gray-700 bg-gray-900 p-6">
        <div class="mb-4 flex items-center justify-between">
          <h3 class="text-sm font-semibold uppercase tracking-wider text-gray-500">
            Recent Signatures
          </h3>
          {recentSignatures.value.length > 0 && (
            <Link
              href="/sign-it/signatures/"
              class="text-xs text-amber-400 hover:text-amber-300"
            >
              View all
            </Link>
          )}
        </div>

        {recentSignatures.value.length === 0 ? (
          <p class="py-4 text-center text-sm text-gray-500">
            No signatures yet. Sign a file above to get started.
          </p>
        ) : (
          <div class="space-y-3">
            {recentSignatures.value.slice(0, 5).map((sig, i) => (
              <div
                key={i}
                class="flex items-center gap-3 rounded-lg border border-gray-700 bg-gray-800 p-3"
              >
                <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-amber-500/20">
                  <svg class="h-4 w-4 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                    <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                  </svg>
                </div>
                <div class="min-w-0 flex-1">
                  <p class="truncate text-xs font-mono text-gray-300">
                    {sig.file_hash.slice(0, 24)}...
                  </p>
                  <p class="text-xs text-gray-500">
                    {new Date(sig.signed_at).toLocaleDateString()}
                  </p>
                </div>
                <span class="rounded-full bg-gray-700 px-2 py-0.5 text-xs text-gray-300">
                  {sig.action_hash ? "On DHT" : "Local"}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
});
