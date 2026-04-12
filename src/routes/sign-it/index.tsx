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
import { SignQuotaMeter, type SignQuotaState } from "~/components/sign-it/SignQuotaMeter";

// Shared select styling matching Settings auto-lock dropdown
const selectClass =
  "w-full rounded-md border border-gray-600 bg-gray-800 px-4 py-2.5 text-sm text-gray-200 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400";

function formatRelativeTime(timestampMs: number): string {
  const now = Date.now();
  const diff = now - timestampMs;
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(timestampMs).toLocaleDateString();
}

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

interface FileEntry {
  path: string;
  name: string;
  hash: string;
  integrityReport: IntegrityReport | null;
  perceptualHash: any | null;
}

/** Get the default thumbnail SVG path based on available signature data. */
function getDefaultThumbnail(sig: any): string {
  // Check perceptual hash type first (most reliable)
  const hashType = sig.perceptual_hash?.hash_type;
  if (hashType === "ImagePHash") return "/sign-it/thumbnails/image.svg";
  if (hashType === "AudioChromaprint") return "/sign-it/thumbnails/audio.svg";
  if (hashType === "VideoPHash") return "/sign-it/thumbnails/video.svg";

  // Fall back to file extension from fileName
  const name = (sig.fileName || "").toLowerCase();
  if (/\.(png|jpe?g|gif|bmp|tiff?|webp|svg)$/i.test(name)) return "/sign-it/thumbnails/image.svg";
  if (/\.(mp3|wav|flac|ogg|aac|m4a|wma)$/i.test(name)) return "/sign-it/thumbnails/audio.svg";
  if (/\.(mp4|mkv|avi|webm|mov|wmv)$/i.test(name)) return "/sign-it/thumbnails/video.svg";
  if (/\.(pdf|doc|docx|odt|rtf|txt|pages)$/i.test(name)) return "/sign-it/thumbnails/document.svg";
  if (/\.(js|ts|py|rs|go|java|c|cpp|h|css|html|json|xml|yaml|yml|sh|rb|php)$/i.test(name)) return "/sign-it/thumbnails/code.svg";
  if (/\.(zip|tar|gz|bz2|7z|rar|xz)$/i.test(name)) return "/sign-it/thumbnails/archive.svg";

  return "/sign-it/thumbnails/file.svg";
}

type SigningStep = "idle" | "selected" | "analyzing" | "ready" | "signing" | "done";

export default component$(() => {
  const step = useSignal<SigningStep>("idle");
  const selectedFile = useSignal<string | null>(null);
  const fileName = useSignal("");
  const fileSize = useSignal(0);
  const fileHash = useSignal("");
  const integrityReport = useSignal<IntegrityReport | null>(null);
  const perceptualHash = useSignal<any | null>(null);
  const signResult = useSignal<SignResult | null>(null);
  const error = useSignal("");
  const isDragOver = useSignal(false);
  const recentSignatures = useSignal<SignResult[]>([]);
  const signaturesLoaded = useSignal(false);
  const existingSignatures = useSignal<any[]>([]);

  // Thumbnail state (auto-generated for images)
  const thumbnailData = useSignal<string | null>(null);

  // Multi-file state
  const fileEntries = useSignal<FileEntry[]>([]);
  const hashingProgress = useSignal("");
  const signingProgress = useSignal(0);
  const signResults = useSignal<any[]>([]);
  const isBatch = useSignal(false);

  // Revocation dialog state
  const revokeTarget = useSignal<any | null>(null);
  const revokeReason = useSignal("");
  const revoking = useSignal(false);

  // Phase 8: Sign quota (HMAC-signed local cache + online refresh)
  const quota = useSignal<SignQuotaState | null>(null);
  const quotaLoading = useSignal(true);

  const refreshQuota = $(async () => {
    // Try online first via the public quota-by-agent endpoint.
    // Prefer web_agent_pub_key (the linked Flowsta account) over the local
    // Vault agent — that's the one the user's subscription is attached to.
    try {
      const id = await invoke<{ agent_pub_key: string; web_agent_pub_key: string | null }>("get_identity");
      const agentKey = id?.web_agent_pub_key || id?.agent_pub_key;
      if (agentKey) {
        const apiUrl = (window as any).__API_URL__ || "https://auth-api-staging.flowsta.com";
        const resp = await fetch(
          `${apiUrl}/api/v1/sign-it/quota/by-agent?agent_pub_key=${encodeURIComponent(agentKey)}`,
          { cache: "no-store" }
        );
        if (resp.ok) {
          const fresh = await resp.json();
          // Sync to HMAC-signed local cache
          const cached = await invoke<SignQuotaState | null>("write_quota_cache", {
            cache: {
              tier: fresh.tier,
              used: fresh.used,
              limit: Number.isFinite(fresh.limit) ? fresh.limit : 0,
              period_end: fresh.resets_at || null,
              last_synced_at: Date.now(),
              write_counter: 0,
            },
          });
          quota.value = { ...(cached as any), source: "online" };
          quotaLoading.value = false;
          return;
        }
      }
    } catch { /* offline — fall through to cache */ }

    // Offline fallback: use HMAC-signed cache
    try {
      const cached = await invoke<SignQuotaState | null>("read_quota_cache");
      if (cached) {
        quota.value = { ...(cached as any), source: "cache" };
      }
    } catch { /* no cache yet */ }
    quotaLoading.value = false;
  });

  // Signals to receive file paths from Tauri drag-drop (bridges native event → Qwik reactivity)
  const droppedFilePath = useSignal<string | null>(null);
  const droppedFilePaths = useSignal<string[] | null>(null);

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
          if (paths.length === 1) {
            droppedFilePath.value = paths[0];
          } else {
            // Multi-file drop — use batch flow
            droppedFilePaths.value = paths;
          }
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

      // Generate perceptual hash
      try {
        const phash = await inv<any>("generate_perceptual_hash", { path: filePath });
        perceptualHash.value = phash;
      } catch { perceptualHash.value = null; }

      // Generate thumbnail (images only)
      try {
        const thumb = await inv<string | null>("generate_thumbnail", { path: filePath });
        thumbnailData.value = thumb;
      } catch { thumbnailData.value = null; }

      // Check existing signatures (API first, local conductor fallback)
      existingSignatures.value = [];
      try {
        const apiUrl = (window as any).__API_URL__ || "https://auth-api-staging.flowsta.com";
        const resp = await fetch(`${apiUrl}/api/v1/sign-it/verify?hash=${hash}`);
        if (resp.ok) {
          const data = await resp.json();
          if (data.signatures?.length > 0) existingSignatures.value = data.signatures;
        }
      } catch {
        try {
          const localSigs = await inv<any[]>("get_signatures_for_hash", { fileHash: hash });
          if (Array.isArray(localSigs) && localSigs.length > 0) existingSignatures.value = localSigs;
        } catch { /* offline, no check available */ }
      }

      step.value = "ready";
    } catch (e: any) {
      error.value = `Analysis failed: ${e}`;
      step.value = "idle";
    }
  });

  // React to multi-file drop — batch hash and analyze
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async ({ track }) => {
    const paths = track(() => droppedFilePaths.value);
    if (!paths || paths.length === 0) return;
    droppedFilePaths.value = null;

    error.value = "";
    isBatch.value = true;
    step.value = "analyzing";
    hashingProgress.value = `0 of ${paths.length}`;

    try {
      const { invoke: inv } = await import("@tauri-apps/api/core");
      const entries: FileEntry[] = [];

      for (let i = 0; i < paths.length; i++) {
        const filePath = paths[i];
        const parts = filePath.replace(/\\/g, "/").split("/");
        const name = parts[parts.length - 1];
        hashingProgress.value = `${i + 1} of ${paths.length}`;

        const hash = await inv<string>("hash_file", { path: filePath });
        const report = await inv<IntegrityReport>("analyze_file", { path: filePath });

        let phash = null;
        try { phash = await inv<any>("generate_perceptual_hash", { path: filePath }); } catch {}

        entries.push({ path: filePath, name, hash, integrityReport: report, perceptualHash: phash });
      }

      fileEntries.value = entries;
      step.value = "ready";
    } catch (e: any) {
      error.value = `Analysis failed: ${e}`;
      step.value = "idle";
    }
  });

  // Phase 8: refresh quota when the Vault window regains focus.
  // Covers the case where a user signs on Website → switches to Vault:
  // the meter updates to reflect the server-side change.
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ cleanup }) => {
    const onFocus = () => { refreshQuota(); };
    const onVisibility = () => {
      if (document.visibilityState === "visible") refreshQuota();
    };
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVisibility);
    cleanup(() => {
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onVisibility);
    });
  });

  // Load recent signatures from the signing DNA on mount.
  // Retries a few times since the conductor may still be starting up.
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async () => {
    const { invoke: inv } = await import("@tauri-apps/api/core");
    // Phase 8: load sign quota in parallel (don't block signature loading)
    refreshQuota();
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        const sigs = await inv<any[]>("get_my_signatures");
        if (Array.isArray(sigs) && sigs.length > 0) {
          recentSignatures.value = sigs;
          signaturesLoaded.value = true;
          return;
        }
        // Successful call but empty — conductor is ready, genuinely no signatures
        if (Array.isArray(sigs)) {
          signaturesLoaded.value = true;
          return;
        }
      } catch (e) {
        // Conductor may not be ready yet — keep retrying
      }
      await new Promise((r) => setTimeout(r, (attempt + 1) * 2000 + 1000));
    }
    // All retries exhausted
    signaturesLoaded.value = true;
  });

  // Metadata form — all empty by default (opt-in declarations)
  const metadata = useStore({
    intent: "authorship",
    aiGeneration: "",
    license: "",
    commercialLicensing: "",
    aiTraining: "",
    contactPreference: "",
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

      // Generate perceptual hash (for fuzzy matching)
      try {
        const phash = await invoke<any>("generate_perceptual_hash", { path: filePath });
        perceptualHash.value = phash;
      } catch {
        perceptualHash.value = null;
      }

      // Generate thumbnail (images only)
      try {
        const thumb = await invoke<string | null>("generate_thumbnail", { path: filePath });
        thumbnailData.value = thumb;
      } catch {
        thumbnailData.value = null;
      }

      // Check for existing signatures (API first, fall back to local conductor)
      existingSignatures.value = [];
      try {
        const apiUrl = (window as any).__API_URL__ || "https://auth-api-staging.flowsta.com";
        const resp = await fetch(`${apiUrl}/api/v1/sign-it/verify?hash=${hash}`);
        if (resp.ok) {
          const data = await resp.json();
          if (data.signatures?.length > 0) {
            existingSignatures.value = data.signatures;
          }
        }
      } catch {
        // Offline or API unavailable — try local conductor
        try {
          const localSigs = await invoke<any[]>("get_signatures_for_hash", { fileHash: hash });
          if (Array.isArray(localSigs) && localSigs.length > 0) {
            existingSignatures.value = localSigs;
          }
        } catch {
          // No existing signatures check available — continue anyway
        }
      }

      step.value = "ready";
    } catch (e) {
      error.value = `Analysis failed: ${e}`;
      step.value = "idle";
    }
  });

  const handleFilePick = $(async () => {
    const selected = await open({
      multiple: true,
      title: "Select files to sign",
    });
    if (selected) {
      if (Array.isArray(selected)) {
        if (selected.length === 1) {
          await processFile(selected[0]);
        } else if (selected.length > 1) {
          droppedFilePaths.value = selected;
        }
      } else {
        await processFile(selected as string);
      }
    }
  });

  const buildContentRights = $(() => {
    const cr: Record<string, string> = {};
    if (metadata.license) cr.license = metadata.license;
    if (metadata.commercialLicensing) cr.commercial_licensing = metadata.commercialLicensing;
    if (metadata.aiTraining) cr.ai_training = metadata.aiTraining;
    if (metadata.contactPreference) cr.contact_preference = metadata.contactPreference;
    return Object.keys(cr).length > 0 ? cr : null;
  });

  const filterReport = (report: IntegrityReport | null) => {
    if (!report) return null;
    const concerns = report.issues_found.filter(
      (i) => i.severity === "Warning" || i.severity === "Critical"
    );
    return {
      checks_performed: report.checks_performed,
      issues_found: concerns,
      checked_at: report.checked_at,
    };
  };

  const handleSign = $(async () => {
    // Phase 8: refresh quota first (online preferred, fallback to cache)
    await refreshQuota();
    const q = quota.value;

    const requested = isBatch.value ? fileEntries.value.length : 1;
    if (q && Number.isFinite(q.limit)) {
      const remaining = Math.max(0, q.limit - q.used);
      if (requested > remaining) {
        error.value = remaining === 0
          ? `You've used all ${q.limit} signature${q.limit === 1 ? '' : 's'} for this period (${q.tier}). Upgrade at flowsta.com/dashboard/premium to keep signing.`
          : `Batch of ${requested} exceeds your remaining quota (${remaining} of ${q.limit} on ${q.tier}). Upgrade or sign fewer files.`;
        step.value = "ready";
        return;
      }
    }

    step.value = "signing";
    error.value = "";

    const contentRights = await buildContentRights();

    if (isBatch.value && fileEntries.value.length > 0) {
      // Batch signing
      signingProgress.value = 0;
      const results: any[] = [];

      for (let i = 0; i < fileEntries.value.length; i++) {
        const entry = fileEntries.value[i];
        signingProgress.value = i + 1;
        try {
          const result = await invoke<SignResult>("sign_file", {
            fileHash: entry.hash,
            intent: metadata.intent,
            aiGeneration: metadata.aiGeneration || null,
            contentRights: contentRights,
            integrityReport: filterReport(entry.integrityReport),
            perceptualHash: entry.perceptualHash || null,
          });
          results.push({ ...result, fileName: entry.name, success: true });
          // Phase 8: increment local cache + update meter from cache (authoritative for display)
          const updatedCache = await invoke<SignQuotaState | null>("increment_quota_used").catch(() => null);
          if (updatedCache) {
            quota.value = { ...(updatedCache as any), source: quota.value?.source || "cache" };
          }
          // Sync to server in background — meter already updated from cache
          const apiUrl = (window as any).__API_URL__ || "https://auth-api-staging.flowsta.com";
          invoke("sync_quota_to_server", { apiUrl, count: 1 }).catch((err) => {
            console.warn("quota sync failed:", err);
          });
        } catch (e) {
          results.push({ fileName: entry.name, file_hash: entry.hash, success: false, error: `${e}` });
        }
      }

      signResults.value = results;
      const successful = results.filter(r => r.success);
      recentSignatures.value = [...successful, ...recentSignatures.value.slice(0, Math.max(0, 10 - successful.length))];
      step.value = "done";
    } else if (fileHash.value) {
      // Single file signing
      try {
        const result = await invoke<SignResult>("sign_file", {
          fileHash: fileHash.value,
          intent: metadata.intent,
          aiGeneration: metadata.aiGeneration || null,
          contentRights: contentRights,
          integrityReport: filterReport(integrityReport.value),
          perceptualHash: perceptualHash.value || null,
        });

        signResult.value = result;
        step.value = "done";
        // Phase 8: increment local cache + update meter from cache
        const updatedCache = await invoke<SignQuotaState | null>("increment_quota_used").catch(() => null);
        if (updatedCache) {
          quota.value = { ...(updatedCache as any), source: quota.value?.source || "cache" };
        }
        // Sync to server in background — meter already updated from cache
        const apiUrl = (window as any).__API_URL__ || "https://auth-api-staging.flowsta.com";
        invoke("sync_quota_to_server", { apiUrl, count: 1 }).catch((err) => {
          console.warn("quota sync failed:", err);
        });
        const enrichedResult = { ...result, fileName: fileName.value, thumbnail: thumbnailData.value };
        recentSignatures.value = [enrichedResult, ...recentSignatures.value.slice(0, 9)];

        // Store thumbnail on DHT (non-blocking, best-effort)
        if (thumbnailData.value && result.action_hash) {
          invoke("set_thumbnail", {
            actionHashHex: result.action_hash,
            thumbnail: thumbnailData.value,
          }).catch(() => { /* non-blocking — thumbnail is cosmetic */ });
        }
      } catch (e) {
        error.value = `Signing failed: ${e}`;
        step.value = "ready";
      }
    }
  });

  const resetForm = $(() => {
    step.value = "idle";
    selectedFile.value = null;
    fileName.value = "";
    fileSize.value = 0;
    fileHash.value = "";
    integrityReport.value = null;
    perceptualHash.value = null;
    signResult.value = null;
    existingSignatures.value = [];
    error.value = "";
    thumbnailData.value = null;
    // Batch state
    fileEntries.value = [];
    signResults.value = [];
    isBatch.value = false;
    signingProgress.value = 0;
    hashingProgress.value = "";
  });

  const handleRevoke = $(async () => {
    if (!revokeTarget.value?.action_hash) return;
    revoking.value = true;
    try {
      await invoke("revoke_signature", {
        actionHashHex: revokeTarget.value.action_hash,
        reason: revokeReason.value || null,
      });
      // Remove from local list
      recentSignatures.value = recentSignatures.value.filter(
        (s) => s.action_hash !== revokeTarget.value?.action_hash
      );
      revokeTarget.value = null;
      revokeReason.value = "";
    } catch (e) {
      error.value = `Revocation failed: ${e}`;
    } finally {
      revoking.value = false;
    }
  });

  return (
    <div>
      <h1 class="mb-6 text-2xl font-bold text-white">Sign It</h1>

      {/* Phase 8: Sign quota meter (HMAC-signed local cache + online refresh) */}
      <div class="mb-6">
        <SignQuotaMeter quota={quota.value} loading={quotaLoading.value} />
      </div>

      {/* ── Sign a File section ────────────────────────────────── */}
      <div class="mb-6 rounded-lg border border-gray-700 bg-gray-900 p-6">
        <h3 class="mb-4 text-sm font-semibold uppercase tracking-wider text-gray-500">
          Sign Files
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
                Drag and drop files here
              </p>
              <p class="text-xs text-gray-500">or click to select files</p>
            </div>

            {/* File picker button (alternative) */}
            <div class="mt-3 flex justify-center">
              <GlassButton variant="secondary" onClick$={handleFilePick}>
                Choose Files
              </GlassButton>
            </div>
          </div>
        )}

        {step.value === "analyzing" && (
          <div class="flex flex-col items-center py-8">
            <div class="mb-3 h-8 w-8 animate-spin rounded-full border-2 border-amber-400 border-t-transparent" />
            <p class="text-sm text-gray-300">
              {isBatch.value
                ? <>Analyzing files... <span class="font-medium text-white">{hashingProgress.value}</span></>
                : <>Analyzing <span class="font-medium text-white">{fileName.value}</span>...</>}
            </p>
          </div>
        )}

        {(step.value === "ready" || step.value === "signing") && isBatch.value && (
          <div>
            {/* Batch file list */}
            <div class="mb-4 rounded-lg border border-gray-700 bg-gray-800 p-4">
              <div class="flex items-center justify-between mb-3">
                <p class="text-sm font-medium text-white">
                  {fileEntries.value.length} file{fileEntries.value.length !== 1 ? "s" : ""} ready to sign
                </p>
                <button class="text-xs text-gray-500 hover:text-gray-300" onClick$={resetForm}>Change</button>
              </div>
              <div class="space-y-2 max-h-48 overflow-y-auto">
                {fileEntries.value.map((entry, i) => (
                  <div key={i} class="flex items-center gap-3">
                    <div class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-amber-500/20">
                      <svg class="h-3.5 w-3.5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={1.5}>
                        <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                      </svg>
                    </div>
                    <div class="min-w-0 flex-1">
                      <p class="truncate text-sm text-white">{entry.name}</p>
                      <p class="truncate text-xs font-mono text-gray-500">{entry.hash.slice(0, 16)}...</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Content Rights for batch */}
            <div class="mb-4">
              <details class="rounded-lg border border-gray-700 bg-gray-800">
                <summary class="cursor-pointer px-4 py-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
                  Content Rights (applied to all files)
                </summary>
                <div class="space-y-3 px-4 pb-4 pt-2">
                  <div>
                    <label class="mb-1 block text-xs text-gray-500">AI Generation</label>
                    <select style={{ colorScheme: "dark" }} class={selectClass} value={metadata.aiGeneration}
                      onChange$={(e) => { metadata.aiGeneration = (e.target as HTMLSelectElement).value; }}>
                      <option value="">-- Not declared --</option>
                      <option value="none">No AI</option>
                      <option value="generated">AI Generated</option>
                      <option value="assisted">Part AI Generated</option>
                    </select>
                  </div>
                  <div>
                    <label class="mb-1 block text-xs text-gray-500">License</label>
                    <select style={{ colorScheme: "dark" }} class={selectClass} value={metadata.license}
                      onChange$={(e) => { metadata.license = (e.target as HTMLSelectElement).value; }}>
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
                    <select style={{ colorScheme: "dark" }} class={selectClass} value={metadata.commercialLicensing}
                      onChange$={(e) => {
                        metadata.commercialLicensing = (e.target as HTMLSelectElement).value;
                        if ((e.target as HTMLSelectElement).value === "open_to_licensing") metadata.contactPreference = "allow_contact_requests";
                      }}>
                      <option value="">-- Not declared --</option>
                      <option value="not_available">Not available for licensing</option>
                      <option value="open_to_licensing">Open to licensing enquiries</option>
                    </select>
                  </div>
                  <div>
                    <label class="mb-1 block text-xs text-gray-500">AI Training</label>
                    <select style={{ colorScheme: "dark" }} class={selectClass} value={metadata.aiTraining}
                      onChange$={(e) => {
                        metadata.aiTraining = (e.target as HTMLSelectElement).value;
                        if ((e.target as HTMLSelectElement).value === "requires_license") metadata.contactPreference = "allow_contact_requests";
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
                    <select style={{ colorScheme: "dark" }} class={selectClass} value={metadata.contactPreference}
                      onChange$={(e) => { metadata.contactPreference = (e.target as HTMLSelectElement).value; }}>
                      <option value="">-- Not declared --</option>
                      <option value="no_contact">Do not contact me</option>
                      <option value="allow_contact_requests">Allow contact requests</option>
                    </select>
                    {metadata.contactPreference === "allow_contact_requests" && (
                      <p class="mt-1.5 text-xs text-gray-500">
                        Your email and contact details are never shared. Messages are relayed privately through Flowsta.
                      </p>
                    )}
                  </div>
                </div>
              </details>
            </div>

            {/* Sign button */}
            <div class="flex gap-3">
              <GlassButton variant="secondary" onClick$={resetForm}>Cancel</GlassButton>
              <GlassButton
                class="flex-1"
                onClick$={handleSign}
                disabled={step.value === "signing"}
              >
                {step.value === "signing"
                  ? `Signing ${signingProgress.value} of ${fileEntries.value.length}...`
                  : `Sign ${fileEntries.value.length} Files`}
              </GlassButton>
            </div>
          </div>
        )}

        {(step.value === "ready" || step.value === "signing") && !isBatch.value && (
          <div>
            {/* Single file info */}
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
            {integrityReport.value && (() => {
              const warnings = integrityReport.value!.issues_found.filter(
                (i) => i.severity === "Warning" || i.severity === "Critical"
              );
              const info = integrityReport.value!.issues_found.filter(
                (i) => i.severity === "Info"
              );
              return (
                <div class="mb-4 rounded-lg border border-gray-700 bg-gray-800 p-4">
                  <h4 class="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
                    File Analysis
                  </h4>

                  {/* Summary line */}
                  <div class="flex items-center gap-2 mb-2">
                    <span class={[
                      "h-2 w-2 rounded-full",
                      warnings.length > 0 ? "bg-yellow-400" : "bg-green-400",
                    ].join(" ")} />
                    <span class={[
                      "text-sm",
                      warnings.length > 0 ? "text-yellow-400" : "text-green-400",
                    ].join(" ")}>
                      {warnings.length > 0
                        ? `${warnings.length} concern${warnings.length > 1 ? "s" : ""} found`
                        : `${integrityReport.value!.checks_performed.length} checks passed`}
                    </span>
                  </div>

                  {/* Warnings (if any) */}
                  {warnings.length > 0 && (
                    <div class="space-y-1.5 mb-3">
                      {warnings.map((issue, i) => (
                        <div key={i} class="flex items-start gap-2">
                          <span class={[
                            "mt-1 h-2 w-2 shrink-0 rounded-full",
                            issue.severity === "Critical" ? "bg-red-400" : "bg-yellow-400",
                          ].join(" ")} />
                          <span class="text-xs text-gray-300">{issue.description}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* File contents (Info items — always shown) */}
                  {info.length > 0 && (
                    <details class="mt-1">
                      <summary class="cursor-pointer text-xs text-gray-500 hover:text-gray-400">
                        What's in this file ({info.length} item{info.length > 1 ? "s" : ""})
                      </summary>
                      <div class="mt-2 space-y-1.5">
                        {info.map((issue, i) => (
                          <div key={i} class="flex items-start gap-2">
                            <span class="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-gray-500" />
                            <span class="text-xs text-gray-400">{issue.description}</span>
                          </div>
                        ))}
                      </div>
                    </details>
                  )}
                </div>
              );
            })()}

            {/* Existing signatures notice */}
            {existingSignatures.value.length > 0 && (
              <div class="mb-4 rounded-lg border border-amber-700/50 bg-amber-900/20 p-4">
                <div class="flex items-start gap-3">
                  <svg class="mt-0.5 h-4 w-4 shrink-0 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
                  </svg>
                  <div>
                    <p class="text-sm text-amber-300">
                      This file has been signed by {existingSignatures.value.length} other {existingSignatures.value.length === 1 ? "person" : "people"}
                    </p>
                    <p class="mt-1 text-xs text-gray-400">
                      You can still sign it — this is normal for shared documents, contracts, and collaborations.
                    </p>
                    <details class="mt-2">
                      <summary class="cursor-pointer text-xs text-amber-400/70 hover:text-amber-400">
                        View existing signatures
                      </summary>
                      <div class="mt-2 space-y-1.5">
                        {existingSignatures.value.map((sig: any, i: number) => (
                          <div key={i} class="flex items-center justify-between text-xs">
                            <span class="font-mono text-gray-400 truncate max-w-[200px]">
                              {sig.signer_did || sig.signer || sig.agent_pub_key || "Unknown"}
                            </span>
                            <span class="text-gray-500 whitespace-nowrap ml-2">
                              {sig.signed_at ? new Date(sig.signed_at).toLocaleDateString() : ""}
                              {sig.intent ? ` · ${sig.intent}` : ""}
                            </span>
                          </div>
                        ))}
                      </div>
                    </details>
                  </div>
                </div>
              </div>
            )}

            {/* Content Rights (all metadata grouped together) */}
            <div class="mb-4">
              <details class="rounded-lg border border-gray-700 bg-gray-800">
                <summary class="cursor-pointer px-4 py-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
                  Content Rights
                </summary>
                <div class="space-y-3 px-4 pb-4 pt-2">
                  <div>
                    <label class="mb-1 block text-xs text-gray-500">AI Generation</label>
                    <select
                      style={{ colorScheme: "dark" }}
                      class={selectClass}
                      value={metadata.aiGeneration}
                      onChange$={(e) => { metadata.aiGeneration = (e.target as HTMLSelectElement).value; }}
                    >
                      <option value="">-- Not declared --</option>
                      <option value="none">No AI</option>
                      <option value="generated">AI Generated</option>
                      <option value="assisted">Part AI Generated</option>
                    </select>
                  </div>
                  <div>
                    <label class="mb-1 block text-xs text-gray-500">License</label>
                    <select
                      style={{ colorScheme: "dark" }}
                      class={selectClass}
                      value={metadata.license}
                      onChange$={(e) => { metadata.license = (e.target as HTMLSelectElement).value; }}
                    >
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
                    <select
                      style={{ colorScheme: "dark" }}
                      class={selectClass}
                      value={metadata.commercialLicensing}
                      onChange$={(e) => {
                        metadata.commercialLicensing = (e.target as HTMLSelectElement).value;
                        // Auto-enable contact requests if open to licensing enquiries
                        if ((e.target as HTMLSelectElement).value === "open_to_licensing") {
                          metadata.contactPreference = "allow_contact_requests";
                        }
                      }}
                    >
                      <option value="">-- Not declared --</option>
                      <option value="not_available">Not available for licensing</option>
                      <option value="open_to_licensing">Open to licensing enquiries</option>
                    </select>
                  </div>
                  <div>
                    <label class="mb-1 block text-xs text-gray-500">AI Training</label>
                    <select
                      style={{ colorScheme: "dark" }}
                      class={selectClass}
                      value={metadata.aiTraining}
                      onChange$={(e) => {
                        metadata.aiTraining = (e.target as HTMLSelectElement).value;
                        if ((e.target as HTMLSelectElement).value === "requires_license") {
                          metadata.contactPreference = "allow_contact_requests";
                        }
                      }}
                    >
                      <option value="">-- Not declared --</option>
                      <option value="not_allowed">Do not use to train AI</option>
                      <option value="requires_license">Get permission before training AI</option>
                      <option value="allowed_with_attribution">Can train AI if they credit me</option>
                      <option value="allowed">Anyone can use this to train AI</option>
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
                      <option value="">-- Not declared --</option>
                      <option value="no_contact">Do not contact me</option>
                      <option value="allow_contact_requests">Allow contact requests</option>
                    </select>
                    {metadata.contactPreference === "allow_contact_requests" && (
                      <p class="mt-1.5 text-xs text-gray-500">
                        Your email and contact details are never shared. Messages are relayed privately through Flowsta.
                      </p>
                    )}
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

        {step.value === "done" && isBatch.value && signResults.value.length > 0 && (
          <div>
            <div class="mb-4 flex flex-col items-center py-4">
              <div class="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-green-500/20">
                <svg class="h-6 w-6 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                  <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                </svg>
              </div>
              <p class="text-lg font-semibold text-white">
                {signResults.value.filter((r: any) => r.success).length} of {signResults.value.length} files signed
              </p>
              {signResults.value.some((r: any) => !r.success) && (
                <p class="text-xs text-red-400">{signResults.value.filter((r: any) => !r.success).length} failed</p>
              )}
            </div>

            <div class="mb-4 max-h-48 overflow-y-auto space-y-2 rounded-lg border border-gray-700 bg-gray-800 p-4">
              {signResults.value.map((r: any, i: number) => (
                <div key={i} class="flex items-center gap-2 text-xs">
                  {r.success ? (
                    <span class="h-2 w-2 shrink-0 rounded-full bg-green-400" />
                  ) : (
                    <span class="h-2 w-2 shrink-0 rounded-full bg-red-400" />
                  )}
                  <span class="truncate text-gray-300">{r.fileName || r.file_hash?.slice(0, 16) + "..."}</span>
                </div>
              ))}
            </div>

            <GlassButton class="w-full" onClick$={resetForm}>
              Sign More Files
            </GlassButton>
          </div>
        )}

        {step.value === "done" && !isBatch.value && signResult.value && (
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

        {!signaturesLoaded.value ? (
          <div class="flex items-center justify-center gap-3 py-6">
            <div class="h-4 w-4 animate-spin rounded-full border-2 border-amber-400 border-t-transparent" />
            <p class="text-sm text-gray-500">Loading signatures...</p>
          </div>
        ) : recentSignatures.value.length === 0 ? (
          <p class="py-4 text-center text-sm text-gray-500">
            No signatures yet. Sign a file above to get started.
          </p>
        ) : (
          <div class="space-y-3">
            {recentSignatures.value
              .filter((s) => !s.revoked)
              .sort((a, b) => (b.signed_at || 0) - (a.signed_at || 0))
              .slice(0, 5)
              .map((sig, i) => (
              <div
                key={i}
                class="flex items-center gap-3 rounded-lg border border-gray-700 bg-gray-800 p-3"
              >
                <img
                  src={(sig as any).thumbnail || getDefaultThumbnail(sig)}
                  alt=""
                  width={40}
                  height={40}
                  class="h-10 w-10 shrink-0 rounded-lg object-cover"
                />
                <div class="min-w-0 flex-1">
                  {(sig as any).fileName ? (
                    <p class="truncate text-sm text-white">
                      {(sig as any).fileName}
                    </p>
                  ) : (
                    <p class="truncate text-xs font-mono text-gray-400">
                      {sig.file_hash?.slice(0, 16)}...
                    </p>
                  )}
                  <p class="text-xs text-gray-500">
                    {sig.signed_at ? formatRelativeTime(sig.signed_at) : ""}
                    {sig.intent ? ` · ${sig.intent}` : ""}
                  </p>
                </div>
                {sig.action_hash && (
                  <button
                    class="shrink-0 text-xs text-gray-500 hover:text-red-400 transition-colors"
                    onClick$={() => {
                      revokeTarget.value = sig;
                      revokeReason.value = "";
                    }}
                  >
                    Revoke
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Revocation confirmation dialog */}
      {revokeTarget.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div class="mx-4 w-full max-w-sm rounded-xl border border-gray-600 bg-gray-800 p-6 shadow-2xl">
            <h3 class="mb-2 text-base font-semibold text-white">Revoke Signature</h3>
            <p class="mb-4 text-xs text-gray-400">
              This will publicly mark this signature as revoked. The original record stays on the DHT but verifiers will see it as revoked.
            </p>

            <div class="mb-4 rounded-lg border border-gray-700 bg-gray-900 p-3">
              <p class="truncate text-xs font-mono text-gray-400">
                {(revokeTarget.value as any).fileName || revokeTarget.value.file_hash?.slice(0, 24) + "..."}
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
                value={revokeReason.value}
                onInput$={(e) => { revokeReason.value = (e.target as HTMLInputElement).value; }}
              />
            </div>

            <div class="flex gap-3">
              <GlassButton
                variant="secondary"
                class="flex-1"
                onClick$={() => { revokeTarget.value = null; }}
              >
                Cancel
              </GlassButton>
              <GlassButton
                variant="danger"
                class="flex-1"
                disabled={revoking.value}
                onClick$={handleRevoke}
              >
                {revoking.value ? "Revoking..." : "Revoke"}
              </GlassButton>
            </div>
          </div>
        </div>
      )}
    </div>
  );
});
