import { component$, useContext, useSignal, $ } from "@builder.io/qwik";
import { Link } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { GlassButton } from "~/components/common/GlassButton";
import { LoadingSignatures } from "~/components/sign-it/LoadingSignatures";
import EditThumbnailModal from "~/components/sign-it/EditThumbnailModal";
import RevokeSignatureModal from "~/components/sign-it/RevokeSignatureModal";
import AmendSignatureModal from "~/components/sign-it/AmendSignatureModal";
import EditHistoryExpander from "~/components/sign-it/EditHistoryExpander";
import { formatLicense, formatAiGeneration } from "~/lib/sign-it-labels";
import { signaturesContext } from "~/lib/context";
import { persistSignaturesCache } from "~/lib/signatures-cache";

function getDefaultThumbnail(sig: any): string {
  const hashType = sig.perceptual_hash?.hash_type;
  if (hashType === "ImagePHash") return "/sign-it/thumbnails/image.svg";
  if (hashType === "AudioChromaprint") return "/sign-it/thumbnails/audio.svg";
  if (hashType === "VideoPHash") return "/sign-it/thumbnails/video.svg";
  const name = (sig.fileName || "").toLowerCase();
  if (/\.(png|jpe?g|gif|bmp|tiff?|webp|svg)$/i.test(name)) return "/sign-it/thumbnails/image.svg";
  if (/\.(mp3|wav|flac|ogg|aac|m4a)$/i.test(name)) return "/sign-it/thumbnails/audio.svg";
  if (/\.(mp4|mkv|avi|webm|mov)$/i.test(name)) return "/sign-it/thumbnails/video.svg";
  if (/\.(pdf|doc|docx|odt|rtf|txt)$/i.test(name)) return "/sign-it/thumbnails/document.svg";
  if (/\.(js|ts|py|rs|go|java|c|cpp|css|html|json|xml|yaml|sh)$/i.test(name)) return "/sign-it/thumbnails/code.svg";
  if (/\.(zip|tar|gz|bz2|7z|rar)$/i.test(name)) return "/sign-it/thumbnails/archive.svg";
  return "/sign-it/thumbnails/file.svg";
}

/** Human label for `perceptual_hash.hash_type`. Falls back to "File" so
 * the badge slot stays consistent for documents/code/archives. */
function fileTypeLabel(hashType: string | null | undefined): string {
  switch (hashType) {
    case "ImagePHash":
      return "Image";
    case "AudioChromaprint":
      return "Audio";
    case "VideoPHash":
      return "Video";
    default:
      return "File";
  }
}

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

export default component$(() => {
  // Shared signatures store from layout — same fetch backs Overview, Sign It,
  // and this page so navigation between them is instant and re-using sigs
  // doesn't trigger another fetch.
  const sigStore = useContext(signaturesContext);
  const signatures = sigStore.signatures;
  const loaded = sigStore.loaded;
  const showRevoked = useSignal(false);

  // Modal targets. Internal state (form values, in-flight flags, errors)
  // lives inside each shared modal component below.
  const revokeTarget = useSignal<any | null>(null);
  const amendTarget = useSignal<any | null>(null);
  const editThumbTarget = useSignal<any | null>(null);

  const onRevoked = $((actionHash: string) => {
    signatures.value = signatures.value.filter((s) => s.action_hash !== actionHash);
    persistSignaturesCache(signatures.value);
  });

  const onAmended = $(async () => {
    try {
      const sigs = await invoke<any[]>("get_my_signatures");
      if (Array.isArray(sigs)) {
        signatures.value = sigs;
        persistSignaturesCache(sigs);
      }
    } catch { /* conductor not ready */ }
  });

  // No fetch task here — the layout's signaturesContext already owns the
  // fetch. We just consume the shared signal.

  return (
    <div>
      <div class="mb-6 flex items-center gap-3">
        <Link
          href="/sign-it/"
          class="flex h-8 w-8 items-center justify-center rounded-full border border-gray-700 text-gray-400 hover:border-gray-600 hover:text-white transition-colors"
        >
          <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
            <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 19.5L8.25 12l7.5-7.5" />
          </svg>
        </Link>
        <h1 class="text-2xl font-bold text-white">All Signatures</h1>
      </div>

      <div class="rounded-lg border border-gray-700 bg-gray-900 p-6">
        {!loaded.value ? (
          <LoadingSignatures />
        ) : signatures.value.length === 0 ? (
          <div class="py-8 text-center">
            <svg class="mx-auto mb-3 h-10 w-10 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={1.5}>
              <path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931z" />
            </svg>
            <p class="mb-1 text-sm text-gray-400">No signatures yet</p>
            <p class="mb-4 text-xs text-gray-500">
              Sign a file to get started.
            </p>
            <Link href="/sign-it/">
              <GlassButton>Sign a File</GlassButton>
            </Link>
          </div>
        ) : (() => {
          const active = signatures.value.filter((s: any) => !s.revoked && !s.superseded_by)
            .sort((a: any, b: any) => (b.signed_at || 0) - (a.signed_at || 0));
          const revoked = signatures.value.filter((s: any) => s.revoked)
            .sort((a: any, b: any) => (b.signed_at || 0) - (a.signed_at || 0));
          return (
            <div>
              {/* Active signatures */}
              <div class="space-y-3">
                {active.map((sig: any, i: number) => (
                  <div key={i} class="rounded-lg border border-gray-700 bg-gray-800 p-4">
                    <div class="flex items-center gap-3 mb-3 min-w-0">
                      <img
                        src={sig.thumbnail || getDefaultThumbnail(sig)}
                        alt=""
                        width={48}
                        height={48}
                        class="h-12 w-12 shrink-0 rounded-lg object-cover"
                      />
                      <span class="truncate text-sm font-mono text-gray-400 flex-1 min-w-0">
                        {sig.file_hash?.slice(0, 16)}...
                      </span>
                      <span class="ml-2 shrink-0 rounded-full bg-green-900/30 px-2 py-0.5 text-xs text-green-400">Active</span>
                    </div>
                    <div class="flex flex-wrap items-center gap-2 text-xs text-gray-500">
                      <span class="rounded-full bg-gray-700/50 px-2 py-0.5 text-gray-300">
                        {fileTypeLabel(sig.perceptual_hash?.hash_type)}
                      </span>
                      {sig.intent && (
                        <span class="rounded-full bg-gray-700/50 px-2 py-0.5">{sig.intent}</span>
                      )}
                      {sig.ai_generation && sig.ai_generation !== "None" && (
                        <span class="rounded-full bg-amber-900/30 px-2 py-0.5 text-amber-400">
                          {formatAiGeneration(sig.ai_generation)}
                        </span>
                      )}
                      {sig.content_rights?.license && (
                        <span class="rounded-full bg-sky-900/30 px-2 py-0.5 text-sky-400">
                          {formatLicense(sig.content_rights.license)}
                        </span>
                      )}
                      {sig.expires_at && (sig.expires_at > Date.now() ? (
                        <span class="rounded-full bg-gray-700/50 px-2 py-0.5 text-gray-300">
                          Expires {new Date(sig.expires_at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })}
                        </span>
                      ) : (
                        <span class="rounded-full bg-amber-900/30 px-2 py-0.5 text-amber-300">
                          Expired {new Date(sig.expires_at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })}
                        </span>
                      ))}
                      {sig.tags?.map((tag: string) => (
                        <span key={tag} class="rounded-full bg-gray-700/30 px-2 py-0.5 text-gray-400">
                          #{tag}
                        </span>
                      ))}
                      {sig.signed_at && (
                        <span class="px-1">{formatRelativeTime(sig.signed_at)}</span>
                      )}
                      {sig.action_hash && (
                        <div class="ml-auto flex flex-wrap gap-2">
                          {(sig.signing_app_id === "flowsta_signing_v1_3" || sig.signing_app_id === "flowsta_signing_v1_4") && (
                            <button
                              class="rounded-full border border-gray-600 bg-gray-700 px-3 py-1 text-xs font-medium text-gray-200 hover:border-amber-400 hover:text-amber-300 transition-colors"
                              onClick$={() => { editThumbTarget.value = sig; }}
                            >
                              Edit thumbnail
                            </button>
                          )}
                          <button
                            class="rounded-full border border-gray-600 bg-gray-700 px-3 py-1 text-xs font-medium text-gray-200 hover:border-sky-400 hover:text-sky-400 transition-colors"
                            onClick$={() => { amendTarget.value = sig; }}
                          >
                            Amend
                          </button>
                          <button
                            class="rounded-full border border-gray-600 bg-gray-700 px-3 py-1 text-xs font-medium text-gray-200 hover:border-red-400 hover:text-red-400 transition-colors"
                            onClick$={() => { revokeTarget.value = sig; }}
                          >
                            Revoke
                          </button>
                        </div>
                      )}
                    </div>
                    {sig.comment && (
                      <p class="mt-2 text-xs italic text-gray-400 line-clamp-2" title={sig.comment}>
                        {sig.comment}
                      </p>
                    )}
                    <EditHistoryExpander current={sig as any} allSigs={signatures.value as any} />
                  </div>
                ))}
              </div>

              {/* Revoked signatures toggle */}
              {revoked.length > 0 && (
                <div class="mt-4">
                  <button
                    class="text-xs text-gray-500 hover:text-gray-400 transition-colors"
                    onClick$={() => { showRevoked.value = !showRevoked.value; }}
                  >
                    {showRevoked.value ? "Hide" : "Show"} revoked ({revoked.length})
                  </button>
                  {showRevoked.value && (
                    <div class="mt-3 space-y-3">
                      {revoked.map((sig: any, i: number) => (
                        <div key={i} class="rounded-lg border border-red-900/30 bg-gray-800/50 p-4 opacity-60">
                          <div class="flex items-center justify-between mb-2">
                            <span class="truncate text-sm font-mono text-gray-500 line-through">
                              {sig.file_hash?.slice(0, 16)}...
                            </span>
                            <span class="ml-3 shrink-0 rounded-full bg-red-900/30 px-2 py-0.5 text-xs text-red-400">Revoked</span>
                          </div>
                          <div class="flex flex-wrap gap-3 text-xs text-gray-600">
                            {sig.revocation_reason && (
                              <span>{sig.revocation_reason}</span>
                            )}
                            {sig.revoked_at && (
                              <span>Revoked {formatRelativeTime(sig.revoked_at)}</span>
                            )}
                            {sig.signed_at && (
                              <span>Signed {formatRelativeTime(sig.signed_at)}</span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })()}
      </div>

      <EditThumbnailModal
        target={editThumbTarget}
        onSaved$={$((actionHash: string, thumbnail: string) => {
          signatures.value = signatures.value.map((s) =>
            s.action_hash === actionHash ? { ...s, thumbnail } : s
          );
          persistSignaturesCache(signatures.value);
        })}
      />

      <RevokeSignatureModal target={revokeTarget} onRevoked$={onRevoked} />
      <AmendSignatureModal target={amendTarget} onAmended$={onAmended} />
    </div>
  );
});
