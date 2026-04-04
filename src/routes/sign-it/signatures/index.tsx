import { component$, useSignal } from "@builder.io/qwik";
import { Link } from "@builder.io/qwik-city";
import { GlassButton } from "~/components/common/GlassButton";

export default component$(() => {
  // TODO: Load all signatures from signing DNA via Tauri command
  // once conductor zome call integration is wired up.
  // For now, show placeholder.
  const signatures = useSignal<any[]>([]);

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
        {signatures.value.length === 0 ? (
          <div class="py-8 text-center">
            <svg class="mx-auto mb-3 h-10 w-10 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={1.5}>
              <path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931z" />
            </svg>
            <p class="mb-1 text-sm text-gray-400">No signatures yet</p>
            <p class="mb-4 text-xs text-gray-500">
              Signatures will appear here once you sign files and the signing DNA is active on your conductor.
            </p>
            <Link href="/sign-it/">
              <GlassButton>Sign a File</GlassButton>
            </Link>
          </div>
        ) : (
          <div class="space-y-3">
            {signatures.value.map((sig: any, i: number) => (
              <div
                key={i}
                class="rounded-lg border border-gray-700 bg-gray-800 p-4"
              >
                <div class="flex items-center justify-between mb-2">
                  <span class="truncate text-sm font-mono text-gray-300 max-w-[300px]">
                    {sig.file_hash}
                  </span>
                  <span class={[
                    "rounded-full px-2 py-0.5 text-xs",
                    sig.revoked
                      ? "bg-red-900/30 text-red-400"
                      : "bg-green-900/30 text-green-400",
                  ].join(" ")}>
                    {sig.revoked ? "Revoked" : "Active"}
                  </span>
                </div>
                <div class="flex gap-4 text-xs text-gray-500">
                  {sig.intent && <span>Intent: {sig.intent}</span>}
                  {sig.signed_at && (
                    <span>{new Date(sig.signed_at).toLocaleDateString()}</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
});
