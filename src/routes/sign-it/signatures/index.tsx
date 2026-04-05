import { component$, useSignal, useVisibleTask$ } from "@builder.io/qwik";
import { Link } from "@builder.io/qwik-city";
import { GlassButton } from "~/components/common/GlassButton";

export default component$(() => {
  const signatures = useSignal<any[]>([]);
  const loaded = useSignal(false);

  // Load all signatures from the signing DNA
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async () => {
    const { invoke: inv } = await import("@tauri-apps/api/core");
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        const sigs = await inv<any[]>("get_my_signatures");
        if (Array.isArray(sigs)) {
          signatures.value = sigs;
          loaded.value = true;
          return;
        }
      } catch {
        // Conductor may not be ready yet
      }
      await new Promise((r) => setTimeout(r, (attempt + 1) * 2000 + 1000));
    }
    loaded.value = true;
  });

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
          <div class="flex items-center justify-center gap-3 py-6">
            <div class="h-4 w-4 animate-spin rounded-full border-2 border-amber-400 border-t-transparent" />
            <p class="text-sm text-gray-500">Loading signatures...</p>
          </div>
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
        ) : (
          <div class="space-y-3">
            {signatures.value.map((sig: any, i: number) => (
              <div
                key={i}
                class="rounded-lg border border-gray-700 bg-gray-800 p-4"
              >
                <div class="flex items-center justify-between mb-2">
                  <span class="break-all text-sm font-mono text-gray-300">
                    {sig.file_hash}
                  </span>
                  <span class="ml-3 shrink-0 rounded-full bg-green-900/30 px-2 py-0.5 text-xs text-green-400">
                    Active
                  </span>
                </div>
                <div class="flex flex-wrap gap-3 text-xs text-gray-500">
                  {sig.intent && (
                    <span class="rounded-full bg-gray-700/50 px-2 py-0.5">{sig.intent}</span>
                  )}
                  {sig.ai_generation && sig.ai_generation !== "None" && (
                    <span class="rounded-full bg-amber-900/30 px-2 py-0.5 text-amber-400">
                      AI: {sig.ai_generation}
                    </span>
                  )}
                  {sig.content_rights?.license && (
                    <span class="rounded-full bg-sky-900/30 px-2 py-0.5 text-sky-400">
                      {sig.content_rights.license}
                    </span>
                  )}
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
