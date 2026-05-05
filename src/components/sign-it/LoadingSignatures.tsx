import { component$, useSignal, useVisibleTask$ } from "@builder.io/qwik";

// Cycles through informative messages so the user has a sense of progress
// during the cold-conductor warm-up (which can still be 30-60s on a fresh
// vault unlock even after backend parallelisation).
const MESSAGES: { atMs: number; text: string }[] = [
  { atMs: 0, text: "Loading signatures..." },
  { atMs: 6_000, text: "Warming up your local Holochain conductor..." },
  { atMs: 14_000, text: "Querying signing DNA versions in parallel..." },
  { atMs: 25_000, text: "Fetching thumbnails and revocation status..." },
  { atMs: 40_000, text: "First load can take a moment while peers warm up..." },
];

export const LoadingSignatures = component$(() => {
  const message = useSignal(MESSAGES[0].text);

  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ cleanup }) => {
    const startedAt = Date.now();
    const tick = () => {
      const elapsed = Date.now() - startedAt;
      // Pick the latest message whose atMs threshold has passed.
      let next = MESSAGES[0].text;
      for (const m of MESSAGES) {
        if (elapsed >= m.atMs) next = m.text;
      }
      message.value = next;
    };
    const id = setInterval(tick, 1000);
    cleanup(() => clearInterval(id));
  });

  return (
    <div class="flex items-center justify-center gap-3 py-6">
      <div class="h-4 w-4 animate-spin rounded-full border-2 border-amber-400 border-t-transparent" />
      <p class="text-sm text-gray-500">{message.value}</p>
    </div>
  );
});
