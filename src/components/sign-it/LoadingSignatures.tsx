import { component$, useSignal, useVisibleTask$ } from "@builder.io/qwik";

// Cycles through informative messages so the user has a sense of progress
// during cold-start DHT warmup. On a fresh install with a returning agent
// (signatures on the DHT but not yet on this device's local cell) the
// underlying get_links / get calls can run for a few minutes the first
// time — long after the conductor is up, while Iroh peers and DHT data
// are being gossiped in. The WebSocket request timeout is 300s to ride
// it out; these messages keep the user oriented while it runs.
const MESSAGES: { atMs: number; text: string }[] = [
  { atMs: 0, text: "Loading signatures..." },
  { atMs: 6_000, text: "Warming up your local Holochain conductor..." },
  { atMs: 14_000, text: "Querying signing DNA versions in parallel..." },
  { atMs: 25_000, text: "Fetching thumbnails and revocation status..." },
  { atMs: 40_000, text: "First load can take a moment while peers warm up..." },
  { atMs: 75_000, text: "Pulling your signatures from the network — still going..." },
  { atMs: 150_000, text: "Cold-start DHT sync is slow the first time. Hang tight." },
  { atMs: 240_000, text: "Almost there — peers are still gossiping your data in." },
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
