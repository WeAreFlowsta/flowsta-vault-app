import { component$, useContext, useSignal, useVisibleTask$ } from "@builder.io/qwik";
import type { DocumentHead } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { signaturesContext } from "~/lib/context";
import { dedupeLinkedApps } from "~/lib/linked-apps";
import { ActivityRow } from "~/components/vault/ActivityRow";
import { buildFeed, dayLabel, timeOfDay, type ActivityLogEntry, type BackupStatsLike, type LinkedAppLike } from "~/lib/activity";

/**
 * Everything that happened in this Vault, newest first, grouped by day:
 * sign-ins and what they shared, email grants, remembered sites, app
 * links, signatures, backups, the email and password changes. All of it
 * is read from this device - nothing here is fetched from Flowsta.
 */
export default component$(() => {
  const sigStore = useContext(signaturesContext);
  const log = useSignal<ActivityLogEntry[]>([]);
  const stats = useSignal<BackupStatsLike | null>(null);
  const linkedApps = useSignal<LinkedAppLike[]>([]);
  const loading = useSignal(true);

  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async ({ cleanup }) => {
    const load = async () => {
      const [entries, s, apps] = await Promise.all([
        invoke<ActivityLogEntry[]>("get_activity", { limit: 500 }).catch(() => []),
        invoke<BackupStatsLike>("get_backup_stats").catch(() => null),
        invoke<any[]>("get_linked_third_party_apps").catch(() => []),
      ]);
      log.value = entries;
      stats.value = s;
      linkedApps.value = dedupeLinkedApps(apps as any) as any;
      loading.value = false;
    };
    await load();
    const unlisten = await listen("activity-recorded", load);
    const unlistenLinked = await listen("linked-app-revoked", load);
    cleanup(() => {
      unlisten();
      unlistenLinked();
    });
  });

  const feed = buildFeed({
    log: log.value,
    sigs: sigStore.signatures.value.filter((s: any) => !(s as any).superseded_by),
    sigsLoaded: sigStore.loaded.value,
    stats: stats.value,
    linkedApps: linkedApps.value,
  });
  const groups: { day: string; items: typeof feed }[] = [];
  for (const item of feed) {
    const day = dayLabel(item.timestamp);
    const last = groups[groups.length - 1];
    if (last && last.day === day) last.items.push(item);
    else groups.push({ day, items: [item] });
  }

  return (
    <div>
      <h1 class="mb-1 text-2xl font-bold text-white">Activity</h1>
      <p class="mb-6 text-sm text-gray-400">
        What has happened in your Vault: sign-ins, what you shared, signatures, backups and changes. Kept on this device only.
      </p>

      {loading.value ? (
        <div class="rounded-xl border border-gray-700 bg-[#15203a] p-6 text-sm text-gray-500">Loading…</div>
      ) : feed.length === 0 ? (
        <div class="rounded-xl border border-gray-700 bg-[#15203a] p-6 text-center text-sm text-gray-500">
          Nothing yet - sign in to an app, sign a file or connect an app and it shows up here.
        </div>
      ) : (
        <div class="space-y-6">
          {groups.map((g) => (
            <div key={g.day} class="rounded-xl border border-gray-700 bg-[#15203a] p-6">
              <h2 class="mb-4 text-xs font-semibold uppercase tracking-wider text-gray-400">{g.day}</h2>
              <div class="space-y-3">
                {g.items.map((item) => (
                  <ActivityRow key={item.key} item={item} when={timeOfDay(item.timestamp)} />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
});

export const head: DocumentHead = {
  title: "Activity - Flowsta Vault",
};
