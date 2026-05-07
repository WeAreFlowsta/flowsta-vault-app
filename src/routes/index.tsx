import { component$, useContext, useSignal, useVisibleTask$ } from "@builder.io/qwik";
import type { DocumentHead } from "@builder.io/qwik-city";
import { Link } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { CopyButton } from "~/components/ui/CopyButton";
import { signaturesContext } from "~/lib/context";

interface VaultIdentity {
  agent_pub_key: string;
  did: string;
  installed_app_ids: string[];
  created_at: number;
  display_name: string | null;
  profile_picture: string | null;
  web_email: string | null;
  web_username: string | null;
  web_agent_pub_key: string | null;
}

interface BackupStats {
  app_count: number;
  total_backups: number;
  total_size: number;
  apps: { app_name: string; last_backup_at: number }[];
}

interface LinkedApp {
  app_name: string;
  app_agent_pub_key: string;
  linked_at: number;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(i > 0 ? 1 : 0)} ${sizes[i]}`;
}

function timeAgo(unixSecs: number): string {
  const now = Math.floor(Date.now() / 1000);
  const diff = now - unixSecs;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
  return new Date(unixSecs * 1000).toLocaleDateString();
}

export default component$(() => {
  const identity = useSignal<VaultIdentity | null>(null);
  const backupStats = useSignal<BackupStats | null>(null);
  const linkedApps = useSignal<LinkedApp[]>([]);
  const loading = useSignal(true);
  const showFullDid = useSignal(false);

  // Shared signatures store from layout — count + last-known list are
  // already populated from cache by the time the user reaches Overview.
  const sigStore = useContext(signaturesContext);

  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async ({ cleanup }) => {
    try {
      const [id, stats, apps] = await Promise.all([
        invoke<VaultIdentity>("get_identity"),
        invoke<BackupStats>("get_backup_stats"),
        invoke<LinkedApp[]>("get_linked_third_party_apps"),
      ]);
      identity.value = id;
      backupStats.value = stats;
      linkedApps.value = apps;
    } catch {
      // Vault might be locked
    } finally {
      loading.value = false;
    }

    // Refresh identity when profile is synced from web account
    const unlisten = await listen("profile-synced", async () => {
      try {
        identity.value = await invoke<VaultIdentity>("get_identity");
      } catch { /* ignore */ }
    });
    cleanup(() => unlisten());
  });

  if (loading.value) {
    return (
      <div>
        <div class="mb-6 h-8 w-32 animate-pulse rounded bg-gray-700" />
        <div class="mb-6 animate-pulse rounded-lg border border-gray-700 bg-gray-900 p-6">
          <div class="mb-3 h-4 w-24 rounded bg-gray-700" />
          <div class="mb-2 h-4 w-full rounded bg-gray-700" />
          <div class="h-4 w-3/4 rounded bg-gray-700" />
        </div>
        <div class="grid grid-cols-1 gap-4 sm:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <div key={i} class="animate-pulse rounded-lg border border-gray-700 bg-gray-900 p-4">
              <div class="mb-2 h-3 w-20 rounded bg-gray-700" />
              <div class="h-6 w-12 rounded bg-gray-700" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  const id = identity.value;
  if (!id) return null;

  const stats = backupStats.value;
  const hasDisplayName = !!id.display_name;
  const sigCount = sigStore.signatures.value.length;
  const sigsLoaded = sigStore.loaded.value;
  const activeSigs = sigStore.signatures.value.filter((s: any) => !s.revoked).length;
  const revokedSigs = sigCount - activeSigs;
  // Sign It is gated on Windows in v0.5.2 (see /sign-it/index.tsx). On
  // Windows the count comes back as 0 because the underlying fetch can't
  // run reliably; show "—" with a friendlier subtitle instead of "0 — Sign
  // your first file" which would be misleading.
  const isWindows =
    typeof navigator !== "undefined" && /windows/i.test(navigator.userAgent);

  // Find most recent backup across all apps
  const lastBackupTime = stats?.apps.reduce(
    (max, app) => Math.max(max, app.last_backup_at),
    0,
  ) ?? 0;

  return (
    <div>
      <h1 class="mb-6 text-2xl font-bold text-white">Overview</h1>

      {/* Identity Card */}
      <div class="mb-6 rounded-lg border border-gray-700 bg-gray-900 p-6">
        <div class="flex items-start justify-between">
          <div class="flex items-center gap-4">
            {/* Avatar */}
            {id.profile_picture ? (
              <img
                src={id.profile_picture}
                alt="Profile"
                class="h-14 w-14 rounded-full object-cover border border-gray-600"
                width={56}
                height={56}
              />
            ) : (
              <div class="flex h-14 w-14 items-center justify-center rounded-full bg-gradient-to-br from-blue-600 to-blue-800 text-xl font-bold text-white">
                {hasDisplayName
                  ? id.display_name!.charAt(0).toUpperCase()
                  : "V"}
              </div>
            )}

            <div>
              {hasDisplayName && (
                <h2 class="text-lg font-semibold text-white">
                  {id.display_name}
                </h2>
              )}
              {id.web_email && (
                <p class="text-sm text-gray-400">{id.web_email}</p>
              )}
              {id.web_username && (
                <p class="text-sm text-gray-600">@{id.web_username}</p>
              )}
              {!hasDisplayName && !id.web_email && (
                <h2 class="text-lg font-semibold text-white">Your Vault</h2>
              )}
              <p class="mt-0.5 text-xs text-gray-500">
                Created{" "}
                {new Date(id.created_at * 1000).toLocaleDateString(undefined, {
                  year: "numeric",
                  month: "short",
                  day: "numeric",
                })}
              </p>
            </div>
          </div>

        </div>

        {/* DID */}
        <div class="mt-4 rounded-lg bg-gray-800/50 px-4 py-3">
          <div class="flex items-center justify-between mb-1">
            <span class="text-xs font-medium text-gray-500">DID</span>
            <button
              type="button"
              class="text-[10px] text-gray-500 hover:text-gray-400 transition-colors"
              onClick$={() => { showFullDid.value = !showFullDid.value; }}
            >
              {showFullDid.value ? "Collapse" : "Expand"}
            </button>
          </div>
          <div class="flex items-center gap-2">
            <code class="flex-1 font-mono text-sm text-sky-400 break-all">
              {showFullDid.value
                ? id.did
                : id.did.length > 50
                  ? id.did.slice(0, 24) + "..." + id.did.slice(-20)
                  : id.did}
            </code>
            <CopyButton text={id.did} label="Copy DID" />
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div class="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        {/* Signatures */}
        <Link
          href="/sign-it/"
          class="rounded-lg border border-gray-700 bg-gray-900 p-5 transition-colors hover:border-gray-600 hover:bg-gray-800/80"
        >
          <div class="mb-3 flex items-center gap-2 text-gray-400">
            <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
              <path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
            </svg>
            <span class="text-sm font-medium">Signatures</span>
          </div>
          <p class="text-3xl font-bold text-white">
            {isWindows ? (
              "—"
            ) : sigsLoaded ? (
              sigCount
            ) : (
              <span class="inline-block h-7 w-10 animate-pulse rounded bg-gray-700 align-middle" />
            )}
          </p>
          <p class="mt-1 text-xs text-gray-500">
            {isWindows
              ? "Sign at flowsta.com — coming soon here"
              : !sigsLoaded
                ? "Loading..."
                : sigCount === 0
                  ? "Sign your first file"
                  : revokedSigs > 0
                    ? `${activeSigs} active, ${revokedSigs} revoked`
                    : `${activeSigs} active`}
          </p>
        </Link>

        {/* Connected Apps */}
        <Link
          href="/identities/"
          class="rounded-lg border border-gray-700 bg-gray-900 p-5 transition-colors hover:border-gray-600 hover:bg-gray-800/80"
        >
          <div class="mb-3 flex items-center gap-2 text-gray-400">
            <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
              <path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
            </svg>
            <span class="text-sm font-medium">Connected Apps</span>
          </div>
          <p class="text-3xl font-bold text-white">
            {linkedApps.value.length}
          </p>
          <p class="mt-1 text-xs text-gray-500">
            {linkedApps.value.length === 0
              ? "No apps linked yet"
              : linkedApps.value.length === 1
                ? linkedApps.value[0].app_name
                : `${linkedApps.value.map((a) => a.app_name).join(", ")}`}
          </p>
        </Link>

        {/* Backups */}
        <Link
          href="/your-data/"
          class="rounded-lg border border-gray-700 bg-gray-900 p-5 transition-colors hover:border-gray-600 hover:bg-gray-800/80"
        >
          <div class="mb-3 flex items-center gap-2 text-gray-400">
            <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
              <path stroke-linecap="round" stroke-linejoin="round" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
            </svg>
            <span class="text-sm font-medium">Backups</span>
          </div>
          <p class="text-3xl font-bold text-white">
            {stats?.total_backups ?? 0}
          </p>
          <p class="mt-1 text-xs text-gray-500">
            {stats && stats.total_backups > 0
              ? `${formatBytes(stats.total_size)} across ${stats.app_count} app${stats.app_count !== 1 ? "s" : ""}`
              : "No backups yet"}
          </p>
        </Link>
      </div>

      {/* Recent Activity */}
      <div class="mb-6 rounded-lg border border-gray-700 bg-gray-900 p-6">
        <h3 class="mb-4 text-sm font-semibold uppercase tracking-wider text-gray-500">
          Recent Activity
        </h3>

        {linkedApps.value.length === 0 && (stats?.total_backups ?? 0) === 0 ? (
          <p class="py-4 text-center text-sm text-gray-500">
            No activity yet. Connected apps will show up here.
          </p>
        ) : (
          <div class="space-y-3">
            {/* Most recent backup */}
            {lastBackupTime > 0 && (() => {
              const recentApp = stats!.apps.reduce((a, b) =>
                a.last_backup_at > b.last_backup_at ? a : b
              );
              return (
                <div class="flex items-center gap-3">
                  <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-blue-900/30">
                    <svg class="h-4 w-4 text-sky-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                      <path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
                    </svg>
                  </div>
                  <div class="min-w-0 flex-1">
                    <p class="text-sm text-white">
                      <span class="font-medium">{recentApp.app_name}</span>{" "}
                      backed up data
                    </p>
                    <p class="text-xs text-gray-500">
                      {timeAgo(recentApp.last_backup_at)}
                    </p>
                  </div>
                </div>
              );
            })()}

            {/* Linked apps (most recent first) */}
            {[...linkedApps.value]
              .sort((a, b) => b.linked_at - a.linked_at)
              .slice(0, 3)
              .map((app) => (
                <div key={app.app_agent_pub_key} class="flex items-center gap-3">
                  <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-green-900/30">
                    <svg class="h-4 w-4 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                      <path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                    </svg>
                  </div>
                  <div class="min-w-0 flex-1">
                    <p class="text-sm text-white">
                      <span class="font-medium">{app.app_name}</span>{" "}
                      linked identity
                    </p>
                    <p class="text-xs text-gray-500">
                      {timeAgo(app.linked_at)}
                    </p>
                  </div>
                </div>
              ))}
          </div>
        )}
      </div>

    </div>
  );
});

export const head: DocumentHead = {
  title: "Overview - Flowsta Vault",
};
