import { component$, useSignal, useVisibleTask$, $ } from "@builder.io/qwik";
import type { DocumentHead } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { CopyButton } from "~/components/ui/CopyButton";
import { GlassButton } from "~/components/common/GlassButton";

interface BackupAppSummary {
  client_id: string;
  app_name: string;
  backup_count: number;
  total_size: number;
  last_backup_at: number;
}

interface BackupStats {
  app_count: number;
  total_backups: number;
  total_size: number;
  apps: BackupAppSummary[];
}

interface BackupMeta {
  client_id: string;
  app_name: string;
  label: string | null;
  created_at: number;
  data_size: number;
  content_type: string;
}

interface VaultIdentity {
  agent_pub_key: string;
  did: string;
  created_at: number;
  display_name: string | null;
  web_email: string | null;
  web_agent_pub_key: string | null;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(i > 0 ? 1 : 0)} ${sizes[i]}`;
}

function formatDate(unixSecs: number): string {
  return new Date(unixSecs * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function formatDateTime(unixSecs: number): string {
  return new Date(unixSecs * 1000).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function timeAgo(unixSecs: number): string {
  const now = Math.floor(Date.now() / 1000);
  const diff = now - unixSecs;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default component$(() => {
  const identity = useSignal<VaultIdentity | null>(null);
  const backupStats = useSignal<BackupStats>({
    app_count: 0,
    total_backups: 0,
    total_size: 0,
    apps: [],
  });
  const linkedAppsCount = useSignal(0);
  const loading = useSignal(true);
  const exporting = useSignal(false);
  const exportSuccess = useSignal(false);

  // Expanded app -> its individual backups
  const expandedApp = useSignal<string | null>(null);
  const appBackups = useSignal<BackupMeta[]>([]);
  const loadingBackups = useSignal(false);

  // Delete state
  const deleteConfirm = useSignal<string | null>(null);
  const deleting = useSignal(false);
  const deleteSingleConfirm = useSignal<string | null>(null);
  const deletingSingle = useSignal(false);

  // Single backup export
  const exportingLabel = useSignal<string | null>(null);

  // Load data on mount
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async () => {
    try {
      const [id, stats, apps] = await Promise.all([
        invoke<VaultIdentity>("get_identity"),
        invoke<BackupStats>("get_backup_stats"),
        invoke<{ app_name: string }[]>("get_linked_third_party_apps"),
      ]);
      identity.value = id;
      backupStats.value = stats;
      linkedAppsCount.value = apps.length;
    } catch (e) {
      console.error("Failed to load your data:", e);
    } finally {
      loading.value = false;
    }
  });

  const toggleExpand = $(async (clientId: string) => {
    if (expandedApp.value === clientId) {
      expandedApp.value = null;
      appBackups.value = [];
      return;
    }
    expandedApp.value = clientId;
    loadingBackups.value = true;
    try {
      const metas = await invoke<BackupMeta[]>("list_app_backup_details", { clientId });
      appBackups.value = metas;
    } catch (e) {
      console.error("Failed to load backups:", e);
      appBackups.value = [];
    } finally {
      loadingBackups.value = false;
    }
  });

  const handleExportSingle = $(async (clientId: string, label: string | null) => {
    const key = `${clientId}:${label || "latest"}`;
    exportingLabel.value = key;
    try {
      const result = await invoke<Record<string, unknown>>("export_single_backup", {
        clientId,
        label,
      });
      const appName = (result.app_name as string || "app").toLowerCase().replace(/\s+/g, "-");
      const labelStr = (label || "latest").replace(/\s+/g, "-");
      const date = new Date((result.created_at as number) * 1000).toISOString().split("T")[0];
      const defaultName = `${appName}-${labelStr}-${date}.json`;

      const { save } = await import("@tauri-apps/plugin-dialog");
      const path = await save({
        defaultPath: defaultName,
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (path) {
        await invoke("write_json_file", {
          path,
          content: JSON.stringify(result, null, 2),
        });
      }
    } catch (e) {
      console.error("Export failed:", e);
    } finally {
      exportingLabel.value = null;
    }
  });

  const handleDeleteSingle = $(async (clientId: string, label: string | null) => {
    deletingSingle.value = true;
    try {
      await invoke("delete_single_backup", { clientId, label });
      // Refresh the expanded list and stats
      const [metas, stats] = await Promise.all([
        invoke<BackupMeta[]>("list_app_backup_details", { clientId }),
        invoke<BackupStats>("get_backup_stats"),
      ]);
      appBackups.value = metas;
      backupStats.value = stats;
      deleteSingleConfirm.value = null;
      // If no backups left, collapse
      if (metas.length === 0) {
        expandedApp.value = null;
      }
    } catch (e) {
      console.error("Delete failed:", e);
    } finally {
      deletingSingle.value = false;
    }
  });

  const handleExport = $(async () => {
    exporting.value = true;
    exportSuccess.value = false;
    try {
      const data = await invoke<Record<string, unknown>>("export_all_data");
      const date = new Date().toISOString().split("T")[0];
      const defaultName = `flowsta-vault-export-${date}.json`;

      const { save } = await import("@tauri-apps/plugin-dialog");
      const path = await save({
        defaultPath: defaultName,
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (path) {
        await invoke("write_json_file", {
          path,
          content: JSON.stringify(data, null, 2),
        });
        exportSuccess.value = true;
        setTimeout(() => {
          exportSuccess.value = false;
        }, 5000);
      }
    } catch (e) {
      console.error("Export failed:", e);
    } finally {
      exporting.value = false;
    }
  });

  const handleDeleteAllBackups = $(async (clientId: string) => {
    deleting.value = true;
    try {
      await invoke("delete_app_backup", { clientId });
      backupStats.value = await invoke<BackupStats>("get_backup_stats");
      deleteConfirm.value = null;
      if (expandedApp.value === clientId) {
        expandedApp.value = null;
        appBackups.value = [];
      }
    } catch (e) {
      console.error("Delete failed:", e);
    } finally {
      deleting.value = false;
    }
  });

  if (loading.value) {
    return (
      <div class="flex items-center justify-center py-12">
        <div class="h-8 w-8 animate-spin rounded-full border-2 border-gray-600 border-t-amber-400"></div>
      </div>
    );
  }

  const id = identity.value;

  return (
    <div>
      <h1 class="mb-6 text-2xl font-bold text-white">Your Data</h1>

      {/* Identity Summary */}
      <div class="mb-6 rounded-lg border border-gray-700 bg-gray-900 p-6">
        <h3 class="mb-4 text-lg font-semibold text-white">Identity</h3>
        {id && (
          <div class="space-y-3 text-sm">
            {id.display_name && (
              <div class="flex items-center justify-between">
                <span class="text-gray-400">Name</span>
                <span class="text-white">{id.display_name}</span>
              </div>
            )}
            {id.web_email && (
              <div class="flex items-center justify-between">
                <span class="text-gray-400">Email</span>
                <span class="text-white">{id.web_email}</span>
              </div>
            )}
            <div class="flex items-center justify-between gap-4">
              <span class="shrink-0 text-gray-400">DID</span>
              <div class="flex items-center gap-2 min-w-0">
                <span class="truncate font-mono text-xs text-white">
                  {id.did}
                </span>
                <CopyButton text={id.did} />
              </div>
            </div>
            <div class="flex items-center justify-between gap-4">
              <span class="shrink-0 text-gray-400">Agent Key</span>
              <div class="flex items-center gap-2 min-w-0">
                <span class="truncate font-mono text-xs text-white">
                  {id.agent_pub_key}
                </span>
                <CopyButton text={id.agent_pub_key} />
              </div>
            </div>
            <div class="flex items-center justify-between">
              <span class="text-gray-400">Vault Created</span>
              <span class="text-white">{formatDate(id.created_at)}</span>
            </div>
            {id.web_agent_pub_key && (
              <div class="flex items-center justify-between">
                <span class="text-gray-400">Web Account</span>
                <span class="text-green-400">Linked</span>
              </div>
            )}
            <div class="flex items-center justify-between">
              <span class="text-gray-400">Linked Apps</span>
              <span class="text-white">{linkedAppsCount.value}</span>
            </div>
          </div>
        )}
      </div>

      {/* App Backups */}
      <div class="mb-6 rounded-lg border border-gray-700 bg-gray-900 p-6">
        <div class="mb-4 flex items-center justify-between">
          <h3 class="text-lg font-semibold text-white">App Backups</h3>
          {backupStats.value.app_count > 0 && (
            <span class="text-sm text-gray-400">
              {backupStats.value.total_backups} backup{backupStats.value.total_backups !== 1 ? "s" : ""} &middot;{" "}
              {formatBytes(backupStats.value.total_size)}
            </span>
          )}
        </div>

        {backupStats.value.apps.length === 0 ? (
          <div class="rounded-lg border border-gray-800 bg-gray-800/50 p-8 text-center">
            <div class="mb-2 text-3xl text-gray-600">
              <svg
                class="mx-auto h-10 w-10"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="1.5"
                  d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"
                />
              </svg>
            </div>
            <p class="text-sm text-gray-400">
              No app backups yet. Connected Holochain apps can store data
              backups in your vault for safekeeping.
            </p>
          </div>
        ) : (
          <div class="space-y-3">
            {backupStats.value.apps.map((app) => {
              const isExpanded = expandedApp.value === app.client_id;

              return (
                <div
                  key={app.client_id}
                  class="rounded-lg border border-gray-700 bg-gray-800/50 overflow-hidden"
                >
                  {/* App header row */}
                  <div class="flex items-center justify-between p-4">
                    <button
                      type="button"
                      class="flex items-center gap-3 text-left min-w-0 flex-1"
                      onClick$={() => toggleExpand(app.client_id)}
                    >
                      <span
                        class={`text-gray-500 text-xs transition-transform duration-200 ${isExpanded ? "rotate-90" : ""}`}
                      >
                        &#9654;
                      </span>
                      <div class="min-w-0">
                        <p class="font-medium text-white">{app.app_name}</p>
                        <p class="mt-0.5 text-xs text-gray-400">
                          {app.backup_count} backup{app.backup_count !== 1 ? "s" : ""}{" "}
                          &middot; {formatBytes(app.total_size)} &middot; Last{" "}
                          {timeAgo(app.last_backup_at)}
                        </p>
                      </div>
                    </button>

                    {deleteConfirm.value === app.client_id ? (
                      <div class="flex items-center gap-2 shrink-0">
                        <span class="text-xs text-red-400">Delete all?</span>
                        <button
                          type="button"
                          disabled={deleting.value}
                          class="rounded px-2 py-1 text-xs font-medium text-red-400 border border-red-500/50 hover:bg-red-500/20 transition-colors disabled:opacity-50"
                          onClick$={() => handleDeleteAllBackups(app.client_id)}
                        >
                          {deleting.value ? "..." : "Yes"}
                        </button>
                        <button
                          type="button"
                          class="rounded px-2 py-1 text-xs font-medium text-gray-400 border border-gray-600 hover:bg-gray-700 transition-colors"
                          onClick$={() => {
                            deleteConfirm.value = null;
                          }}
                        >
                          No
                        </button>
                      </div>
                    ) : (
                      <button
                        type="button"
                        class="text-xs text-gray-500 hover:text-red-400 transition-colors shrink-0"
                        onClick$={() => {
                          deleteConfirm.value = app.client_id;
                        }}
                      >
                        Delete all
                      </button>
                    )}
                  </div>

                  {/* Expanded: individual backups */}
                  {isExpanded && (
                    <div class="border-t border-gray-700 bg-gray-900/50">
                      {loadingBackups.value ? (
                        <div class="flex items-center justify-center py-4">
                          <div class="h-5 w-5 animate-spin rounded-full border-2 border-gray-600 border-t-amber-400"></div>
                        </div>
                      ) : appBackups.value.length === 0 ? (
                        <p class="px-4 py-3 text-xs text-gray-500">No backups found.</p>
                      ) : (
                        <div class="divide-y divide-gray-800">
                          {appBackups.value.map((backup) => {
                            const labelKey = `${backup.client_id}:${backup.label || "latest"}`;
                            const isExporting = exportingLabel.value === labelKey;
                            const isDeleteConfirm = deleteSingleConfirm.value === labelKey;

                            return (
                              <div
                                key={labelKey}
                                class="flex items-center justify-between px-4 py-3 pl-11"
                              >
                                <div class="min-w-0">
                                  <p class="text-sm text-white">
                                    {backup.label || "latest"}
                                  </p>
                                  <p class="text-xs text-gray-500">
                                    {formatDateTime(backup.created_at)} &middot;{" "}
                                    {formatBytes(backup.data_size)}
                                  </p>
                                </div>

                                <div class="flex items-center gap-2 shrink-0">
                                  {isDeleteConfirm ? (
                                    <>
                                      <span class="text-xs text-red-400">Delete?</span>
                                      <button
                                        type="button"
                                        disabled={deletingSingle.value}
                                        class="rounded px-2 py-1 text-xs font-medium text-red-400 border border-red-500/50 hover:bg-red-500/20 transition-colors disabled:opacity-50"
                                        onClick$={() => handleDeleteSingle(backup.client_id, backup.label)}
                                      >
                                        {deletingSingle.value ? "..." : "Yes"}
                                      </button>
                                      <button
                                        type="button"
                                        class="rounded px-2 py-1 text-xs font-medium text-gray-400 border border-gray-600 hover:bg-gray-700 transition-colors"
                                        onClick$={() => {
                                          deleteSingleConfirm.value = null;
                                        }}
                                      >
                                        No
                                      </button>
                                    </>
                                  ) : (
                                    <>
                                      <button
                                        type="button"
                                        disabled={isExporting}
                                        class="rounded px-2 py-1 text-xs font-medium text-amber-400 border border-amber-500/50 hover:bg-amber-500/20 transition-colors disabled:opacity-50"
                                        onClick$={() => handleExportSingle(backup.client_id, backup.label)}
                                      >
                                        {isExporting ? "..." : "Export"}
                                      </button>
                                      <button
                                        type="button"
                                        class="text-xs text-gray-500 hover:text-red-400 transition-colors"
                                        onClick$={() => {
                                          deleteSingleConfirm.value = labelKey;
                                        }}
                                      >
                                        Delete
                                      </button>
                                    </>
                                  )}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Export */}
      <div class="rounded-lg border border-gray-700 bg-gray-900 p-6">
        <h3 class="mb-2 text-lg font-semibold text-white">Export All Data</h3>
        <p class="mb-4 text-sm text-gray-400">
          Download a complete copy of your vault — your identity, cryptographic
          keys, connected apps, and all app data backups. This gives you
          everything you need to recreate your Flowsta identity independently.
        </p>

        <div class="mb-4 rounded-lg border border-yellow-700/50 bg-yellow-900/20 p-3">
          <p class="text-sm text-yellow-400 font-medium mb-1">
            This file will contain your private keys
          </p>
          <p class="text-xs text-yellow-400/70">
            Your export includes the cryptographic seed that proves your
            identity on the network. Store it somewhere safe and never share
            it — anyone with this file could sign as you.
          </p>
        </div>

        {exportSuccess.value && (
          <div class="mb-4 rounded-lg border border-green-700/50 bg-green-900/20 p-3">
            <p class="text-sm text-green-400">
              Export downloaded successfully. Keep it somewhere safe!
            </p>
          </div>
        )}

        <GlassButton
          onClick$={handleExport}
          disabled={exporting.value}
        >
          {exporting.value ? "Exporting..." : "Download Export"}
        </GlassButton>
      </div>
    </div>
  );
});

export const head: DocumentHead = {
  title: "Your Data - Flowsta Vault",
};
