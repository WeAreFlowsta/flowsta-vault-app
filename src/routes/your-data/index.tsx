import { component$, useSignal, useVisibleTask$, $ } from "@builder.io/qwik";
import type { DocumentHead } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { CopyButton } from "~/components/ui/CopyButton";
import { GlassButton } from "~/components/common/GlassButton";
import { dedupeLinkedApps } from "~/lib/linked-apps";
import Callout from "~/components/dashboard/Callout";
import { PillButton } from "~/components/ui/PillButton";

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

interface BackupRecordSummary {
  counts_by_entry_type: Record<string, number>;
  total_records: number;
}

interface BackupMeta {
  client_id: string;
  app_name: string;
  label: string | null;
  created_at: number;
  data_size: number;
  content_type: string;
  summary?: BackupRecordSummary | null;
}

/**
 * Format a BackupRecordSummary as "12 polls, 38 votes". Pluralises
 * lowercase entry-type names; returns null when nothing to show.
 */
function formatSummary(s: BackupRecordSummary | null | undefined): string | null {
  if (!s || s.total_records === 0) return null;
  const parts = Object.entries(s.counts_by_entry_type)
    .filter(([, n]) => n > 0)
    .map(([t, n]) => {
      const lower = t.toLowerCase();
      const plural = n === 1 ? lower : `${lower}s`;
      return `${n} ${plural}`;
    });
  return parts.length > 0 ? parts.join(", ") : null;
}

interface VaultIdentity {
  agent_pub_key: string;
  did: string;
  created_at: number;
  display_name: string | null;
  web_email: string | null;
  web_username: string | null;
  web_agent_pub_key: string | null;
}

interface SealedListItem {
  action_hash: string;
  entry_type: string;
  created_at: number;
  body: unknown;
  refs: string[];
}

interface ImportResult {
  sealed_restored: number;
  sealed_skipped: number;
  backups_restored: number;
  backups_skipped: number;
}

/** "profile" -> "Profile", "app_record" -> "App record" */
function formatEntryType(t: string): string {
  const words = t.replace(/[_-]/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
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

  // Sealed private records, aggregated to counts by entry type.
  // Status matters: "couldn't reach the conductor" must never render as
  // "you have no private records".
  const sealedCounts = useSignal<Record<string, number>>({});
  const sealedTotal = useSignal(0);
  const sealedStatus = useSignal<"loading" | "ready" | "error">("loading");

  // Import state
  const importing = useSignal(false);
  const importResult = useSignal<ImportResult | null>(null);
  const importError = useSignal<string | null>(null);

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

  // Retries while the conductor finishes starting — right after unlock the
  // app websocket can lag the UI by many seconds.
  const loadSealed = $(async () => {
    sealedStatus.value = "loading";
    const attempts = 8;
    for (let i = 0; i < attempts; i++) {
      try {
        const records = await invoke<SealedListItem[]>("sealed_list");
        const counts: Record<string, number> = {};
        for (const r of records) {
          counts[r.entry_type] = (counts[r.entry_type] || 0) + 1;
        }
        sealedCounts.value = counts;
        sealedTotal.value = records.length;
        sealedStatus.value = "ready";
        return;
      } catch (e) {
        if (i === attempts - 1) {
          console.error("Failed to load private records:", e);
          sealedStatus.value = "error";
        } else {
          await new Promise((r) => setTimeout(r, 2500));
        }
      }
    }
  });

  // Load data on mount
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async () => {
    try {
      const [id, stats, apps] = await Promise.all([
        invoke<VaultIdentity>("get_identity"),
        invoke<BackupStats>("get_backup_stats"),
        invoke<{ app_name: string; app_agent_pub_key: string; linked_at: number; client_id: string | null }[]>(
          "get_linked_third_party_apps",
        ),
      ]);
      identity.value = id;
      backupStats.value = stats;
      // Count distinct apps, not per-install agent links.
      linkedAppsCount.value = dedupeLinkedApps(apps).length;
    } catch (e) {
      console.error("Failed to load your data:", e);
    } finally {
      loading.value = false;
    }

    // Private records load separately — needs the conductor, and a failure
    // here shouldn't blank the rest of the page.
    await loadSealed();
  });

  const refreshAfterImport = $(async () => {
    try {
      backupStats.value = await invoke<BackupStats>("get_backup_stats");
    } catch (e) {
      console.error("Refresh after import failed:", e);
    }
    await loadSealed();
  });

  const handleImport = $(async () => {
    importError.value = null;
    importResult.value = null;
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({
      multiple: false,
      filters: [{ name: "Flowsta export", extensions: ["json"] }],
    });
    if (!path || typeof path !== "string") return;
    importing.value = true;
    try {
      const result = await invoke<ImportResult>("import_vault_export", { path });
      importResult.value = result;
      await refreshAfterImport();
    } catch (e) {
      importError.value = String(e);
    } finally {
      importing.value = false;
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
      <div class="mb-6 rounded-xl border border-gray-700 bg-[#15203a] p-6">
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
            {id.web_username && (
              <div class="flex items-center justify-between gap-4">
                <span class="shrink-0 text-gray-400">Username</span>
                <div class="flex items-center gap-2 min-w-0">
                  <span class="truncate text-white">@{id.web_username}</span>
                  <CopyButton text={id.web_username} />
                </div>
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
            <p class="rounded-lg border border-gray-700/60 bg-black/20 px-3 py-2 text-xs leading-relaxed text-gray-400">
              {id.web_username
                ? "Your username and your DID are two ways people can find you. Your username is short and memorable; your DID is the longer, permanent identifier behind it — an open standard that stays the same even if your username changes."
                : "Your DID is your permanent identifier — an open standard others can use to find and verify you. Claim a username on your Overview for a short, memorable address that points to the same identity."}
            </p>
            <div class="flex items-center justify-between">
              <span class="text-gray-400">Vault Created</span>
              <span class="text-white">{formatDate(id.created_at)}</span>
            </div>
            <div class="flex items-center justify-between">
              <span class="text-gray-400">Linked Apps</span>
              <span class="text-white">{linkedAppsCount.value}</span>
            </div>
          </div>
        )}
      </div>

      {/* Private Records */}
      <div class="mb-6 rounded-xl border border-gray-700 bg-[#15203a] p-6">
        <div class="mb-2 flex items-center justify-between">
          <h3 class="text-lg font-semibold text-white">Private Records</h3>
          {sealedTotal.value > 0 && (
            <span class="text-sm text-gray-400">
              {sealedTotal.value} record{sealedTotal.value !== 1 ? "s" : ""}
            </span>
          )}
        </div>
        <p class="mb-4 text-sm text-gray-400">
          Your profile, activity, and app records — encrypted and stored only
          in this vault, on this device. Nothing here is on any server, which
          is the point: no one in the middle. It also means only your export
          file keeps these safe if this device is lost.
        </p>
        {sealedStatus.value === "loading" ? (
          <div class="flex items-center gap-3 rounded-lg border border-gray-800 bg-black/30 p-4">
            <div class="h-4 w-4 animate-spin rounded-full border-2 border-gray-600 border-t-amber-400"></div>
            <p class="text-sm text-gray-400">
              Reading your records from this device...
            </p>
          </div>
        ) : sealedStatus.value === "error" ? (
          <div class="flex items-center justify-between rounded-lg border border-gray-800 bg-black/30 p-4">
            <p class="text-sm text-gray-400">
              Couldn't reach your local node to read them — it may still be
              starting.
            </p>
            <PillButton accent="amber" onClick$={loadSealed}>
              Retry
            </PillButton>
          </div>
        ) : sealedTotal.value === 0 ? (
          <p class="rounded-lg border border-gray-800 bg-black/30 p-4 text-sm text-gray-400">
            No private records yet.
          </p>
        ) : (
          <div class="space-y-2 text-sm">
            {Object.entries(sealedCounts.value)
              .filter(([, count]) => count > 0)
              .map(([type, count]) => (
                <div key={type} class="flex items-center justify-between">
                  <span class="text-gray-400">{formatEntryType(type)}</span>
                  <span class="text-white">{count}</span>
                </div>
              ))}
          </div>
        )}
      </div>

      {/* App Backups */}
      <div class="mb-6 rounded-xl border border-gray-700 bg-[#15203a] p-6">
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
          <div class="rounded-lg border border-gray-800 bg-black/30 p-8 text-center">
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
              // The vault's own migration snapshot lives in the same store
              // as third-party app backups — present it as what it is, not
              // as an app that stopped backing up.
              const isMigrationSnapshot = app.client_id === "flowsta";

              return (
                <div
                  key={app.client_id}
                  class="rounded-lg border border-gray-700 bg-black/30 overflow-hidden"
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
                        <p class="font-medium text-white">
                          {isMigrationSnapshot
                            ? "Flowsta Account — migration snapshot"
                            : app.app_name}
                        </p>
                        <p class="mt-0.5 text-xs text-gray-400">
                          {isMigrationSnapshot ? (
                            <>
                              Your account exactly as it arrived on this
                              device &middot; {formatDate(app.last_backup_at)}{" "}
                              &middot; doesn't update — your live data is in
                              Private Records above
                            </>
                          ) : (
                            <>
                              {app.backup_count} backup
                              {app.backup_count !== 1 ? "s" : ""} &middot;{" "}
                              {formatBytes(app.total_size)} &middot; Last{" "}
                              {timeAgo(app.last_backup_at)}
                            </>
                          )}
                        </p>
                      </div>
                    </button>

                    {deleteConfirm.value === app.client_id ? (
                      <div class="flex items-center gap-2 shrink-0">
                        <span class="text-xs text-red-400">Delete all?</span>
                        <PillButton variant="danger" disabled={deleting.value}
                          onClick$={() => handleDeleteAllBackups(app.client_id)}
                        >
                          {deleting.value ? "..." : "Yes"}
                        </PillButton>
                        <PillButton
                          onClick$={() => {
                            deleteConfirm.value = null;
                          }}
                        >
                          No
                        </PillButton>
                      </div>
                    ) : (
                      <PillButton accent="red" class="shrink-0"
                        onClick$={() => {
                          deleteConfirm.value = app.client_id;
                        }}
                      >
                        Delete all
                      </PillButton>
                    )}
                  </div>

                  {/* Expanded: individual backups */}
                  {isExpanded && (
                    <div class="border-t border-gray-700 bg-black/30">
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
                            const summaryLabel = formatSummary(backup.summary);

                            return (
                              <div
                                key={labelKey}
                                class="flex items-center justify-between px-4 py-3 pl-11"
                              >
                                <div class="min-w-0">
                                  <p class="text-sm text-white">
                                    {backup.label?.startsWith("account-migration-")
                                      ? "Migration snapshot"
                                      : backup.label || "latest"}
                                  </p>
                                  <p class="text-xs text-gray-500">
                                    {formatDateTime(backup.created_at)} &middot;{" "}
                                    {formatBytes(backup.data_size)}
                                    {summaryLabel && (
                                      <>
                                        {" "}&middot;{" "}
                                        <span class="text-gray-400">{summaryLabel}</span>
                                      </>
                                    )}
                                  </p>
                                </div>

                                <div class="flex items-center gap-2 shrink-0">
                                  {isDeleteConfirm ? (
                                    <>
                                      <span class="text-xs text-red-400">Delete?</span>
                                      <PillButton variant="danger" disabled={deletingSingle.value}
                                        onClick$={() => handleDeleteSingle(backup.client_id, backup.label)}
                                      >
                                        {deletingSingle.value ? "..." : "Yes"}
                                      </PillButton>
                                      <PillButton
                                        onClick$={() => {
                                          deleteSingleConfirm.value = null;
                                        }}
                                      >
                                        No
                                      </PillButton>
                                    </>
                                  ) : (
                                    <>
                                      <PillButton accent="amber" disabled={isExporting}
                                        onClick$={() => handleExportSingle(backup.client_id, backup.label)}
                                      >
                                        {isExporting ? "..." : "Export"}
                                      </PillButton>
                                      <PillButton accent="red"
                                        onClick$={() => {
                                          deleteSingleConfirm.value = labelKey;
                                        }}
                                      >
                                        Delete
                                      </PillButton>
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
      <div class="mb-6 rounded-xl border border-gray-700 bg-[#15203a] p-6">
        <h3 class="mb-2 text-lg font-semibold text-white">Export All Data</h3>
        <p class="mb-4 text-sm text-gray-400">
          Download a complete copy of your vault — your identity keys, private
          records, connected apps, and your app data backups. Your recovery
          phrase can restore your <em>identity</em> anywhere; this file is how
          your <em>data</em> survives losing this device. Everything in it is
          readable JSON you own outright — no Flowsta needed to use it.
        </p>

        <div class="mb-4">
          <Callout intent="warning" title="This file will contain your private keys">
            <p>
              Your export includes the cryptographic seed that proves your
              identity on the network. Store it somewhere safe and never share
              it — anyone with this file could sign as you.
            </p>
          </Callout>
        </div>

        {exportSuccess.value && (
          <div class="mb-4">
            <Callout intent="success">
              <p>Export downloaded successfully. Keep it somewhere safe!</p>
            </Callout>
          </div>
        )}

        <GlassButton
          onClick$={handleExport}
          disabled={exporting.value}
        >
          {exporting.value ? "Exporting..." : "Download Export"}
        </GlassButton>
      </div>

      {/* Restore from export */}
      <div class="rounded-xl border border-gray-700 bg-[#15203a] p-6">
        <h3 class="mb-2 text-lg font-semibold text-white">
          Restore from an Export
        </h3>
        <p class="mb-4 text-sm text-gray-400">
          Reset your vault or moved to a new device? After restoring your
          identity with your recovery phrase, import an export file to bring
          your private records and app backups home. Only your own exports
          work — the file must match this vault's identity. Safe to run more
          than once: records you already have are skipped, never duplicated.
        </p>

        {importError.value && (
          <div class="mb-4">
            <Callout intent="warning" title="Import didn't complete">
              <p>{importError.value}</p>
            </Callout>
          </div>
        )}

        {importResult.value && (
          <div class="mb-4">
            <Callout intent="success">
              <p>
                {importResult.value.sealed_restored === 0 &&
                importResult.value.backups_restored === 0
                  ? "Everything in that export is already here — nothing to restore."
                  : `Restored ${importResult.value.sealed_restored} private record${
                      importResult.value.sealed_restored !== 1 ? "s" : ""
                    } and ${importResult.value.backups_restored} app backup${
                      importResult.value.backups_restored !== 1 ? "s" : ""
                    }${
                      importResult.value.sealed_skipped +
                        importResult.value.backups_skipped >
                      0
                        ? ` (${
                            importResult.value.sealed_skipped +
                            importResult.value.backups_skipped
                          } already here)`
                        : ""
                    }.`}
              </p>
            </Callout>
          </div>
        )}

        <GlassButton onClick$={handleImport} disabled={importing.value}>
          {importing.value ? "Importing..." : "Choose Export File"}
        </GlassButton>
      </div>
    </div>
  );
});

export const head: DocumentHead = {
  title: "Your Data - Flowsta Vault",
};
