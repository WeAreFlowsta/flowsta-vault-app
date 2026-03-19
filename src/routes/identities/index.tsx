import { component$, useSignal, useVisibleTask$, $ } from "@builder.io/qwik";
import type { DocumentHead } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { CopyButton } from "~/components/ui/CopyButton";
import { GlassButton } from "~/components/common/GlassButton";

declare const __API_URL__: string;

interface ConnectedSite {
  origin: string;
  first_seen: number;
  last_request: number;
  request_count: number;
  last_action: string;
  has_authenticated: boolean;
  trusted: boolean;
}

function isInternalOrigin(origin: string): boolean {
  try {
    const host = new URL(origin).hostname;
    return host === "localhost" || host === "127.0.0.1" || host === "[::1]"
      || host.endsWith("flowsta.com");
  } catch {
    return false;
  }
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
  // Web account link state
  const linkStatus = useSignal<"idle" | "linking" | "success" | "error">("idle");
  const linkMessage = useSignal("");
  const linkedWebKey = useSignal<string | null>(null);

  // Linked third-party apps
  const linkedApps = useSignal<
    { app_name: string; app_agent_pub_key: string; linked_at: number; client_id: string | null }[]
  >([]);
  // Granted scopes per app, keyed by client_id
  const appScopes = useSignal<Record<string, string[]>>({});

  // Connected sites (IPC origins)
  const connectedSites = useSignal<ConnectedSite[]>([]);

  const loading = useSignal(true);

  // Load all data on mount
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async () => {
    try {
      const [identity, apps, sites, scopes] = await Promise.all([
        invoke<{
          agent_pub_key: string;
          did: string;
          installed_app_ids: string[];
          created_at: number;
          web_agent_pub_key: string | null;
        }>("get_identity"),
        invoke<{ app_name: string; app_agent_pub_key: string; linked_at: number; client_id: string | null }[]>(
          "get_linked_third_party_apps"
        ),
        invoke<ConnectedSite[]>("get_connected_sites"),
        invoke<Record<string, string[]>>("get_all_linked_app_scopes"),
      ]);

      if (identity.web_agent_pub_key) {
        linkedWebKey.value = identity.web_agent_pub_key;
        linkStatus.value = "success";
      }

      linkedApps.value = apps;
      appScopes.value = scopes;
      connectedSites.value = sites.filter((s) => !isInternalOrigin(s.origin));
    } catch {
      // Vault might be locked
    } finally {
      loading.value = false;
    }
  });

  // Poll connected sites every 5s
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ cleanup }) => {
    const id = setInterval(async () => {
      try {
        const sites = await invoke<ConnectedSite[]>("get_connected_sites");
        connectedSites.value = sites.filter((s) => !isInternalOrigin(s.origin));
      } catch { /* ignore */ }
    }, 5_000);
    cleanup(() => clearInterval(id));
  });

  // Listen for real-time linked app changes
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async () => {
    const unlistenAdd = await listen("linked-app-added", async () => {
      // Re-fetch the full list so we get client_id and fresh scopes
      try {
        const [apps, scopes] = await Promise.all([
          invoke<{ app_name: string; app_agent_pub_key: string; linked_at: number; client_id: string | null }[]>(
            "get_linked_third_party_apps"
          ),
          invoke<Record<string, string[]>>("get_all_linked_app_scopes"),
        ]);
        linkedApps.value = apps;
        appScopes.value = scopes;
      } catch { /* ignore */ }
    });

    const unlistenRevoke = await listen<{
      app_agent_pub_key: string;
    }>("linked-app-revoked", (event) => {
      linkedApps.value = linkedApps.value.filter(
        (a) => a.app_agent_pub_key !== event.payload.app_agent_pub_key,
      );
    });

    return () => {
      unlistenAdd();
      unlistenRevoke();
    };
  });

  const handleLinkWebAccount = $(async () => {
    linkStatus.value = "linking";
    linkMessage.value = "";

    try {
      const result = await invoke<{
        success: boolean;
        web_agent_key: string | null;
        message: string;
      }>("link_web_account", { apiUrl: __API_URL__ });

      if (result.success) {
        linkStatus.value = "success";
        linkMessage.value = result.message;
        linkedWebKey.value = result.web_agent_key;
      } else {
        linkStatus.value = "error";
        linkMessage.value = result.message || "Linking failed";
      }
    } catch (err) {
      linkStatus.value = "error";
      linkMessage.value =
        err instanceof Error ? err.message : "An unexpected error occurred";
    }
  });

  const handleRevokeLinkedApp = $(async (appAgentPubKey: string) => {
    try {
      await invoke("revoke_linked_third_party_app", { appAgentPubKey });
      linkedApps.value = linkedApps.value.filter(
        (a) => a.app_agent_pub_key !== appAgentPubKey,
      );
    } catch (err) {
      console.error("Failed to revoke linked app:", err);
    }
  });

  const handleRevokeSite = $(async (origin: string) => {
    try {
      await invoke("revoke_site", { origin });
      connectedSites.value = connectedSites.value.filter(
        (s) => s.origin !== origin,
      );
    } catch (e) {
      console.error("Failed to revoke site:", e);
    }
  });

  const handleToggleTrust = $(async (origin: string, trusted: boolean) => {
    try {
      await invoke("toggle_site_trust", { origin, trusted });
      connectedSites.value = connectedSites.value.map((s) =>
        s.origin === origin ? { ...s, trusted } : s,
      );
    } catch (e) {
      console.error("Failed to toggle site trust:", e);
    }
  });

  if (loading.value) {
    return (
      <div>
        <div class="mb-6 h-8 w-48 animate-pulse rounded bg-gray-700" />
        <div class="space-y-4">
          {[1, 2].map((i) => (
            <div key={i} class="animate-pulse rounded-lg border border-gray-700 bg-gray-900 p-6">
              <div class="mb-3 h-4 w-32 rounded bg-gray-700" />
              <div class="h-4 w-full rounded bg-gray-700" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div>
      <h1 class="mb-6 text-2xl font-bold text-white">Connected Apps</h1>

      {/* Flowsta Web Account */}
      <div class="mb-6 rounded-lg border border-gray-700 bg-gray-900 p-6">
        <div class="mb-3 flex items-center gap-2">
          <svg class="h-5 w-5 text-sky-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={1.5}>
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
          </svg>
          <h3 class="text-lg font-semibold text-white">Flowsta Web Account</h3>
        </div>

        {linkStatus.value === "success" && linkedWebKey.value ? (
          <div class="rounded-lg border border-green-700/50 bg-green-900/20 p-4">
            <div class="mb-2 flex items-center gap-2">
              <svg class="h-4 w-4 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span class="text-sm font-medium text-green-400">Linked</span>
            </div>
            <div>
              <label class="mb-1 block text-xs text-gray-400">Web Agent Key</label>
              <div class="flex items-start gap-2">
                <code class="flex-1 break-all rounded bg-gray-900 px-2 py-1 font-mono text-xs text-gray-300">
                  {linkedWebKey.value}
                </code>
                <CopyButton text={linkedWebKey.value} label="Copy" />
              </div>
            </div>
          </div>
        ) : linkStatus.value === "linking" ? (
          <div class="flex items-center gap-3 rounded-lg border border-gray-700 bg-gray-900/50 p-4">
            <div class="h-5 w-5 animate-spin rounded-full border-2 border-gray-600 border-t-amber-400" />
            <div>
              <p class="text-sm text-gray-300">Linking with web account...</p>
              <p class="text-xs text-gray-500">Signing key pair and submitting to DHT</p>
            </div>
          </div>
        ) : (
          <div>
            {linkStatus.value === "error" && linkMessage.value && (
              <div class="mb-3 rounded-lg border border-red-700/50 bg-red-900/20 p-3">
                <span class="text-xs text-red-400">{linkMessage.value}</span>
              </div>
            )}
            <div class="flex items-center justify-between rounded-lg border border-dashed border-gray-600 bg-gray-900/50 p-4">
              <div>
                <p class="text-sm text-gray-400">Not linked yet</p>
                <p class="text-xs text-gray-500">
                  Requires a Flowsta web account with the same recovery phrase
                </p>
              </div>
              <button
                onClick$={handleLinkWebAccount}
                class="shrink-0 rounded-lg bg-amber-500 px-4 py-2 text-sm font-medium text-gray-900 transition-colors hover:bg-amber-400"
              >
                Link Now
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Apps & Sites list */}
      <div class="rounded-lg border border-gray-700 bg-gray-900 p-6">
        <div class="mb-4 flex items-center justify-between">
          <h3 class="text-lg font-semibold text-white">Apps & Sites</h3>
          <span class="text-xs text-gray-500">
            {linkedApps.value.length + connectedSites.value.length} connected
          </span>
        </div>

        {linkedApps.value.length === 0 && connectedSites.value.length === 0 ? (
          <div class="rounded-lg border border-dashed border-gray-600 bg-gray-900/50 p-8 text-center">
            <svg class="mx-auto mb-3 h-8 w-8 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={1.5}>
              <path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
            </svg>
            <p class="text-sm text-gray-500">No apps or sites connected yet.</p>
            <p class="mt-1 text-xs text-gray-600">
              Apps using the Flowsta SDK will appear here when they connect.
            </p>
          </div>
        ) : (
          <div class="space-y-2">
            {/* Identity-linked apps first */}
            {linkedApps.value.map((app) => {
              const scopes = (app.client_id ? appScopes.value[app.client_id] : null) ?? [];
              const scopeLabels: Record<string, string> = {
                openid: "Identity",
                display_name: "Display name",
                username: "Username",
                profile_picture: "Profile picture",
                email: "Email",
                did: "DID",
                public_key: "Public key",
                holochain: "Holochain",
              };
              const visibleScopes = scopes.filter((s) => s !== "openid");
              return (
                <div
                  key={`app-${app.app_agent_pub_key}`}
                  class="rounded-lg border border-blue-800/50 bg-blue-900/10 px-4 py-3"
                >
                  <div class="flex items-center justify-between gap-3">
                    <div class="min-w-0 flex-1">
                      <div class="flex items-center gap-2">
                        <div class="flex h-6 w-6 shrink-0 items-center justify-center rounded bg-blue-900/50 text-xs text-sky-400">
                          {app.app_name.charAt(0).toUpperCase()}
                        </div>
                        <span class="text-sm font-medium text-white">{app.app_name}</span>
                        <span class="rounded-full bg-blue-900/30 px-2 py-0.5 text-[10px] font-medium text-sky-400">
                          Identity linked
                        </span>
                      </div>
                      <div class="mt-1 flex items-center gap-3 text-xs text-gray-500">
                        <span>Linked {new Date(app.linked_at * 1000).toLocaleDateString()}</span>
                        <code class="truncate font-mono">
                          {app.app_agent_pub_key.substring(0, 8)}...{app.app_agent_pub_key.substring(app.app_agent_pub_key.length - 6)}
                        </code>
                      </div>
                      {visibleScopes.length > 0 && (
                        <div class="mt-2 flex flex-wrap gap-1">
                          {visibleScopes.map((scope) => (
                            <span
                              key={scope}
                              class="rounded-full border border-gray-700 bg-gray-800/80 px-2 py-0.5 text-[10px] text-gray-400"
                            >
                              {scopeLabels[scope] ?? scope}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                    <GlassButton
                      variant="danger"
                      onClick$={() => handleRevokeLinkedApp(app.app_agent_pub_key)}
                    >
                      Revoke
                    </GlassButton>
                  </div>
                </div>
              );
            })}

            {/* Connected sites */}
            {connectedSites.value.map((site) => (
              <div
                key={`site-${site.origin}`}
                class={[
                  "flex items-center justify-between rounded-lg border px-4 py-3",
                  site.trusted
                    ? "border-green-800/50 bg-green-900/10"
                    : "border-gray-700 bg-gray-800/50",
                ].join(" ")}
              >
                <div class="min-w-0 flex-1">
                  <div class="flex items-center gap-2">
                    <div class="flex h-6 w-6 items-center justify-center rounded bg-gray-700 text-xs text-gray-400">
                      {(() => {
                        try {
                          return new URL(site.origin).hostname.charAt(0).toUpperCase();
                        } catch {
                          return "?";
                        }
                      })()}
                    </div>
                    <span class="truncate text-sm font-medium text-white">
                      {site.origin}
                    </span>
                    {site.trusted && (
                      <span class="flex items-center gap-1 rounded-full bg-green-900/30 px-2 py-0.5 text-[10px] font-medium text-green-400">
                        <svg class="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2.5}>
                          <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                        Trusted
                      </span>
                    )}
                  </div>
                  <div class="mt-1 flex items-center gap-3 text-xs text-gray-500">
                    <span>{site.request_count} request{site.request_count !== 1 ? "s" : ""}</span>
                    <span>Last: {timeAgo(site.last_request)}</span>
                    <span class="rounded bg-gray-700 px-1.5 py-0.5 text-[10px] text-gray-400">
                      {site.last_action}
                    </span>
                  </div>
                </div>
                <div class="ml-4 flex items-center gap-2">
                  {site.has_authenticated && (
                    <button
                      type="button"
                      title={site.trusted ? "Revoke auto-approve" : "Auto-approve authentication"}
                      class={[
                        "flex h-8 w-8 items-center justify-center rounded-full transition-all",
                        site.trusted
                          ? "bg-green-900/30 text-green-400 hover:bg-green-900/50"
                          : "bg-gray-700/50 text-gray-500 hover:bg-gray-700 hover:text-gray-300",
                      ].join(" ")}
                      onClick$={() => handleToggleTrust(site.origin, !site.trusted)}
                    >
                      <svg class="h-4 w-4" fill={site.trusted ? "currentColor" : "none"} viewBox="0 0 24 24" stroke="currentColor" stroke-width={site.trusted ? 0 : 2}>
                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                    </button>
                  )}
                  <GlassButton
                    variant="danger"
                    onClick$={() => handleRevokeSite(site.origin)}
                  >
                    Remove
                  </GlassButton>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Web connected sites info */}
      <div class="mt-6 rounded-lg border border-gray-700 bg-gray-800/50 p-4">
        <div class="flex items-start gap-3">
          <svg class="h-5 w-5 text-gray-400 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={1.5}>
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
          </svg>
          <div>
            <h4 class="text-sm font-medium text-gray-300">Web Connected Sites</h4>
            <p class="mt-1 text-xs text-gray-500">
              Websites that use Flowsta Auth for login are managed separately through
              your web dashboard at flowsta.com under Connected Sites.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
});

export const head: DocumentHead = {
  title: "Connected Apps - Flowsta Vault",
};
