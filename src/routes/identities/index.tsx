import { component$, useComputed$, useSignal, useVisibleTask$, $ } from "@builder.io/qwik";
import type { DocumentHead } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { CopyButton } from "~/components/ui/CopyButton";
import { GlassButton } from "~/components/common/GlassButton";
import { dedupeLinkedApps } from "~/lib/linked-apps";
import { PillButton } from "~/components/ui/PillButton";

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

// Granted powers in the user's language, not scope strings.
const POWER_LABELS: Record<string, string> = {
  display_name: "your name",
  username: "your username",
  email: "your email address",
  profile_picture: "your profile picture",
  did: "your DID",
  public_key: "your public key",
  holochain: "Holochain access",
};
function humanPowers(perms: unknown): string {
  const list = (Array.isArray(perms) ? perms : [])
    .filter((x: string) => x !== "openid")
    .map((x: string) => POWER_LABELS[x] || x);
  return list.length > 0 ? list.join(", ") : "your identity";
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
  // Hosting model drives the account card: device-hosted vaults ARE the
  // account (nothing to link); sync-mode vaults companion a web account.
  const deviceHosted = useSignal(false);
  // Web account link state
  const linkStatus = useSignal<"idle" | "linking" | "success" | "error">("idle");
  const linkMessage = useSignal("");
  const linkedWebKey = useSignal<string | null>(null);

  // Linked third-party apps
  const linkedApps = useSignal<
    { app_name: string; app_agent_pub_key: string; linked_at: number; client_id: string | null }[]
  >([]);
  // One row per distinct app - collapses multiple installs/agents of the same
  // app (e.g. a reinstalled ProofPoll) into a single entry. Display-only; the
  // raw per-agent list above still backs scopes + per-agent revocation.
  const dedupedApps = useComputed$(() => dedupeLinkedApps(linkedApps.value));
  // Granted scopes per app, keyed by client_id
  const appScopes = useSignal<Record<string, string[]>>({});

  // Connected sites (IPC origins). A row here is TRAFFIC, not consent -
  // only origins the user granted auto-approve to (trusted) appear in the
  // grants list; the rest live in the collapsed Bridge Activity log.
  const connectedSites = useSignal<ConnectedSite[]>([]);
  const trustedSites = useComputed$(() => connectedSites.value.filter((s) => s.trusted));
  const activitySites = useComputed$(() => connectedSites.value.filter((s) => !s.trusted));
  const activityOpen = useSignal(false);

  // Web sign-ins (OAuth grants) - server-authoritative, fetched with a
  // vault-grant session so this page shows the COMPLETE picture. The web
  // dashboard keeps a thin editor for these rows; app connections live
  // only here.
  const webSites = useSignal<any[]>([]);
  const webSitesState = useSignal<"loading" | "ok" | "unavailable">("loading");
  const webToken = useSignal<string | null>(null);
  const revokingWebId = useSignal("");

  const loadWebSites = $(async () => {
    try {
      const grant = await invoke<{ token: string }>("vault_grant_login", {
        apiUrl: __API_URL__,
      });
      webToken.value = grant.token;
      const resp = await fetch(`${__API_URL__}/auth/sites`, {
        headers: { authorization: `Bearer ${grant.token}` },
      });
      if (!resp.ok) throw new Error(`${resp.status}`);
      const data = await resp.json();
      webSites.value = data.sites || [];
      webSitesState.value = "ok";
    } catch {
      // Offline, or a custodial-linked vault (no vault-grant) - the web
      // dashboard remains the place to manage these.
      webSitesState.value = "unavailable";
    }
  });

  const disconnectWebSite = $(async (siteId: string, appName: string) => {
    if (!webToken.value || revokingWebId.value) return;
    if (!confirm(`Disconnect from "${appName}"? This signs you out of it and revokes its access token.`)) return;
    revokingWebId.value = siteId;
    try {
      const resp = await fetch(`${__API_URL__}/auth/sites/${siteId}`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${webToken.value}` },
      });
      if (!resp.ok) throw new Error(`${resp.status}`);
      webSites.value = webSites.value.filter((x) => x.id !== siteId);
    } catch (e) {
      console.error("Failed to disconnect web site:", e);
    } finally {
      revokingWebId.value = "";
    }
  });

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
          hosting_model: string | null;
        }>("get_identity"),
        invoke<{ app_name: string; app_agent_pub_key: string; linked_at: number; client_id: string | null }[]>(
          "get_linked_third_party_apps"
        ),
        invoke<ConnectedSite[]>("get_connected_sites"),
        invoke<Record<string, string[]>>("get_all_linked_app_scopes"),
      ]);

      deviceHosted.value = identity.hosting_model === "device-hosted";
      if (identity.web_agent_pub_key) {
        linkedWebKey.value = identity.web_agent_pub_key;
        linkStatus.value = "success";
      }

      linkedApps.value = apps;
      appScopes.value = scopes;
      connectedSites.value = sites.filter((s) => !isInternalOrigin(s.origin));
      loadWebSites();
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

  // Revoke every agent linked for one app (the deduped row may cover several
  // installs/devices - revoking the app should unlink all of them).
  const handleRevokeLinkedApp = $(async (appAgentPubKeys: string[]) => {
    try {
      for (const appAgentPubKey of appAgentPubKeys) {
        await invoke("revoke_linked_third_party_app", { appAgentPubKey });
      }
      linkedApps.value = linkedApps.value.filter(
        (a) => !appAgentPubKeys.includes(a.app_agent_pub_key),
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
            <div key={i} class="animate-pulse rounded-lg border border-gray-700 bg-[#15203a] p-6">
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
      <h1 class="mb-1 text-2xl font-bold text-white">Connections</h1>
      <p class="mb-6 text-sm text-gray-400">
        Apps and sites that can use your identity. Disconnect anything you no
        longer use.
      </p>

      {/* Sync-mode vaults companion a web account and need the link flow;
          for everyone else the page needs no preamble - the list IS the page. */}
      {!deviceHosted.value && (
      <div class="mb-6 rounded-lg border border-gray-700 bg-[#15203a] p-6">
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
          <div class="flex items-center gap-3 rounded-lg border border-gray-700 bg-black/30 p-4">
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
            <div class="flex items-center justify-between rounded-lg border border-dashed border-gray-600 bg-black/30 p-4">
              <div>
                <p class="text-sm text-gray-400">Not linked yet</p>
                <p class="text-xs text-gray-500">
                  Requires a Flowsta web account with the same recovery phrase
                </p>
              </div>
              <GlassButton class="shrink-0" onClick$={handleLinkWebAccount}>
                Link Now
              </GlassButton>
            </div>
          </div>
        )}
      </div>
      )}

      {/* Apps & Sites list */}
      <div class="rounded-lg border border-gray-700 bg-[#15203a] p-6">
        <div class="mb-4 flex items-center justify-between">
          <h3 class="text-lg font-semibold text-white">Apps & Sites</h3>
          <span class="text-xs text-gray-500">
            {dedupedApps.value.length + trustedSites.value.length + webSites.value.length} connected
          </span>
        </div>

        {linkedApps.value.length === 0 && trustedSites.value.length === 0 && webSites.value.length === 0 ? (
          <div class="rounded-lg border border-dashed border-gray-600 bg-black/30 p-8 text-center">
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
            {/* Identity-linked apps first (one row per app, installs collapsed) */}
            {dedupedApps.value.map((app) => {
              const scopes = (app.client_id ? appScopes.value[app.client_id] : null) ?? [];
              const deviceCount = app.agent_keys.length;
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
                  key={`app-${app.client_id ?? app.app_name}`}
                  class="rounded-lg border border-violet-800/50 bg-violet-900/10 px-4 py-3"
                >
                  <div class="flex items-center justify-between gap-3">
                    <div class="min-w-0 flex-1">
                      <div class="flex items-center gap-2">
                        <div class="flex h-6 w-6 shrink-0 items-center justify-center rounded bg-violet-900/50 text-xs text-violet-400">
                          {app.app_name.charAt(0).toUpperCase()}
                        </div>
                        <span class="text-sm font-medium text-white">{app.app_name}</span>
                        <span class="rounded-full border border-violet-800 bg-violet-900/20 px-2 py-0.5 text-[10px] font-medium text-violet-400">
                          App
                        </span>
                      </div>
                      <div class="mt-1 flex items-center gap-3 text-xs text-gray-500">
                        <span>Linked {new Date(app.linked_at * 1000).toLocaleDateString()}</span>
                        {deviceCount > 1 ? (
                          <span>{deviceCount} devices</span>
                        ) : (
                          <code class="truncate font-mono">
                            {app.agent_keys[0].substring(0, 8)}...{app.agent_keys[0].substring(app.agent_keys[0].length - 6)}
                          </code>
                        )}
                      </div>
                      {visibleScopes.length > 0 && (
                        <div class="mt-2 flex flex-wrap gap-1">
                          {visibleScopes.map((scope) => (
                            <span
                              key={scope}
                              class="rounded-full border border-gray-700 bg-black/30 px-2 py-0.5 text-[10px] text-gray-400"
                            >
                              {scopeLabels[scope] ?? scope}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                    <GlassButton
                      variant="danger"
                      onClick$={() => handleRevokeLinkedApp(app.agent_keys)}
                    >
                      Revoke
                    </GlassButton>
                  </div>
                </div>
              );
            })}

            {/* Auto-approve grants: origins the user explicitly trusted to
                sign in without a dialog. This IS a grant - it lives with
                the other grants. Plain traffic is in Bridge Activity below. */}
            {trustedSites.value.map((site) => (
              <div
                key={`trusted-${site.origin}`}
                class="flex items-center justify-between rounded-lg border border-green-800/50 bg-green-900/10 px-4 py-3"
              >
                <div class="min-w-0 flex-1">
                  <div class="flex items-center gap-2">
                    <div class="flex h-6 w-6 items-center justify-center rounded bg-green-900/50 text-xs text-green-400">
                      {(() => {
                        try {
                          return new URL(site.origin).hostname.charAt(0).toUpperCase();
                        } catch {
                          return "?";
                        }
                      })()}
                    </div>
                    <span class="truncate text-sm font-medium text-white">
                      {site.origin.replace(/^https?:\/\//, "")}
                    </span>
                    <span class="rounded-full border border-green-800 bg-green-900/20 px-2 py-0.5 text-[10px] font-medium text-green-400">
                      Trusted
                    </span>
                  </div>
                  <div class="mt-1 text-xs text-gray-500">
                    Signs you in without asking · since {new Date(site.first_seen * 1000).toLocaleDateString()}
                  </div>
                </div>
                <GlassButton
                  variant="danger"
                  onClick$={() => handleToggleTrust(site.origin, false)}
                >
                  Revoke
                </GlassButton>
              </div>
            ))}

            {/* Connected sites */}
            {connectedSites.value.map((site) => (
              <div
                key={`site-${site.origin}`}
                class={[
                  "flex items-center justify-between rounded-lg border px-4 py-3",
                  site.trusted
                    ? "border-green-800/50 bg-green-900/10"
                    : "border-gray-700 bg-black/30",
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

            {/* Web sign-ins (OAuth grants) - server-authoritative */}
            {webSites.value.map((site: any) => (
              <div
                key={`web-${site.id}`}
                class="flex items-center justify-between rounded-lg border border-blue-800/50 bg-blue-900/10 px-4 py-3"
              >
                <div class="min-w-0 flex-1">
                  <div class="flex items-center gap-2">
                    {site.logoUrl ? (
                      <img src={site.logoUrl} alt="" width={24} height={24} class="h-6 w-6 shrink-0 rounded" />
                    ) : (
                      <div class="flex h-6 w-6 shrink-0 items-center justify-center rounded bg-blue-900/50 text-xs text-blue-400">
                        {(site.appName || site.clientId || "?").charAt(0).toUpperCase()}
                      </div>
                    )}
                    <span class="truncate text-sm font-medium text-white">
                      {site.appName || site.clientId || "Web sign-in"}
                    </span>
                    <span class="rounded-full border border-blue-800 bg-blue-900/20 px-2 py-0.5 text-[10px] font-medium text-blue-400">
                      Web
                    </span>
                  </div>
                  <div class="mt-1 flex items-center gap-3 text-xs text-gray-500">
                    {site.firstConnectedAt && (
                      <span>
                        Connected {new Date(site.firstConnectedAt).toLocaleDateString()}
                      </span>
                    )}
                    <span class="truncate">Can see: {humanPowers(site.permissions)}</span>
                  </div>
                </div>
                <GlassButton
                  variant="danger"
                  disabled={revokingWebId.value === site.id}
                  onClick$={() => disconnectWebSite(site.id, site.appName || "this site")}
                >
                  {revokingWebId.value === site.id ? "…" : "Disconnect"}
                </GlassButton>
              </div>
            ))}
          </div>
        )}

        {webSitesState.value === "unavailable" && (
          <p class="mt-3 text-xs text-gray-500">
            Web sign-ins couldn't be loaded right now - manage them anytime at
            flowsta.com under Connected Sites.
          </p>
        )}
      </div>

      {/* Bridge activity - traffic log, NOT grants. Origins that called
          this device's bridge without holding any standing permission. */}
      {activitySites.value.length > 0 && (
        <div class="mt-6 rounded-lg border border-gray-700 bg-[#15203a] p-6">
          <button
            type="button"
            class="flex w-full items-center justify-between"
            onClick$={() => (activityOpen.value = !activityOpen.value)}
          >
            <div class="text-left">
              <h3 class="text-sm font-semibold text-white">Bridge activity</h3>
              <p class="mt-0.5 text-xs text-gray-500">
                {activitySites.value.length} site{activitySites.value.length !== 1 ? "s" : ""} contacted this Vault without holding any permission
              </p>
            </div>
            <svg
              class={["h-4 w-4 text-gray-500 transition-transform", activityOpen.value ? "rotate-180" : ""].join(" ")}
              fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}
            >
              <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
            </svg>
          </button>

          {activityOpen.value && (
            <div class="mt-4 space-y-2">
              {activitySites.value.map((site) => (
                <div
                  key={`activity-${site.origin}`}
                  class="flex items-center justify-between rounded-lg border border-gray-700 bg-black/30 px-4 py-2.5"
                >
                  <div class="min-w-0 flex-1">
                    <span class="truncate text-sm text-gray-300">{site.origin}</span>
                    <div class="mt-0.5 flex items-center gap-3 text-xs text-gray-500">
                      <span>{site.request_count} request{site.request_count !== 1 ? "s" : ""}</span>
                      <span>Last: {timeAgo(site.last_request)}</span>
                      <span class="rounded bg-gray-700 px-1.5 py-0.5 text-[10px] text-gray-400">{site.last_action}</span>
                    </div>
                  </div>
                  <div class="ml-4 flex items-center gap-2">
                    {site.has_authenticated && (
                      <PillButton
                        accent="green"
                        title="Trust this site to sign you in without asking"
                        onClick$={() => handleToggleTrust(site.origin, true)}
                      >
                        Trust
                      </PillButton>
                    )}
                    <PillButton
                      accent="red"
                      title="Clear from this log"
                      onClick$={() => handleRevokeSite(site.origin)}
                    >
                      Clear
                    </PillButton>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

    </div>
  );
});

export const head: DocumentHead = {
  title: "Connections - Flowsta Vault",
};
