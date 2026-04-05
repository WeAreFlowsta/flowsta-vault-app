import { component$, useSignal, useStore, useVisibleTask$, useContextProvider, $, Slot } from "@builder.io/qwik";
import { useLocation, Link } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { emit, listen } from "@tauri-apps/api/event";
import { SetupWizard } from "~/components/vault/SetupWizard";
import { UnlockScreen } from "~/components/vault/UnlockScreen";
import { StatusIndicator } from "~/components/vault/StatusIndicator";
import type { ConnectionStatus } from "~/components/vault/StatusIndicator";
import { connectionStatusContext, autoLockContext } from "~/lib/context";
import { GlassButton } from "~/components/common/GlassButton";

type AppScreen = "loading" | "setup" | "unlock" | "dashboard";

declare const __API_URL__: string;
declare const __APP_VERSION__: string;

const navItems = [
  { label: "Overview", href: "/", icon: "home" },
  { label: "Sign It", href: "/sign-it/", icon: "pencil" },
  { label: "Connected Apps", href: "/identities/", icon: "link" },
  { label: "Your Data", href: "/your-data/", icon: "database" },
  { label: "Settings", href: "/settings/", icon: "cog" },
];

export default component$(() => {
  const screen = useSignal<AppScreen>("loading");
  const connectionStatus = useSignal<ConnectionStatus>("offline");
  useContextProvider(connectionStatusContext, connectionStatus);
  const conductorStatus = useSignal<"stopped" | "starting" | "ready" | "error">("stopped");
  const conductorMessage = useSignal("");
  const autoLockMinutes = useSignal(15);
  useContextProvider(autoLockContext, autoLockMinutes);
  const loc = useLocation();
  const userProfile = useStore({
    displayName: "",
    profilePicture: "",
    email: "",
  });

  // Auth approval dialog state
  const pendingAuth = useSignal<{
    id: string;
    app_name: string;
    origin: string | null;
    reason: string | null;
  } | null>(null);
  const rememberApp = useSignal(false);

  // Link-identity approval dialog state
  const pendingLinkIdentity = useSignal<{
    id: string;
    app_name: string;
    origin: string | null;
    organization_name: string | null;
    scopes: string[];
    description: string | null;
    logo_url: string | null;
    replacing_existing: boolean;
  } | null>(null);

  // Document-sign approval dialog state (Sign It)
  const pendingDocumentSign = useSignal<{
    id: string;
    app_name: string;
    file_hash: string;
    label: string | null;
    origin: string | null;
  } | null>(null);

  // Fetch profile from unlocked vault for header display
  const fetchProfile = $(async () => {
    try {
      const identity = await invoke<{
        display_name: string | null;
        profile_picture: string | null;
        web_email: string | null;
      }>("get_identity");

      userProfile.displayName = identity.display_name ?? "";
      userProfile.profilePicture = identity.profile_picture ?? "";
      userProfile.email = identity.web_email ?? "";
    } catch {
      // Non-critical — header just won't show profile info
    }
  });

  const checkConnectivity = $(async () => {
    try {
      const online = await invoke<boolean>("check_api_connectivity", {
        apiUrl: __API_URL__,
      });
      connectionStatus.value = online ? "online" : "offline";
    } catch {
      connectionStatus.value = "offline";
    }
  });

  const handleUnlockPassword = $(async (password: string) => {
    await invoke("unlock_vault", { password });
    // Refresh profile data (username, display name, picture) from the API so that
    // changes made on the website are reflected without requiring a vault reset.
    // Awaited so the overview page sees the updated data on first load.
    await invoke("refresh_cached_profile", { apiUrl: __API_URL__, password }).catch(() => {});
    await fetchProfile();
    screen.value = "dashboard";
    checkConnectivity();
    try {
      autoLockMinutes.value = await invoke<number>("get_auto_lock_minutes");
    } catch { /* use default */ }
  });

  // Poll connectivity every 30s while on dashboard
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ track, cleanup }) => {
    const s = track(() => screen.value);
    if (s !== "dashboard") return;

    const id = setInterval(async () => {
      try {
        const online = await invoke<boolean>("check_api_connectivity", {
          apiUrl: __API_URL__,
        });
        connectionStatus.value = online ? "online" : "offline";
      } catch {
        connectionStatus.value = "offline";
      }
    }, 30_000);

    cleanup(() => clearInterval(id));
  });

  // Auto-lock: lock vault after inactivity
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ track, cleanup }) => {
    const s = track(() => screen.value);
    const minutes = track(() => autoLockMinutes.value);
    if (s !== "dashboard" || minutes === 0) return;

    let timer: ReturnType<typeof setTimeout>;

    const resetTimer = () => {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        try {
          await invoke("lock_vault");
          screen.value = "unlock";
        } catch {
          // ignore
        }
      }, minutes * 60_000);
    };

    const events = ["mousemove", "mousedown", "keydown", "touchstart", "scroll"];
    events.forEach((e) => document.addEventListener(e, resetTimer));
    resetTimer();

    cleanup(() => {
      clearTimeout(timer);
      events.forEach((e) => document.removeEventListener(e, resetTimer));
    });
  });

  // Listen for auth-request events from the IPC server
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ track, cleanup }) => {
    const s = track(() => screen.value);
    if (s !== "dashboard") return;

    const unlistenPromise = listen<{
      id: string;
      app_name: string;
      origin: string | null;
      reason: string | null;
    }>("auth-request", (event) => {
      pendingAuth.value = event.payload;
      rememberApp.value = false;
    });

    cleanup(() => {
      unlistenPromise.then((unlisten) => unlisten());
    });
  });

  // Listen for link-identity-request events from the IPC server
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ track, cleanup }) => {
    const s = track(() => screen.value);
    if (s !== "dashboard") return;

    const unlistenPromise = listen<{
      id: string;
      app_name: string;
      organization_name: string | null;
      scopes: string[];
      description: string | null;
      logo_url: string | null;
      origin: string | null;
      replacing_existing: boolean;
    }>("link-identity-request", (event) => {
      pendingLinkIdentity.value = event.payload;
    });

    cleanup(() => {
      unlistenPromise.then((unlisten) => unlisten());
    });
  });

  // Listen for document-sign-request from IPC server (Sign It)
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ cleanup }) => {
    const unlistenPromise = listen<{
      id: string;
      app_name: string;
      file_hash: string;
      label: string | null;
      origin: string | null;
    }>("document-sign-request", (event) => {
      pendingDocumentSign.value = event.payload;
    });

    cleanup(() => {
      unlistenPromise.then((unlisten) => unlisten());
    });
  });

  // Listen for vault-lock-requested from system tray
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ cleanup }) => {
    const unlistenPromise = listen("vault-lock-requested", async () => {
      try {
        await invoke("lock_vault");
        screen.value = "unlock";
      } catch {
        // ignore — vault may already be locked
      }
    });

    cleanup(() => {
      unlistenPromise.then((unlisten) => unlisten());
    });
  });

  // Listen for conductor-status events + initial poll
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ track, cleanup }) => {
    const s = track(() => screen.value);
    if (s !== "dashboard") return;

    // Initial poll
    invoke<{ status: string; message?: string }>("get_conductor_status")
      .then((result) => {
        conductorStatus.value = result.status as typeof conductorStatus.value;
        if (result.message) conductorMessage.value = result.message;
      })
      .catch(() => {});

    // Listen for real-time updates from conductor startup sequence
    const unlistenPromise = listen<{ status: string; message?: string }>(
      "conductor-status",
      (event) => {
        conductorStatus.value = event.payload.status as typeof conductorStatus.value;
        conductorMessage.value = event.payload.message ?? "";
      },
    );

    // Listen for profile sync (profile picture/name updated from web account)
    const unlistenProfilePromise = listen("profile-synced", () => {
      fetchProfile();
    });

    cleanup(() => {
      unlistenPromise.then((unlisten) => unlisten());
      unlistenProfilePromise.then((unlisten) => unlisten());
    });
  });

  const handleAuthResponse = $(async (approved: boolean) => {
    try {
      await invoke("respond_auth_request", {
        approved,
        remember: approved && rememberApp.value,
      });
    } catch (e) {
      console.error("Failed to respond to auth request:", e);
    } finally {
      pendingAuth.value = null;
      rememberApp.value = false;
    }
  });

  const handleLinkIdentityResponse = $(async (approved: boolean) => {
    try {
      await invoke("respond_link_identity_request", { approved });
    } catch (e) {
      console.error("Failed to respond to link-identity request:", e);
    } finally {
      pendingLinkIdentity.value = null;
    }
  });

  const handleDocumentSignResponse = $(async (approved: boolean) => {
    try {
      await invoke("respond_document_sign_request", { approved });
    } catch (e) {
      console.error("Failed to respond to document-sign request:", e);
    } finally {
      pendingDocumentSign.value = null;
    }
  });

  // Check vault status on mount
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async () => {
    // Signal Rust backend that the frontend has loaded (shows the window)
    emit("frontend-ready");
    try {
      const status = await invoke<{
        initialized: boolean;
        unlocked: boolean;
      }>("get_vault_status");

      if (!status.initialized) {
        screen.value = "setup";
      } else if (!status.unlocked) {
        screen.value = "unlock";
      } else {
        screen.value = "dashboard";
        await fetchProfile();
        checkConnectivity();
        try {
          autoLockMinutes.value = await invoke<number>("get_auto_lock_minutes");
        } catch { /* use default */ }
      }
    } catch {
      screen.value = "setup";
    }
  });

  if (screen.value === "loading") {
    return (
      <div class="flex min-h-screen items-center justify-center bg-gray-900">
        <div class="text-center">
          <div class="mb-4 inline-flex h-12 w-12 items-center justify-center">
            <svg
              class="h-8 w-8 animate-spin text-amber-400"
              fill="none"
              viewBox="0 0 24 24"
            >
              <circle
                class="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                stroke-width="4"
              />
              <path
                class="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
              />
            </svg>
          </div>
          <p class="text-sm text-gray-400">Loading Flowsta Vault...</p>
        </div>
      </div>
    );
  }

  if (screen.value === "setup") {
    return (
      <SetupWizard
        onComplete$={async () => {
          screen.value = "dashboard";
          await fetchProfile();
          checkConnectivity();
        }}
      />
    );
  }

  if (screen.value === "unlock") {
    return (
      <UnlockScreen
        onUnlock$={handleUnlockPassword}
        onResetVault$={() => {
          screen.value = "setup";
        }}
      />
    );
  }

  // Only show profile if displayName is set — never show raw hashes
  const displayName = userProfile.displayName || "";

  // Dashboard: full-width header at top, then sidebar + content below
  return (
    <div class="flex min-h-screen flex-col bg-gray-800">
      {/* Full-width header */}
      <header class="sticky top-0 z-40 w-full border-b border-gray-700 bg-gray-900">
        <div class="flex items-center justify-between py-3 px-6">
          {/* Left: Logo + VAULT badge */}
          <div class="flex items-center">
            <img src="/logo-dark.svg" alt="Flowsta" class="h-10" />
            <div class="ml-2 rounded-md bg-white px-2 py-0.5 flex items-center justify-center">
              <span class="text-xs font-bold tracking-wider text-gray-900">
                VAULT
              </span>
            </div>
          </div>

          {/* Right: Profile — only shown if display name is set */}
          {displayName && (
            <div class="flex items-center gap-2">
              <span class="text-sm text-gray-300">{displayName}</span>
              {userProfile.profilePicture ? (
                <img
                  src={userProfile.profilePicture}
                  alt="Profile"
                  class="h-8 w-8 rounded-full object-cover border border-gray-600"
                  width={32}
                  height={32}
                />
              ) : (
                <div class="flex h-8 w-8 items-center justify-center rounded-full bg-blue-600 text-sm font-medium text-white">
                  {displayName.charAt(0).toUpperCase()}
                </div>
              )}
            </div>
          )}
        </div>
      </header>

      {/* Below header: sidebar + content */}
      <div class="flex flex-1">
        {/* Sidebar */}
        <aside class="flex w-64 flex-col border-r border-gray-700 bg-gray-900">
          {/* Navigation */}
          <nav class="flex-1 px-4 pt-5">
            {navItems.map((item) => {
              const isActive =
                item.href === "/"
                  ? loc.url.pathname === "/"
                  : loc.url.pathname.startsWith(item.href);

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  class={[
                    "mb-2 flex items-center gap-3 rounded-full px-4 py-3 text-sm font-medium transition-colors relative",
                    isActive
                      ? "text-white"
                      : "text-gray-300 hover:bg-gray-800 hover:text-white",
                  ].join(" ")}
                >
                  {isActive && (
                    <span class="absolute left-2 h-1.5 w-1.5 rounded-full bg-current" />
                  )}
                  <NavIcon name={item.icon} />
                  {item.label}
                </Link>
              );
            })}
          </nav>

          {/* Status + Lock */}
          <div class="border-t border-gray-700 px-4 py-4">
            <div class="mb-2 flex items-center justify-between">
              <StatusIndicator status={connectionStatus.value} />
              <span class="text-xs text-gray-500">v{__APP_VERSION__}</span>
            </div>
            <div
              class="mb-3 flex items-center gap-2"
              title={conductorMessage.value || undefined}
            >
              <span class="relative flex h-2.5 w-2.5 shrink-0">
                {(conductorStatus.value === "starting" || conductorStatus.value === "ready") && (
                  <span class={[
                    "absolute inline-flex h-full w-full animate-ping rounded-full opacity-75",
                    conductorStatus.value === "ready" ? "bg-green-400" : "bg-blue-400",
                  ].join(" ")} />
                )}
                <span
                  class={[
                    "relative inline-flex h-2.5 w-2.5 rounded-full",
                    conductorStatus.value === "ready"
                      ? "bg-green-400"
                      : conductorStatus.value === "starting"
                        ? "bg-blue-400"
                        : conductorStatus.value === "error"
                          ? "bg-red-400"
                          : "bg-gray-500",
                  ].join(" ")}
                />
              </span>
              <span class="text-xs text-gray-400 truncate">
                {conductorStatus.value === "starting"
                  ? (conductorMessage.value || "Starting...")
                  : conductorStatus.value === "error"
                    ? "HC Error"
                    : "Holochain"}
              </span>
            </div>
            <button
              type="button"
              class="flex w-full items-center justify-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-xs text-gray-400 hover:bg-gray-800 hover:text-gray-300 transition-colors"
              onClick$={async () => {
                await invoke("lock_vault");
                screen.value = "unlock";
              }}
            >
              <svg class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              Lock Vault
            </button>
          </div>
        </aside>

        {/* Main content */}
        <main class="flex-1 overflow-y-auto">
          <div class="py-6 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
            <Slot />
          </div>
        </main>
      </div>

      {/* Auth approval dialog overlay */}
      {pendingAuth.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div class="mx-4 w-full max-w-sm rounded-xl border border-gray-600 bg-gray-800 p-6 shadow-2xl">
            <div class="mb-4 flex items-center gap-3">
              <div class="flex h-10 w-10 items-center justify-center rounded-full bg-amber-500/20">
                <svg
                  class="h-5 w-5 text-amber-400"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  stroke-width={2}
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                  />
                </svg>
              </div>
              <div>
                <h3 class="text-base font-semibold text-white">
                  Authentication Request
                </h3>
                <p class="text-xs text-gray-400">
                  An app wants to verify your identity
                </p>
              </div>
            </div>

            <div class="mb-4 space-y-2 rounded-lg border border-gray-700 bg-gray-900 p-3">
              <div>
                <span class="text-xs text-gray-500">App Name</span>
                <p class="text-sm font-medium text-white">
                  {pendingAuth.value.app_name}
                </p>
              </div>
              {pendingAuth.value.origin && (
                <div>
                  <span class="text-xs text-gray-500">Origin</span>
                  <p class="text-sm text-gray-300">
                    {pendingAuth.value.origin}
                  </p>
                </div>
              )}
              {pendingAuth.value.reason && (
                <div>
                  <span class="text-xs text-gray-500">Reason</span>
                  <p class="text-sm text-gray-300">
                    {pendingAuth.value.reason}
                  </p>
                </div>
              )}
            </div>

            <p class="mb-4 text-xs text-gray-400">
              This will share your DID and public key. Your private key never
              leaves the vault.
            </p>

            <label class="mb-4 flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={rememberApp.value}
                onChange$={(e) => {
                  rememberApp.value = (e.target as HTMLInputElement).checked;
                }}
                class="h-4 w-4 rounded border-gray-600 bg-gray-700 text-amber-500 focus:ring-amber-500 focus:ring-offset-0"
              />
              <span class="text-xs text-gray-400">
                Remember this site (auto-approve next time)
              </span>
            </label>

            <div class="flex gap-3">
              <GlassButton
                variant="secondary"
                class="flex-1"
                onClick$={() => handleAuthResponse(false)}
              >
                Deny
              </GlassButton>
              <GlassButton
                class="flex-1"
                onClick$={() => handleAuthResponse(true)}
              >
                Allow
              </GlassButton>
            </div>
          </div>
        </div>
      )}

      {/* Link-identity approval dialog overlay */}
      {pendingLinkIdentity.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div class="mx-4 w-full max-w-sm rounded-xl border border-gray-600 bg-gray-800 p-6 shadow-2xl">
            <div class="mb-4 flex items-center gap-3">
              <div class="flex h-10 w-10 items-center justify-center rounded-full bg-blue-500/20">
                <svg
                  class="h-5 w-5 text-sky-400"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  stroke-width={2}
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"
                  />
                </svg>
              </div>
              <div>
                <h3 class="text-base font-semibold text-white">
                  {pendingLinkIdentity.value.app_name}
                </h3>
                {pendingLinkIdentity.value.organization_name && (
                  <p class="text-xs text-gray-400">
                    by {pendingLinkIdentity.value.organization_name}
                  </p>
                )}
              </div>
            </div>

            {pendingLinkIdentity.value.replacing_existing && (
              <p class="mb-3 text-xs text-amber-400">
                This app has updated its registration. Approving will update your existing link.
              </p>
            )}

            {pendingLinkIdentity.value.scopes && pendingLinkIdentity.value.scopes.length > 0 && (
              <div class="mb-4 rounded-lg border border-gray-700 bg-gray-900 p-3">
                <p class="mb-2 text-xs font-medium text-gray-400">
                  This app will be able to access:
                </p>
                <ul class="space-y-1.5">
                  {pendingLinkIdentity.value.scopes.filter((s) => s !== "openid").map((scope) => {
                    const labels: Record<string, { label: string; elevated?: boolean }> = {
                      did: { label: "Decentralized ID (DID)" },
                      public_key: { label: "Public key" },
                      email: { label: "Email address" },
                      display_name: { label: "Display name" },
                      username: { label: "Username" },
                      profile_picture: { label: "Profile picture" },
                      holochain: { label: "Holochain identity" },
                    };
                    const info = labels[scope] || { label: scope };
                    return (
                      <li
                        key={scope}
                        class={[
                          "flex items-center gap-2 text-xs",
                          info.elevated ? "text-amber-400" : "text-gray-300",
                        ].join(" ")}
                      >
                        <span class={info.elevated ? "text-amber-500" : "text-green-500"}>
                          {info.elevated ? "\u26A0" : "\u2713"}
                        </span>
                        {info.label}
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}

            <p class="mb-4 text-xs text-gray-500">
              Your private key never leaves the vault.
            </p>

            <div class="flex gap-3">
              <GlassButton
                variant="secondary"
                class="flex-1"
                onClick$={() => handleLinkIdentityResponse(false)}
              >
                Deny
              </GlassButton>
              <GlassButton
                class="flex-1"
                onClick$={() => handleLinkIdentityResponse(true)}
              >
                {pendingLinkIdentity.value.replacing_existing ? 'Update' : 'Allow'}
              </GlassButton>
            </div>
          </div>
        </div>
      )}

      {/* Document sign approval dialog (Sign It) */}
      {pendingDocumentSign.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div class="mx-4 w-full max-w-sm rounded-xl border border-gray-600 bg-gray-800 p-6 shadow-2xl">
            <div class="mb-4 flex items-center gap-3">
              <div class="flex h-10 w-10 items-center justify-center rounded-full bg-amber-500/20">
                <svg class="h-5 w-5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                  <path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931z" />
                </svg>
              </div>
              <div>
                <h3 class="text-base font-semibold text-white">Sign Document</h3>
                <p class="text-xs text-gray-400">
                  {pendingDocumentSign.value.app_name}
                </p>
              </div>
            </div>

            <div class="mb-4 space-y-2 rounded-lg border border-gray-700 bg-gray-900 p-3">
              {pendingDocumentSign.value.label && (
                <div class="flex justify-between">
                  <span class="text-xs text-gray-500">File</span>
                  <span class="text-xs text-white truncate max-w-[200px]">
                    {pendingDocumentSign.value.label}
                  </span>
                </div>
              )}
              <div class="flex justify-between">
                <span class="text-xs text-gray-500">Hash</span>
                <span class="text-xs font-mono text-gray-300 truncate max-w-[200px]">
                  {pendingDocumentSign.value.file_hash.slice(0, 16)}...
                </span>
              </div>
              {pendingDocumentSign.value.origin && (
                <div class="flex justify-between">
                  <span class="text-xs text-gray-500">From</span>
                  <span class="text-xs text-gray-300 truncate max-w-[200px]">
                    {pendingDocumentSign.value.origin}
                  </span>
                </div>
              )}
            </div>

            <p class="mb-4 text-xs text-gray-400">
              This app wants you to cryptographically sign a file. Your signature will be publicly verifiable on the DHT.
            </p>

            <div class="flex gap-3">
              <GlassButton
                variant="secondary"
                class="flex-1"
                onClick$={() => handleDocumentSignResponse(false)}
              >
                Deny
              </GlassButton>
              <GlassButton
                class="flex-1"
                onClick$={() => handleDocumentSignResponse(true)}
              >
                Sign
              </GlassButton>
            </div>
          </div>
        </div>
      )}
    </div>
  );
});

// Simple nav icon component
const NavIcon = component$<{ name: string }>(({ name }) => {
  const iconPaths: Record<string, string> = {
    home: "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6",
    link: "M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1",
    database: "M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4",
    pencil: "M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10",
    cog: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z",
  };

  return (
    <svg
      class="h-5 w-5"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      stroke-width={1.5}
    >
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        d={iconPaths[name] ?? ""}
      />
    </svg>
  );
});
