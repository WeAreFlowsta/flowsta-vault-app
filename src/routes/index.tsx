import { $, component$, useComputed$, useContext, useSignal, useVisibleTask$ } from "@builder.io/qwik";
import type { DocumentHead } from "@builder.io/qwik-city";
import { Link } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-shell";
import { listen } from "@tauri-apps/api/event";
import { CopyButton } from "~/components/ui/CopyButton";
import { PillButton } from "~/components/ui/PillButton";
import { GlassButton } from "~/components/common/GlassButton";
import ImageCropper from "~/components/sign-it/ImageCropper";
import { signaturesContext } from "~/lib/context";
import { dedupeLinkedApps } from "~/lib/linked-apps";

declare const __API_URL__: string;
declare const __WEB_URL__: string;

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

interface BackupRecordSummary {
  counts_by_entry_type: Record<string, number>;
  total_records: number;
}

interface BackupStats {
  app_count: number;
  total_backups: number;
  total_size: number;
  apps: {
    app_name: string;
    last_backup_at: number;
    /** Latest backup's per-entry-type summary, if canonical-shape. */
    latest_summary?: BackupRecordSummary | null;
  }[];
}

/** "12 polls, 38 votes" or null if nothing to show. */
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

interface LinkedApp {
  app_name: string;
  app_agent_pub_key: string;
  linked_at: number;
  client_id?: string | null;
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
  // One entry per distinct app (collapses multiple installs/agents of the
  // same app — see dedupeLinkedApps).
  const connectedApps = useComputed$(() => dedupeLinkedApps(linkedApps.value));
  const loading = useSignal(true);
  // Plan/quota status — public endpoint, keyed to the account the
  // subscription is attached to. Upgrading is a web (Stripe) flow.
  const planInfo = useSignal<{ tier: string; used: number; limit: number } | null>(null);

  // Username claim/change — the registrar lives server-side (uniqueness,
  // login lookup, the public URL, billing tiers); the command authenticates
  // with a vault-grant and mirrors the result on-device.
  const usernameEditing = useSignal(false);
  const usernameInput = useSignal("");
  const usernameBusy = useSignal(false);
  const usernameError = useSignal("");
  // Set when a claim is refused for an unverified email — offers resend.
  const usernameNeedsVerify = useSignal(false);
  const resendBusy = useSignal(false);
  const resendNote = useSignal("");

  // In-app profile edits — name inline, picture via the cropper modal.
  const nameEditing = useSignal(false);
  const nameInput = useSignal("");
  const nameBusy = useSignal(false);
  const nameError = useSignal("");
  const avatarImage = useSignal<string | null>(null);
  const avatarCanvas = useSignal<HTMLCanvasElement | null>(null);
  const avatarBusy = useSignal(false);
  const avatarError = useSignal("");

  // Push the edit to the server's public-profile cache (what flowsta.com/<u>
  // and Sign It verification enrichment show). Best-effort: the Vault write
  // is canonical; offline just means the cache catches up on a later edit.
  const refreshServerProfile = $(async (body: { displayName?: string; profilePicture?: string }) => {
    try {
      const grant = await invoke<{ token: string }>("vault_grant_login", {
        apiUrl: __API_URL__,
      });
      const path = body.profilePicture ? "/auth/profile-picture" : "/auth/profile";
      await fetch(`${__API_URL__}${path}`, {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${grant.token}`,
        },
        body: JSON.stringify(body),
      });
    } catch { /* offline — cache refreshes on a later edit */ }
  });

  const saveDisplayName = $(async () => {
    const n = nameInput.value.trim();
    if (!n || nameBusy.value) return;
    nameBusy.value = true;
    nameError.value = "";
    try {
      await invoke("update_local_profile", { displayName: n });
      if (identity.value) identity.value = { ...identity.value, display_name: n };
      nameEditing.value = false;
      await refreshServerProfile({ displayName: n });
    } catch (e) {
      nameError.value = `${e}`;
    } finally {
      nameBusy.value = false;
    }
  });

  const handleAvatarChosen = $((_: Event, el: HTMLInputElement) => {
    const file = el.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      avatarImage.value = e.target?.result as string;
    };
    reader.readAsDataURL(file);
    el.value = "";
  });

  const saveAvatar = $(async () => {
    if (!avatarCanvas.value || avatarBusy.value) return;
    avatarBusy.value = true;
    avatarError.value = "";
    try {
      const pic = avatarCanvas.value.toDataURL("image/jpeg", 0.85);
      await invoke("update_local_profile", { profilePicture: pic });
      if (identity.value) identity.value = { ...identity.value, profile_picture: pic };
      avatarImage.value = null;
      avatarCanvas.value = null;
      await refreshServerProfile({ profilePicture: pic });
    } catch (e) {
      avatarError.value = `${e}`;
    } finally {
      avatarBusy.value = false;
    }
  });

  const resendVerification = $(async () => {
    if (resendBusy.value) return;
    resendBusy.value = true;
    resendNote.value = "";
    try {
      const grant = await invoke<{ token: string }>("vault_grant_login", {
        apiUrl: __API_URL__,
      });
      const resp = await fetch(`${__API_URL__}/auth/resend-verification`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${grant.token}`,
        },
        body: JSON.stringify({ email: identity.value?.web_email ?? "" }),
      });
      const data = await resp.json().catch(() => null);
      resendNote.value = resp.ok
        ? `Verification email sent to ${identity.value?.web_email} — click the link, then claim your username.`
        : data?.error || "Could not send the verification email. Try again in a few minutes.";
    } catch (e) {
      resendNote.value = `${e}`;
    } finally {
      resendBusy.value = false;
    }
  });

  const claimUsername = $(async () => {
    const u = usernameInput.value.trim().toLowerCase();
    if (!u || usernameBusy.value) return;
    usernameBusy.value = true;
    usernameError.value = "";
    try {
      const confirmed = await invoke<string>("claim_web_username", {
        apiUrl: __API_URL__,
        username: u,
      });
      if (identity.value) {
        identity.value = { ...identity.value, web_username: confirmed };
      }
      usernameEditing.value = false;
      usernameInput.value = "";
    } catch (e) {
      usernameError.value = `${e}`;
      usernameNeedsVerify.value = `${e}`.toLowerCase().includes("verify your email");
    } finally {
      usernameBusy.value = false;
    }
  });

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
      try {
        const key = id.web_agent_pub_key || id.agent_pub_key;
        const resp = await fetch(
          `${__API_URL__}/api/v1/sign-it/quota/by-agent?agent_pub_key=${encodeURIComponent(key)}`,
          { cache: "no-store" },
        );
        if (resp.ok) {
          const q = await resp.json();
          planInfo.value = { tier: q.tier || "free", used: q.used ?? 0, limit: q.limit ?? 0 };
        }
      } catch { /* offline — plan card shows a dash */ }
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

    // Keep the connected-apps list live: the IPC server emits these when an app
    // links or is revoked, so refetch instead of waiting for a manual reload.
    const refreshApps = async () => {
      try {
        linkedApps.value = await invoke<LinkedApp[]>("get_linked_third_party_apps");
      } catch { /* Vault may be locked */ }
    };
    const unlistenAdded = await listen("linked-app-added", refreshApps);
    const unlistenRevoked = await listen("linked-app-revoked", refreshApps);
    cleanup(() => unlistenAdded());
    cleanup(() => unlistenRevoked());
  });

  if (loading.value) {
    return (
      <div>
        <div class="mb-6 animate-pulse rounded-lg border border-gray-700 bg-[#15203a] p-6">
          <div class="mb-3 h-4 w-24 rounded bg-gray-700" />
          <div class="mb-2 h-4 w-full rounded bg-gray-700" />
          <div class="h-4 w-3/4 rounded bg-gray-700" />
        </div>
        <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} class="animate-pulse rounded-lg border border-gray-700 bg-[#15203a] p-4">
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
  const sigsLoaded = sigStore.loaded.value;
  const currentSigs = sigStore.signatures.value.filter((s: any) => !(s as any).superseded_by);
  const sigCount = currentSigs.length;
  const activeSigs = currentSigs.filter((s: any) => !s.revoked).length;
  const revokedSigs = sigCount - activeSigs;
  const amendedSigs = sigStore.signatures.value.filter((s: any) => (s as any).superseded_by).length;
  // Unified Recent Activity feed across signatures + backups + linked apps.
  // currentSigs already filters out superseded chain entries, so an amended
  // signature shows once (its latest signed_at) rather than twice.
  type Activity =
    | { kind: "signature"; timestamp: number; label: string }
    | { kind: "backup"; timestamp: number; appName: string; summary?: BackupRecordSummary | null }
    | { kind: "link"; timestamp: number; appName: string };
  const recentActivities: Activity[] = [];
  // Only surface sigs in the activity feed once linked has settled —
  // otherwise we'd leak the same partial count the Signatures tile is
  // hiding behind "Syncing from the network…".
  if (sigsLoaded) {
    for (const sig of currentSigs as any[]) {
      if (typeof sig.signed_at === "number" && sig.signed_at > 0) {
        const label =
          sig.fileName ||
          (typeof sig.file_hash === "string" && sig.file_hash.length >= 8
            ? `${sig.file_hash.slice(0, 8)}…`
            : "a file");
        // `signed_at` is committed by the signing DNA in milliseconds
        // (commands.rs uses `as_millis()`), but `timeAgo` + the other
        // activity sources (backups, links) deal in seconds — convert
        // so the merged feed sorts and renders correctly.
        recentActivities.push({
          kind: "signature",
          timestamp: Math.floor(sig.signed_at / 1000),
          label,
        });
      }
    }
  }
  for (const app of stats?.apps ?? []) {
    if (app.last_backup_at > 0) {
      recentActivities.push({
        kind: "backup",
        timestamp: app.last_backup_at,
        appName: app.app_name,
        summary: app.latest_summary,
      });
    }
  }
  for (const app of linkedApps.value) {
    if (app.linked_at > 0) {
      recentActivities.push({ kind: "link", timestamp: app.linked_at, appName: app.app_name });
    }
  }
  recentActivities.sort((a, b) => b.timestamp - a.timestamp);
  const recentActivitiesTop = recentActivities.slice(0, 5);

  return (
    <div>
      {/* Stats Grid */}
      <div class="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Signatures */}
        <Link
          href="/sign-it/"
          class="rounded-xl border border-white/10 bg-white/[0.06] p-5 transition-colors hover:border-white/20 hover:bg-white/[0.1]"
        >
          <div class="mb-3 flex items-center gap-2 text-gray-400">
            <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
              <path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
            </svg>
            <span class="text-sm font-medium">Signatures</span>
          </div>
          <p class="text-3xl font-bold text-white">
            {sigsLoaded ? (
              sigCount
            ) : (
              <span class="inline-block h-7 w-10 animate-pulse rounded bg-gray-700 align-middle" />
            )}
          </p>
          <p class="mt-1 text-xs text-gray-500">
            {!sigsLoaded
              ? "Syncing — first load takes a few minutes"
              : sigCount === 0
                ? "Sign your first file"
                : [
                    `${activeSigs} active`,
                    revokedSigs > 0 ? `${revokedSigs} revoked` : null,
                    amendedSigs > 0 ? `${amendedSigs} amendment${amendedSigs === 1 ? "" : "s"}` : null,
                  ].filter(Boolean).join(", ")}
          </p>
        </Link>

        {/* Connected Apps */}
        <Link
          href="/identities/"
          class="rounded-xl border border-white/10 bg-white/[0.06] p-5 transition-colors hover:border-white/20 hover:bg-white/[0.1]"
        >
          <div class="mb-3 flex items-center gap-2 text-gray-400">
            <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
              <path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
            </svg>
            <span class="text-sm font-medium">Connected Apps</span>
          </div>
          <p class="text-3xl font-bold text-white">
            {connectedApps.value.length}
          </p>
          <p class="mt-1 text-xs text-gray-500">
            {connectedApps.value.length === 0
              ? "No apps linked yet"
              : connectedApps.value.map((a) => a.app_name).join(", ")}
          </p>
        </Link>

        {/* Backups */}
        <Link
          href="/your-data/"
          class="rounded-xl border border-white/10 bg-white/[0.06] p-5 transition-colors hover:border-white/20 hover:bg-white/[0.1]"
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
          {stats && stats.apps.length > 0 && (
            <p class="mt-0.5 text-xs italic text-gray-600">
              Last backup {timeAgo(Math.max(...stats.apps.map((a) => a.last_backup_at)))}
            </p>
          )}
        </Link>

        {/* Plan */}
        <button
          type="button"
          class="rounded-xl border border-white/10 bg-white/[0.06] p-5 text-left transition-colors hover:border-white/20 hover:bg-white/[0.1]"
          onClick$={() => open(`${__WEB_URL__}/dashboard/premium/`)}
        >
          <div class="mb-3 flex items-center gap-2 text-gray-400">
            <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
              <path stroke-linecap="round" stroke-linejoin="round" d="M11.48 3.499a.562.562 0 011.04 0l2.125 5.111a.563.563 0 00.475.345l5.518.442c.499.04.701.663.321.988l-4.204 3.602a.563.563 0 00-.182.557l1.285 5.385a.562.562 0 01-.84.61l-4.725-2.885a.563.563 0 00-.586 0L6.982 20.54a.562.562 0 01-.84-.61l1.285-5.386a.562.562 0 00-.182-.557l-4.204-3.602a.563.563 0 01.321-.988l5.518-.442a.563.563 0 00.475-.345L11.48 3.5z" />
            </svg>
            <span class="text-sm font-medium">Plan</span>
          </div>
          <p class="text-3xl font-bold text-white">
            {planInfo.value
              ? planInfo.value.tier === "free"
                ? "Free"
                : planInfo.value.tier.charAt(0).toUpperCase() +
                  planInfo.value.tier.slice(1).replace("_", " ")
              : "—"}
          </p>
          <p class="mt-1 text-sm text-gray-400">
            {planInfo.value
              ? `${planInfo.value.used} of ${planInfo.value.limit} signs used this month`
              : "Plan status unavailable offline"}
          </p>
          <p class="mt-0.5 text-xs text-sky-400">
            {planInfo.value && planInfo.value.tier !== "free"
              ? "Manage plan →"
              : "Upgrade →"}
          </p>
        </button>
      </div>

      {/* Public profile — the identity hero: your link front and center,
          Change lives on the link itself, DID shown in full as the quiet
          technical line (copy / document). */}
      <div class="mb-6 rounded-lg border border-gray-700 bg-[#15203a] p-6">
        <div class="mb-3 flex items-center justify-between">
          <h3 class="text-lg font-semibold text-white">Public Profile</h3>
          <PillButton onClick$={() => open(`${__WEB_URL__}/${id.web_username || id.agent_pub_key}`)}>
            <span class="relative flex h-1.5 w-1.5">
              <span class="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-60" />
              <span class="relative inline-flex h-1.5 w-1.5 rounded-full bg-green-400" />
            </span>
            View live page
            <svg class="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
              <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
            </svg>
          </PillButton>
        </div>

        {/* Who you are: picture + name + email */}
        <div class="mb-4 flex items-center gap-4">
          <label class="group relative h-14 w-14 shrink-0 cursor-pointer" title="Change picture">
            <input type="file" accept="image/*" class="hidden" onChange$={handleAvatarChosen} />
            {id.profile_picture ? (
              <img
                src={id.profile_picture}
                alt="Profile"
                width={56}
                height={56}
                class="h-14 w-14 rounded-full border border-gray-600 object-cover"
              />
            ) : (
              <div class="flex h-14 w-14 items-center justify-center rounded-full bg-blue-600 text-xl font-medium text-white">
                {(id.display_name || id.web_username || "U").charAt(0).toUpperCase()}
              </div>
            )}
            <span class="absolute inset-0 hidden items-center justify-center rounded-full bg-black/60 group-hover:flex">
              <svg class="h-4 w-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                <path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L6.832 19.82a4.5 4.5 0 01-1.897 1.13l-2.685.8.8-2.685a4.5 4.5 0 011.13-1.897L16.863 4.487z" />
              </svg>
            </span>
          </label>
          <div class="min-w-0 flex-1">
            {nameEditing.value ? (
              <div class="flex items-center gap-2">
                <input
                  type="text"
                  value={nameInput.value}
                  placeholder="Your name"
                  maxLength={80}
                  autoFocus
                  class="min-w-0 flex-1 rounded-md border border-white/10 bg-black/30 px-4 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  onInput$={(_, el) => {
                    nameInput.value = el.value;
                  }}
                  onKeyDown$={(e) => {
                    if ((e as KeyboardEvent).key === "Enter") saveDisplayName();
                  }}
                />
                <button
                  type="button"
                  class="px-3 py-2 text-sm text-gray-400 transition-colors hover:text-gray-200"
                  disabled={nameBusy.value}
                  onClick$={() => {
                    nameEditing.value = false;
                    nameError.value = "";
                  }}
                >
                  Cancel
                </button>
                <GlassButton
                  disabled={nameBusy.value || nameInput.value.trim().length === 0}
                  onClick$={saveDisplayName}
                >
                  {nameBusy.value ? "Saving…" : "Save"}
                </GlassButton>
              </div>
            ) : (
              <div class="flex items-center gap-3">
                <p class={`truncate text-xl font-semibold ${id.display_name ? "text-white" : "text-gray-500"}`}>
                  {id.display_name || "Add your name"}
                </p>
                <PillButton
                  accent="amber"
                  class="shrink-0"
                  onClick$={() => {
                    nameInput.value = id.display_name || "";
                    nameError.value = "";
                    nameEditing.value = true;
                  }}
                >
                  <svg class="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                    <path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L6.832 19.82a4.5 4.5 0 01-1.897 1.13l-2.685.8.8-2.685a4.5 4.5 0 011.13-1.897L16.863 4.487z" />
                  </svg>
                  Edit
                </PillButton>
              </div>
            )}
            {nameError.value && (
              <p class="mt-1 text-xs text-red-400">{nameError.value}</p>
            )}
            {id.web_email && !nameEditing.value && (
              <p class="mt-0.5 truncate text-sm text-gray-400">{id.web_email}</p>
            )}
          </div>
        </div>

        {usernameEditing.value ? (
          /* Claim / change form — Website input treatment. */
          <div>
            <div class="flex items-center gap-2">
              <span class="hidden shrink-0 font-mono text-sm text-gray-500 sm:inline">
                {__WEB_URL__.replace(/^https?:\/\//, "")}/
              </span>
              <input
                type="text"
                value={usernameInput.value}
                placeholder="yourname (8+ characters on the free plan)"
                maxLength={30}
                autoFocus
                class="min-w-0 flex-1 rounded-md border border-white/10 bg-black/30 px-4 py-2 font-mono text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                onInput$={(_, el) => {
                  usernameInput.value = el.value;
                }}
                onKeyDown$={(e) => {
                  if ((e as KeyboardEvent).key === "Enter") claimUsername();
                }}
              />
              <button
                type="button"
                class="px-3 py-2 text-sm text-gray-400 transition-colors hover:text-gray-200"
                disabled={usernameBusy.value}
                onClick$={() => {
                  usernameEditing.value = false;
                  usernameError.value = "";
                }}
              >
                Cancel
              </button>
              <GlassButton
                disabled={usernameBusy.value || usernameInput.value.trim().length === 0}
                onClick$={claimUsername}
              >
                {usernameBusy.value ? "Saving…" : "Save"}
              </GlassButton>
            </div>
            {usernameError.value && (
              <p class="mt-2 text-sm text-red-400">{usernameError.value}</p>
            )}
            {usernameNeedsVerify.value && (
              <div class="mt-2 flex items-center gap-2">
                <PillButton disabled={resendBusy.value} onClick$={resendVerification}>
                  {resendBusy.value ? "Sending…" : "Resend verification email"}
                </PillButton>
                {resendNote.value && (
                  <p class="text-xs text-gray-400">{resendNote.value}</p>
                )}
              </div>
            )}
          </div>
        ) : id.web_username ? (
          /* Hero: the profile link, with Change living on the link itself */
          <div class="flex items-center justify-between gap-3 rounded-md border border-white/10 bg-black/30 px-4 py-3">
            <div class="min-w-0 flex-1 truncate font-mono text-lg">
              <span class="text-gray-500">{__WEB_URL__.replace(/^https?:\/\//, "")}/</span>
              <span class="font-semibold text-white">{id.web_username}</span>
            </div>
            <PillButton
              accent="amber"
              class="shrink-0"
              onClick$={() => {
                usernameInput.value = id.web_username || "";
                usernameError.value = "";
                usernameEditing.value = true;
              }}
            >
              <svg class="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                <path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L6.832 19.82a4.5 4.5 0 01-1.897 1.13l-2.685.8.8-2.685a4.5 4.5 0 011.13-1.897L16.863 4.487z" />
              </svg>
              Change
            </PillButton>
          </div>
        ) : (
          /* No username yet — show what the link looks like today and why
             a name beats it. One emphasized action. */
          <div class="rounded-lg border border-sky-500/30 bg-sky-500/10 px-4 py-3.5 text-sm text-sky-100">
            <p class="mb-1">Your profile link right now:</p>
            <p class="mb-3 break-all font-mono text-xs text-sky-200/80">
              {`${__WEB_URL__.replace(/^https?:\/\//, "")}/${id.agent_pub_key}`}
            </p>
            <p class="mb-3">
              Claim a username for a short, memorable profile —{" "}
              <span class="font-mono text-sky-300">
                {`${__WEB_URL__.replace(/^https?:\/\//, "")}/yourname`}
              </span>{" "}
              — and one identity people recognize everywhere. Change it anytime.
            </p>
            <GlassButton
              onClick$={() => {
                usernameInput.value = "";
                usernameError.value = "";
                usernameEditing.value = true;
              }}
            >
              Claim a username
            </GlassButton>
          </div>
        )}

        {/* DID — the permanent identifier, shown in full. No collapse. */}
        <div class="mt-3 flex items-start gap-2 px-1">
          <span class="mt-1.5 shrink-0 text-xs font-medium text-gray-500">DID</span>
          <code class="mt-1 min-w-0 flex-1 break-all font-mono text-[11px] leading-relaxed text-gray-400">
            {id.did}
          </code>
          <div class="flex shrink-0 items-center gap-1.5">
            <CopyButton text={id.did} label="Copy DID" />
            <PillButton
              accent="sky"
              title="Open the machine-readable DID document"
              onClick$={() => open(`${__API_URL__}/did/${id.agent_pub_key}`)}
            >
              <svg class="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                <path stroke-linecap="round" stroke-linejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
              </svg>
              Document
            </PillButton>
          </div>
        </div>

      </div>

      {/* Avatar cropper — opens when a picture is picked */}
      {avatarImage.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div class="mx-4 w-full max-w-md rounded-xl border border-gray-600 bg-gray-800 p-6 shadow-2xl">
            <h3 class="mb-4 text-base font-semibold text-white">Change Profile Picture</h3>
            <ImageCropper
              imageSrc={avatarImage.value}
              cropShape="circle"
              outputSize={300}
              onCropComplete$={(c) => {
                avatarCanvas.value = c;
              }}
            />
            {avatarError.value && (
              <p class="mt-3 text-xs text-red-400">{avatarError.value}</p>
            )}
            <div class="mt-4 flex gap-3">
              <GlassButton
                variant="secondary"
                class="flex-1"
                onClick$={() => {
                  avatarImage.value = null;
                  avatarCanvas.value = null;
                  avatarError.value = "";
                }}
              >
                Cancel
              </GlassButton>
              <GlassButton
                class="flex-1"
                disabled={avatarBusy.value || !avatarCanvas.value}
                onClick$={saveAvatar}
              >
                {avatarBusy.value ? "Saving…" : "Save"}
              </GlassButton>
            </div>
          </div>
        </div>
      )}

      {/* Recent Activity — unified feed: signatures, backups, linked apps. */}
      <div class="mb-6 rounded-lg border border-gray-700 bg-[#15203a] p-6">
        <h3 class="mb-4 text-lg font-semibold text-white">
          Recent Activity
        </h3>

        {recentActivitiesTop.length === 0 ? (
          <p class="py-4 text-center text-sm text-gray-500">
            No activity yet — sign a file or connect an app to see it here.
          </p>
        ) : (
          <div class="space-y-3">
            {recentActivitiesTop.map((a, i) => {
              if (a.kind === "signature") {
                return (
                  <div key={`s${i}`} class="flex items-center gap-3">
                    <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-amber-900/30">
                      <svg class="h-4 w-4 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                        <path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
                      </svg>
                    </div>
                    <div class="min-w-0 flex-1">
                      <p class="truncate text-sm text-white">
                        Signed <span class="font-medium">{a.label}</span>
                      </p>
                      <p class="text-xs text-gray-500">{timeAgo(a.timestamp)}</p>
                    </div>
                  </div>
                );
              }
              if (a.kind === "backup") {
                const summaryLabel = formatSummary(a.summary);
                return (
                  <div key={`b${i}`} class="flex items-center gap-3">
                    <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-blue-900/30">
                      <svg class="h-4 w-4 text-sky-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                        <path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
                      </svg>
                    </div>
                    <div class="min-w-0 flex-1">
                      <p class="text-sm text-white">
                        <span class="font-medium">{a.appName}</span>{" "}
                        {summaryLabel
                          ? <>backed up <span class="text-gray-400">{summaryLabel}</span></>
                          : "backed up data"}
                      </p>
                      <p class="text-xs text-gray-500">{timeAgo(a.timestamp)}</p>
                    </div>
                  </div>
                );
              }
              return (
                <div key={`l${i}`} class="flex items-center gap-3">
                  <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-green-900/30">
                    <svg class="h-4 w-4 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                      <path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                    </svg>
                  </div>
                  <div class="min-w-0 flex-1">
                    <p class="text-sm text-white">
                      <span class="font-medium">{a.appName}</span> linked identity
                    </p>
                    <p class="text-xs text-gray-500">{timeAgo(a.timestamp)}</p>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

    </div>
  );
});

export const head: DocumentHead = {
  title: "Overview - Flowsta Vault",
};
