import { $, component$, useComputed$, useContext, useSignal, useVisibleTask$ } from "@builder.io/qwik";
import type { DocumentHead } from "@builder.io/qwik-city";
import { Link } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-shell";
import { listen } from "@tauri-apps/api/event";
import { CopyButton } from "~/components/ui/CopyButton";
import { PillButton } from "~/components/ui/PillButton";
import { GlassButton } from "~/components/common/GlassButton";
import Callout from "~/components/dashboard/Callout";
import ImageCropper from "~/components/sign-it/ImageCropper";
import { UpgradeAccountCard } from "~/components/vault/UpgradeAccountCard";
import { ContactCard } from "~/components/vault/ContactCard";
import { connectionStatusContext, signaturesContext } from "~/lib/context";
import { normalizeEmail, isValidEmail, emailsMatch, EMAIL_INVALID, EMAIL_MISMATCH } from "~/lib/email";
import { dedupeLinkedApps } from "~/lib/linked-apps";
import { ActivityRow } from "~/components/vault/ActivityRow";
import { buildFeed, timeAgo, recentlyRestored, type ActivityLogEntry } from "~/lib/activity";

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
  /** Flowsta's confirmation of that address; null = not learned yet. */
  email_verified: boolean | null;
  web_username: string | null;
  web_agent_pub_key: string | null;
  hosting_model: string | null;
  pending_reconcile: boolean;
  pending_registration: boolean;
  registration_conflict: boolean;
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


export default component$(() => {
  const identity = useSignal<VaultIdentity | null>(null);
  // The Vault's own log (sign-ins, grants, changes) - the rest of the feed
  // is derived from signatures, backups and links.
  const activityLog = useSignal<ActivityLogEntry[]>([]);
  // Restored vault: re-enter the registered email (confirmed against the hash).
  const confirmEmailInput = useSignal("");
  const confirmEmailInput2 = useSignal("");
  const confirmEmailNote = useSignal("");
  const confirmEmailBusy = useSignal(false);
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async ({ cleanup }) => {
    const unlisten = await listen("activity-recorded", async () => {
      activityLog.value = await invoke<ActivityLogEntry[]>("get_activity", { limit: 20 }).catch(() => []);
    });
    cleanup(() => unlisten());
  });
  // Soft update notice: a newer Vault is shipped. Dismissed per version.
  const vaultUpdate = useSignal<{ current: string; latest: string | null; summary: string | null; download_url: string; update_available: boolean } | null>(null);
  const updateDismissed = useSignal(true);
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async () => {
    try {
      const info = await invoke<{ current: string; latest: string | null; summary: string | null; download_url: string; update_available: boolean }>("check_vault_update", { apiUrl: __API_URL__ });
      vaultUpdate.value = info;
      let dismissedFor = "";
      try { dismissedFor = localStorage.getItem("flowsta_vault_update_dismissed") || ""; } catch { /* no storage */ }
      updateDismissed.value = !info.update_available || dismissedFor === info.latest;
    } catch { /* offline or older API - no notice */ }
  });
  const backupStats = useSignal<BackupStats | null>(null);
  const linkedApps = useSignal<LinkedApp[]>([]);
  // One entry per distinct app (collapses multiple installs/agents of the
  // same app - see dedupeLinkedApps).
  const connectedApps = useComputed$(() => dedupeLinkedApps(linkedApps.value));
  const loading = useSignal(true);
  // Plan/quota status - public endpoint, keyed to the account the
  // subscription is attached to. Upgrading is a web (Stripe) flow.
  const planInfo = useSignal<{ tier: string; used: number; limit: number } | null>(null);
  // Restore-or-fresh question after an identity restore: while pending,
  // the bridge refuses third-party backup writes.
  const restoreChoicePending = useSignal(false);
  const resolvingChoice = useSignal(false);
  const startFresh = $(async () => {
    resolvingChoice.value = true;
    try {
      await invoke("resolve_restore_choice");
      restoreChoicePending.value = false;
    } finally {
      resolvingChoice.value = false;
    }
  });
  // Offline-create email collision: retry with a different address.
  const conflictEmail = useSignal("");
  const conflictEmail2 = useSignal("");
  const conflictBusy = useSignal(false);
  const conflictNote = useSignal("");
  const retryRegistrationEmail = $(async () => {
    const email = normalizeEmail(conflictEmail.value);
    if (!isValidEmail(email)) {
      conflictNote.value = EMAIL_INVALID;
      return;
    }
    if (!emailsMatch(email, conflictEmail2.value)) {
      conflictNote.value = EMAIL_MISMATCH;
      return;
    }
    conflictBusy.value = true;
    conflictNote.value = "";
    try {
      await invoke("update_pending_registration_email", {
        apiUrl: __API_URL__,
        email,
      });
      conflictNote.value = "";
      conflictEmail.value = "";
      conflictEmail2.value = "";
      identity.value = await invoke<VaultIdentity>("get_identity");
    } catch (e) {
      conflictNote.value = String(e).includes("email_already_registered")
        ? "That address is registered to another account too - try a different one."
        : String(e);
    } finally {
      conflictBusy.value = false;
    }
  });
  // Plan fetch is retryable: it aborts fast while offline (fire-drill
  // finding) and re-runs when connectivity returns or the profile syncs.
  const fetchPlan = $(async () => {
    const id = identity.value;
    if (!id) return;
    try {
      const key = id.hosting_model === "device-hosted"
        ? id.agent_pub_key
        : (id.web_agent_pub_key || id.agent_pub_key);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      const resp = await fetch(
        `${__API_URL__}/api/v1/sign-it/quota/by-agent?agent_pub_key=${encodeURIComponent(key)}`,
        { cache: "no-store", signal: controller.signal },
      );
      clearTimeout(timer);
      if (resp.ok) {
        const q = await resp.json();
        planInfo.value = { tier: q.tier || "free", used: q.used ?? 0, limit: q.limit ?? 0 };
      }
    } catch { /* offline - plan card shows a dash */ }
  });

  // Username claim/change - the registrar lives server-side (uniqueness,
  // login lookup, the public URL, billing tiers); the command authenticates
  // with a vault-grant and mirrors the result on-device.
  const usernameEditing = useSignal(false);
  const usernameInput = useSignal("");
  const usernameBusy = useSignal(false);
  const usernameError = useSignal("");
  // Set when a claim is refused for an unverified email - offers resend.
  const usernameNeedsVerify = useSignal(false);
  const resendBusy = useSignal(false);
  const resendNote = useSignal("");
  // After a phrase restore the vault doesn't know the email (the server
  // holds only a hash) - the user types it, the API verifies it against
  // the hash, and we remember it on success.
  const resendEmailInput = useSignal("");
  const resendEmailInput2 = useSignal("");

  // Copy-link feedback on the profile link row.
  const copiedLink = useSignal(false);
  const copyProfileLink = $(async () => {
    const u = identity.value?.web_username;
    if (!u) return;
    try {
      await navigator.clipboard.writeText(`${__WEB_URL__}/${u}`);
      copiedLink.value = true;
      setTimeout(() => (copiedLink.value = false), 1800);
    } catch { /* clipboard unavailable - the link itself still opens */ }
  });
  // The verify-first step reads the Vault's cached flag; while it says
  // "not verified" the person may have clicked the emailed link since, so
  // ask once on arrival and again on "check again".
  const verifyChecking = useSignal(false);
  const verifyChecked = useSignal(false);
  const checkVerified = $(async () => {
    if (verifyChecking.value) return;
    verifyChecking.value = true;
    try {
      const v = await invoke<boolean | null>("refresh_email_verified");
      if (identity.value && v !== null) {
        identity.value = { ...identity.value, email_verified: v };
        if (v) usernameNeedsVerify.value = false;
      }
    } catch { /* offline - the cached state stands */ }
    finally { verifyChecking.value = false; }
  });
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ track }) => {
    const id = track(() => identity.value);
    if (!id || verifyChecked.value) return;
    if (id.hosting_model === "device-hosted" && id.email_verified !== true && !id.web_username) {
      verifyChecked.value = true;
      checkVerified();
    }
  });

  // In-app profile edits - name inline, picture via the cropper modal.
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
    } catch { /* offline - cache refreshes on a later edit */ }
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
    const typed = !identity.value?.web_email;
    const email = identity.value?.web_email || normalizeEmail(resendEmailInput.value);
    if (!email) {
      resendNote.value = "Enter your account email above first.";
      return;
    }
    if (typed && !isValidEmail(email)) {
      resendNote.value = EMAIL_INVALID;
      return;
    }
    if (typed && !emailsMatch(email, resendEmailInput2.value)) {
      resendNote.value = EMAIL_MISMATCH;
      return;
    }
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
        body: JSON.stringify({ email }),
      });
      const data = await resp.json().catch(() => null);
      if (resp.ok) {
        resendNote.value = `Verification email sent to ${email} - click the link, then claim your username.`;
        // The API accepted it (hash-verified) - remember it in the vault.
        if (!identity.value?.web_email) {
          try {
            await invoke("set_web_email", { email });
            if (identity.value) {
              identity.value = { ...identity.value, web_email: email };
            }
          } catch (e) {
            console.warn("Could not persist email to vault config:", e);
          }
        }
      } else if (data?.error === "email_mismatch") {
        resendNote.value =
          "That address doesn't match the one this account registered with.";
      } else {
        resendNote.value =
          data?.error || "Could not send the verification email. Try again in a few minutes.";
      }
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

  // Shared signatures store from layout - count + last-known list are
  // already populated from cache by the time the user reaches Overview.
  const sigStore = useContext(signaturesContext);
  const connectionStatus = useContext(connectionStatusContext);

  // Back online with an empty plan card (offline unlock / fire-drill
  // reconnect): fetch it now instead of waiting for a page reload.
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ track }) => {
    const status = track(() => connectionStatus.value);
    if (status === "online" && planInfo.value === null) {
      fetchPlan();
    }
  });

  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async ({ cleanup }) => {
    try {
      const [id, stats, apps, choicePending, log] = await Promise.all([
        invoke<VaultIdentity>("get_identity"),
        invoke<BackupStats>("get_backup_stats"),
        invoke<LinkedApp[]>("get_linked_third_party_apps"),
        invoke<boolean>("restore_choice_pending").catch(() => false),
        invoke<ActivityLogEntry[]>("get_activity", { limit: 20 }).catch(() => []),
      ]);
      identity.value = id;
      backupStats.value = stats;
      linkedApps.value = apps;
      activityLog.value = log;
      restoreChoicePending.value = choicePending;
      // Paint NOW - everything above is local. The plan fetch below is
      // network-bound and must never hold the identity render hostage: on
      // a black-holed API (fire-drill finding) an untimed fetch hangs for
      // the OS TCP retry cycle and the page sat in its loading skeleton
      // for minutes.
      loading.value = false;
      await fetchPlan();
    } catch {
      // Vault might be locked
    } finally {
      loading.value = false;
    }

    // Refresh identity when the profile changes - synced from the web
    // account, edited in-app, or written via an approved bridge request.
    const refreshIdentity = async () => {
      try {
        identity.value = await invoke<VaultIdentity>("get_identity");
        fetchPlan();
      } catch { /* ignore */ }
    };
    const unlisten = await listen("profile-synced", refreshIdentity);
    // Bridge-approved edits carry the changed fields; push them to the
    // server's public-profile cache through the same best-effort path an
    // in-app edit uses. In-app edits emit an empty payload (their caller
    // already refreshed the cache) - nothing to push then.
    const unlistenEdit = await listen<{ display_name?: string; profile_picture?: string }>(
      "profile-updated",
      async (event) => {
        await refreshIdentity();
        const changed = event.payload ?? {};
        if (changed.display_name) {
          await refreshServerProfile({ displayName: changed.display_name });
        }
        if (changed.profile_picture) {
          await refreshServerProfile({ profilePicture: changed.profile_picture });
        }
      },
    );
    cleanup(() => unlisten());
    cleanup(() => unlistenEdit());

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
  // Unified Recent Activity feed: the Vault's log + signatures + backups +
  // linked apps, newest first. The Activity page shows all of it.
  const recentActivitiesTop = buildFeed({
    log: activityLog.value,
    sigs: currentSigs,
    sigsLoaded,
    stats,
    linkedApps: linkedApps.value,
  }).slice(0, 3);

  return (
    <div>
      {/* A restored vault holds no email: Flowsta keeps only its hash, so the
          person re-enters the address and the server confirms it. Until
          then no app can be offered the email. */}
      {identity.value && identity.value.hosting_model === "device-hosted" && !identity.value.web_email && (
        <Callout intent="info" title="Add the email you registered with" class="mb-6">
          <p class="mb-3">
            This Vault doesn't hold your email yet - Flowsta keeps only a fingerprint of it and can't send it back.
            Enter the address you registered this identity with and apps you allow can ask for it. A wrong address is
            simply refused; nothing is changed or sent.
          </p>
          <form
            preventdefault:submit
            class="flex flex-col gap-2 sm:flex-row sm:items-start"
            onSubmit$={async () => {
              const email = normalizeEmail(confirmEmailInput.value);
              if (!isValidEmail(email)) { confirmEmailNote.value = EMAIL_INVALID; return; }
              if (!emailsMatch(email, confirmEmailInput2.value)) { confirmEmailNote.value = EMAIL_MISMATCH; return; }
              confirmEmailBusy.value = true;
              confirmEmailNote.value = "";
              try {
                await invoke<boolean>("confirm_account_email", { apiUrl: __API_URL__, email });
                identity.value = { ...identity.value!, web_email: email };
                confirmEmailInput.value = "";
                confirmEmailInput2.value = "";
              } catch (e) {
                const msg = String(e);
                confirmEmailNote.value = msg.includes("email_mismatch")
                  ? "That address doesn't match the one this account registered with."
                  : msg.includes("rate_limited")
                    ? "Too many tries - wait a few minutes."
                    : "Couldn't reach Flowsta to confirm it. Are you online?";
              } finally {
                confirmEmailBusy.value = false;
              }
            }}
          >
            <div class="flex min-w-0 flex-1 flex-col gap-2">
              <input
                type="email"
                autocomplete="email"
                placeholder="Your account email"
                class="w-full rounded-md border border-gray-600 bg-gray-900 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none"
                value={confirmEmailInput.value}
                onInput$={(_, el) => { confirmEmailInput.value = el.value; confirmEmailNote.value = ""; }}
              />
              <input
                type="email"
                autocomplete="off"
                placeholder="Repeat your email"
                class="w-full rounded-md border border-gray-600 bg-gray-900 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none"
                value={confirmEmailInput2.value}
                onInput$={(_, el) => { confirmEmailInput2.value = el.value; confirmEmailNote.value = ""; }}
              />
              {confirmEmailNote.value && <p class="text-xs text-red-300">{confirmEmailNote.value}</p>}
            </div>
            <GlassButton type="submit" disabled={confirmEmailBusy.value || !confirmEmailInput.value}>
              {confirmEmailBusy.value ? "Checking…" : "Confirm"}
            </GlassButton>
          </form>
        </Callout>
      )}

      {vaultUpdate.value?.update_available && !updateDismissed.value && (
        <Callout
          intent="info"
          banner
          title={`Flowsta Vault ${vaultUpdate.value.latest} is available`}
          actionLabel="Get the update"
          onAction$={() => open(vaultUpdate.value?.download_url || `${__WEB_URL__}/vault/`)}
          dismissLabel="Later"
          dismissible
          onDismiss$={() => {
            updateDismissed.value = true;
            try { localStorage.setItem("flowsta_vault_update_dismissed", vaultUpdate.value?.latest || ""); } catch { /* no storage */ }
          }}
        >
          You're on {vaultUpdate.value.current}. Update from the download page - your identity and data stay as they are.
          {vaultUpdate.value.summary ? ` Highlights: ${vaultUpdate.value.summary}` : ""}
        </Callout>
      )}
      {/* The restore-or-fresh question - the one instruction the product
          never used to give: import your export BEFORE you open your
          apps. While unanswered, the bridge refuses third-party backup
          writes so an app launched too early can't claim an empty slot
          the export was about to fill. */}
      {restoreChoicePending.value && (
        <div class="mb-6 rounded-lg border border-amber-700/60 bg-amber-950/30 p-5">
          <p class="mb-1 text-sm font-semibold text-amber-200">
            Restore your app backups, or start fresh?
          </p>
          <p class="mb-4 text-sm text-gray-300">
            If you kept a Vault export file, import it now - your private
            records, app backups and email come back before you open your
            apps.
          </p>
          <div class="flex flex-col-reverse gap-2 sm:flex-row sm:items-center">
            <button
              class="rounded-full border border-gray-600 px-5 py-2 text-sm text-gray-300 hover:border-gray-400 hover:text-white disabled:opacity-50"
              disabled={resolvingChoice.value}
              onClick$={startFresh}
            >
              Start fresh
            </button>
            <GlassButton onClick$={() => (window.location.href = "/your-data/#restore")}>
              Import
            </GlassButton>
          </div>
        </div>
      )}

      {/* Account upgrade: a vault from the custodial-linked era (or an
          upgrade interrupted before the account flipped) finishes moving
          the account onto this device from here. The card verifies for
          itself that there is an upgrade to run. */}
      {id && !id.pending_reconcile && !id.pending_registration && (
        <UpgradeAccountCard
          hostingModel={id.hosting_model}
          webEmail={id.web_email}
          onUpgraded$={() => {
            window.location.reload();
          }}
        />
      )}

      {/* Offline-restore reconcile banner: identity is network-confirmed;
          only the account-layer conveniences are still detached. Clears
          itself when the reconcile task lands (profile-synced refetch). */}
      {(id?.pending_reconcile || id?.pending_registration) && (
        <div class="mb-6 rounded-lg border border-sky-800/50 bg-sky-950/30 p-4">
          <p class="mb-1 text-sm font-semibold text-sky-200">
            {id?.pending_registration
              ? "Created offline - your identity is active on the Flowsta network"
              : "Restored offline - your identity is active on the Flowsta network"}
          </p>
          <p class="text-xs text-gray-400">
            {sigCount > 0
              ? `✓ ${sigCount} record${sigCount === 1 ? "" : "s"} found via community nodes - the network itself confirms this identity.`
              : sigsLoaded
                ? "No public records yet for this identity - that's normal for identities that haven't signed anything."
                : "Looking for your records on the community network…"}
            {" "}
            {id?.pending_registration
              ? "Your Flowsta account attaches automatically when Flowsta is reachable - your email is checked and confirmed then (it isn't reserved until that moment)."
              : "Your @username, display name, and email reconnect automatically when Flowsta is reachable."}
          </p>
          {id?.registration_conflict && (
            <div class="mt-3 border-t border-sky-800/50 pt-3">
              <p class="mb-2 text-xs text-amber-300">
                That email already belongs to another Flowsta account. Use a
                different address - or if that account is yours, restore it
                with its recovery phrase instead.
              </p>
              <div class="flex flex-wrap gap-2">
                <input
                  type="email"
                  autocomplete="email"
                  value={conflictEmail.value}
                  onInput$={(e) => {
                    conflictEmail.value = (e.target as HTMLInputElement).value;
                    conflictNote.value = "";
                  }}
                  placeholder="you@example.com"
                  class="min-w-[12rem] flex-1 rounded-md border border-white/10 bg-black/30 px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <input
                  type="email"
                  autocomplete="off"
                  value={conflictEmail2.value}
                  onInput$={(e) => {
                    conflictEmail2.value = (e.target as HTMLInputElement).value;
                    conflictNote.value = "";
                  }}
                  onPaste$={(e) => e.preventDefault()}
                  placeholder="Repeat your email"
                  class="min-w-[12rem] flex-1 rounded-md border border-white/10 bg-black/30 px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <PillButton
                  accent="sky"
                  disabled={conflictBusy.value || !normalizeEmail(conflictEmail.value) || !normalizeEmail(conflictEmail2.value)}
                  onClick$={retryRegistrationEmail}
                >
                  {conflictBusy.value ? "Attaching…" : "Use this email"}
                </PillButton>
              </div>
              {conflictNote.value && (
                <p class="mt-2 text-xs text-red-400">{conflictNote.value}</p>
              )}
            </div>
          )}
        </div>
      )}

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
              ? "Syncing - first load takes a few minutes"
              : sigCount === 0
                ? recentlyRestored(activityLog.value)
                  ? "Syncing from the network - your signatures return in a few minutes"
                  : "Sign your first file"
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
              : "-"}
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

      {/* Public profile - a miniature of the public page: what you edit is
          what people see. Three things (picture, name, link) edit in place;
          the only pills are Copy link and Change. Email lives in Settings and
          shows here only while it blocks the username. The permanent ID is
          one quiet footer line, in full - the length of the identity key is
          the argument for a username, never something to hide. */}
      {(() => {
        const web = __WEB_URL__.replace(/^https?:\/\//, "");
        const deviceHosted = id.hosting_model === "device-hosted";
        const needsVerify = deviceHosted && (id.email_verified === false || usernameNeedsVerify.value);
        const createdMs = id.created_at > 1e12 ? id.created_at : id.created_at * 1000;
        const since = deviceHosted
          ? new Date(createdMs).toLocaleDateString("en-US", { month: "long", year: "numeric" })
          : null;
        const sigCount = sigStore.loaded.value
          ? sigStore.signatures.value.filter((sg: any) => !sg.superseded_by).length
          : 0;
        const pencil = (
          <svg class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
            <path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L6.832 19.82a4.5 4.5 0 01-1.897 1.13l-2.685.8.8-2.685a4.5 4.5 0 011.13-1.897l12.682-12.682z" />
          </svg>
        );
        return (
      <div class="mb-6 rounded-lg border border-gray-700 bg-[#15203a] p-6">
        {/* Who you are: picture + name, both edit in place */}
        <div class="mb-5 flex items-center gap-4">
          <label class="relative h-20 w-20 shrink-0 cursor-pointer" title="Change picture">
            <input type="file" accept="image/*" class="hidden" onChange$={handleAvatarChosen} />
            {id.profile_picture ? (
              <img
                src={id.profile_picture}
                alt="Profile"
                width={80}
                height={80}
                class="h-20 w-20 rounded-full border border-gray-600 object-cover"
              />
            ) : id.display_name || id.web_username ? (
              <div class="flex h-20 w-20 items-center justify-center rounded-full bg-blue-600 text-3xl font-medium text-white">
                {(id.display_name || id.web_username || "U").charAt(0).toUpperCase()}
              </div>
            ) : (
              <div class="flex h-20 w-20 items-center justify-center rounded-full border border-dashed border-gray-500 bg-black/30 text-gray-400">
                <svg class="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={1.6}>
                  <circle cx="12" cy="8" r="4" />
                  <path stroke-linecap="round" d="M4 21c0-4 3.6-7 8-7s8 3 8 7" />
                </svg>
              </div>
            )}
            <span class="absolute -bottom-0.5 -right-0.5 flex h-6 w-6 items-center justify-center rounded-full border-2 border-[#15203a] bg-white text-gray-900">
              {pencil}
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
              <button
                type="button"
                class="group flex max-w-full items-center gap-2 text-left"
                title={id.display_name ? "Edit your name" : "Add your name"}
                onClick$={() => {
                  nameInput.value = id.display_name || "";
                  nameError.value = "";
                  nameEditing.value = true;
                }}
              >
                <span class={`truncate text-2xl font-semibold ${id.display_name ? "text-white" : "text-gray-500"}`}>
                  {id.display_name || "Add your name"}
                </span>
                <span class="shrink-0 text-gray-500 opacity-70 transition-opacity group-hover:opacity-100">{pencil}</span>
              </button>
            )}
            {nameError.value && (
              <p class="mt-1 text-xs text-red-400">{nameError.value}</p>
            )}
            {id.web_username && !nameEditing.value && (
              <p class="mt-0.5 truncate text-base text-gray-400">@{id.web_username}</p>
            )}
            {since && !nameEditing.value && (
              <p class="mt-0.5 text-sm text-gray-400">
                On Flowsta since {since}
                {sigCount > 0 ? ` · ${sigCount} signature${sigCount === 1 ? "" : "s"}` : ""}
              </p>
            )}
          </div>
        </div>

        {/* Your link: the hero once a username exists; before that, one
            callout for both remaining steps (verify the email, then pick). */}
        {id.web_username && !usernameEditing.value ? (
          <div class="flex items-center justify-between gap-3 rounded-md border border-white/10 bg-black/30 px-4 py-3">
            <button
              type="button"
              class="group flex min-w-0 items-center gap-2 text-left font-mono text-lg"
              title="Open your page"
              onClick$={() => open(`${__WEB_URL__}/${id.web_username}`)}
            >
              <span class="truncate">
                <span class="text-gray-500">{web}/</span>
                <span class="font-semibold text-white group-hover:underline">{id.web_username}</span>
              </span>
              <svg class="h-3.5 w-3.5 shrink-0 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
              </svg>
            </button>
            <div class="flex shrink-0 gap-2">
              <PillButton accent="sky" onClick$={copyProfileLink}>
                {copiedLink.value ? "Copied" : "Copy link"}
              </PillButton>
              <PillButton
                accent="amber"
                onClick$={() => {
                  usernameInput.value = id.web_username || "";
                  usernameError.value = "";
                  usernameEditing.value = true;
                }}
              >
                {pencil}
                Change
              </PillButton>
            </div>
          </div>
        ) : (
          <>
            {needsVerify && !usernameEditing.value ? (
              <Callout
                intent="info"
                title="Verify your email to pick a username"
                actionLabel={resendBusy.value ? "Sending…" : "Resend email"}
                onAction$={resendVerification}
              >
                {id.web_email ? (
                  <p>We sent a link to {id.web_email}. Open it, then come back here.</p>
                ) : (
                  <div class="space-y-2">
                    <p>Enter your account email and we will send the link again.</p>
                    <input
                      type="email"
                      autocomplete="email"
                      placeholder="Your account email"
                      value={resendEmailInput.value}
                      onInput$={(_, el) => { resendEmailInput.value = el.value; resendNote.value = ""; }}
                      class="w-full max-w-xs rounded-md border border-white/10 bg-black/30 px-3 py-1.5 text-sm text-white placeholder-gray-500 focus:border-sky-500 focus:outline-none"
                    />
                    <input
                      type="email"
                      autocomplete="off"
                      placeholder="Repeat your email"
                      value={resendEmailInput2.value}
                      onInput$={(_, el) => { resendEmailInput2.value = el.value; resendNote.value = ""; }}
                      onPaste$={(e) => e.preventDefault()}
                      class="w-full max-w-xs rounded-md border border-white/10 bg-black/30 px-3 py-1.5 text-sm text-white placeholder-gray-500 focus:border-sky-500 focus:outline-none"
                    />
                  </div>
                )}
                {resendNote.value && <p class="mt-2 text-xs text-gray-400">{resendNote.value}</p>}
                <p class="mt-2 text-xs text-gray-400">
                  Already clicked it?{" "}
                  <button type="button" class="text-sky-400 hover:text-sky-300" disabled={verifyChecking.value} onClick$={checkVerified}>
                    {verifyChecking.value ? "Checking…" : "Check again"}
                  </button>
                  {" "}· Wrong address?{" "}
                  <Link href="/settings/" class="text-sky-400 hover:text-sky-300">Change it in Settings</Link>
                </p>
              </Callout>
            ) : (
              <Callout intent="info" title={id.web_username ? "Change your username" : "Pick your username"}>
                <p>Your page lives at {web}/yourname. Choose it once; change it anytime.</p>
                <div class="mt-3 flex items-center gap-2">
                  <div class="flex min-w-0 flex-1 items-center rounded-md border border-white/10 bg-black/30 pl-3 focus-within:ring-2 focus-within:ring-blue-500">
                    <span class="shrink-0 font-mono text-sm text-gray-500">{web}/</span>
                    <input
                      type="text"
                      value={usernameInput.value}
                      placeholder="yourname"
                      maxLength={30}
                      autoFocus={usernameEditing.value}
                      class="min-w-0 flex-1 bg-transparent px-2 py-2 font-mono text-sm text-white placeholder-gray-500 focus:outline-none"
                      onInput$={(_, el) => {
                        usernameInput.value = el.value;
                      }}
                      onKeyDown$={(e) => {
                        if ((e as KeyboardEvent).key === "Enter") claimUsername();
                      }}
                    />
                  </div>
                  {usernameEditing.value && (
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
                  )}
                  <GlassButton
                    disabled={usernameBusy.value || usernameInput.value.trim().length === 0}
                    onClick$={claimUsername}
                  >
                    {usernameBusy.value ? "Saving…" : "Save"}
                  </GlassButton>
                </div>
                <p class="mt-2 text-xs text-gray-400">8 characters or more on the free plan. Shorter names come with Pro.</p>
                {usernameError.value && <p class="mt-2 text-sm text-red-400">{usernameError.value}</p>}
              </Callout>
            )}
            {!id.web_username && (
              <p class="mt-3 text-sm leading-relaxed text-gray-400">
                Until you pick one, your page is{" "}
                <span class="break-all font-mono text-gray-300">{web}/{id.agent_pub_key}</span>
                {" "}- your identity's key. It works, but nobody will remember it.
              </p>
            )}
          </>
        )}

        {/* Permanent ID - in full, one quiet line. Copy takes the whole
            thing; the DID document link lives on Your Data. */}
        <div class="mt-4 border-t border-gray-700/60 pt-3">
          <div class="flex items-start gap-2">
            <span class="mt-1 shrink-0 text-xs font-medium text-gray-400">Permanent ID</span>
            <code class="mt-0.5 min-w-0 flex-1 break-all font-mono text-[11px] leading-relaxed text-gray-300">
              {id.did}
            </code>
            <CopyButton text={id.did} label="Copy your permanent ID" />
          </div>
          <p class="mt-1.5 text-xs leading-relaxed text-gray-400">
            Your username is how people find you. Your permanent ID is how your signatures and sign-ins prove they came from you. It never changes, and anyone can check it without asking Flowsta.
          </p>
        </div>
      </div>
        );
      })()}
      {/* Messages through the profile page - optional, off by default. */}
      {id.hosting_model === "device-hosted" && <ContactCard />}

      {/* Avatar cropper - opens when a picture is picked */}
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

      {/* Recent Activity - the latest three; the Activity page has everything. */}
      <div class="mb-6 rounded-lg border border-gray-700 bg-[#15203a] p-6">
        <div class="mb-4 flex items-center justify-between">
          <h3 class="text-lg font-semibold text-white">Recent Activity</h3>
          <Link href="/activity/" class="text-sm text-amber-400 hover:text-amber-300">
            See all activity →
          </Link>
        </div>

        {recentActivitiesTop.length === 0 ? (
          <p class="py-4 text-center text-sm text-gray-500">
            No activity yet - sign in to an app, sign a file or connect an app to see it here.
          </p>
        ) : (
          <div class="space-y-3">
            {recentActivitiesTop.map((item) => (
              <ActivityRow key={item.key} item={item} when={timeAgo(item.timestamp)} />
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
