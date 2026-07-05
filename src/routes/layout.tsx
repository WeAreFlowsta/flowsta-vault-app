import { component$, useSignal, useStore, useVisibleTask$, useContextProvider, $, Slot } from "@builder.io/qwik";
import { useLocation, useNavigate, Link } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { emit, listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { open } from "@tauri-apps/plugin-shell";
import { SetupWizard } from "~/components/vault/SetupWizard";
import { UnlockScreen } from "~/components/vault/UnlockScreen";
import { StatusIndicator } from "~/components/vault/StatusIndicator";
import type { ConnectionStatus } from "~/components/vault/StatusIndicator";
import { connectionStatusContext, autoLockContext, signaturesContext, pendingSignPathsContext } from "~/lib/context";
import { hydrateSignaturesCache, persistSignaturesCache, setActiveSignatureAgent } from "~/lib/signatures-cache";
import { GlassButton } from "~/components/common/GlassButton";

type AppScreen = "loading" | "setup" | "unlock" | "dashboard";

declare const __API_URL__: string;
declare const __APP_VERSION__: string;
declare const __WEB_URL__: string;

// Same icon set + pill styling as the Website dashboard nav.
const navItems = [
  { label: "Overview", href: "/", icon: "🏠" },
  { label: "Sign It", href: "/sign-it/", icon: "✍️" },
  { label: "Connected Apps", href: "/identities/", icon: "🌐" },
  { label: "Your Data", href: "/your-data/", icon: "🔐" },
  { label: "Settings", href: "/settings/", icon: "⚙️" },
];

export default component$(() => {
  const screen = useSignal<AppScreen>("loading");
  const connectionStatus = useSignal<ConnectionStatus>("offline");
  useContextProvider(connectionStatusContext, connectionStatus);
  const conductorStatus = useSignal<"stopped" | "starting" | "ready" | "error">("stopped");
  const conductorMessage = useSignal("");

  // Set when the API's dna-versions endpoint reports this build is below
  // min_vault_version (e.g. once the network moves to a new transport and
  // old clients can no longer gossip). Holds the required version string.
  // The banner is advisory — the vault still opens so the user keeps local
  // access ("warn but allow"). Never cleared within a session: once below
  // min, still below min until a newer build is installed.
  const appUpdateRequired = useSignal<string | null>(null);
  const autoLockMinutes = useSignal(15);
  useContextProvider(autoLockContext, autoLockMinutes);

  // App-wide signatures store. Owned by the layout so navigating between
  // Overview / Sign It / View All doesn't re-trigger fetches.
  const signaturesSig = useSignal<any[]>([]);
  const signaturesLoaded = useSignal(false);
  const signaturesRefreshing = useSignal(false);
  // If refresh is requested while one is already running, mark a follow-up.
  // Important because state may change during the in-flight call (e.g.
  // auto-link caches the linked agent key mid-fetch, so the next round will
  // pick up linked-agent sigs that the current call missed).
  const pendingRefresh = useSignal(false);
  // A confident "no linked agents" answer holds for the whole app session —
  // re-checking pays a fixed ~10s DHT timeout on EVERY refresh for
  // vault-native accounts that will never have linked history.
  const linkedConfirmedNone = useSignal(false);
  const refreshSignatures = $(async () => {
    if (signaturesRefreshing.value) {
      pendingRefresh.value = true;
      return;
    }
    signaturesRefreshing.value = true;
    try {
      // Own + linked are dispatched as two independent Tauri commands so
      // the cold-DHT linked path can't block the fast local own query.
      // Own results paint IMMEDIATELY (additive merge — nothing is ever
      // evicted, so a not-yet-settled linked leg can't be misread as
      // records disappearing); the "loaded" badge still waits for linked
      // confidence, and a background interval re-fires until it arrives.

      // Own: local source-chain query, retry on Err. Returns null when all
      // attempts failed — own truth UNKNOWN (cells can take ~20s+ to enable
      // after unlock, longer than this retry span). null must never be
      // treated as "zero new records": the caller keeps the cache AND keeps
      // the background retry alive until a real read succeeds.
      const fetchOwn = async (): Promise<any[] | null> => {
        for (let i = 0; i < 3; i++) {
          try {
            const r = await invoke<any[]>("get_my_own_signatures");
            return Array.isArray(r) ? r : [];
          } catch {
            if (i < 2) await new Promise((r) => setTimeout(r, 2_000));
          }
        }
        return null;
      };

      // Linked: DHT-bound, can take minutes on cold start. Up to 3 attempts
      // per refresh; the outer background retry keeps trying across refreshes.
      // `confident = true` means we trust the result enough to display:
      //   - has_linked_agents = false → authoritative no-linked (no web account)
      //   - has_linked_agents = true AND sigs.length > 0 → got real data
      //   - all 3 attempts returned ok-but-empty → genuine zero-sig user
      // `confident = false` means at least one attempt threw (DHT timeout
      // or unreachable), so the empty result could be a cold-DHT false
      // negative — keep retrying via the background interval.
      const fetchLinked = async (): Promise<{ sigs: any[]; confident: boolean }> => {
        if (linkedConfirmedNone.value) return { sigs: [], confident: true };
        let lastRes: { signatures: any[]; has_linked_agents: boolean } | null = null;
        let allAttemptsOk = true;
        for (let i = 0; i < 3; i++) {
          try {
            const r = await invoke<{ signatures: any[]; has_linked_agents: boolean }>(
              "get_my_linked_signatures",
            );
            lastRes = r;
            if (!r.has_linked_agents) {
              linkedConfirmedNone.value = true;
              return { sigs: [], confident: true };
            }
            if (r.signatures.length > 0) return { sigs: r.signatures, confident: true };
          } catch {
            allAttemptsOk = false;
          }
          if (i < 2) await new Promise((r) => setTimeout(r, 5_000));
        }
        if (lastRes && !lastRes.has_linked_agents) {
          linkedConfirmedNone.value = true;
          return { sigs: [], confident: true };
        }
        if (allAttemptsOk) return { sigs: [], confident: true };
        return { sigs: lastRes?.signatures ?? [], confident: false };
      };

      // Merge a round of results into the displayed list — ADDITIVE only.
      // By action_hash: the new round wins for present hashes, anything
      // missing from this round is preserved from the existing signal so a
      // partial round can't clobber cached data.
      //
      // Field-level merge for sigs in both new + cache: prefer the new
      // round's data overall, but preserve cached `thumbnail` and
      // `revoked*` when the new round returned null (Rust's per-sig
      // enrichment has a 15 s budget; on cold DHT it can return null even
      // when gossip has the data — without this, thumbnails flicker).
      // `revoked` is one-way (revocations never retract) so cached `true`
      // always wins.
      const mergeRound = (round: any[]) => {
        if (round.length === 0) return;
        const cachedByHash = new Map<string, any>(
          signaturesSig.value
            .filter((s: any) => s.action_hash)
            .map((s: any) => [s.action_hash as string, s]),
        );
        const enriched = round.map((newSig: any) => {
          const old = cachedByHash.get(newSig.action_hash);
          if (!old) return newSig;
          return {
            ...newSig,
            thumbnail: newSig.thumbnail ?? old.thumbnail,
            revoked: old.revoked || newSig.revoked,
            revoked_at: newSig.revoked_at ?? old.revoked_at,
            revocation_reason: newSig.revocation_reason ?? old.revocation_reason,
          };
        });
        const newHashes = new Set(
          enriched.map((s: any) => s.action_hash).filter(Boolean) as string[],
        );
        const merged = [
          ...enriched,
          ...signaturesSig.value.filter(
            (s: any) => s.action_hash && !newHashes.has(s.action_hash),
          ),
        ];
        signaturesSig.value = merged;
        persistSignaturesCache(merged);
      };

      do {
        pendingRefresh.value = false;

        // Own is local truth — paint it the MOMENT it arrives. The linked
        // leg is DHT-bound (can sit on a 10s timeout); it merges in
        // additively when it settles. This is the product rule: anything
        // the Vault knows shows instantly, the network only ever adds.
        const linkedPromise = fetchLinked();
        const ownRes = await fetchOwn();
        const ownOk = ownRes !== null;
        if (ownRes && ownRes.length > 0) {
          mergeRound(ownRes);
        }

        const linkedRes = await linkedPromise;
        const ownHashes = new Set(
          (ownRes ?? []).map((s) => s.action_hash).filter(Boolean) as string[],
        );
        mergeRound(
          linkedRes.sigs.filter(
            (s) => s.action_hash && !ownHashes.has(s.action_hash),
          ),
        );
        // Empty rounds never overwrite the cache — keep whatever we had.

        // Promote to "loaded" only when linked is confident AND the own
        // read actually succeeded. A failed own read (cells still
        // enabling after unlock) must keep the background retry alive —
        // otherwise the view freezes on the stale cache with the user's
        // newest records missing.
        if (linkedRes.confident && ownOk) {
          signaturesLoaded.value = true;
        }
      } while (pendingRefresh.value);
    } finally {
      signaturesRefreshing.value = false;
    }
  });
  useContextProvider(signaturesContext, {
    signatures: signaturesSig,
    loaded: signaturesLoaded,
    refreshing: signaturesRefreshing,
    refresh: refreshSignatures,
  });

  // Files queued by the OS "Sign with Flowsta Vault" integration. Populated
  // by the drain task below; consumed (and cleared) by the Sign It page.
  const pendingSignPaths = useSignal<string[]>([]);
  useContextProvider(pendingSignPathsContext, pendingSignPaths);

  const loc = useLocation();
  const nav = useNavigate();
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

  // Document-sign approval dialog state (Sign It). `commit` means the
  // signature will be PUBLISHED to the Sign It network, not just returned.
  const pendingDocumentSign = useSignal<{
    id: string;
    app_name: string;
    file_hash: string;
    label: string | null;
    origin: string | null;
    commit?: boolean;
    amends?: boolean;
  } | null>(null);

  // A Flowsta page's committing request is waiting for the conductor —
  // show a visible preparing state instead of dead air before the dialog.
  // Bridge-operation activity: after an approval the Vault narrates what it
  // is doing on the user's behalf — the requesting app may tell its own
  // story, or none at all (third-party callers). Card = current/latest op;
  // list = recent history for "wait, what did I just approve?".
  const opActivity = useSignal<any | null>(null);
  const opRecent = useSignal<any[]>([]);
  const opRecentOpen = useSignal(false);

  // Signature-management approval (dashboard delegating revoke/thumbnail)
  const pendingCellOp = useSignal<{
    id: string;
    op: string;
    origin: string | null;
    detail: string | null;
  } | null>(null);

  // Profile-update approval (dashboard delegating a profile write here)
  const pendingProfileUpdate = useSignal<{
    id: string;
    origin: string | null;
    display_name: string | null;
    picture_changed: boolean;
  } | null>(null);

  // Generic /sign approval (linked apps signing outside the linking ceremony)
  const pendingRawSign = useSignal<{
    id: string;
    app_name: string;
    origin: string | null;
    sign_type: string;
    payload_bytes: number;
  } | null>(null);
  // Transient notice when a remembered app authenticated without a dialog.
  const autoApprovedNotice = useSignal<string | null>(null);

  // Relay login — approve a sign-in happening on another device.
  // The approval screen is ALWAYS shown (no remember option): cross-device
  // approval is the phishing surface, the screen is the defense.
  const pendingRelayClaim = useSignal<{
    app_name: string;
    ua_family: string | null;
    ip_prefix: string | null;
    expires_in: number;
  } | null>(null);
  // Set while a Flowsta page's request (sign / profile) is waiting behind
  // the lock screen — its approval dialog appears the moment we unlock.
  const unlockAttention = useSignal<{ reason: string; origin: string | null } | null>(null);
  const relayCodeModal = useSignal(false);
  const relayCodeInput = useSignal("");
  const relayBusy = useSignal(false);
  const relayError = useSignal<string | null>(null);
  const relayApprovedFlash = useSignal(false);
  // A flowsta:// code that arrived while locked — processed after unlock.
  const queuedRelayCode = useSignal<string | null>(null);

  // Fetch profile from unlocked vault for header display + register
  // the active identity with the signatures cache so per-agent reads
  // and writes work correctly. Called from each of the three paths
  // that establish a dashboard session (handleUnlockPassword, the
  // app-startup-already-unlocked branch, and SetupWizard onComplete).
  const fetchProfile = $(async () => {
    try {
      const identity = await invoke<{
        agent_pub_key: string;
        display_name: string | null;
        profile_picture: string | null;
        web_email: string | null;
      }>("get_identity");

      userProfile.displayName = identity.display_name ?? "";
      userProfile.profilePicture = identity.profile_picture ?? "";
      userProfile.email = identity.web_email ?? "";

      // Scope the signatures cache to this agent_pub_key. If a previous
      // identity sat in localStorage (Reset Vault → new identity, restore
      // from a different recovery phrase, multiple users on one machine)
      // this prevents the old data from being hydrated into the new
      // session — hydrate returns [] when the cache key doesn't match.
      setActiveSignatureAgent(identity.agent_pub_key);
      const cached = hydrateSignaturesCache<any>();
      if (cached.length > 0 && signaturesSig.value.length === 0) {
        signaturesSig.value = cached;
        signaturesLoaded.value = true;
      }
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
    // Process a relay sign-in code that arrived while locked.
    if (queuedRelayCode.value) {
      const code = queuedRelayCode.value;
      queuedRelayCode.value = null;
      startRelayClaim(code);
    }
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
      commit: boolean;
      amends: boolean;
    }>("document-sign-request", (event) => {
      pendingDocumentSign.value = event.payload;
    });
    const unlistenProfile = listen<{
      id: string;
      origin: string | null;
      display_name: string | null;
      picture_changed: boolean;
    }>("profile-update-request", (event) => {
      pendingProfileUpdate.value = event.payload;
    });
    // A signature published through the localhost bridge (web-delegated
    // signing) — refresh the signatures view so it appears immediately.
    const unlistenPublished = listen("signature-published", () => {
      refreshSignatures();
    });
    const unlistenAttention = listen<{ reason: string; origin: string | null }>(
      "unlock-attention",
      (event) => {
        unlockAttention.value = event.payload;
      },
    );
    const unlistenAttentionClear = listen("unlock-attention-clear", () => {
      unlockAttention.value = null;
    });
    const unlistenOpPending = listen<{ op: string; origin: string | null }>(
      "op-pending",
      (event) => {
        // Pre-approval conductor wait — the first chapter of the same
        // bottom-right story the rest of the operation tells (this was a
        // separate top-of-page banner).
        opActivity.value = {
          op: event.payload.op,
          origin: event.payload.origin,
          label: null,
          stage: "working",
          title: "Getting your Vault ready…",
          preparing: true,
          at: Date.now(),
        };
      },
    );
    const unlistenOpPendingClear = listen("op-pending-clear", () => {
      // Cleared when the wait ends: the approval dialog (then op-progress)
      // takes over on success; a failure arrives as its own op-outcome.
      if (opActivity.value?.preparing) opActivity.value = null;
    });
    const unlistenCellOp = listen<{
      id: string;
      op: string;
      origin: string | null;
      detail: string | null;
    }>("cell-op-request", (event) => {
      pendingCellOp.value = event.payload;
    });

    // Bridge-op narration: progress fires the moment an approval resolves,
    // outcome closes the story (success / failure / user's own denial).
    const OP_DOING: Record<string, string> = {
      sign: "Signing…",
      amend: "Publishing the amended signature…",
      revoke: "Publishing the revocation…",
      thumbnail: "Publishing the preview…",
      profile: "Updating your profile…",
    };
    const OP_DONE: Record<string, string> = {
      sign: "Signed",
      amend: "Amended signature published",
      revoke: "Revocation published",
      thumbnail: "Preview updated",
      profile: "Profile updated",
    };
    // Pre-dialog refusals (validation, wrong origin) never showed the user
    // anything — log them to the list but don't pop a card out of nowhere.
    const QUIET_ERRORS = [
      "tier_forbidden", "invalid_file_hash", "invalid_supersedes",
      "invalid_thumbnail", "invalid_comment", "invalid_action_hash",
      "invalid_reason", "reserved_prefix", "nothing_to_update",
      "vault_locked", "invalid_display_name", "invalid_profile_picture",
    ];
    const unlistenOpProgress = listen<any>("op-progress", (event) => {
      const p = event.payload;
      const title =
        p.op === "sign" && p.publish
          ? "Signing & publishing…"
          : OP_DOING[p.op] || "Working…";
      opActivity.value = {
        op: p.op, publish: p.publish, origin: p.origin, label: p.label,
        stage: "working", title, at: Date.now(),
      };
    });
    const unlistenOpOutcome = listen<any>("op-outcome", (event) => {
      const p = event.payload;
      const denied = p.error === "user_denied";
      const wasPublish = opActivity.value?.op === p.op ? opActivity.value?.publish : undefined;
      const title = p.ok
        ? p.op === "sign" && wasPublish
          ? "Signed & published"
          : p.op === "sign" && wasPublish === false
            ? "Signed — returned to the app"
            : OP_DONE[p.op] || "Done"
        : denied
          ? "You declined — nothing was changed"
          : "Nothing was changed";
      const entry = {
        op: p.op, origin: p.origin, label: p.label,
        stage: p.ok ? "ok" : denied ? "denied" : "failed",
        title, description: p.ok ? null : p.description, at: Date.now(),
      };
      opRecent.value = [entry, ...opRecent.value].slice(0, 6);
      const quiet = !p.ok && !denied && QUIET_ERRORS.includes(p.error);
      if (!quiet || opActivity.value) {
        opActivity.value = entry;
        // Success/denied auto-dismiss; failures stay until dismissed or the
        // next operation replaces them.
        if (entry.stage !== "failed") {
          const at = entry.at;
          setTimeout(() => {
            if (opActivity.value?.at === at) opActivity.value = null;
          }, 6500);
        }
      }
    });

    cleanup(() => {
      unlistenPromise.then((unlisten) => unlisten());
      unlistenProfile.then((unlisten) => unlisten());
      unlistenPublished.then((unlisten) => unlisten());
      unlistenAttention.then((unlisten) => unlisten());
      unlistenAttentionClear.then((unlisten) => unlisten());
      unlistenCellOp.then((unlisten) => unlisten());
      unlistenOpPending.then((unlisten) => unlisten());
      unlistenOpPendingClear.then((unlisten) => unlisten());
      unlistenOpProgress.then((unlisten) => unlisten());
      unlistenOpOutcome.then((unlisten) => unlisten());
    });
  });

  // Generic /sign approvals + auto-approved authentication notices
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ cleanup }) => {
    const unlistenSign = listen<{
      id: string;
      app_name: string;
      origin: string | null;
      sign_type: string;
      payload_bytes: number;
    }>("raw-sign-request", (event) => {
      pendingRawSign.value = event.payload;
    });
    const unlistenAuto = listen<{ app_name: string; origin: string | null }>(
      "auth-auto-approved",
      (event) => {
        autoApprovedNotice.value = event.payload.app_name || event.payload.origin || "A linked app";
        setTimeout(() => (autoApprovedNotice.value = null), 6000);
      },
    );
    cleanup(() => {
      unlistenSign.then((u) => u());
      unlistenAuto.then((u) => u());
    });
  });

  // Relay login codes arriving via flowsta://. Unlocked → claim and
  // show the approval screen; locked → queue client-side and banner the
  // unlock screen. Registered on every screen (deep links arrive any time).
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ cleanup }) => {
    const route = (code: string) => {
      if (screen.value === "dashboard") {
        startRelayClaim(code);
      } else {
        queuedRelayCode.value = code;
      }
    };

    const unlistenPromise = listen<string>("relay-code-received", (event) => {
      // The Rust side also queued it; drain that copy so a stale code isn't
      // re-processed at the next unlock.
      invoke<string | null>("take_pending_relay_code").catch(() => {});
      route(event.payload);
    });

    // Drain a code that arrived before the frontend mounted (app woken by
    // the deep link itself).
    invoke<string | null>("take_pending_relay_code")
      .then((code) => {
        if (code) route(code);
      })
      .catch(() => {});

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

    // Poll until ready — the conductor-status event may fire before this
    // listener is registered, so keep polling while status isn't "ready".
    const pollStatus = () => {
      invoke<{ status: string; message?: string }>("get_conductor_status")
        .then((result) => {
          conductorStatus.value = result.status as typeof conductorStatus.value;
          if (result.message) conductorMessage.value = result.message;
          if (result.status !== "ready" && result.status !== "error" && result.status !== "stopped") {
            setTimeout(pollStatus, 2000);
          }
        })
        .catch(() => {});
    };
    pollStatus();

    // Listen for real-time updates from conductor startup sequence
    const unlistenPromise = listen<{ status: string; message?: string }>(
      "conductor-status",
      (event) => {
        conductorStatus.value = event.payload.status as typeof conductorStatus.value;
        conductorMessage.value = event.payload.message ?? "";
      },
    );

    // Listen for profile sync (profile picture/name updated from web account).
    // This event also signals that auto-link is complete, so the cached web
    // agent key is now available — refresh signatures to pick up linked-agent
    // sigs that the first fetch may have missed.
    const unlistenProfilePromise = listen("profile-synced", () => {
      fetchProfile();
      refreshSignatures();
    });

    cleanup(() => {
      unlistenPromise.then((unlisten) => unlisten());
      unlistenProfilePromise.then((unlisten) => unlisten());
    });
  });

  // Background retry for the signatures fetch. On a fresh install with
  // a returning agent, the cold-DHT `get_signatures_for_agent` query
  // for linked-agent sigs can take minutes to gossip in. Each refresh
  // tries up to 3 times internally; while linked hasn't returned a
  // confident result, signaturesLoaded stays false and this interval
  // re-fires the refresh every 30s. Stops as soon as linked succeeds.
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ track, cleanup }) => {
    const s = track(() => screen.value);
    const loaded = track(() => signaturesLoaded.value);
    if (s !== "dashboard" || loaded) return;

    const id = setInterval(() => {
      if (!signaturesLoaded.value) refreshSignatures();
    }, 30_000);
    cleanup(() => clearInterval(id));
  });

  // Re-fetch signatures when the Vault window regains focus. Covers the
  // case where the user signs something on flowsta.com (or another
  // device) while Vault is open in the background — without this, the
  // refresh only fires on conductor-ready / profile-synced / lock+unlock,
  // so a new linked-agent sig wouldn't appear until the next unlock
  // cycle. `refreshSignatures` is internally idempotent (coalesces via
  // pendingRefresh) so spurious focus changes are cheap.
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ track, cleanup }) => {
    const scr = track(() => screen.value);
    if (scr !== "dashboard") return;

    const unlistenPromise = getCurrentWindow().onFocusChanged(({ payload: focused }) => {
      if (focused) refreshSignatures();
    });
    cleanup(() => {
      unlistenPromise.then((unlisten) => unlisten());
    });
  });

  // Listen for the DNA-updater's verdict on this app version. When the API's
  // dna-versions endpoint reports a min_vault_version newer than this build,
  // dna_updater emits `dna-update-status` with status `app_update_required`.
  // Surface it as a persistent banner: the vault still works (warn but
  // allow), but the user is told they won't sync with the network until
  // they update. The other statuses (checking/done) are ignored — `done`
  // always fires afterwards, so clearing on it would hide the banner.
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ track, cleanup }) => {
    const s = track(() => screen.value);
    if (s !== "dashboard") return;

    const unlistenPromise = listen<{ status: string; min_vault_version?: string }>(
      "dna-update-status",
      (event) => {
        if (event.payload.status === "app_update_required") {
          appUpdateRequired.value = event.payload.min_vault_version ?? "";
        }
      },
    );

    cleanup(() => {
      unlistenPromise.then((unlisten) => unlisten());
    });
  });

  // Note: hydration from localStorage moved into fetchProfile() so it
  // runs AFTER the active identity is known. On a fresh app launch the
  // layout mounts before unlock — hydrating here unconditionally would
  // pull whatever the previous user cached. Per-agent hydration in
  // fetchProfile is the correct ordering.

  // Trigger the first fetch as soon as the conductor reports ready while we
  // are on the dashboard. Each lock/unlock cycle restarts the conductor, so
  // this fires once per unlock (ready transition).
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ track }) => {
    const status = track(() => conductorStatus.value);
    const scr = track(() => screen.value);
    if (scr === "dashboard" && status === "ready") {
      refreshSignatures();
    }
  });

  // OS file-explorer "Sign with Flowsta Vault" integration. The Rust side
  // queues file paths from CLI args + Apple Events + single-instance args;
  // we drain that queue here, expose the paths via context for the Sign It
  // page to pick up, and route the user to /sign-it/.
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async ({ track, cleanup }) => {
    const scr = track(() => screen.value);
    if (scr !== "dashboard") return;

    const drain = async () => {
      try {
        const paths = await invoke<string[]>("take_pending_sign_paths");
        if (paths.length === 0) return;
        pendingSignPaths.value = paths;
        if (loc.url.pathname !== "/sign-it/") {
          await nav("/sign-it/");
        }
      } catch (e) {
        console.warn("take_pending_sign_paths failed:", e);
      }
    };

    // Drain anything queued before the listener registers (e.g. files passed
    // as CLI args at first launch, before vault unlock).
    drain();

    const unlistenPromise = listen("sign-files-requested", () => { drain(); });
    cleanup(() => { unlistenPromise.then((u) => u()); });
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

  const handleProfileUpdateResponse = $(async (approved: boolean) => {
    try {
      await invoke("respond_profile_update_request", { approved });
    } catch (e) {
      console.error("Failed to respond to profile-update request:", e);
    } finally {
      pendingProfileUpdate.value = null;
    }
  });

  const handleCellOpResponse = $(async (approved: boolean) => {
    try {
      await invoke("respond_cell_op_request", { approved });
    } catch (e) {
      console.error("Failed to respond to operation request:", e);
    } finally {
      pendingCellOp.value = null;
    }
  });

  const handleRawSignResponse = $(async (approved: boolean) => {
    try {
      await invoke("respond_raw_sign_request", { approved });
    } catch (e) {
      console.error("Failed to respond to sign request:", e);
    } finally {
      pendingRawSign.value = null;
    }
  });

  // Claim a relay code (typed or deep-linked) and open the approval screen.
  const startRelayClaim = $(async (rawCode: string) => {
    relayBusy.value = true;
    relayError.value = null;
    try {
      const claim = await invoke<{
        app_name: string;
        ua_family: string | null;
        ip_prefix: string | null;
        expires_in: number;
      }>("relay_claim", { apiUrl: __API_URL__, userCode: rawCode });
      pendingRelayClaim.value = claim;
      relayCodeModal.value = false;
      relayCodeInput.value = "";
    } catch (e: any) {
      const s = String(e);
      relayError.value = s.includes("code_not_found")
        ? "That code wasn't found — it may have expired. Get a fresh code on your other device."
        : s.includes("already_claimed")
          ? "That code was already used. If that wasn't you, deny the request on your other device and get a fresh code."
          : s.includes("invalid_code")
            ? "Codes are 8 letters, shown as XXXX-XXXX."
            : s.includes("vault_locked")
              ? "Unlock your Vault first."
              : "Couldn't check that code — are you online?";
      // Surface the error in the code modal (also for the deep-link path).
      relayCodeModal.value = true;
    } finally {
      relayBusy.value = false;
    }
  });

  const handleRelayResponse = $(async (approved: boolean) => {
    const wasApproving = approved;
    pendingRelayClaim.value = null;
    try {
      if (approved) {
        await invoke("relay_approve", { apiUrl: __API_URL__ });
        relayApprovedFlash.value = true;
        setTimeout(() => (relayApprovedFlash.value = false), 5000);
      } else {
        await invoke("relay_deny", { apiUrl: __API_URL__ });
      }
    } catch (e) {
      console.error("Relay response failed:", e);
      if (wasApproving) {
        relayError.value =
          "Approval failed — the request may have expired. Get a fresh code on your other device.";
        relayCodeModal.value = true;
      }
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
      <>
        {unlockAttention.value && (
          <div class="fixed top-0 inset-x-0 z-50 bg-amber-500/15 border-b border-amber-500/40 px-4 py-3 text-center">
            <p class="text-sm text-amber-200">
              {unlockAttention.value.origin || "A Flowsta page"} is waiting to
              {unlockAttention.value.reason === "profile"
                ? " update your profile"
                : " sign a file"}{" "}
              — unlock your Vault to review and approve it.
            </p>
          </div>
        )}
        {queuedRelayCode.value && (
          <div class="fixed top-0 inset-x-0 z-50 bg-amber-500/15 border-b border-amber-500/40 px-4 py-3 text-center">
            <p class="text-sm text-amber-200">
              A sign-in from another device is waiting — unlock your Vault to
              review it. The code expires about five minutes after it was
              requested.
            </p>
          </div>
        )}
        <UnlockScreen
          onUnlock$={handleUnlockPassword}
          onResetVault$={async () => {
            // Must WIPE on disk (vault.enc + lair keystore + conductor), not
            // just navigate — otherwise the next create/restore inherits the
            // old lair keystore under a mismatched passphrase and the conductor
            // crashes on connect (ConnectionReset → "Connection refused"). The
            // Settings reset already does this; the lock-screen path must too.
            try {
              await invoke("reset_vault");
            } catch (e) {
              console.error("reset_vault failed:", e);
            }
            screen.value = "setup";
          }}
        />
      </>
    );
  }

  // Only show profile if displayName is set — never show raw hashes
  const displayName = userProfile.displayName || "";

  // Dashboard: full-width header at top, then sidebar + content below
  return (
    <div class="flex h-screen flex-col bg-gray-900">
      {/* Full-width header */}
      <header class="sticky top-0 z-40 w-full bg-gray-900">
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

      {/* App-update banner — shown when the API reports this build is below
          min_vault_version. Advisory only: the vault stays usable. */}
      {appUpdateRequired.value !== null && (
        <div class="flex items-center gap-3 border-b border-amber-500/40 bg-amber-500/10 px-6 py-2.5">
          <svg
            class="h-4 w-4 shrink-0 text-amber-400"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            stroke-width={2}
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
            />
          </svg>
          <p class="flex-1 text-xs text-amber-200">
            A new version of Flowsta Vault is available
            {appUpdateRequired.value ? ` (v${appUpdateRequired.value} or newer)` : ""}.
            Until you update you won't sync with the network — your local data
            stays safe and accessible.
          </p>
          <button
            type="button"
            class="shrink-0 rounded-md border border-amber-500/50 bg-amber-500/20 px-3 py-1 text-xs font-medium text-amber-100 transition-colors hover:bg-amber-500/30"
            onClick$={() => open(`${__WEB_URL__}/vault/`)}
          >
            Update
          </button>
        </div>
      )}

      {/* Below header: sidebar + content. min-h-0 lets the row shrink below
          its content size so <main>'s overflow-y-auto can actually scroll
          internally instead of expanding the row past the viewport. */}
      <div class="flex flex-1 min-h-0">
        {/* Sidebar */}
        <aside class="flex w-64 flex-col bg-gray-900">
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
                    "mb-2 flex items-center rounded-full px-4 py-3 text-sm font-medium transition-colors relative",
                    isActive
                      ? "text-white"
                      : "text-gray-300 hover:bg-gray-800 hover:text-white",
                  ].join(" ")}
                >
                  {isActive && (
                    <span class="absolute left-2 h-1.5 w-1.5 rounded-full bg-current" />
                  )}
                  <span class="mr-3 text-xl">{item.icon}</span>
                  {item.label}
                </Link>
              );
            })}
          </nav>

          {/* Status + Lock */}
          <div class="px-4 py-4">
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
              class="mb-2 flex w-full items-center justify-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-xs text-gray-400 hover:bg-gray-800 hover:text-gray-300 transition-colors"
              onClick$={() => {
                relayError.value = null;
                relayCodeInput.value = "";
                relayCodeModal.value = true;
              }}
            >
              <svg class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
              </svg>
              Approve a sign-in
            </button>
            <button
              type="button"
              class="flex w-full items-center justify-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-xs text-gray-400 hover:bg-gray-800 hover:text-gray-300 transition-colors"
              onClick$={async () => {
                // Cache is intentionally NOT cleared here. Signature metadata
                // is the kind of public-by-design data that gets verified on
                // the DHT, so persisting it across lock gives the same user
                // an instant Overview/Sign It view on next unlock.
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

      {/* Generic /sign approval dialog */}
      {pendingRawSign.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div class="mx-4 w-full max-w-sm rounded-xl border border-gray-600 bg-gray-800 p-6 shadow-2xl">
            <div class="mb-4 flex items-center gap-3">
              <div class="flex h-10 w-10 items-center justify-center rounded-full bg-amber-500/20">
                <svg class="h-5 w-5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                  <path stroke-linecap="round" stroke-linejoin="round" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                </svg>
              </div>
              <div>
                <h3 class="text-base font-semibold text-white">Signing Request</h3>
                <p class="text-xs text-gray-400">A linked app wants a signature</p>
              </div>
            </div>
            <div class="mb-4 space-y-2 rounded-lg border border-gray-700 bg-gray-900 p-3">
              <div>
                <span class="text-xs text-gray-500">App</span>
                <p class="text-sm font-medium text-white">{pendingRawSign.value.app_name}</p>
              </div>
              <div>
                <span class="text-xs text-gray-500">What</span>
                <p class="text-sm text-gray-300">
                  Sign {pendingRawSign.value.payload_bytes > 0 ? `${pendingRawSign.value.payload_bytes} bytes of data` : "data"} with your identity key
                </p>
              </div>
            </div>
            <p class="mb-4 text-xs text-amber-200/90">
              Only approve if you expect this app to be signing something
              right now. A signature made with your key speaks as you.
            </p>
            <div class="flex gap-3">
              <GlassButton variant="secondary" class="flex-1" onClick$={() => handleRawSignResponse(false)}>
                Deny
              </GlassButton>
              <GlassButton class="flex-1" onClick$={() => handleRawSignResponse(true)}>
                Approve
              </GlassButton>
            </div>
          </div>
        </div>
      )}

      {/* Auto-approved authentication notice */}
      {autoApprovedNotice.value && (
        <div class="fixed bottom-6 left-6 z-50 rounded-lg border border-sky-500/40 bg-sky-500/15 px-4 py-3 shadow-xl">
          <p class="text-sm text-sky-200">
            {autoApprovedNotice.value} signed in with your identity (remembered app).
          </p>
        </div>
      )}

      {/* Relay login: enter-code modal */}
      {relayCodeModal.value && !pendingRelayClaim.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div class="mx-4 w-full max-w-sm rounded-xl border border-gray-600 bg-gray-800 p-6 shadow-2xl">
            <h3 class="mb-1 text-base font-semibold text-white">
              Approve a sign-in
            </h3>
            <p class="mb-4 text-xs text-gray-400">
              Signing in on a phone or another browser? Enter the code it
              shows you.
            </p>
            <input
              type="text"
              value={relayCodeInput.value}
              placeholder="XXXX-XXXX"
              autoCapitalize="characters"
              autoCorrect="off"
              spellcheck={false}
              maxLength={9}
              class="mb-3 w-full rounded-lg border border-gray-600 bg-gray-900 px-4 py-3 text-center font-mono text-lg tracking-widest text-white placeholder-gray-600 focus:border-amber-400 focus:outline-none"
              onInput$={(_, el) => {
                relayCodeInput.value = el.value;
              }}
              onKeyDown$={(e) => {
                if (e.key === "Enter" && relayCodeInput.value.trim() && !relayBusy.value) {
                  startRelayClaim(relayCodeInput.value);
                }
              }}
            />
            {relayError.value && (
              <p class="mb-3 text-xs text-red-300">{relayError.value}</p>
            )}
            <div class="flex gap-3">
              <GlassButton
                variant="secondary"
                class="flex-1"
                onClick$={() => {
                  relayCodeModal.value = false;
                  relayError.value = null;
                }}
              >
                Cancel
              </GlassButton>
              <GlassButton
                class="flex-1"
                disabled={relayBusy.value || !relayCodeInput.value.trim()}
                onClick$={() => startRelayClaim(relayCodeInput.value)}
              >
                {relayBusy.value ? "Checking…" : "Continue"}
              </GlassButton>
            </div>
          </div>
        </div>
      )}

      {/* Relay login: approval dialog. Deliberately NO remember
          option — every cross-device sign-in is reviewed. */}
      {pendingRelayClaim.value && (
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
                    d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"
                  />
                </svg>
              </div>
              <div>
                <h3 class="text-base font-semibold text-white">
                  Sign in on another device?
                </h3>
                <p class="text-xs text-gray-400">
                  A sign-in is waiting for your approval
                </p>
              </div>
            </div>

            <div class="mb-4 space-y-2 rounded-lg border border-gray-700 bg-gray-900 p-3">
              <div>
                <span class="text-xs text-gray-500">Signs you in to</span>
                <p class="text-sm font-medium text-white">
                  {pendingRelayClaim.value.app_name}
                </p>
              </div>
              <div>
                <span class="text-xs text-gray-500">Where</span>
                <p class="text-sm text-gray-300">
                  {pendingRelayClaim.value.ua_family || "A browser"}
                  {pendingRelayClaim.value.ip_prefix
                    ? ` near ${pendingRelayClaim.value.ip_prefix}.x.x`
                    : ""}
                </p>
              </div>
            </div>

            <p class="mb-4 text-xs text-amber-200/90">
              Only approve if YOU just requested this on your other device.
              If someone asked you to enter a code for them, deny it — that is
              a scam.
            </p>

            <div class="flex gap-3">
              <GlassButton
                variant="secondary"
                class="flex-1"
                onClick$={() => handleRelayResponse(false)}
              >
                Deny
              </GlassButton>
              <GlassButton
                class="flex-1"
                onClick$={() => handleRelayResponse(true)}
              >
                Approve
              </GlassButton>
            </div>
          </div>
        </div>
      )}

      {/* Relay login: success flash */}
      {relayApprovedFlash.value && (
        <div class="fixed bottom-6 right-6 z-50 rounded-lg border border-green-500/40 bg-green-500/15 px-4 py-3 shadow-xl">
          <p class="text-sm text-green-200">
            Approved — your other device is now signed in.
          </p>
        </div>
      )}

      {/* Bridge-operation activity: what the Vault is doing / just did */}
      {opActivity.value && (
        <div
          class={`fixed bottom-6 right-6 z-40 w-80 rounded-lg border px-4 py-3 shadow-xl ${
            opActivity.value.stage === "ok"
              ? "border-green-500/40 bg-green-500/15"
              : opActivity.value.stage === "failed"
                ? "border-red-500/40 bg-red-500/15"
                : opActivity.value.stage === "denied"
                  ? "border-gray-500/40 bg-gray-800/90"
                  : "border-sky-500/40 bg-sky-500/15"
          }`}
        >
          <div class="flex items-start gap-2.5">
            {opActivity.value.stage === "working" ? (
              <div class="mt-0.5 h-4 w-4 shrink-0 animate-spin rounded-full border-2 border-sky-400 border-t-transparent" />
            ) : opActivity.value.stage === "ok" ? (
              <svg class="mt-0.5 h-4 w-4 shrink-0 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />
              </svg>
            ) : (
              <svg
                class={`mt-0.5 h-4 w-4 shrink-0 ${opActivity.value.stage === "failed" ? "text-red-400" : "text-gray-400"}`}
                fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}
              >
                <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            )}
            <div class="min-w-0 flex-1">
              <p
                class={`text-sm ${
                  opActivity.value.stage === "ok"
                    ? "text-green-200"
                    : opActivity.value.stage === "failed"
                      ? "text-red-200"
                      : opActivity.value.stage === "denied"
                        ? "text-gray-300"
                        : "text-sky-200"
                }`}
              >
                {opActivity.value.title}
              </p>
              <p class="mt-0.5 truncate text-xs text-gray-400">
                {opActivity.value.label ? `${opActivity.value.label} · ` : ""}
                requested by {(opActivity.value.origin || "an app").replace(/^https?:\/\//, "")}
              </p>
              {opActivity.value.stage === "failed" && opActivity.value.description && (
                <p class="mt-1 text-xs text-red-200/80">{opActivity.value.description}</p>
              )}
              {opRecent.value.length > 1 && (
                <button
                  class="mt-1.5 text-xs text-gray-400 underline-offset-2 hover:underline"
                  onClick$={() => (opRecentOpen.value = !opRecentOpen.value)}
                >
                  {opRecentOpen.value ? "Hide recent activity" : `Recent activity (${opRecent.value.length})`}
                </button>
              )}
              {opRecentOpen.value && (
                <ul class="mt-1.5 space-y-1 border-t border-white/10 pt-1.5">
                  {opRecent.value.map((r: any, i: number) => (
                    <li key={i} class="truncate text-xs text-gray-400">
                      <span
                        class={
                          r.stage === "ok"
                            ? "text-green-400"
                            : r.stage === "failed"
                              ? "text-red-400"
                              : "text-gray-500"
                        }
                      >
                        {r.stage === "ok" ? "✓" : r.stage === "failed" ? "✕" : "—"}
                      </span>{" "}
                      {r.title}
                      {r.label ? ` · ${r.label}` : ""} ·{" "}
                      {(r.origin || "app").replace(/^https?:\/\//, "")}
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <button
              class="shrink-0 text-gray-400 hover:text-white"
              aria-label="Dismiss"
              onClick$={() => (opActivity.value = null)}
            >
              ×
            </button>
          </div>
        </div>
      )}

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

      {pendingCellOp.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div class="mx-4 w-full max-w-sm rounded-xl border border-gray-600 bg-gray-800 p-6 shadow-2xl">
            <h3 class="mb-1 text-base font-semibold text-white">
              {pendingCellOp.value.op === "revoke" ? "Revoke Signature" : "Update Thumbnail"}
            </h3>
            <p class="mb-3 text-xs text-gray-400">
              {pendingCellOp.value.origin || "A Flowsta page"}
            </p>
            <p class="mb-4 text-xs text-gray-400">
              {pendingCellOp.value.op === "revoke"
                ? "This publicly and permanently marks your signature as revoked on the Sign It network."
                : "This attaches a new preview image to one of your published signatures."}
            </p>
            {pendingCellOp.value.op === "revoke" && pendingCellOp.value.detail && (
              <div class="mb-4 rounded-lg border border-gray-700 bg-gray-900 p-3">
                <span class="text-xs text-gray-500">Reason: </span>
                <span class="text-xs text-white">{pendingCellOp.value.detail}</span>
              </div>
            )}
            <div class="flex gap-3">
              <GlassButton
                variant="secondary"
                class="flex-1"
                onClick$={() => handleCellOpResponse(false)}
              >
                Deny
              </GlassButton>
              <GlassButton class="flex-1" onClick$={() => handleCellOpResponse(true)}>
                {pendingCellOp.value.op === "revoke" ? "Revoke" : "Update"}
              </GlassButton>
            </div>
          </div>
        </div>
      )}

      {pendingProfileUpdate.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div class="mx-4 w-full max-w-sm rounded-xl border border-gray-600 bg-gray-800 p-6 shadow-2xl">
            <h3 class="mb-1 text-base font-semibold text-white">Update Your Profile</h3>
            <p class="mb-4 text-xs text-gray-400">
              {pendingProfileUpdate.value.origin || "A Flowsta page"} wants to update
              the profile stored in your Vault.
            </p>
            <div class="mb-4 space-y-2 rounded-lg border border-gray-700 bg-gray-900 p-3">
              {pendingProfileUpdate.value.display_name && (
                <div class="flex justify-between">
                  <span class="text-xs text-gray-500">New display name</span>
                  <span class="text-xs text-white truncate max-w-[200px]">
                    {pendingProfileUpdate.value.display_name}
                  </span>
                </div>
              )}
              {pendingProfileUpdate.value.picture_changed && (
                <div class="flex justify-between">
                  <span class="text-xs text-gray-500">Profile picture</span>
                  <span class="text-xs text-white">will be replaced</span>
                </div>
              )}
            </div>
            <div class="flex gap-3">
              <GlassButton
                variant="secondary"
                class="flex-1"
                onClick$={() => handleProfileUpdateResponse(false)}
              >
                Deny
              </GlassButton>
              <GlassButton class="flex-1" onClick$={() => handleProfileUpdateResponse(true)}>
                Update
              </GlassButton>
            </div>
          </div>
        </div>
      )}

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
              {pendingDocumentSign.value.commit
                ? pendingDocumentSign.value.amends
                  ? 'This publishes an updated signature that replaces an earlier one you made — the original stays visible in its history.'
                  : 'This will publish a signature from this device to the Sign It network — publicly verifiable, and it speaks as you.'
                : 'This app wants you to cryptographically sign a file. Your signature will be publicly verifiable on the DHT.'}
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
                {pendingDocumentSign.value.commit ? 'Sign & publish' : 'Sign'}
              </GlassButton>
            </div>
          </div>
        </div>
      )}
    </div>
  );
});

