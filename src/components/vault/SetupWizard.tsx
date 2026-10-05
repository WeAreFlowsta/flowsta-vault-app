import { component$, useSignal, useStore, useVisibleTask$, $, type QRL } from "@builder.io/qwik";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-shell";
import { GlassButton } from "~/components/common/GlassButton";
import { PasswordField } from "~/components/common/PasswordField";
import { PasswordStrength } from "~/components/vault/PasswordStrength";
import { checkVaultPassword } from "~/lib/password-strength";
import { normalizeEmail, isValidEmail, emailsMatch, EMAIL_INVALID, EMAIL_MISMATCH } from "~/lib/email";

interface RestoreImportResult {
  sealed_restored: number;
  sealed_skipped: number;
  backups_restored: number;
  backups_skipped: number;
  backups_failed: number;
  backups_unsupported: number;
  first_failure: string | null;
  email_status?: "absent" | "already_set" | "restored" | "mismatch" | "unreachable";
}

/** The done screen's one-paragraph account of an import, same outcomes as Your Data. */
export function summarizeRestoreImport(r: RestoreImportResult): { title: string; body: string } {
  const restored = r.sealed_restored + r.backups_restored;
  const skipped = r.sealed_skipped + r.backups_skipped;
  const email =
    r.email_status === "restored"
      ? " Your email is back on this device."
      : r.email_status === "mismatch"
        ? " The email in that export no longer matches your account - add your current one from the Overview."
        : r.email_status === "unreachable"
          ? " Couldn't reach Flowsta to confirm your email - add it from the Overview when you're online."
          : "";
  if (r.backups_failed > 0) {
    return {
      title: "Import was incomplete",
      body: `${r.backups_failed} backup${r.backups_failed === 1 ? "" : "s"} could not be restored${
        r.first_failure ? ` (${r.first_failure})` : ""
      }. Restored ${restored}. You can try again from Your Data.${email}`,
    };
  }
  if (restored === 0 && skipped === 0) {
    if (r.email_status === "restored") {
      return {
        title: "Your email is back",
        body: "That export holds no private records or app backups, and your email is back on this device.",
      };
    }
    return {
      title: "Nothing to bring back",
      body: `That export holds no private records or app backups.${email}`,
    };
  }
  if (restored === 0) {
    return { title: "Everything was already here", body: `Every record in that export already exists in this Vault.${email}` };
  }
  return {
    title: "Your data is home",
    body: `Restored ${restored} item${restored === 1 ? "" : "s"}${skipped > 0 ? ` (${skipped} already here)` : ""}.${email}`,
  };
}

interface SetupWizardProps {
  onComplete$: QRL<() => void>;
  /** "add": another identity beside the ones already here - created new
   *  or brought with its recovery phrase. The wizard opens on the choice
   *  (without the legacy move, which needs an empty device) and Back from
   *  the choice returns to the unlock screen. */
  mode?: "add";
  onCancel$?: QRL<() => void>;
}

type Step =
  | "choose"
  | "create-form"
  | "create-phrase"
  | "restore-phrase"
  | "existing"
  | "pair-password"
  | "pair-code"
  | "signin"
  | "twofa"
  | "no-phrase"
  | "phrase"
  | "upgrade-offer"
  | "migrate-choose"
  | "migrate-phrase"
  | "migrate-ceremony"
  | "migrate-confirm"
  | "migrate-done"
  | "progress"
  | "done";

declare const __API_URL__: string;
declare const __WEB_URL__: string;
const WEB_PHRASE_URL = `${__WEB_URL__}/dashboard/settings/password/`;

/** Which of the wizard's three journeys the person is on. Chosen on the
* welcome screen; the phrase-first move sets it when a Restore turns out
* to be a flowsta.com phrase. Labels and circles follow the journey, so a
* new person never sees "Connect" or "Verify" for creating an identity. */
type Flow = "create" | "restore" | "move" | "pair";

const FLOW_LABELS: Record<Flow, string[]> = {
create: ["Your details", "Recovery phrase", "Ready"],
restore: ["Recovery phrase", "Ready"],
pair: ["Password", "Code", "Ready"],
move: ["Sign in", "Recovery phrase", "Ready"],
};

function stepToCircle(s: Step, flow: Flow): number {
if (flow === "pair") return s === "pair-password" ? 0 : s === "pair-code" ? 1 : 2;
if (flow === "restore") return s === "restore-phrase" || s === "choose" || s === "existing" ? 0 : 1;
if (flow === "create") {
if (s === "choose" || s === "create-form") return 0;
if (s === "create-phrase") return 1;
return 2;
}
if (s === "signin" || s === "twofa" || s === "no-phrase" || s === "upgrade-offer" || s === "choose") return 0;
if (s === "phrase" || s === "migrate-choose" || s === "migrate-phrase" || s === "migrate-ceremony" || s === "migrate-confirm") return 1;
return 2;
}

export const SetupWizard = component$<SetupWizardProps>((props) => {
  const step = useSignal<Step>("choose");
  const flow = useSignal<Flow>("create");
  const email = useSignal("");
  const loginPassword = useSignal("");
  const tfaCode = useSignal("");
  const tempToken = useSignal("");
  const jwt = useSignal("");
  const webUser = useStore({ email: "", username: "", agentPubKey: "", displayName: "", profilePicture: "" });
  const mnemonic = useSignal("");
  // Phrase-first upgrade: set when a restore attempt finds no Vault
  // identity but the phrase may belong to a flowsta.com account.
  const phraseUpgradeOffer = useSignal(false);
  // True when mnemonic.value was already PROVEN against the account (the
  // phrase-first sign-in decrypted the recovery email with it) - the
  // upgrade flow then skips the re-entry step.
  const phraseProven = useSignal(false);
  // True when this vault was created/restored via the offline path - the
  // done screen explains the reconcile story.
  const restoredOffline = useSignal(false);
  const createdOffline = useSignal(false);
  const phraseVerified = useSignal(false);
  const error = useSignal("");
  const loading = useSignal(false);
  const progressMessage = useSignal("");
  const result = useStore({ agentPubKey: "", did: "" });
  const showTechDetails = useSignal(false);
  // Restore-or-fresh, asked right here after a phrase restore. The import
  // needs the conductor, which the restore already started. Two paths only
  // (field, 2026-09-17); the Overview card remains the fallback if the app is
  // closed on this screen, because the bridge holds third-party backup
  // writes until the question is answered.
  const restoreImporting = useSignal(false);
  const restoreImportProgress = useSignal<string | null>(null);
  const restoreImportError = useSignal<string | null>(null);
  const restoreImportResult = useSignal<RestoreImportResult | null>(null);
  const importExportNow = $(async () => {
    restoreImportError.value = null;
    const { open: openFile } = await import("@tauri-apps/plugin-dialog");
    const path = await openFile({
      multiple: false,
      filters: [{ name: "Flowsta export", extensions: ["json"] }],
    });
    if (!path || typeof path !== "string") return;
    restoreImporting.value = true;
    const { listen } = await import("@tauri-apps/api/event");
    const unlisten = await listen<{ op: string; stage: string }>("your-data-progress", (ev) => {
      if (ev.payload.op === "import") restoreImportProgress.value = ev.payload.stage;
    });
    try {
      restoreImportResult.value = await invoke<RestoreImportResult>("import_vault_export", {
        path,
        overwrite: false,
        apiUrl: __API_URL__,
      });
    } catch (e) {
      restoreImportError.value = String(e);
    } finally {
      unlisten();
      restoreImporting.value = false;
      restoreImportProgress.value = null;
    }
  });
  const continueWithoutImport = $(async () => {
    try {
      await invoke("resolve_restore_choice");
    } catch {
      // The Overview card keeps asking - nothing is lost.
    }
    await props.onComplete$();
  });
  // True only for the phrase-restore path - the done screen then nudges
  // toward importing an export file, since the phrase brings back identity
  // but not data.
  const restoredFromPhrase = useSignal(false);
  // The first minutes after the phrase: what has arrived from the other devices.
  const siblingSync = useSignal<{ joined: boolean; other_devices: string[]; records_arrived: boolean } | null>(null);
  const siblingWaitStarted = useSignal(0);
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(({ track, cleanup }) => {
    const on = track(() => step.value === "done" && restoredFromPhrase.value);
    if (!on) return;
    siblingWaitStarted.value = Date.now();
    const poll = async () => {
      try {
        siblingSync.value = await invoke<{ joined: boolean; other_devices: string[]; records_arrived: boolean }>("sibling_sync");
      } catch { /* the network is still starting */ }
    };
    poll();
    const id = setInterval(poll, 5_000);
    cleanup(() => clearInterval(id));
  });
  const showImportLink = useSignal(false);

  // Adding this device with a code typed on another device.
  const pairPassword = useSignal("");
  const pairPassword2 = useSignal("");
  const pairCode = useSignal("");
  const pairWaitingApproval = useSignal(false);
  const pairedFromDevice = useSignal(false);

  const showPairCode = $(async () => {
    error.value = "";
    const pw = checkVaultPassword(pairPassword.value);
    if (!pw.valid) {
      error.value = pw.hint || "Choose a stronger vault password.";
      return;
    }
    if (pairPassword.value !== pairPassword2.value) {
      error.value = "Passwords don't match.";
      return;
    }
    loading.value = true;
    pairWaitingApproval.value = false;
    try {
      const { listen } = await import("@tauri-apps/api/event");
      const unlisten = await listen<{ state: string; reason?: string; agent_pub_key?: string; did?: string }>(
        "pair-status",
        (ev) => {
          const status = ev.payload;
          if (status.state === "waiting_for_approval") {
            pairWaitingApproval.value = true;
            return;
          }
          unlisten();
          if (status.state === "done") {
            result.agentPubKey = status.agent_pub_key || "";
            result.did = status.did || "";
            pairPassword.value = "";
            pairPassword2.value = "";
            pairedFromDevice.value = true;
            step.value = "done";
            return;
          }
          // Failed: say why in one line and offer a new code.
          pairCode.value = "";
          pairWaitingApproval.value = false;
          const reason = status.reason || "";
          error.value = reason.includes("code_mismatch")
            ? "That code didn't match. Get a new one and try again."
            : reason.includes("pair_closed")
              ? "It was cancelled on your other device."
              : reason.includes("pair_timeout") || reason.includes("mailbox_gone")
                ? "That code expired."
                : reason.includes("api_unreachable")
                  ? "Couldn't reach Flowsta. Check your connection, or use your recovery phrase."
                  : reason.includes("already in this Vault")
                    ? "That identity is already in this Vault."
                    : "That didn't work. Get a new code and try again.";
        },
      );
      pairCode.value = await invoke<string>("pair_begin", { apiUrl: __API_URL__, password: pairPassword.value });
      step.value = "pair-code";
    } catch (e) {
      const msg = String(e);
      error.value = msg.includes("api_unreachable")
        ? "Couldn't reach Flowsta. Check your connection, or use your recovery phrase."
        : msg;
    } finally {
      loading.value = false;
    }
  });

  const cancelPairing = $(async () => {
    await invoke("pair_cancel").catch(() => {});
    pairCode.value = "";
    pairWaitingApproval.value = false;
    error.value = "";
    step.value = "existing";
  });

  // Create-new-identity state (device-hosted identity)
  const createEmail = useSignal("");
  // Typed twice: a mistyped address used to be unfixable once the identity
  // was registered (change-email exists now, but confirm at the source).
  const createEmail2 = useSignal("");
  const createDisplayName = useSignal("");
  const createPassword = useSignal("");
  const createPassword2 = useSignal("");
  const newMnemonic = useSignal("");
  const verifyIndices = useSignal<number[]>([]);
  const verifyWords = useStore<{ [k: number]: string }>({});
  const phraseSaved = useSignal(false);
  const copied = useSignal(false);
  const downloaded = useSignal(false);
  const downloadPhrase = $(async () => {
    try {
      const { save } = await import("@tauri-apps/plugin-dialog");
      const path = await save({
        defaultPath: "flowsta-recovery-phrase.txt",
        filters: [{ name: "Text", extensions: ["txt"] }],
      });
      if (!path) return;
      await invoke("write_json_file", {
        path,
        content: `Flowsta recovery phrase - these 24 words ARE your identity.\nAnyone with these words can become you. Keep this file offline - \nprint it or move it to secure storage, then delete it from this device.\n\n${newMnemonic.value}\n`,
      });
      downloaded.value = true;
      setTimeout(() => { downloaded.value = false; }, 2000);
    } catch (e) {
      console.error("phrase download failed:", e);
    }
  });
  // Restore-from-phrase state (B6)
  const restorePassword = useSignal("");
  const restorePassword2 = useSignal("");

  // Account-upgrade (migration) state
  const hasWebPhrase = useSignal(false);
  const migSummary = useStore({
    recordsMigrated: 0,
    totpMoved: false,
    totpSkipped: false,
    cellsDisabled: 0,
    email: "",
    did: "",
  });

  // Fetch profile (displayName, profilePicture) from GET /auth/me
  const fetchProfile = $(async (token: string) => {
    if (!token) return;
    try {
      const profile = await invoke<{
        display_name: string | null;
        profile_picture: string | null;
      }>("fetch_web_profile", { apiUrl: __API_URL__, jwt: token });

      if (profile.display_name) webUser.displayName = profile.display_name;
      if (profile.profile_picture) webUser.profilePicture = profile.profile_picture;
    } catch (e) {
      console.warn("Profile fetch failed (non-critical):", e);
    }
  });

  // After successful sign-in: remember whether the account has a recovery
  // phrase, then offer the account upgrade before the legacy link path.
  const checkPhraseAndProceed = $(async (token: string) => {
    if (!token) {
      console.warn("No JWT token - skipping phrase status check");
      hasWebPhrase.value = true;
      step.value = "upgrade-offer";
      return;
    }

    try {
      const status = await invoke<{
        has_recovery_phrase: boolean;
        verified: boolean;
      }>("check_recovery_phrase_status", {
        apiUrl: __API_URL__,
        jwt: token,
      });

      console.log("Recovery phrase status:", status);
      hasWebPhrase.value = status.has_recovery_phrase;
    } catch (e) {
      // If the check fails (e.g. offline), assume a phrase exists - the
      // migration flow verifies it against the account anyway.
      console.error("Recovery phrase status check failed:", e);
      hasWebPhrase.value = true;
    }
    step.value = "upgrade-offer";
  });

  // Legacy path: keep the web account custodial and just link this device.
  // True while the account upgrade runs - the shared progress card shows
  // the interruption-safety note only then.
  const migrating = useSignal(false);

  // Which door the completed upgrade came through - the done screen's
  // password copy differs (password door: the web password now unlocks the
  // vault; phrase door: the password chosen on the restore screen does).
  const usedPhraseDoor = useSignal(false);

  // Cohort-2 / lost-phrase: the server mints (or re-mints) the account's
  // phrase and binds its lookup hash; the user then does the write-down
  // ceremony with it and it becomes the seed of their device identity.
  const startMigrationCeremony = $(async () => {
    error.value = "";
    loading.value = true;
    try {
      newMnemonic.value = await invoke<string>("migration_new_phrase", {
        apiUrl: __API_URL__,
        jwt: jwt.value,
        password: loginPassword.value,
      });
      const picks = new Set<number>();
      while (picks.size < 3) picks.add(Math.floor(Math.random() * 24));
      verifyIndices.value = [...picks].sort((a, b) => a - b);
      verifyIndices.value.forEach((i) => (verifyWords[i] = ""));
      phraseSaved.value = false;
      step.value = "migrate-ceremony";
    } catch (e) {
      error.value = String(e);
    } finally {
      loading.value = false;
    }
  });

  const handleMigratePhraseContinue = $(async () => {
    error.value = "";
    const trimmed = mnemonic.value.trim().toLowerCase().replace(/\s+/g, " ");
    mnemonic.value = trimmed;
    if (!trimmed) return;
    const valid = await invoke<boolean>("validate_recovery_phrase", { mnemonic: trimmed });
    if (!valid) {
      error.value = "Invalid recovery phrase. Please check your words.";
      return;
    }
    step.value = "migrate-confirm";
  });

  const handleMigrateCeremonyFinish = $(() => {
    error.value = "";
    const words = newMnemonic.value.split(" ");
    for (const i of verifyIndices.value) {
      if ((verifyWords[i] ?? "").trim().toLowerCase() !== words[i]) {
        error.value = `Word #${i + 1} doesn't match. Check what you wrote down.`;
        return;
      }
    }
    mnemonic.value = newMnemonic.value;
    step.value = "migrate-confirm";
  });

  const handleRunMigration = $(async () => {
    error.value = "";
    loading.value = true;
    migrating.value = true;
    step.value = "progress";
    progressMessage.value = "Starting the move...";

    const { listen } = await import("@tauri-apps/api/event");
    const unlisten = await listen<{ stage: string; message: string }>(
      "migration-progress",
      (event) => {
        progressMessage.value = event.payload.message;
      }
    );

    try {
      const summary = await invoke<{
        records_migrated: number;
        sessions_skipped: number;
        totp_moved: boolean;
        totp_skipped: boolean;
        cells_disabled: string[];
        backup_label: string;
        email: string;
        did: string;
        agent_pub_key: string;
      }>("migrate_custodial_account", {
        apiUrl: __API_URL__,
        jwt: jwt.value,
        password: loginPassword.value,
        mnemonic: mnemonic.value,
        // Phrase-first entry: the account password is a throwaway the user
        // never saw - the vault must use the password they chose on the
        // restore screen. Password entry: null = the web password becomes
        // the vault password (the copy on the done screen says so).
        vaultPassword: phraseProven.value && restorePassword.value
          ? restorePassword.value
          : null,
      });

      migSummary.recordsMigrated = summary.records_migrated;
      migSummary.totpMoved = summary.totp_moved;
      migSummary.totpSkipped = summary.totp_skipped;
      migSummary.cellsDisabled = summary.cells_disabled.length;
      migSummary.email = summary.email;
      migSummary.did = summary.did;
      result.agentPubKey = summary.agent_pub_key;
      result.did = summary.did;
      webUser.email = summary.email;

      usedPhraseDoor.value = phraseProven.value;
      mnemonic.value = "";
      newMnemonic.value = "";
      loginPassword.value = "";
      restorePassword.value = "";
      restorePassword2.value = "";
      step.value = "migrate-done";
    } catch (e) {
      const msg = String(e);
      if (msg.includes("phrase_mismatch")) {
        error.value =
          "This isn't the recovery phrase on file for this account. Check your words, or use \"I lost my recovery phrase\" to get a new one.";
        step.value = "migrate-phrase";
      } else if (msg.includes("lookup_hash_not_found") || msg.includes("export_missing_phrase")) {
        error.value =
          "This account's recovery phrase must be made again before the move. Use \"I lost it - make a new one\".";
        step.value = "migrate-phrase";
      } else {
        error.value = msg;
        step.value = "migrate-confirm";
      }
    } finally {
      unlisten();
      loading.value = false;
    }
  });

  const handleSignIn = $(async () => {
    error.value = "";
    loading.value = true;

    try {
      const authResult = await invoke<{
        success: boolean;
        requires_2fa: boolean;
        temp_token: string | null;
        token: string | null;
        email: string | null;
        username: string | null;
        agent_pub_key: string | null;
        display_name: string | null;
        profile_picture: string | null;
      }>("authenticate_web_account", {
        apiUrl: __API_URL__,
        emailOrUsername: email.value,
        password: loginPassword.value,
      });

      if (authResult.requires_2fa) {
        tempToken.value = authResult.temp_token ?? "";
        step.value = "twofa";
      } else {
        webUser.email = authResult.email ?? "";
        webUser.username = authResult.username ?? "";
        webUser.agentPubKey = authResult.agent_pub_key ?? "";
        webUser.displayName = authResult.display_name ?? "";
        webUser.profilePicture = authResult.profile_picture ?? "";
        jwt.value = authResult.token ?? "";
        // Fetch profile from /auth/me to ensure displayName + profilePicture
        await fetchProfile(jwt.value);
        await checkPhraseAndProceed(jwt.value);
      }
    } catch (e) {
      error.value = String(e);
    } finally {
      loading.value = false;
    }
  });

  const handle2FA = $(async () => {
    error.value = "";
    loading.value = true;

    try {
      const authResult = await invoke<{
        success: boolean;
        requires_2fa: boolean;
        temp_token: string | null;
        token: string | null;
        email: string | null;
        username: string | null;
        agent_pub_key: string | null;
        display_name: string | null;
        profile_picture: string | null;
      }>("authenticate_2fa", {
        apiUrl: __API_URL__,
        tempToken: tempToken.value,
        code: tfaCode.value,
      });

      webUser.email = authResult.email ?? "";
      webUser.username = authResult.username ?? "";
      webUser.agentPubKey = authResult.agent_pub_key ?? "";
      webUser.displayName = authResult.display_name ?? "";
      webUser.profilePicture = authResult.profile_picture ?? "";
      jwt.value = authResult.token ?? "";
      // Fetch profile from /auth/me (2FA endpoint doesn't return displayName/profilePicture)
      await fetchProfile(jwt.value);
      await checkPhraseAndProceed(jwt.value);
    } catch (e) {
      error.value = String(e);
    } finally {
      loading.value = false;
    }
  });

  const recheckPhrase = $(async () => {
    loading.value = true;
    error.value = "";
    try {
      const status = await invoke<{
        has_recovery_phrase: boolean;
        verified: boolean;
      }>("check_recovery_phrase_status", {
        apiUrl: __API_URL__,
        jwt: jwt.value,
      });

      if (status.has_recovery_phrase) {
        step.value = "phrase";
      } else {
        error.value = "No recovery phrase found yet. Please set it up on the web first.";
      }
    } catch {
      error.value = "Could not check. Please try again.";
    } finally {
      loading.value = false;
    }
  });

  const handleVerifyAndCreate = $(async () => {
    error.value = "";
    phraseVerified.value = false;
    loading.value = true;

    const trimmed = mnemonic.value.trim().toLowerCase().replace(/\s+/g, " ");
    mnemonic.value = trimmed;

    if (!trimmed) {
      loading.value = false;
      return;
    }

    try {
      // Step 1: Validate BIP39
      const valid = await invoke<boolean>("validate_recovery_phrase", {
        mnemonic: trimmed,
      });

      if (!valid) {
        error.value = "Invalid recovery phrase. Please check your words.";
        loading.value = false;
        return;
      }

      // Step 2: Cross-verify against web account
      const matches = await invoke<boolean>("verify_phrase_matches_web_key", {
        apiUrl: __API_URL__,
        mnemonic: trimmed,
        expectedWebAgentKey: webUser.agentPubKey,
      });

      if (!matches) {
        error.value = `This phrase doesn't match the account for ${webUser.email}. Make sure you're using the right recovery phrase.`;
        loading.value = false;
        return;
      }

      phraseVerified.value = true;

      // Step 3: Create vault immediately
      step.value = "progress";
      progressMessage.value = "Creating your keys on this device...";

      const setupResult = await invoke<{ agent_pub_key: string; did: string }>(
        "setup_vault",
        {
          mnemonic: mnemonic.value,
          password: loginPassword.value,
          webAgentPubKey: webUser.agentPubKey || null,
          webEmail: webUser.email || null,
          webUsername: webUser.username || null,
          displayName: webUser.displayName || null,
          profilePicture: webUser.profilePicture || null,
          isRestore: true,
        }
      );

      mnemonic.value = "";
      loginPassword.value = "";

      result.agentPubKey = setupResult.agent_pub_key;
      result.did = setupResult.did;
      step.value = "done";
    } catch (e) {
      step.value = "phrase";
      error.value = String(e);
    } finally {
      loading.value = false;
    }
  });

  // ── Create new identity (B1/B2/B4/B5) ──

  const handleCreateForm = $(async () => {
    error.value = "";
    if (!isValidEmail(createEmail.value)) {
      error.value = EMAIL_INVALID;
      return;
    }
    if (!emailsMatch(createEmail.value, createEmail2.value)) {
      error.value = EMAIL_MISMATCH;
      return;
    }
    const pwCheck = checkVaultPassword(createPassword.value);
    if (!pwCheck.valid) {
      error.value = pwCheck.hint || "Choose a stronger vault password.";
      return;
    }
    if (createPassword.value !== createPassword2.value) {
      error.value = "Passwords don't match.";
      return;
    }
    loading.value = true;
    try {
      // B1: fresh 24-word phrase from OS entropy, generated on-device.
      newMnemonic.value = await invoke<string>("generate_new_mnemonic");
      // B4: pick 3 random words the user must type back (proves it's written down)
      const picks = new Set<number>();
      while (picks.size < 3) picks.add(Math.floor(Math.random() * 24));
      verifyIndices.value = [...picks].sort((a, b) => a - b);
      verifyIndices.value.forEach((i) => (verifyWords[i] = ""));
      phraseSaved.value = false;
      step.value = "create-phrase";
    } catch (e) {
      error.value = String(e);
    } finally {
      loading.value = false;
    }
  });

  const handleCreateFinish = $(async () => {
    error.value = "";
    const words = newMnemonic.value.split(" ");
    for (const i of verifyIndices.value) {
      if ((verifyWords[i] ?? "").trim().toLowerCase() !== words[i]) {
        error.value = `Word #${i + 1} doesn't match. Check what you wrote down.`;
        return;
      }
    }
    loading.value = true;
    step.value = "progress";
    try {
      // B5: register the device pubkey with Flowsta (A3) - zero API cells.
      progressMessage.value = "Registering your identity with Flowsta...";
      const reg = await invoke<{
        user_id: string;
        did: string;
        agent_pub_key: string;
        profile_picture: string | null;
      }>("register_device_identity", {
        apiUrl: __API_URL__,
        mnemonic: newMnemonic.value,
        email: normalizeEmail(createEmail.value),
        displayName: createDisplayName.value.trim() || null,
      });

      progressMessage.value = "Creating your keys on this device...";
      const setupResult = await invoke<{ agent_pub_key: string; did: string }>(
        "setup_vault",
        {
          mnemonic: newMnemonic.value,
          password: createPassword.value,
          webAgentPubKey: null,
          webEmail: normalizeEmail(createEmail.value),
          webUsername: null,
          displayName: createDisplayName.value.trim() || null,
          // The server generates an identicon from the DID at registration -
          // store it so the identity has a face from the first unlock.
          profilePicture: reg.profile_picture ?? null,
          hostingModel: "device-hosted",
        }
      );

      webUser.email = normalizeEmail(createEmail.value);
      newMnemonic.value = "";
      createPassword.value = "";
      createPassword2.value = "";
      result.agentPubKey = setupResult.agent_pub_key;
      result.did = setupResult.did;
      step.value = "done";
    } catch (e) {
      const msg = String(e);
      if (msg.includes("api_unreachable")) {
        // Flowsta unreachable - identity first, account later: create
        // locally now; the deferred registration attaches automatically
        // when Flowsta answers (using the email + name entered above).
        try {
          progressMessage.value =
            "Flowsta unreachable - creating your identity on this device...";
          const setupResult = await invoke<{ agent_pub_key: string; did: string }>(
            "setup_vault",
            {
              mnemonic: newMnemonic.value,
              password: createPassword.value,
              webAgentPubKey: null,
              webEmail: normalizeEmail(createEmail.value),
              webUsername: null,
              displayName: createDisplayName.value.trim() || null,
              profilePicture: null,
              hostingModel: "device-hosted",
              pendingReconcile: true,
              pendingRegistration: true,
            }
          );
          webUser.email = normalizeEmail(createEmail.value);
          newMnemonic.value = "";
          createPassword.value = "";
          createPassword2.value = "";
          result.agentPubKey = setupResult.agent_pub_key;
          result.did = setupResult.did;
          createdOffline.value = true;
          step.value = "done";
        } catch (e2) {
          step.value = "create-phrase";
          error.value = String(e2);
        }
        return;
      }
      step.value = msg.includes("registration_failed") ? "create-form" : "create-phrase";
      if (msg.includes("email_already_registered")) {
        error.value = "An account already exists for this email. Sign in with your Flowsta account instead, or use a different email.";
      } else if (msg.includes("agent_key_already_registered")) {
        error.value = "This identity is already registered. Use 'Restore from recovery phrase' instead.";
      } else {
        error.value = msg;
      }
    } finally {
      loading.value = false;
    }
  });

  // ── Phrase-first account upgrade ──
  // The recovery phrase alone proves ownership of a flowsta.com account
  // (its derived key must decrypt the recovery email server-side). The
  // command rotates the password to a throwaway and returns the same
  // (jwt, email, password) triple the password sign-in produces, so the
  // standard upgrade continuation runs unchanged from here.
  const handlePhraseUpgrade = $(async () => {
  flow.value = "move";
    error.value = "";
    // The vault created by the upgrade is encrypted with the password
    // chosen on this screen - the account has no password in this flow.
    const upgPw = checkVaultPassword(restorePassword.value);
    if (!upgPw.valid) {
      error.value = restorePassword.value
        ? (upgPw.hint || "Choose a stronger vault password.")
        : "Choose a password for this Vault first.";
      return;
    }
    if (restorePassword.value !== restorePassword2.value) {
      error.value = "Vault passwords don't match.";
      return;
    }
    loading.value = true;
    const trimmed = mnemonic.value.trim().toLowerCase().replace(/\s+/g, " ");
    try {
      step.value = "progress";
      progressMessage.value = "Checking your recovery phrase with Flowsta...";
      const res = await invoke<{
        token: string;
        email: string;
        password: string;
        agent_pub_key: string;
      }>("phrase_migration_login", { apiUrl: __API_URL__, phrase: trimmed });

      phraseUpgradeOffer.value = false;
      mnemonic.value = trimmed;
      phraseProven.value = true;
      webUser.email = res.email;
      webUser.agentPubKey = res.agent_pub_key;
      email.value = res.email;
      loginPassword.value = res.password;
      jwt.value = res.token;
      await fetchProfile(jwt.value);
      await checkPhraseAndProceed(jwt.value);
    } catch (e) {
      step.value = "restore-phrase";
      const msg = String(e);
      error.value = msg.includes("no_account_for_phrase")
        ? "No Flowsta account matches this phrase either - double-check the words."
        : msg.includes("account_blocked")
          ? "This account is blocked. Contact support."
          : msg;
    } finally {
      loading.value = false;
    }
  });

  // ── Offline restore ──
  // Flowsta's API is unreachable, but the identity never needed it: keys
  // derive locally from the phrase, the conductor homes to community
  // bootstrap nodes, and signatures gossip back from the network itself.
  // pending_reconcile marks the vault so the account layer (username,
  // display name, picture) reattaches automatically when the API returns.
  const handleOfflineRestore = $(async () => {
    error.value = "";
    loading.value = true;
    const trimmed = mnemonic.value.trim().toLowerCase().replace(/\s+/g, " ");
    try {
      step.value = "progress";
      progressMessage.value =
        "Flowsta unreachable - restoring from your phrase and the community network...";
      const setupResult = await invoke<{ agent_pub_key: string; did: string }>(
        "setup_vault",
        {
          mnemonic: trimmed,
          password: restorePassword.value,
          webAgentPubKey: null,
          webEmail: null,
          webUsername: null,
          displayName: null,
          profilePicture: null,
          hostingModel: "device-hosted",
          pendingReconcile: true,
          isRestore: true,
        }
      );
      mnemonic.value = "";
      restorePassword.value = "";
      restorePassword2.value = "";
      result.agentPubKey = setupResult.agent_pub_key;
      result.did = setupResult.did;
      restoredFromPhrase.value = true;
      restoredOffline.value = true;
      step.value = "done";
    } catch (e) {
      step.value = "restore-phrase";
      error.value = String(e);
    } finally {
      loading.value = false;
    }
  });

  // ── Restore from phrase (B6) ──

  const handleRestoreDevice = $(async () => {
    error.value = "";
    const trimmed = mnemonic.value.trim().toLowerCase().replace(/\s+/g, " ");
    mnemonic.value = trimmed;
    if (!trimmed) return;
    const rPw = checkVaultPassword(restorePassword.value);
    if (!rPw.valid) {
      error.value = rPw.hint || "Choose a stronger vault password.";
      return;
    }
    if (restorePassword.value !== restorePassword2.value) {
      error.value = "Passwords don't match.";
      return;
    }
    loading.value = true;
    try {
      const valid = await invoke<boolean>("validate_recovery_phrase", { mnemonic: trimmed });
      if (!valid) {
        error.value = "Invalid recovery phrase. Please check your words.";
        loading.value = false;
        return;
      }

      step.value = "progress";
      progressMessage.value = "Checking your identity with Flowsta...";
      // Proves key ownership via A4 and fetches the account's public profile.
      const account = await invoke<{
        did: string;
        agent_pub_key: string;
        display_name: string | null;
        username: string | null;
        profile_picture: string | null;
        web_agent_pub_key: string | null;
      }>("restore_device_identity", { apiUrl: __API_URL__, mnemonic: trimmed });

      progressMessage.value = "Rebuilding your identity on this device...";
      const setupResult = await invoke<{ agent_pub_key: string; did: string }>(
        "setup_vault",
        {
          mnemonic: trimmed,
          password: restorePassword.value,
          // Migrated accounts: the original web agent key, recovered from
          // the DID - restores visibility of pre-upgrade signatures.
          webAgentPubKey: account.web_agent_pub_key ?? null,
          webEmail: null,
          webUsername: account.username,
          displayName: account.display_name,
          profilePicture: account.profile_picture,
          hostingModel: "device-hosted",
          isRestore: true,
        }
      );

      mnemonic.value = "";
      restorePassword.value = "";
      restorePassword2.value = "";
      result.agentPubKey = setupResult.agent_pub_key;
      result.did = setupResult.did;
      restoredFromPhrase.value = true;
      step.value = "done";
    } catch (e) {
      const msg = String(e);
      if (msg.includes("api_unreachable")) {
        // Flowsta can't be reached - the identity never needed it. Proceed
        // offline automatically; the done screen and the dashboard banner
        // carry the reconcile story.
        await handleOfflineRestore();
        return;
      }
      step.value = "restore-phrase";
      if (msg.includes("unknown_agent_key")) {
        // Not a Vault identity - but it may be a flowsta.com account's
        // recovery phrase. Offer the phrase-first upgrade right here.
        phraseUpgradeOffer.value = true;
        error.value = "";
      } else if (msg.includes("not_device_hosted")) {
        error.value = "These words belong to a flowsta.com account made before the Vault. Go back and choose \"Move it into this Vault\".";
      } else if (msg.includes("account_blocked")) {
        error.value = "This account is blocked. Contact support.";
      } else if (msg.includes("rate_limited") || msg.includes("Too many")) {
        error.value = "Too many tries from this network for now. Wait an hour, or set up this device from another of your devices.";
      } else if (msg.includes("vault_update_required") || msg.includes("device_not_registered") || msg.includes("approval_required")) {
        error.value = "This device could not be added with the phrase just now. Set it up from another of your devices, or try again in a few minutes.";
      } else if (msg.includes("Invalid recovery phrase") || msg.includes("Key derivation")) {
        error.value = "Invalid recovery phrase. Please check your words.";
      } else {
        // Never a raw code on screen; the log has the detail.
        console.error("restore failed:", msg);
        error.value = "That didn't work. Check your connection and try again, or set up this device from another of your devices.";
      }
    } finally {
      loading.value = false;
    }
  });

  const currentCircle = stepToCircle(step.value, flow.value);
  const circleLabels = FLOW_LABELS[flow.value];

  return (
    <div class="flex min-h-screen items-center justify-center bg-gray-900 p-8">
      <div class="w-full max-w-lg">
        {/* Logo + VAULT badge */}
        <div class="mb-6 flex items-center justify-center">
          <img src="/logo-dark.svg" alt="Flowsta" class="h-10" />
          <div class="ml-2 rounded-md bg-white px-2 py-0.5 flex items-center justify-center">
            <span class="text-xs font-bold tracking-wider text-gray-900">
              VAULT
            </span>
          </div>
        </div>

        {/* Step indicators */}
        <div class="mb-8 flex items-center justify-center gap-2">
          {circleLabels.map((label, i) => (
            <div key={label} class="flex items-center gap-2">
              <div class="flex flex-col items-center gap-1">
                <div
                  class={[
                    "flex h-8 w-8 items-center justify-center rounded-full text-sm font-semibold transition-colors",
                    currentCircle === i
                      ? "bg-sky-500 text-white"
                      : currentCircle > i
                        ? "bg-green-600 text-white"
                        : "bg-gray-700 text-gray-400",
                  ].join(" ")}
                >
                  {currentCircle > i ? (
                    <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={3}>
                      <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                  ) : (
                    i + 1
                  )}
                </div>
                <span class="text-[10px] text-gray-500">{label}</span>
              </div>
              {i < 2 && <div class="mb-4 h-px w-8 bg-gray-700" />}
            </div>
          ))}
        </div>

        {/* ── Step 0: Choose path ── */}
        {step.value === "choose" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 data-testid="wizard-welcome" class="mb-6 text-2xl font-bold text-white">{props.mode === "add" ? "Add another identity" : "Welcome to Flowsta Vault"}</h2>

            <div class="flex flex-col gap-3">
              <GlassButton testId="wizard-create" onClick$={() => { error.value = ""; flow.value = "create"; step.value = "create-form"; }}>
              {props.mode === "add" ? "Create a new identity" : "Create my identity"}
              </GlassButton>
              <GlassButton testId="wizard-existing" variant="secondary" onClick$={() => { error.value = ""; flow.value = "restore"; step.value = "existing"; }}>
              I already have an identity
              </GlassButton>
            </div>

            <p class="mt-4 text-sm text-gray-400">
              {props.mode === "add"
                ? "A second identity gets its own keys, records and apps on this device. One is unlocked at a time; you choose which at unlock."
                : "Your identity is created here and lives on your own device, never on a server. Nobody else, including Flowsta, can sign in as you."}
            </p>

            {props.mode === "add" && props.onCancel$ && (
              <div class="mt-6">
                <GlassButton variant="secondary" onClick$={async () => { error.value = ""; await props.onCancel$!(); }}>
                  Back
                </GlassButton>
              </div>
            )}

            {/* Moving in from the legacy web/phone account is a real path
                for a long time yet (many phone-only users have not moved),
                but it is not one of the two ways to START - it sits below
                them as a plain link so the choice above stays a choice of
                two. Same shape carries to a phone screen. */}
            {props.mode !== "add" && (
            <div class="mt-6 border-t border-gray-700 pt-4 text-sm text-gray-400">
              Created your Flowsta account on flowsta.com before July 2026?{" "}
              <button
                type="button"
                class="text-amber-300 underline decoration-amber-300/40 underline-offset-2 hover:text-amber-200"
                onClick$={() => { error.value = ""; flow.value = "move"; step.value = "signin"; }}
                >
                Move it into this Vault
              </button>
            </div>
            )}
          </div>
        )}

        {/* ── An identity that already exists: two ways in, same result ── */}
        {step.value === "existing" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="text-2xl font-bold text-white">Set up this device</h2>
            <p class="mb-6 text-sm text-gray-400">with your Flowsta identity</p>

            <div class="flex flex-col gap-4">
              <div>
                <GlassButton class="w-full" onClick$={() => { error.value = ""; flow.value = "restore"; step.value = "restore-phrase"; }}>
                  Use my recovery phrase
                </GlassButton>
                <p class="mt-1 text-center text-xs text-gray-400">Your 24 words</p>
              </div>
              <div>
                <GlassButton class="w-full" variant="secondary" onClick$={() => { error.value = ""; flow.value = "pair"; step.value = "pair-password"; }}>
                  Use another device
                </GlassButton>
                <p class="mt-1 text-center text-xs text-gray-400">One that already has your Vault</p>
              </div>
            </div>

            <div class="mt-6">
              <GlassButton variant="secondary" onClick$={() => { error.value = ""; flow.value = "create"; step.value = "choose"; }}>
                Back
              </GlassButton>
            </div>
          </div>
        )}

        {step.value === "pair-password" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-2 text-2xl font-bold text-white">Choose a password for this Vault</h2>
            <p class="mb-4 text-sm text-gray-400">It unlocks your Vault on this device.</p>

            <div class="mb-4">
              <label class="mb-1 block text-xs font-medium text-gray-400">Password for this Vault</label>
              <PasswordField
                class="mb-2"
                placeholder="At least 10 characters"
                autocomplete="new-password"
                value={pairPassword.value}
                onInput$={(v) => { pairPassword.value = v; error.value = ""; }}
              />
              <PasswordStrength password={pairPassword.value} />
            </div>
            <div class="mb-4">
              <label class="mb-1 block text-xs font-medium text-gray-400">Confirm password</label>
              <PasswordField
                placeholder="Repeat your password"
                autocomplete="new-password"
                value={pairPassword2.value}
                onInput$={(v) => { pairPassword2.value = v; error.value = ""; }}
              />
            </div>

            {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}

            <div class="flex justify-between">
              <GlassButton variant="secondary" onClick$={() => { error.value = ""; step.value = "existing"; }}>
                Back
              </GlassButton>
              <GlassButton
                disabled={loading.value || !pairPassword.value || !pairPassword2.value}
                onClick$={showPairCode}
              >
                {loading.value ? "Getting a code..." : "Show my code"}
              </GlassButton>
            </div>
          </div>
        )}

        {step.value === "pair-code" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-3 text-2xl font-bold text-white">Type this code on your other device</h2>
            <ol class="mb-6 list-decimal space-y-1 pl-5 text-sm text-gray-300">
              <li>Open Flowsta Vault on the device that already has your identity.</li>
              <li>Go to <span class="text-white">Settings</span>, then the <span class="text-white">Devices</span> tab.</li>
              <li>Choose <span class="text-white">Add a device</span> and type this code.</li>
            </ol>

            {pairCode.value ? (
              <>
                <p class="mb-4 select-all rounded-lg bg-gray-900 py-5 text-center font-mono text-3xl tracking-widest text-white">
                  {pairCode.value}
                </p>
                <p class="mb-6 flex items-center justify-center gap-2 text-sm text-sky-300">
                  <svg class="h-4 w-4 shrink-0 animate-spin" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
                  </svg>
                  <span>{pairWaitingApproval.value ? "Code received. Choose Add device on your other device." : "Waiting for the code to be typed on your other device..."}</span>
                </p>
              </>
            ) : (
              <p class="mb-6 text-sm text-red-400">{error.value}</p>
            )}

            <div class="flex justify-between">
              <GlassButton variant="secondary" onClick$={cancelPairing}>
                Back
              </GlassButton>
              {!pairCode.value && (
                <GlassButton disabled={loading.value} onClick$={showPairCode}>
                  {loading.value ? "Getting a code..." : "Get a new code"}
                </GlassButton>
              )}
            </div>
          </div>
        )}

        {/* ── Create 1: Account details (B2/B3) ── */}
        {step.value === "create-form" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-2 text-2xl font-bold text-white">Your details</h2>
            <p class="mb-6 text-sm text-gray-400">
              Your keys are made on this device and never leave it. Flowsta
              receives only your public key and email.
            </p>

            <form preventdefault:submit onSubmit$={handleCreateForm}>
              <div class="mb-4">
                <label class="mb-1 block text-xs font-medium text-gray-400">Email</label>
                <input
                  type="email"
                  name="email"
                  autocomplete="email"
                  class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                  placeholder="you@example.com"
                  value={createEmail.value}
                  data-testid="create-email"
                  autoFocus
                  onInput$={(e) => { createEmail.value = (e.target as HTMLInputElement).value; error.value = ""; }}
                />
                <p class="mt-1 text-xs text-gray-400">Used to verify your Flowsta identity and for notices about it - and shared with apps only when you choose to.</p>
              </div>

              <div class="mb-4">
                <label class="mb-1 block text-xs font-medium text-gray-400">Confirm email</label>
                <input
                  type="email"
                  autocomplete="off"
                  class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                  placeholder="Repeat your email"
                  value={createEmail2.value}
                  data-testid="create-email2"
                  onInput$={(e) => { createEmail2.value = (e.target as HTMLInputElement).value; error.value = ""; }}
                  onPaste$={(e) => e.preventDefault()}
                />
              </div>

              <div class="mb-4">
                <label class="mb-1 block text-xs font-medium text-gray-400">Display name (optional)</label>
                <input
                  type="text"
                  class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                  placeholder="How you appear to others"
                  value={createDisplayName.value}
                  data-testid="create-name"
                  onInput$={(e) => { createDisplayName.value = (e.target as HTMLInputElement).value; }}
                />
              </div>

              <div class="mb-4">
                <label class="mb-1 block text-xs font-medium text-gray-400">Password for this Vault</label>
                <PasswordField
                  class="mb-2"
                  placeholder="At least 10 characters"
                  autocomplete="new-password"
                  value={createPassword.value}
                  testId="create-password"
                  onInput$={(v) => { createPassword.value = v; error.value = ""; }}
                />
                <PasswordStrength password={createPassword.value} />
              </div>

              <div class="mb-4">
                <label class="mb-1 block text-xs font-medium text-gray-400">Confirm password</label>
                <PasswordField
                  placeholder="Repeat your password"
                  autocomplete="new-password"
                  value={createPassword2.value}
                  testId="create-password2"
                  onInput$={(v) => { createPassword2.value = v; error.value = ""; }}
                />
                <p class="mt-1 text-xs text-gray-400">
                  You use this password to unlock your Vault on this device.
                </p>
              </div>

              {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}

              <div class="flex justify-between">
                <GlassButton variant="secondary" onClick$={() => { error.value = ""; step.value = "choose"; }}>
                  Back
                </GlassButton>
                <GlassButton
                  testId="create-continue"
                  type="submit"
                  disabled={loading.value || !normalizeEmail(createEmail.value) || !normalizeEmail(createEmail2.value) || !createPassword.value || !createPassword2.value}
                >
                  {loading.value ? "Preparing..." : "Continue"}
                </GlassButton>
              </div>
            </form>
          </div>
        )}

        {/* ── Create 2: Recovery phrase (B4) ── */}
        {step.value === "create-phrase" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-2 text-2xl font-bold text-white">{phraseSaved.value ? "Check your recovery phrase" : "Write down your recovery phrase"}</h2>
            <p class="mb-2 text-sm text-gray-400">
            These 24 words let you bring your identity to another device, or get it back on this device if it's deleted.
            </p>
            <p class="mb-4 text-sm text-gray-400">
            Write them down and keep them somewhere safe - please don't keep them only on this device in case it's lost or deleted.
            </p>
            <div class="mb-4 rounded-md border border-amber-500/40 bg-amber-500/10 p-3">
              <p class="text-xs text-amber-300">
                Flowsta never sees this phrase and <strong>cannot recover it for you</strong>.
                Without it, your identity cannot be accessed or restored again.
              </p>
            </div>

            {!phraseSaved.value && (
            <>
            <div class="mb-4 grid grid-cols-3 gap-2 rounded-md bg-gray-900 p-4">
              {newMnemonic.value.split(" ").map((word, i) => (
                <div key={i} class="flex items-baseline gap-1.5">
                  <span class="w-5 text-right font-mono text-[10px] text-gray-500">{i + 1}.</span>
                  <span data-testid="phrase-word" class="font-mono text-sm text-white">{word}</span>
                </div>
              ))}
            </div>

            {/* Copy the clean, space-separated phrase (no numbers) so users
                don't transcribe it by hand from the numbered grid. */}
            <div class="mb-4 flex items-center gap-3">
              <button
                type="button"
                class="text-xs text-amber-400 hover:text-amber-300 transition-colors"
                onClick$={async () => {
                  try {
                    await navigator.clipboard.writeText(newMnemonic.value);
                    copied.value = true;
                    setTimeout(() => { copied.value = false; }, 2000);
                  } catch (e) {
                    console.error("clipboard write failed:", e);
                  }
                }}
              >
                {copied.value ? "Copied ✓" : "Copy phrase"}
              </button>
              <button
                type="button"
                class="text-xs text-amber-400 hover:text-amber-300 transition-colors"
                onClick$={downloadPhrase}
              >
                {downloaded.value ? "Downloaded ✓" : "Download as file"}
              </button>
              <span class="text-[10px] text-gray-500">
                Paste into a password manager. Clear your clipboard afterward.
              </span>
            </div>
            </>
            )}

            {!phraseSaved.value ? (
              <GlassButton testId="phrase-saved" onClick$={() => { phraseSaved.value = true; error.value = ""; }}>
                I've written it down
              </GlassButton>
            ) : (
              <div>
                <p class="mb-3 text-sm text-gray-400">
                  Type these words from what you wrote down:
                </p>
                <div class="mb-4 flex flex-col gap-3">
                  {verifyIndices.value.map((i) => (
                    <div key={i} class="flex items-center gap-3">
                      <span class="w-20 text-xs text-gray-400">Word #{i + 1}</span>
                      <input
                        type="text"
                        autoComplete="off"
                        class="flex-1 rounded-md border border-gray-600 bg-gray-900 px-3 py-2 text-sm font-mono text-white focus:border-amber-400 focus:outline-none"
                        value={verifyWords[i] ?? ""}
                        data-testid="verify-word"
                        data-word={i}
                        onInput$={(e) => { verifyWords[i] = (e.target as HTMLInputElement).value; error.value = ""; }}
                      />
                    </div>
                  ))}
                </div>

                {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}

                <div class="flex justify-between">
                  <GlassButton variant="secondary" onClick$={() => { phraseSaved.value = false; error.value = ""; }}>
                    Show phrase again
                  </GlassButton>
                  <GlassButton
                    testId="create-finish"
                    disabled={loading.value || verifyIndices.value.some((i) => !(verifyWords[i] ?? "").trim())}
                    onClick$={handleCreateFinish}
                  >
                    {loading.value ? "Creating..." : "Create my identity"}
                  </GlassButton>
                </div>
              </div>
            )}

            {error.value && !phraseSaved.value && (
              <p class="mt-4 text-sm text-red-400">{error.value}</p>
            )}
          </div>
        )}

        {/* ── Restore from phrase (B6) ── */}
        {step.value === "restore-phrase" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-2 text-2xl font-bold text-white">{props.mode === "add" ? "Add an identity with its recovery phrase" : "Restore with your recovery phrase"}</h2>
            <p class="mb-4 text-sm text-gray-400">
            Enter your 24 words. They set up your identity on this device; your username, records and signatures return from the network. Then choose a password for this Vault.
            </p>

            <textarea
              class="mb-4 w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400 resize-none"
              rows={4}
              placeholder="word1 word2 word3 ... word24"
              value={mnemonic.value}
              onInput$={(e) => { mnemonic.value = (e.target as HTMLTextAreaElement).value; error.value = ""; phraseUpgradeOffer.value = false; phraseProven.value = false; }}
            />

            <div class="mb-4">
              <label class="mb-1 block text-xs font-medium text-gray-400">Password for this Vault</label>
              <PasswordField
                class="mb-2"
                placeholder="At least 10 characters"
                autocomplete="new-password"
                value={restorePassword.value}
                onInput$={(v) => { restorePassword.value = v; error.value = ""; }}
              />
              <PasswordStrength password={restorePassword.value} />
            </div>
            <div class="mb-4">
              <label class="mb-1 block text-xs font-medium text-gray-400">Confirm password</label>
              <PasswordField
                placeholder="Repeat your password"
                autocomplete="new-password"
                value={restorePassword2.value}
                onInput$={(v) => { restorePassword2.value = v; error.value = ""; }}
              />
            </div>

            {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}

            {/* Phrase-first upgrade: no Vault identity for this phrase, but
                it may be a flowsta.com account's recovery phrase - the
                phrase alone proves ownership and starts the upgrade. */}
            {phraseUpgradeOffer.value && (
              <div class="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 p-4">
                <p class="mb-1 text-sm font-semibold text-white">
                  These words belong to a flowsta.com account
                </p>
                <p class="mb-3 text-xs text-gray-300">
                  That account was made before the Vault. It can move into
                  this Vault now, and your identity and signatures come with it.
                </p>
                <GlassButton
                  class="w-full"
                  disabled={loading.value}
                  onClick$={handlePhraseUpgrade}
                >
                  {loading.value ? "Checking the phrase..." : "Move my account into this Vault"}
                </GlassButton>
              </div>
            )}

            <div class="flex justify-between">
              <GlassButton variant="secondary" onClick$={async () => { mnemonic.value = ""; phraseUpgradeOffer.value = false; error.value = ""; step.value = "existing"; }}>
                Back
              </GlassButton>
              <GlassButton
                disabled={loading.value || !mnemonic.value.trim() || !restorePassword.value || !restorePassword2.value}
                onClick$={handleRestoreDevice}
              >
                {loading.value ? "Restoring..." : "Restore"}
              </GlassButton>
            </div>
          </div>
        )}

        {/* ── Step 1: Sign In ── */}
        {step.value === "signin" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-2 text-2xl font-bold text-white">
              Sign in to your flowsta.com account
              </h2>
              <p class="mb-6 text-sm text-gray-400">
              Your account moves into this Vault. Afterward you sign in everywhere by approving here.
              </p>

            <form preventdefault:submit onSubmit$={handleSignIn}>
              <div class="mb-4">
                <label class="mb-1 block text-xs font-medium text-gray-400">
                  Email or username
                  </label>
                <input
                  type="text"
                  class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                  placeholder="you@example.com"
                  value={email.value}
                  autoFocus
                  onInput$={(e) => {
                    email.value = (e.target as HTMLInputElement).value;
                    error.value = "";
                  }}
                />
              </div>

              <div class="mb-4">
                <label class="mb-1 block text-xs font-medium text-gray-400">
                  Password
                </label>
                <PasswordField
                  placeholder="Your Flowsta password"
                  autocomplete="current-password"
                  value={loginPassword.value}
                  onInput$={(v) => {
                    loginPassword.value = v;
                    error.value = "";
                  }}
                />
              </div>

              <p class="mb-4 text-xs text-gray-500">
                This password becomes the password for this Vault.
              </p>

              {error.value && (
                <p class="mb-4 text-sm text-red-400">{error.value}</p>
              )}

              <div class="flex items-center justify-between">
                <button
                  type="button"
                  onClick$={() => { error.value = ""; step.value = "create-form"; }}
                  class="text-xs text-amber-400 hover:text-amber-300 transition-colors"
                >
                  Don't have an account?
                </button>
                <GlassButton
                  type="submit"
                  disabled={
                    loading.value ||
                    !email.value.trim() ||
                    !loginPassword.value
                  }
                >
                  {loading.value ? "Signing in..." : "Sign In"}
                </GlassButton>
              </div>
            </form>

            <button
              class="mt-4 text-xs text-gray-500 hover:text-gray-400"
              onClick$={() => { error.value = ""; step.value = "choose"; }}
            >
              ← Other options
            </button>
          </div>
        )}

        {/* ── Step 1b: 2FA ── */}
        {step.value === "twofa" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-2 text-2xl font-bold text-white">
              Enter your 2FA code
              </h2>
            <p class="mb-6 text-sm text-gray-400">
              Enter the 6-digit code from your authenticator app.
            </p>

            <form preventdefault:submit onSubmit$={handle2FA}>
              <div class="mb-4">
                <input
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-center text-lg font-mono tracking-[0.5em] text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                  placeholder="000000"
                  value={tfaCode.value}
                  autoFocus
                  onInput$={(e) => {
                    tfaCode.value = (e.target as HTMLInputElement).value;
                    error.value = "";
                  }}
                />
              </div>

              {error.value && (
                <p class="mb-4 text-sm text-red-400">{error.value}</p>
              )}

              <div class="flex justify-between">
                <GlassButton
                  variant="secondary"
                  onClick$={() => {
                    tfaCode.value = "";
                    error.value = "";
                    step.value = "signin";
                  }}
                >
                  Back
                </GlassButton>
                <GlassButton
                  type="submit"
                  disabled={loading.value || tfaCode.value.length < 6}
                >
                  {loading.value ? "Verifying..." : "Verify"}
                </GlassButton>
              </div>
            </form>
          </div>
        )}

        {/* ── Step 2a: No Recovery Phrase ── */}
        {step.value === "no-phrase" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-2 text-2xl font-bold text-white">
              Set up a recovery phrase first
              </h2>
              <p class="mb-4 text-sm text-gray-400">
              Your account has no recovery phrase yet. Create one on flowsta.com, then come back.
              </p>
            <p class="mb-6 text-sm text-gray-400">
              The phrase makes your keys and is the way back in if you ever lose this device.
            </p>

            {error.value && (
              <p class="mb-4 text-sm text-red-400">{error.value}</p>
            )}

            <div class="flex flex-col gap-3">
              <GlassButton
                onClick$={() => {
                  open(WEB_PHRASE_URL);
                }}
              >
                Set it up on flowsta.com
              </GlassButton>
              <GlassButton
                variant="secondary"
                disabled={loading.value}
                onClick$={recheckPhrase}
              >
                {loading.value ? "Checking..." : "I've set it up - check again"}
              </GlassButton>
              <button
                class="text-xs text-gray-500 hover:text-gray-400"
                onClick$={() => {
                  error.value = "";
                  step.value = "signin";
                }}
              >
                Sign in with a different account
              </button>
            </div>
          </div>
        )}

        {/* ── Step 2b: Recovery Phrase Entry ── */}
        {step.value === "phrase" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-2 text-2xl font-bold text-white">
              Enter your recovery phrase
              </h2>
              <p class="mb-4 text-sm text-gray-400">
              The 24 words you saved on flowsta.com. They prove the account is yours and become its key on this device.
              </p>
              <p class="mb-4 text-xs text-gray-500">
              The words never leave this device.
              </p>

            <textarea
              class="mb-2 w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400 resize-none"
              rows={4}
              placeholder="word1 word2 word3 ... word24"
              value={mnemonic.value}
              onInput$={(e) => {
                mnemonic.value = (e.target as HTMLTextAreaElement).value;
                phraseVerified.value = false;
                error.value = "";
              }}
            />

            <p class="mb-4 text-xs text-gray-500">
              You can find this in your{" "}
              <button
                type="button"
                onClick$={() => open(WEB_PHRASE_URL)}
                class="text-amber-400 hover:text-amber-300 transition-colors"
              >
                Flowsta web dashboard
              </button>
              {" "}under Settings.
            </p>

            {error.value && (
              <p class="mb-4 text-sm text-red-400">{error.value}</p>
            )}

            <div class="flex justify-between">
              <GlassButton
                variant="secondary"
                onClick$={() => {
                  mnemonic.value = "";
                  phraseVerified.value = false;
                  error.value = "";
                  step.value = "signin";
                }}
              >
                Back
              </GlassButton>
              <GlassButton
                disabled={!mnemonic.value.trim() || loading.value}
                onClick$={handleVerifyAndCreate}
              >
                {loading.value ? "Verifying..." : "Continue"}
              </GlassButton>
            </div>
          </div>
        )}

        {/* ── Upgrade offer: shown right after a custodial sign-in ── */}
        {step.value === "upgrade-offer" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-2 text-2xl font-bold text-white">Move your account into this Vault</h2>
            <p class="mb-4 text-sm text-gray-400">
            Today your keys and personal data live on Flowsta's servers. After the move they live here, and only you can unlock them.
            </p>
            <ul class="mb-6 list-disc space-y-1 pl-5 text-xs text-gray-400">
              <li>Your personal data moves into this Vault, encrypted.</li>
              <li>You keep the same identity, username, and signatures.</li>
              <li>You sign in by approving in the Vault instead of typing a password.</li>
            </ul>

            {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}

            <div class="flex flex-col gap-3">
              <GlassButton
                disabled={loading.value}
                onClick$={() => {
                  error.value = "";
                  if (phraseProven.value && mnemonic.value.trim()) {
                    // Phrase-first entry: the phrase already proved itself
                    // against the account - straight to confirm.
                    step.value = "migrate-confirm";
                  } else {
                    // Password entry: let the user choose how to set up their
                    // phrase - enter one they have, or create a fresh one.
                    // The password already proved ownership; we never demand
                    // the existing phrase.
                    mnemonic.value = "";
                    step.value = "migrate-choose";
                  }
                }}
              >
                {loading.value ? "Preparing..." : "Move my account"}
              </GlassButton>
              <button
                type="button"
                class="text-xs text-gray-500 transition-colors hover:text-gray-300"
                onClick$={() => {
                  error.value = "";
                  step.value = "signin";
                }}
              >
                Back to sign-in
              </button>
            </div>

            <p class="mt-6 text-xs text-gray-500">
              The move takes a few minutes. Only the way you sign in changes.
            </p>
          </div>
        )}

        {/* ── Upgrade: choose how to set up the recovery phrase ── */}
        {step.value === "migrate-choose" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-2 text-2xl font-bold text-white">Do you have your recovery phrase?</h2>
            <p class="mb-6 text-sm text-gray-400">
              It becomes the only key to your account. {hasWebPhrase.value
              ? "Enter the one you saved, or create a new one."
              : "We will create one for you to save."}
            </p>

            {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}

            <div class="flex flex-col gap-3">
              {hasWebPhrase.value && (
                <GlassButton
                  disabled={loading.value}
                  onClick$={() => {
                    error.value = "";
                    mnemonic.value = "";
                    step.value = "migrate-phrase";
                  }}
                >
                  I have it
                </GlassButton>
              )}
              <GlassButton
                variant={hasWebPhrase.value ? "secondary" : "primary"}
                disabled={loading.value}
                onClick$={startMigrationCeremony}
              >
                {loading.value ? "Preparing..." : "Create a new recovery phrase"}
              </GlassButton>
              <button
                type="button"
                class="mt-1 text-xs text-gray-500 transition-colors hover:text-gray-300"
                onClick$={() => { error.value = ""; step.value = "upgrade-offer"; }}
              >
                Back
              </button>
            </div>

            {hasWebPhrase.value && (
              <p class="mt-6 text-xs text-gray-500">
                A new phrase replaces the old one, which stops working.
                Choose this only if you no longer have it.
              </p>
            )}
          </div>
        )}

        {/* ── Upgrade: enter the existing recovery phrase ── */}
        {step.value === "migrate-phrase" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-2 text-2xl font-bold text-white">Enter your recovery phrase</h2>
            <p class="mb-4 text-sm text-gray-400">
            Your 24 words become the key to your account in this Vault. They are checked against your account before anything changes.
            </p>
            <textarea
              class="mb-2 w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400 resize-none"
              rows={4}
              placeholder="word1 word2 word3 ... word24"
              value={mnemonic.value}
              onInput$={(e) => {
                mnemonic.value = (e.target as HTMLTextAreaElement).value;
                error.value = "";
              }}
            />

            <button
              type="button"
              class="mb-4 text-xs text-amber-400 hover:text-amber-300 transition-colors"
              disabled={loading.value}
              onClick$={startMigrationCeremony}
            >
              I lost it - make a new one
            </button>

            {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}

            <div class="flex justify-between">
              <GlassButton
                variant="secondary"
                onClick$={() => { mnemonic.value = ""; error.value = ""; step.value = "migrate-choose"; }}
              >
                Back
              </GlassButton>
              <GlassButton
                disabled={loading.value || !mnemonic.value.trim()}
                onClick$={handleMigratePhraseContinue}
              >
                Continue
              </GlassButton>
            </div>
          </div>
        )}

        {/* ── Upgrade: new-phrase ceremony (no phrase yet / lost phrase) ── */}
        {step.value === "migrate-ceremony" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-2 text-2xl font-bold text-white">{phraseSaved.value ? "Check your recovery phrase" : "Write down your new recovery phrase"}</h2>
            <p class="mb-2 text-sm text-gray-400">
            These 24 words replace your old recovery phrase. They let you bring your identity to another device, or get it back on this device if it's deleted.
            </p>
            <p class="mb-4 text-sm text-gray-400">
            Write them down and keep them somewhere safe - please don't keep them only on this device in case it's lost or deleted.
            </p>
            <div class="mb-4 rounded-md border border-amber-500/40 bg-amber-500/10 p-3">
              <p class="text-xs text-amber-300">
                After the move this phrase is the <strong>only</strong> way to
                recover your identity. Flowsta cannot recover it for you.
              </p>
            </div>

            {!phraseSaved.value && (
            <>
            <div class="mb-4 grid grid-cols-3 gap-2 rounded-md bg-gray-900 p-4">
              {newMnemonic.value.split(" ").map((word, i) => (
                <div key={i} class="flex items-baseline gap-1.5">
                  <span class="w-5 text-right font-mono text-[10px] text-gray-500">{i + 1}.</span>
                  <span data-testid="phrase-word" class="font-mono text-sm text-white">{word}</span>
                </div>
              ))}
            </div>

            <div class="mb-4 flex items-center gap-3">
              <button
                type="button"
                class="text-xs text-amber-400 hover:text-amber-300 transition-colors"
                onClick$={async () => {
                  try {
                    await navigator.clipboard.writeText(newMnemonic.value);
                    copied.value = true;
                    setTimeout(() => { copied.value = false; }, 2000);
                  } catch (e) {
                    console.error("clipboard write failed:", e);
                  }
                }}
              >
                {copied.value ? "Copied ✓" : "Copy phrase"}
              </button>
              <button
                type="button"
                class="text-xs text-amber-400 hover:text-amber-300 transition-colors"
                onClick$={downloadPhrase}
              >
                {downloaded.value ? "Downloaded ✓" : "Download as file"}
              </button>
              <span class="text-[10px] text-gray-500">
                Paste into a password manager. Clear your clipboard afterward.
              </span>
            </div>
            </>
            )}

            {!phraseSaved.value ? (
              <GlassButton testId="phrase-saved" onClick$={() => { phraseSaved.value = true; error.value = ""; }}>
                I've written it down
              </GlassButton>
            ) : (
              <div>
                <p class="mb-3 text-sm text-gray-400">
                  Type these words from what you wrote down:
                </p>
                <div class="mb-4 flex flex-col gap-3">
                  {verifyIndices.value.map((i) => (
                    <div key={i} class="flex items-center gap-3">
                      <span class="w-20 text-xs text-gray-400">Word #{i + 1}</span>
                      <input
                        type="text"
                        autoComplete="off"
                        class="flex-1 rounded-md border border-gray-600 bg-gray-900 px-3 py-2 text-sm font-mono text-white focus:border-amber-400 focus:outline-none"
                        value={verifyWords[i] ?? ""}
                        data-testid="verify-word"
                        data-word={i}
                        onInput$={(e) => { verifyWords[i] = (e.target as HTMLInputElement).value; error.value = ""; }}
                      />
                    </div>
                  ))}
                </div>

                {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}

                <div class="flex justify-between">
                  <GlassButton variant="secondary" onClick$={() => { phraseSaved.value = false; error.value = ""; }}>
                    Show phrase again
                  </GlassButton>
                  <GlassButton
                    disabled={verifyIndices.value.some((i) => !(verifyWords[i] ?? "").trim())}
                    onClick$={handleMigrateCeremonyFinish}
                  >
                    Continue
                  </GlassButton>
                </div>
              </div>
            )}

            {error.value && !phraseSaved.value && (
              <p class="mt-4 text-sm text-red-400">{error.value}</p>
            )}
          </div>
        )}

        {/* ── Upgrade: explicit consent before anything changes ── */}
        {step.value === "migrate-confirm" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-2 text-2xl font-bold text-white">Ready to move your account</h2>
            <p class="mb-4 text-sm text-gray-400">
              Four steps, in order. Your account doesn't change until the
              last one succeeds:
            </p>
            <ol class="mb-4 list-decimal space-y-1 pl-5 text-xs text-gray-400">
              <li>Your account data downloads to this device and is decrypted here - nowhere else.</li>
              <li>It's re-encrypted so only your recovery phrase can unlock it.</li>
              <li>An encrypted backup of everything is saved on this device.</li>
              <li>Sign-in switches from your password to this Vault.</li>
            </ol>
            <div class="mb-4 rounded-md border border-amber-500/40 bg-amber-500/10 p-3">
              <p class="text-xs text-amber-300">
                Afterward your password only unlocks this Vault. Every browser
                and device signs in through the Vault instead.
              </p>
            </div>
            <p class="mb-4 text-xs text-gray-500">
              If the move is interrupted, nothing is lost. Your account stays
              as it is until the last step completes, and you can run it again.
            </p>

            {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}

            <div class="flex justify-between">
              <GlassButton
                variant="secondary"
                onClick$={() => {
                  error.value = "";
                  step.value = hasWebPhrase.value ? "migrate-phrase" : "upgrade-offer";
                }}
              >
                Back
              </GlassButton>
              <GlassButton disabled={loading.value} onClick$={handleRunMigration}>
                {loading.value ? "Moving..." : "Move my account"}
              </GlassButton>
            </div>
          </div>
        )}

        {/* ── Upgrade complete ── */}
        {step.value === "migrate-done" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8 text-center">
            <div class="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-full bg-green-600/20">
              <svg class="h-6 w-6 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <h2 class="mb-2 text-xl font-bold text-white">This Vault Is Your Account Now</h2>
            <p class="mb-3 text-sm text-gray-400">
              Your identity, data and sign-in all moved here.
              {usedPhraseDoor.value
                ? " The vault password you chose unlocks this Vault - sign-ins everywhere else are approved from it."
                : " Your old password now only unlocks this Vault - sign-ins everywhere else are approved from it."}
            </p>
            <p class="mb-6 text-xs text-amber-300">
              Your recovery phrase is now the one key to your account. No one
              - including Flowsta - can recover it for you, so keep the
              phrase somewhere safe.
            </p>

            <div class="mb-6 rounded-lg bg-gray-900 p-4 text-left">
              {migSummary.email && (
                <div class="mb-3">
                  <span class="text-xs font-medium text-gray-400">Account</span>
                  <p class="text-sm text-white">{migSummary.email}</p>
                </div>
              )}
              <div class="mb-3">
                <span class="text-xs font-medium text-gray-400">Moved to this device</span>
                <p class="text-sm text-white">
                  {migSummary.recordsMigrated} records
                  {migSummary.totpMoved ? " · 2FA settings" : ""}
                  {" · encrypted local backup"}
                </p>
                {migSummary.totpSkipped && (
                  <p class="mt-1 text-xs text-gray-400">
                    Your old 2FA settings couldn't be carried over - that's
                    fine: approving sign-ins from this Vault replaces 2FA.
                  </p>
                )}
              </div>
              <button
                class="text-xs text-gray-500 hover:text-gray-400"
                onClick$={() => { showTechDetails.value = !showTechDetails.value; }}
              >
                {showTechDetails.value ? "Hide" : "Show"} technical details
              </button>
              {showTechDetails.value && (
                <div class="mt-3 space-y-3 border-t border-gray-800 pt-3">
                  <div>
                    <span class="text-xs font-medium text-gray-400">DID (unchanged)</span>
                    <p class="font-mono text-sm text-sky-400 break-all">{migSummary.did}</p>
                  </div>
                  <div>
                    <span class="text-xs font-medium text-gray-400">Device Agent Key</span>
                    <p class="font-mono text-sm text-gray-300 break-all">{result.agentPubKey}</p>
                  </div>
                </div>
              )}
            </div>

            <GlassButton onClick$={props.onComplete$}>
              Open Dashboard
            </GlassButton>
          </div>
        )}

        {/* ── Step 3a: Progress ── */}
        {step.value === "progress" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8 text-center">
            <div class="mb-4 inline-flex h-12 w-12 items-center justify-center">
              <svg class="h-8 w-8 animate-spin text-amber-400" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
            </div>
            <h2 class="mb-2 text-xl font-bold text-white">Setting up your Vault...</h2>
            <p class="text-sm text-gray-400">{progressMessage.value}</p>
            {migrating.value && (
              <p class="mt-4 text-xs text-gray-500">
                Your account does not change until the last step succeeds.
                If this is interrupted, run the move again.
              </p>
            )}
          </div>
        )}

        {/* ── Step 3b: Done ── */}
        {step.value === "done" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8 text-center">
            <div class="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-full bg-green-600/20">
              <svg class="h-6 w-6 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2}>
                <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <h2 data-testid="wizard-done" class="mb-2 text-xl font-bold text-white">Your Vault is ready</h2>
            <p class="mb-6 text-sm text-gray-400">
            Your identity lives on your own device, not on a server. Sign in to Flowsta apps and websites by approving here.
            </p>

            <div class="mb-6 rounded-lg bg-gray-900 p-4 text-left">
              {/* Show the email used to sign in - prefer webUser.email if it looks like an email, otherwise use the sign-in input */}
              {(webUser.email.includes("@") ? webUser.email : email.value) && (
                <div class="mb-3">
                  <span class="text-xs font-medium text-gray-400">
                    Email
                  </span>
                  <p class="text-sm text-white">
                    {webUser.email.includes("@") ? webUser.email : email.value}
                  </p>
                </div>
              )}

              {/* Technical details toggle */}
              <button
                class="text-xs text-gray-500 hover:text-gray-400"
                onClick$={() => { showTechDetails.value = !showTechDetails.value; }}
              >
                {showTechDetails.value ? "Hide" : "Show"} technical details
              </button>

              {showTechDetails.value && (
                <div class="mt-3 space-y-3 border-t border-gray-800 pt-3">
                  <div>
                    <span class="text-xs font-medium text-gray-400">DID</span>
                    <p class="font-mono text-sm text-sky-400 break-all">
                      {result.did}
                    </p>
                  </div>
                  <div>
                    <span class="text-xs font-medium text-gray-400">
                      Device Agent Key
                    </span>
                    <p class="font-mono text-sm text-gray-300 break-all">
                      {result.agentPubKey}
                    </p>
                  </div>
                </div>
              )}
            </div>

            {createdOffline.value && (
            <div class="mb-4 rounded-lg border border-sky-800/50 bg-sky-950/30 p-4 text-left">
              <p class="mb-1 text-sm font-semibold text-sky-200">
                Created offline
              </p>
              <p class="text-xs text-gray-400">
                Your identity works now. Your Flowsta account and email attach
                by themselves when Flowsta is reachable. Nothing to do.
              </p>
            </div>
          )}
          {restoredOffline.value && (
            <div class="mb-4 rounded-lg border border-sky-800/50 bg-sky-950/30 p-4 text-left">
              <p class="mb-1 text-sm font-semibold text-sky-200">
                Restored offline
              </p>
              <p class="text-xs text-gray-400">
                Your records return as this device syncs. Your username,
                display name and email reconnect when Flowsta is reachable.
                Nothing to do.
              </p>
            </div>
          )}
          {pairedFromDevice.value && (
            <div class="mb-4 rounded-lg border border-sky-800/50 bg-sky-950/30 p-4 text-left">
              <p class="mb-1 text-sm font-semibold text-sky-200">
                This device is now one of your devices
              </p>
              <p class="text-xs text-gray-400">
                Your private data arrives from your other device while both are on. Nothing to do.
              </p>
            </div>
          )}
          {restoredFromPhrase.value && !restoreImportResult.value && (
              <div class="mb-6 rounded-lg border border-sky-800/50 bg-sky-950/30 p-4 text-left">
                <p class="mb-1 flex items-center gap-2 text-sm font-semibold text-sky-200">
                  {!(siblingSync.value?.records_arrived) && (
                    <svg class="h-4 w-4 shrink-0 animate-spin" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
                      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
                    </svg>
                  )}
                  <span>
                    {siblingSync.value?.records_arrived
                      ? "Your things are arriving from your other devices."
                      : siblingSync.value && siblingSync.value.other_devices.length > 0
                        ? `Found ${siblingSync.value.other_devices.join(", ")}. Your things are arriving.`
                        : Date.now() - siblingWaitStarted.value > 150_000
                          ? "No other device has answered yet."
                          : "Looking for your other devices..."}
                  </span>
                </p>
                <p class="mb-3 text-sm text-gray-300">
                  {siblingSync.value?.records_arrived
                    ? "Your private records, connections and app backups come across by themselves. Nothing to do."
                    : "Your private data arrives from your other devices when one of them is on. Nothing to do."}
                </p>
                {!showImportLink.value ? (
                  <button
                    type="button"
                    class="text-xs text-gray-400 underline decoration-gray-600 underline-offset-2 hover:text-gray-200"
                    onClick$={() => { showImportLink.value = true; }}
                  >
                    Lost your only device? Restore from an export file
                  </button>
                ) : (
                  <p class="mb-3 text-xs text-gray-400">
                    If you kept a Vault export file, import it now. Your private records and app backups come back from it.
                  </p>
                )}
                {restoreImportError.value && (
                  <p class="mb-3 text-sm text-red-300">{restoreImportError.value}</p>
                )}
                {restoreImporting.value ? (
                  <p class="flex items-center gap-2 text-sm text-sky-300">
                    <svg class="h-4 w-4 shrink-0 animate-spin" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
                      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
                    </svg>
                    <span>{restoreImportProgress.value || "Importing your export..."}</span>
                  </p>
                ) : (
                  <div class="mt-3 flex flex-col-reverse gap-2 sm:flex-row sm:items-center sm:justify-end">
                    {showImportLink.value && (
                      <button
                        class="rounded-full border border-gray-600 px-5 py-2 text-sm text-gray-300 hover:border-gray-400 hover:text-white"
                        onClick$={importExportNow}
                      >
                        Import an export file
                      </button>
                    )}
                    <GlassButton onClick$={continueWithoutImport}>Continue</GlassButton>
                  </div>
                )}
              </div>
            )}
            {restoredFromPhrase.value && restoreImportResult.value && (
              <div class="mb-6 rounded-lg border border-sky-800/50 bg-sky-950/30 p-4 text-left">
                <p class="mb-1 text-sm font-medium text-sky-300">
                  {summarizeRestoreImport(restoreImportResult.value).title}
                </p>
                <p class="text-sm text-gray-400">
                  {summarizeRestoreImport(restoreImportResult.value).body}
                </p>
              </div>
            )}

            {(!restoredFromPhrase.value || restoreImportResult.value) && (
              <GlassButton testId="wizard-finish" onClick$={props.onComplete$}>
                Continue
              </GlassButton>
            )}
          </div>
        )}
      </div>
    </div>
  );
});
