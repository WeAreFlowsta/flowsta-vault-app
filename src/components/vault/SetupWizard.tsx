import { component$, useSignal, useStore, $, type QRL } from "@builder.io/qwik";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-shell";
import { GlassButton } from "~/components/common/GlassButton";

interface SetupWizardProps {
  onComplete$: QRL<() => void>;
}

type Step =
  | "choose"
  | "create-form"
  | "create-phrase"
  | "restore-phrase"
  | "signin"
  | "twofa"
  | "no-phrase"
  | "phrase"
  | "upgrade-offer"
  | "migrate-phrase"
  | "migrate-ceremony"
  | "migrate-confirm"
  | "migrate-done"
  | "progress"
  | "done";

declare const __API_URL__: string;
declare const __WEB_URL__: string;
const WEB_PHRASE_URL = `${__WEB_URL__}/dashboard/settings/password/`;

function stepToCircle(s: Step): number {
  if (s === "choose" || s === "create-form" || s === "signin" || s === "twofa" || s === "upgrade-offer") return 0;
  if (
    s === "create-phrase" || s === "restore-phrase" || s === "no-phrase" || s === "phrase" ||
    s === "migrate-phrase" || s === "migrate-ceremony" || s === "migrate-confirm"
  ) return 1;
  return 2;
}

const circleLabels = ["Connect", "Verify Identity", "Ready"];

export const SetupWizard = component$<SetupWizardProps>((props) => {
  const step = useSignal<Step>("choose");
  const email = useSignal("");
  const loginPassword = useSignal("");
  const tfaCode = useSignal("");
  const tempToken = useSignal("");
  const jwt = useSignal("");
  const webUser = useStore({ email: "", username: "", agentPubKey: "", displayName: "", profilePicture: "" });
  const mnemonic = useSignal("");
  const phraseVerified = useSignal(false);
  const error = useSignal("");
  const loading = useSignal(false);
  const progressMessage = useSignal("");
  const result = useStore({ agentPubKey: "", did: "" });
  const showTechDetails = useSignal(false);

  // Create-new-identity state (device-hosted identity)
  const createEmail = useSignal("");
  const createDisplayName = useSignal("");
  const createPassword = useSignal("");
  const createPassword2 = useSignal("");
  const newMnemonic = useSignal("");
  const verifyIndices = useSignal<number[]>([]);
  const verifyWords = useStore<{ [k: number]: string }>({});
  const phraseSaved = useSignal(false);
  const copied = useSignal(false);
  // Restore-from-phrase state (B6)
  const restorePassword = useSignal("");
  const restorePassword2 = useSignal("");

  // Account-upgrade (migration) state
  const hasWebPhrase = useSignal(false);
  const migSummary = useStore({
    recordsMigrated: 0,
    totpMoved: false,
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
      console.warn("No JWT token — skipping phrase status check");
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
      // If the check fails (e.g. offline), assume a phrase exists — the
      // migration flow verifies it against the account anyway.
      console.error("Recovery phrase status check failed:", e);
      hasWebPhrase.value = true;
    }
    step.value = "upgrade-offer";
  });

  // Legacy path: keep the web account custodial and just link this device.
  // True while the account upgrade runs — the shared progress card shows
  // the interruption-safety note only then.
  const migrating = useSignal(false);

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
    progressMessage.value = "Starting your account upgrade…";

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
      });

      migSummary.recordsMigrated = summary.records_migrated;
      migSummary.totpMoved = summary.totp_moved;
      migSummary.cellsDisabled = summary.cells_disabled.length;
      migSummary.email = summary.email;
      migSummary.did = summary.did;
      result.agentPubKey = summary.agent_pub_key;
      result.did = summary.did;
      webUser.email = summary.email;

      mnemonic.value = "";
      newMnemonic.value = "";
      loginPassword.value = "";
      step.value = "migrate-done";
    } catch (e) {
      const msg = String(e);
      if (msg.includes("phrase_mismatch")) {
        error.value =
          "This isn't the recovery phrase on file for this account. Check your words, or use \"I lost my recovery phrase\" to get a new one.";
        step.value = "migrate-phrase";
      } else if (msg.includes("lookup_hash_not_found") || msg.includes("export_missing_phrase")) {
        error.value =
          "This account's recovery phrase needs to be re-created before upgrading. Use \"I lost my recovery phrase\" to get a new one.";
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
      progressMessage.value = "Deriving keys and encrypting vault...";

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
    const em = createEmail.value.trim();
    if (!em.includes("@") || em.length < 5) {
      error.value = "Please enter a valid email address.";
      return;
    }
    if (createPassword.value.length < 10) {
      error.value = "Vault password must be at least 10 characters.";
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
      // B5: register the device pubkey with Flowsta (A3) — zero API cells.
      progressMessage.value = "Registering your identity with Flowsta...";
      await invoke("register_device_identity", {
        apiUrl: __API_URL__,
        mnemonic: newMnemonic.value,
        email: createEmail.value.trim(),
        displayName: createDisplayName.value.trim() || null,
      });

      progressMessage.value = "Deriving keys and encrypting vault...";
      const setupResult = await invoke<{ agent_pub_key: string; did: string }>(
        "setup_vault",
        {
          mnemonic: newMnemonic.value,
          password: createPassword.value,
          webAgentPubKey: null,
          webEmail: createEmail.value.trim(),
          webUsername: null,
          displayName: createDisplayName.value.trim() || null,
          profilePicture: null,
          hostingModel: "device-hosted",
        }
      );

      webUser.email = createEmail.value.trim();
      newMnemonic.value = "";
      createPassword.value = "";
      createPassword2.value = "";
      result.agentPubKey = setupResult.agent_pub_key;
      result.did = setupResult.did;
      step.value = "done";
    } catch (e) {
      const msg = String(e);
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

  // ── Restore from phrase (B6) ──

  const handleRestoreDevice = $(async () => {
    error.value = "";
    const trimmed = mnemonic.value.trim().toLowerCase().replace(/\s+/g, " ");
    mnemonic.value = trimmed;
    if (!trimmed) return;
    if (restorePassword.value.length < 10) {
      error.value = "Vault password must be at least 10 characters.";
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
      progressMessage.value = "Verifying your identity with Flowsta...";
      // Proves key ownership via A4 and fetches the account's public profile.
      const account = await invoke<{
        did: string;
        agent_pub_key: string;
        display_name: string | null;
        username: string | null;
        profile_picture: string | null;
      }>("restore_device_identity", { apiUrl: __API_URL__, mnemonic: trimmed });

      progressMessage.value = "Rebuilding your vault on this device...";
      const setupResult = await invoke<{ agent_pub_key: string; did: string }>(
        "setup_vault",
        {
          mnemonic: trimmed,
          password: restorePassword.value,
          webAgentPubKey: null,
          webEmail: null,
          webUsername: account.username,
          displayName: account.display_name,
          profilePicture: account.profile_picture,
          hostingModel: "device-hosted",
        }
      );

      mnemonic.value = "";
      restorePassword.value = "";
      restorePassword2.value = "";
      result.agentPubKey = setupResult.agent_pub_key;
      result.did = setupResult.did;
      step.value = "done";
    } catch (e) {
      const msg = String(e);
      step.value = "restore-phrase";
      if (msg.includes("unknown_agent_key")) {
        error.value = "No Vault-created identity found for this phrase. If you signed up on flowsta.com, use 'Sign in with your Flowsta account' instead.";
      } else if (msg.includes("not_device_hosted")) {
        error.value = "This phrase belongs to a flowsta.com web account. Use 'Sign in with your Flowsta account' to restore it.";
      } else if (msg.includes("account_blocked")) {
        error.value = "This account is blocked. Contact support.";
      } else {
        error.value = msg;
      }
    } finally {
      loading.value = false;
    }
  });

  const currentCircle = stepToCircle(step.value);

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
            <h2 class="mb-2 text-2xl font-bold text-white">Welcome to Flowsta Vault</h2>
            <p class="mb-6 text-sm text-gray-400">
              Your identity and keys live on this device — not on anyone's server.
            </p>

            <div class="flex flex-col gap-3">
              <GlassButton onClick$={() => { error.value = ""; step.value = "create-form"; }}>
                Create a new identity
              </GlassButton>
              <GlassButton variant="secondary" onClick$={() => { error.value = ""; step.value = "restore-phrase"; }}>
                Restore from recovery phrase
              </GlassButton>
              <GlassButton variant="secondary" onClick$={() => { error.value = ""; step.value = "signin"; }}>
                Sign in with your Flowsta account
              </GlassButton>
            </div>

            <p class="mt-6 text-xs text-gray-500">
              New here? "Create a new identity" makes a fresh self-custody identity in about a minute.
              Already have a flowsta.com account? Use "Sign in with your Flowsta account".
            </p>
          </div>
        )}

        {/* ── Create 1: Account details (B2/B3) ── */}
        {step.value === "create-form" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-2 text-2xl font-bold text-white">Create Your Identity</h2>
            <p class="mb-6 text-sm text-gray-400">
              Your keys are generated on this device and never leave it. Flowsta
              only receives your public key and email.
            </p>

            <form preventdefault:submit onSubmit$={handleCreateForm}>
              <div class="mb-4">
                <label class="mb-1 block text-xs font-medium text-gray-400">Email</label>
                <input
                  type="email"
                  class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                  placeholder="you@example.com"
                  value={createEmail.value}
                  autoFocus
                  onInput$={(e) => { createEmail.value = (e.target as HTMLInputElement).value; error.value = ""; }}
                />
                <p class="mt-1 text-xs text-gray-500">Used to verify your account and for account notices.</p>
              </div>

              <div class="mb-4">
                <label class="mb-1 block text-xs font-medium text-gray-400">Display name (optional)</label>
                <input
                  type="text"
                  class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                  placeholder="How you appear to others"
                  value={createDisplayName.value}
                  onInput$={(e) => { createDisplayName.value = (e.target as HTMLInputElement).value; }}
                />
              </div>

              <div class="mb-4">
                <label class="mb-1 block text-xs font-medium text-gray-400">Vault password</label>
                <input
                  type="password"
                  class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                  placeholder="At least 10 characters"
                  value={createPassword.value}
                  onInput$={(e) => { createPassword.value = (e.target as HTMLInputElement).value; error.value = ""; }}
                />
              </div>

              <div class="mb-4">
                <label class="mb-1 block text-xs font-medium text-gray-400">Confirm vault password</label>
                <input
                  type="password"
                  class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                  placeholder="Repeat your password"
                  value={createPassword2.value}
                  onInput$={(e) => { createPassword2.value = (e.target as HTMLInputElement).value; error.value = ""; }}
                />
                <p class="mt-1 text-xs text-gray-500">
                  Unlocks your vault on this device. It is not a Flowsta account password.
                </p>
              </div>

              {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}

              <div class="flex justify-between">
                <GlassButton variant="secondary" onClick$={() => { error.value = ""; step.value = "choose"; }}>
                  Back
                </GlassButton>
                <GlassButton
                  type="submit"
                  disabled={loading.value || !createEmail.value.trim() || !createPassword.value || !createPassword2.value}
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
            <h2 class="mb-2 text-2xl font-bold text-white">Save Your Recovery Phrase</h2>
            <p class="mb-4 text-sm text-gray-400">
              These 24 words are your identity. Write them down and store them somewhere safe — on paper, not on this computer.
            </p>
            <div class="mb-4 rounded-md border border-amber-500/40 bg-amber-500/10 p-3">
              <p class="text-xs text-amber-300">
                This phrase is currently the <strong>only</strong> way to recover your identity.
                Flowsta never sees it and cannot recover it for you. Lose the phrase and this
                device, and your identity is gone.
              </p>
            </div>

            <div class="mb-4 grid grid-cols-3 gap-2 rounded-md bg-gray-900 p-4">
              {newMnemonic.value.split(" ").map((word, i) => (
                <div key={i} class="flex items-baseline gap-1.5">
                  <span class="w-5 text-right font-mono text-[10px] text-gray-500">{i + 1}.</span>
                  <span class="font-mono text-sm text-white">{word}</span>
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
              <span class="text-[10px] text-gray-500">
                Paste into a password manager. Clear your clipboard afterward.
              </span>
            </div>

            {!phraseSaved.value ? (
              <GlassButton onClick$={() => { phraseSaved.value = true; error.value = ""; }}>
                I've written it down
              </GlassButton>
            ) : (
              <div>
                <p class="mb-3 text-sm text-gray-400">
                  Confirm by typing these words from what you wrote down:
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
            <h2 class="mb-2 text-2xl font-bold text-white">Restore Your Identity</h2>
            <p class="mb-4 text-sm text-gray-400">
              Enter the 24-word recovery phrase of an identity created in Vault.
              Your key is re-derived on this device and proven to Flowsta — no password needed.
            </p>

            <textarea
              class="mb-4 w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400 resize-none"
              rows={4}
              placeholder="word1 word2 word3 ... word24"
              value={mnemonic.value}
              onInput$={(e) => { mnemonic.value = (e.target as HTMLTextAreaElement).value; error.value = ""; }}
            />

            <div class="mb-4">
              <label class="mb-1 block text-xs font-medium text-gray-400">New vault password</label>
              <input
                type="password"
                class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                placeholder="At least 10 characters"
                value={restorePassword.value}
                onInput$={(e) => { restorePassword.value = (e.target as HTMLInputElement).value; error.value = ""; }}
              />
            </div>
            <div class="mb-4">
              <label class="mb-1 block text-xs font-medium text-gray-400">Confirm vault password</label>
              <input
                type="password"
                class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                placeholder="Repeat your password"
                value={restorePassword2.value}
                onInput$={(e) => { restorePassword2.value = (e.target as HTMLInputElement).value; error.value = ""; }}
              />
            </div>

            {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}

            <div class="flex justify-between">
              <GlassButton variant="secondary" onClick$={() => { mnemonic.value = ""; error.value = ""; step.value = "choose"; }}>
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
              Connect Your Account
            </h2>
            <p class="mb-6 text-sm text-gray-400">
              Sign in with your Flowsta account to set up your desktop vault.
              Your vault gives you offline access and self-custody of your identity.
            </p>

            <form preventdefault:submit onSubmit$={handleSignIn}>
              <div class="mb-4">
                <label class="mb-1 block text-xs font-medium text-gray-400">
                  Email or Username
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
                <input
                  type="password"
                  class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                  placeholder="Your Flowsta password"
                  value={loginPassword.value}
                  onInput$={(e) => {
                    loginPassword.value = (e.target as HTMLInputElement).value;
                    error.value = "";
                  }}
                />
              </div>

              <p class="mb-4 text-xs text-gray-500">
                This password will also unlock your desktop vault.
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
              Two-Factor Authentication
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
              Recovery Phrase Needed
            </h2>
            <p class="mb-4 text-sm text-gray-400">
              Your account doesn't have a recovery phrase yet. You need to create one on the web before setting up your desktop vault.
            </p>
            <p class="mb-6 text-sm text-gray-400">
              Your recovery phrase is what generates your cryptographic keys, connects your devices, and lets you recover your account if anything is ever lost.
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
                Set Up Recovery Phrase
              </GlassButton>
              <GlassButton
                variant="secondary"
                disabled={loading.value}
                onClick$={recheckPhrase}
              >
                {loading.value ? "Checking..." : "I've set it up — check again"}
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
              Verify Your Identity
            </h2>
            <p class="mb-4 text-sm text-gray-400">
              Enter your 24-word recovery phrase. This proves you own this account and generates your device's cryptographic keys.
            </p>
            <p class="mb-4 text-xs text-gray-500">
              Your phrase stays on this device and is never sent to Flowsta's servers.
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
            <h2 class="mb-2 text-2xl font-bold text-white">Upgrade Your Account</h2>
            <p class="mb-4 text-sm text-gray-400">
              Right now your keys and personal data live on Flowsta's servers.
              Upgrading moves them into this Vault — your identity and data
              belong to this device, and only you can unlock them.
            </p>
            <ul class="mb-6 list-disc space-y-1 pl-5 text-xs text-gray-400">
              <li>Your personal data moves into an encrypted vault on this device.</li>
              <li>You keep the same identity, username, and signatures.</li>
              <li>You'll sign in with Vault instead of a password.</li>
            </ul>

            {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}

            <div class="flex flex-col gap-3">
              <GlassButton
                disabled={loading.value}
                onClick$={() => {
                  error.value = "";
                  if (hasWebPhrase.value) {
                    mnemonic.value = "";
                    step.value = "migrate-phrase";
                  } else {
                    startMigrationCeremony();
                  }
                }}
              >
                {loading.value ? "Preparing..." : "Upgrade to this device"}
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
              Upgrading takes a few minutes. Everything about your account
              works the same afterward — only the way you sign in changes.
            </p>
          </div>
        )}

        {/* ── Upgrade: enter the existing recovery phrase ── */}
        {step.value === "migrate-phrase" && (
          <div class="rounded-lg border border-gray-700 bg-gray-800 p-8">
            <h2 class="mb-2 text-2xl font-bold text-white">Enter Your Recovery Phrase</h2>
            <p class="mb-4 text-sm text-gray-400">
              Your 24-word recovery phrase becomes the seed of your device
              identity. It stays on this device and is verified against your
              account before anything changes.
            </p>
            <p class="mb-4 text-xs text-gray-500">
              Started an upgrade before that didn't finish? The phrase it
              showed you is the one on file — if you didn't save it, use
              "I lost my recovery phrase" below to get a new one.
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
              I lost my recovery phrase — create a new one
            </button>

            {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}

            <div class="flex justify-between">
              <GlassButton
                variant="secondary"
                onClick$={() => { mnemonic.value = ""; error.value = ""; step.value = "upgrade-offer"; }}
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
            <h2 class="mb-2 text-2xl font-bold text-white">Save Your Recovery Phrase</h2>
            <p class="mb-4 text-sm text-gray-400">
              These 24 words are now your identity. Write them down and store
              them somewhere safe — on paper, not on this computer.
            </p>
            <div class="mb-4 rounded-md border border-amber-500/40 bg-amber-500/10 p-3">
              <p class="text-xs text-amber-300">
                After the upgrade this phrase is the <strong>only</strong> way to
                recover your identity. Flowsta cannot recover it for you.
              </p>
            </div>

            <div class="mb-4 grid grid-cols-3 gap-2 rounded-md bg-gray-900 p-4">
              {newMnemonic.value.split(" ").map((word, i) => (
                <div key={i} class="flex items-baseline gap-1.5">
                  <span class="w-5 text-right font-mono text-[10px] text-gray-500">{i + 1}.</span>
                  <span class="font-mono text-sm text-white">{word}</span>
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
              <span class="text-[10px] text-gray-500">
                Paste into a password manager. Clear your clipboard afterward.
              </span>
            </div>

            {!phraseSaved.value ? (
              <GlassButton onClick$={() => { phraseSaved.value = true; error.value = ""; }}>
                I've written it down
              </GlassButton>
            ) : (
              <div>
                <p class="mb-3 text-sm text-gray-400">
                  Confirm by typing these words from what you wrote down:
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
            <h2 class="mb-2 text-2xl font-bold text-white">Ready to Upgrade</h2>
            <p class="mb-4 text-sm text-gray-400">
              Four steps, in order. Your account doesn't change until the
              last one succeeds:
            </p>
            <ol class="mb-4 list-decimal space-y-1 pl-5 text-xs text-gray-400">
              <li>Your account data downloads to this device and is decrypted here — nowhere else.</li>
              <li>It's re-encrypted so only your recovery phrase can unlock it.</li>
              <li>An encrypted backup of everything is saved on this device.</li>
              <li>Sign-in switches from your password to this Vault.</li>
            </ol>
            <div class="mb-4 rounded-md border border-amber-500/40 bg-amber-500/10 p-3">
              <p class="text-xs text-amber-300">
                Afterward your password stops signing you in anywhere — it
                becomes this Vault's unlock password. Every browser and
                device signs in through this Vault instead.
              </p>
            </div>
            <p class="mb-4 text-xs text-gray-500">
              If the upgrade is interrupted, nothing is lost — your account
              stays exactly as it is until the final step completes, and you
              can simply run it again.
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
                {loading.value ? "Upgrading..." : "Upgrade my account"}
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
              Your identity, your data, and your sign-in all moved here.
              Your old password now only unlocks this Vault — sign-ins
              everywhere else are approved from it.
            </p>
            <p class="mb-6 text-xs text-amber-300">
              Your recovery phrase is now the one key to your account. No one
              — including Flowsta — can recover it for you, so keep the
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
            <h2 class="mb-2 text-xl font-bold text-white">Setting Up Your Vault...</h2>
            <p class="text-sm text-gray-400">{progressMessage.value}</p>
            {migrating.value && (
              <p class="mt-4 text-xs text-gray-500">
                Your account doesn't change until the final step succeeds —
                if this is interrupted, you can safely run the upgrade again.
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
            <h2 class="mb-2 text-xl font-bold text-white">Your Vault is Ready</h2>
            <p class="mb-6 text-sm text-gray-400">
              Your identity is secured on this device. Your personal data is now
              in your Vault and you can now use Flowsta offline without needing
              the web.
            </p>

            <div class="mb-6 rounded-lg bg-gray-900 p-4 text-left">
              {/* Show the email used to sign in — prefer webUser.email if it looks like an email, otherwise use the sign-in input */}
              {(webUser.email.includes("@") ? webUser.email : email.value) && (
                <div class="mb-3">
                  <span class="text-xs font-medium text-gray-400">
                    Linked Account
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

            <GlassButton onClick$={props.onComplete$}>
              Open Dashboard
            </GlassButton>
          </div>
        )}
      </div>
    </div>
  );
});
