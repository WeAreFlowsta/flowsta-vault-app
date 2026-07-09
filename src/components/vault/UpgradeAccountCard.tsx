import { $, component$, useSignal, useStore, useVisibleTask$, type QRL } from "@builder.io/qwik";
import { invoke } from "@tauri-apps/api/core";
import { GlassButton } from "~/components/common/GlassButton";

declare const __API_URL__: string;

interface UpgradeAccountCardProps {
  /** Current vault hosting model (null/undefined = custodial-linked era). */
  hostingModel: string | null;
  /** Account email if known — prefills the password fallback. */
  webEmail: string | null;
  /** Called after a completed upgrade (the world changed — refetch). */
  onUpgraded$: QRL<() => void>;
}

type FlowStep = "card" | "phrase" | "password" | "twofa" | "confirm" | "progress" | "done";

/**
 * In-place account upgrade for a vault that predates device hosting, and
 * resume entry for an upgrade that was interrupted after the vault side
 * finished. Shows itself only when the account bound to this vault's
 * phrase is still web-hosted; runs the standard migration pipeline
 * against the already-unlocked vault (which keeps its own password).
 */
export const UpgradeAccountCard = component$<UpgradeAccountCardProps>((props) => {
  const visible = useSignal(false);
  const step = useSignal<FlowStep>("card");
  const error = useSignal("");
  const loading = useSignal(false);
  const progressMessage = useSignal("");

  const mnemonic = useSignal("");
  const email = useSignal(props.webEmail ?? "");
  const password = useSignal("");
  const twofaCode = useSignal("");
  const tempToken = useSignal("");

  // Set once a sign-in door succeeded.
  const session = useStore({ jwt: "", accountPassword: "", email: "" });
  const summary = useStore({ records: 0, email: "", did: "" });

  // Show the card only when there is genuinely an upgrade to run. The
  // probe resolves where the account bound to this vault's phrase lives:
  // "web" → upgrade needed (custodial-era vault, or an upgrade interrupted
  // before the flip); "device" → already upgraded (possibly from another
  // device — same phrase, same identity), nothing to do; "unknown" → only
  // a custodial-era vault still qualifies (its binding may predate the
  // lookup hash; the flow's password door covers it).
  useVisibleTask$(async () => {
    const isLegacy = props.hostingModel !== "device-hosted";
    try {
      const where = await invoke<string>("check_account_hosting", { apiUrl: __API_URL__ });
      visible.value = where === "web" || (where === "unknown" && isLegacy);
    } catch {
      // API unreachable — the upgrade needs it anyway; a custodial-era
      // vault keeps its card so the doorway stays discoverable.
      visible.value = isLegacy;
    }
  });

  const startPhraseDoor = $(async () => {
    error.value = "";
    const trimmed = mnemonic.value.trim().toLowerCase().replace(/\s+/g, " ");
    mnemonic.value = trimmed;
    if (!trimmed) return;
    loading.value = true;
    try {
      const matches = await invoke<boolean>("phrase_matches_vault", { mnemonic: trimmed });
      if (!matches) {
        error.value =
          "This isn't the recovery phrase this Vault was created from. The upgrade keeps your existing identity, so only that phrase works. If your account's phrase changed since, reset the Vault and start fresh from the new phrase instead.";
        return;
      }
      // Phrase-first sign-in: the phrase alone proves account ownership.
      const res = await invoke<{ token: string; email: string; password: string }>(
        "phrase_migration_login",
        { apiUrl: __API_URL__, phrase: trimmed }
      );
      session.jwt = res.token;
      session.accountPassword = res.password;
      session.email = res.email;
      step.value = "confirm";
    } catch (e) {
      const msg = String(e);
      if (msg.includes("no_account_for_phrase")) {
        error.value =
          "No account matched this phrase directly — sign in with your email and password instead.";
        step.value = "password";
      } else if (msg.includes("Invalid recovery phrase")) {
        error.value = "Invalid recovery phrase. Please check your words.";
      } else {
        // Accounts whose phrase was saved before phrase sign-in existed
        // land here — the password door covers them.
        error.value = "";
        step.value = "password";
      }
    } finally {
      loading.value = false;
    }
  });

  const passwordSignIn = $(async () => {
    error.value = "";
    loading.value = true;
    try {
      const auth = await invoke<{
        requires_2fa: boolean;
        temp_token: string | null;
        token: string | null;
        email: string | null;
      }>("authenticate_web_account", {
        apiUrl: __API_URL__,
        emailOrUsername: email.value,
        password: password.value,
      });
      if (auth.requires_2fa) {
        tempToken.value = auth.temp_token ?? "";
        step.value = "twofa";
        return;
      }
      session.jwt = auth.token ?? "";
      session.accountPassword = password.value;
      session.email = auth.email ?? email.value;
      step.value = "confirm";
    } catch (e) {
      error.value = String(e);
    } finally {
      loading.value = false;
    }
  });

  const twofaSignIn = $(async () => {
    error.value = "";
    loading.value = true;
    try {
      const auth = await invoke<{ token: string | null; email: string | null }>(
        "authenticate_2fa",
        { apiUrl: __API_URL__, tempToken: tempToken.value, code: twofaCode.value }
      );
      session.jwt = auth.token ?? "";
      session.accountPassword = password.value;
      session.email = auth.email ?? email.value;
      step.value = "confirm";
    } catch (e) {
      error.value = String(e);
    } finally {
      loading.value = false;
    }
  });

  const runUpgrade = $(async () => {
    error.value = "";
    loading.value = true;
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
      const result = await invoke<{
        records_migrated: number;
        email: string;
        did: string;
      }>("migrate_custodial_account", {
        apiUrl: __API_URL__,
        jwt: session.jwt,
        password: session.accountPassword,
        mnemonic: mnemonic.value,
        // Existing vault: the command uses the cached unlock passphrase.
        vaultPassword: null,
      });
      summary.records = result.records_migrated;
      summary.email = result.email;
      summary.did = result.did;
      mnemonic.value = "";
      password.value = "";
      session.accountPassword = "";
      step.value = "done";
    } catch (e) {
      const msg = String(e);
      if (msg.includes("vault_phrase_mismatch")) {
        error.value = "This isn't the recovery phrase this Vault was created from.";
        step.value = "phrase";
      } else {
        error.value = msg;
        step.value = "confirm";
      }
    } finally {
      unlisten();
      loading.value = false;
    }
  });

  if (!visible.value) return null;

  return (
    <div class="mb-6 rounded-lg border border-amber-500/30 bg-amber-500/10 p-6">
      {/* ── Entry card ── */}
      {step.value === "card" && (
        <>
          <h3 class="mb-1 text-lg font-semibold text-white">Upgrade your account to this Vault</h3>
          <p class="mb-4 text-sm text-gray-300">
            Your Flowsta account still lives on Flowsta's servers. Upgrading
            moves it into this Vault — your data on this device, sign-ins
            approved here, no password. Your identity, username, and
            signatures stay exactly as they are.
          </p>
          <GlassButton
            onClick$={() => {
              error.value = "";
              step.value = "phrase";
            }}
          >
            Upgrade to this device
          </GlassButton>
        </>
      )}

      {/* ── Phrase door ── */}
      {step.value === "phrase" && (
        <>
          <h3 class="mb-1 text-lg font-semibold text-white">Enter your recovery phrase</h3>
          <p class="mb-4 text-sm text-gray-300">
            The 24-word phrase this Vault was created from proves the account
            is yours and seeds its encryption. It never leaves this device.
          </p>
          <textarea
            class="mb-4 w-full resize-none rounded-md border border-white/10 bg-black/30 px-4 py-3 text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
            rows={3}
            placeholder="word1 word2 word3 ... word24"
            value={mnemonic.value}
            onInput$={(e) => {
              mnemonic.value = (e.target as HTMLTextAreaElement).value;
              error.value = "";
            }}
          />
          {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}
          <div class="flex justify-between">
            <GlassButton
              variant="secondary"
              onClick$={() => {
                error.value = "";
                step.value = "card";
              }}
            >
              Back
            </GlassButton>
            <GlassButton disabled={loading.value || !mnemonic.value.trim()} onClick$={startPhraseDoor}>
              {loading.value ? "Verifying..." : "Continue"}
            </GlassButton>
          </div>
        </>
      )}

      {/* ── Password fallback door ── */}
      {step.value === "password" && (
        <>
          <h3 class="mb-1 text-lg font-semibold text-white">Sign in to your account</h3>
          <p class="mb-4 text-sm text-gray-300">
            Sign in once with your Flowsta email and password to authorize the
            upgrade. Your phrase from the previous step still seeds the vault.
          </p>
          <input
            type="email"
            class="mb-3 w-full rounded-md border border-white/10 bg-black/30 px-4 py-3 text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="you@example.com"
            value={email.value}
            onInput$={(e) => {
              email.value = (e.target as HTMLInputElement).value;
              error.value = "";
            }}
          />
          <input
            type="password"
            class="mb-4 w-full rounded-md border border-white/10 bg-black/30 px-4 py-3 text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="Your Flowsta password"
            value={password.value}
            onInput$={(e) => {
              password.value = (e.target as HTMLInputElement).value;
              error.value = "";
            }}
          />
          {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}
          <div class="flex justify-between">
            <GlassButton
              variant="secondary"
              onClick$={() => {
                error.value = "";
                step.value = "phrase";
              }}
            >
              Back
            </GlassButton>
            <GlassButton
              disabled={loading.value || !email.value.trim() || !password.value}
              onClick$={passwordSignIn}
            >
              {loading.value ? "Signing in..." : "Sign in"}
            </GlassButton>
          </div>
        </>
      )}

      {/* ── 2FA ── */}
      {step.value === "twofa" && (
        <>
          <h3 class="mb-1 text-lg font-semibold text-white">Two-factor code</h3>
          <p class="mb-4 text-sm text-gray-300">Enter the 6-digit code from your authenticator app.</p>
          <input
            type="text"
            inputMode="numeric"
            maxLength={8}
            class="mb-4 w-full rounded-md border border-white/10 bg-black/30 px-4 py-3 text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="123456"
            value={twofaCode.value}
            onInput$={(e) => {
              twofaCode.value = (e.target as HTMLInputElement).value;
              error.value = "";
            }}
          />
          {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}
          <div class="flex justify-between">
            <GlassButton
              variant="secondary"
              onClick$={() => {
                error.value = "";
                step.value = "password";
              }}
            >
              Back
            </GlassButton>
            <GlassButton disabled={loading.value || !twofaCode.value.trim()} onClick$={twofaSignIn}>
              {loading.value ? "Verifying..." : "Continue"}
            </GlassButton>
          </div>
        </>
      )}

      {/* ── Consent ── */}
      {step.value === "confirm" && (
        <>
          <h3 class="mb-1 text-lg font-semibold text-white">Ready to upgrade</h3>
          <ul class="mb-4 list-disc space-y-1 pl-5 text-sm text-gray-300">
            <li>Your personal data moves into this Vault's encrypted private cell.</li>
            <li>Your identity, signatures, and username stay exactly as they are.</li>
            <li>Sign-in switches from your password to this Vault.</li>
            <li>Your recovery phrase becomes the one key to your account — keep it safe.</li>
          </ul>
          <p class="mb-4 text-xs text-gray-400">
            Nothing changes until the final step, and everything before it can
            be safely retried. Your Vault restarts once along the way.
          </p>
          {error.value && <p class="mb-4 text-sm text-red-400">{error.value}</p>}
          <div class="flex justify-between">
            <GlassButton
              variant="secondary"
              onClick$={() => {
                error.value = "";
                step.value = "phrase";
              }}
            >
              Back
            </GlassButton>
            <GlassButton disabled={loading.value} onClick$={runUpgrade}>
              {loading.value ? "Upgrading..." : "Upgrade my account"}
            </GlassButton>
          </div>
        </>
      )}

      {/* ── Progress ── */}
      {step.value === "progress" && (
        <div class="py-2 text-center">
          <div class="mx-auto mb-4 h-8 w-8 animate-spin rounded-full border-2 border-amber-400 border-t-transparent" />
          <p class="mb-2 text-sm text-white">{progressMessage.value}</p>
          <p class="text-xs text-gray-400">
            Nothing changes until the final step — if this is interrupted,
            open this card again and retry with the same phrase.
          </p>
        </div>
      )}

      {/* ── Done ── */}
      {step.value === "done" && (
        <div class="text-center">
          <h3 class="mb-2 text-lg font-semibold text-white">This Vault is your account now</h3>
          <p class="mb-1 text-sm text-gray-300">
            {summary.records} records moved{summary.email ? ` · ${summary.email}` : ""}. Sign-ins
            everywhere are approved from this Vault; your password no longer
            signs you in anywhere.
          </p>
          <p class="mb-4 text-xs text-amber-300">
            Your recovery phrase is now the one key to your account — no one,
            including Flowsta, can recover it for you.
          </p>
          <GlassButton onClick$={props.onUpgraded$}>Continue</GlassButton>
        </div>
      )}
    </div>
  );
});
