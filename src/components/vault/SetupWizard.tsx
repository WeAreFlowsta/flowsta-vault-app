import { component$, useSignal, useStore, $, type QRL } from "@builder.io/qwik";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-shell";
import { GlassButton } from "~/components/common/GlassButton";

interface SetupWizardProps {
  onComplete$: QRL<() => void>;
}

type Step = "signin" | "twofa" | "no-phrase" | "phrase" | "progress" | "done";

declare const __API_URL__: string;
declare const __WEB_URL__: string;
const WEB_PHRASE_URL = `${__WEB_URL__}/dashboard/settings/password/`;

function stepToCircle(s: Step): number {
  if (s === "signin" || s === "twofa") return 0;
  if (s === "no-phrase" || s === "phrase") return 1;
  return 2;
}

const circleLabels = ["Connect", "Verify Identity", "Ready"];

export const SetupWizard = component$<SetupWizardProps>((props) => {
  const step = useSignal<Step>("signin");
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

  // After successful sign-in, check if user has a recovery phrase
  const checkPhraseAndProceed = $(async (token: string) => {
    if (!token) {
      console.warn("No JWT token — skipping phrase status check");
      step.value = "phrase";
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

      if (!status.has_recovery_phrase) {
        step.value = "no-phrase";
      } else {
        step.value = "phrase";
      }
    } catch (e) {
      // If check fails (e.g. offline or bad token), proceed to phrase entry anyway
      console.error("Recovery phrase status check failed:", e);
      step.value = "phrase";
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
                  onClick$={() => open("https://flowsta.com")}
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
