import { component$, useSignal, useContext, $ } from "@builder.io/qwik";
import Callout from "~/components/dashboard/Callout";
import type { DocumentHead } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { GlassButton } from "~/components/common/GlassButton";
import { connectionStatusContext, autoLockContext } from "~/lib/context";
import { clearSignaturesCache } from "~/lib/signatures-cache";

declare const __API_URL__: string;
declare const __APP_VERSION__: string;

const PASSWORD_RULES = [
  { test: (p: string) => p.length >= 8, label: "At least 8 characters" },
  { test: (p: string) => /[A-Z]/.test(p), label: "One uppercase letter" },
  { test: (p: string) => /[a-z]/.test(p), label: "One lowercase letter" },
  { test: (p: string) => /[0-9]/.test(p), label: "One number" },
  {
    test: (p: string) => /[!@#$%^&*()_+\-=\[\]{};\':"|,.<>\/?]/.test(p),
    label: "One special character",
  },
];


export default component$(() => {
  const connectionStatus = useContext(connectionStatusContext);
  const autoLockMinutes = useContext(autoLockContext);

  const activeTab = useSignal<"general" | "about">("general");

  // Change password state
  const currentPassword = useSignal("");
  const newPassword = useSignal("");
  const confirmPassword = useSignal("");
  const changing = useSignal(false);
  const changeError = useSignal("");
  const changeSuccess = useSignal("");
  const needsEmail = useSignal(false);
  const emailOverride = useSignal("");

  const showResetConfirm = useSignal(false);
  const resetting = useSignal(false);

  const isOnline = connectionStatus.value === "online";

  // Validate new password meets all rules
  const passwordValid =
    newPassword.value.length > 0 &&
    PASSWORD_RULES.every((r) => r.test(newPassword.value));
  const passwordsMatch =
    newPassword.value.length > 0 &&
    newPassword.value === confirmPassword.value;
  const notSameAsOld =
    newPassword.value.length > 0 &&
    newPassword.value !== currentPassword.value;
  const canSubmit =
    isOnline &&
    !changing.value &&
    currentPassword.value.length > 0 &&
    passwordValid &&
    passwordsMatch &&
    notSameAsOld &&
    (!needsEmail.value || emailOverride.value.length > 0);

  const handleChangePassword = $(async () => {
    changeError.value = "";
    changeSuccess.value = "";
    changing.value = true;

    try {
      const params: Record<string, string> = {
        apiUrl: __API_URL__,
        currentPassword: currentPassword.value,
        newPassword: newPassword.value,
      };
      if (needsEmail.value && emailOverride.value) {
        params.emailOrUsername = emailOverride.value;
      }

      const message = await invoke<string>("change_password", params);

      changeSuccess.value = message;
      currentPassword.value = "";
      newPassword.value = "";
      confirmPassword.value = "";
      needsEmail.value = false;
      emailOverride.value = "";
    } catch (e) {
      const err = String(e);
      if (err === "NEEDS_EMAIL") {
        needsEmail.value = true;
      } else {
        changeError.value = err;
      }
    } finally {
      changing.value = false;
    }
  });

  const handleResetVault = $(async () => {
    resetting.value = true;
    try {
      // Wipe the localStorage signatures cache before deleting the vault.
      // Reset Vault means "wipe everything" from the user's perspective —
      // and the next identity that unlocks must not see the previous
      // user's signatures (the per-agent cache key would catch this even
      // without the explicit clear, but reset is the right moment to be
      // belt-and-suspenders).
      clearSignaturesCache();
      await invoke("reset_vault");
      window.location.reload();
    } catch (e) {
      resetting.value = false;
      console.error("Failed to reset vault:", e);
    }
  });

  const TAB_LABELS: Record<string, string> = {
    general: "General",
    about: "About",
  };

  return (
    <div>
      <h1 class="mb-6 text-2xl font-bold text-white">Settings</h1>

      {/* Tabs */}
      <div class="mb-6 border-b border-gray-700">
        <div class="flex gap-6">
          {(["general", "about"] as const).map((tab) => (
            <button
              key={tab}
              type="button"
              class={[
                "pb-3 text-sm font-medium transition-colors border-b-2",
                activeTab.value === tab
                  ? "border-amber-400 text-amber-400"
                  : "border-transparent text-gray-400 hover:text-gray-300",
              ].join(" ")}
              onClick$={() => {
                activeTab.value = tab;
              }}
            >
              {TAB_LABELS[tab]}
            </button>
          ))}
        </div>
      </div>

      {/* General tab */}
      {activeTab.value === "general" && (
        <div class="space-y-6">
          {/* Change password */}
          <div class="rounded-lg border border-gray-700 bg-[#15203a] p-6">
            <h3 class="mb-2 text-lg font-semibold text-white">
              Change Password
            </h3>
            {/* Deliberately disabled: a password change re-encrypts the
                vault file but cannot yet rotate the local keystore
                passphrase, which would leave the network layer unable to
                start on the next launch. Re-enable together with keystore
                rotation. */}
            <p class="mb-4 text-sm text-gray-400">
              Your unlock password was set when this vault was created.
              Password changes are coming in a vault update — they need the
              local keystore to be re-encrypted in the same step, and doing
              it halfway would break your Vault's network connection.
            </p>
            <Callout intent="info">
              <p>
                Need a different password now? Back up your recovery phrase,
                then use Reset Vault below and restore from the phrase —
                you'll choose a new password during restore. Your identity,
                signatures, and data are preserved.
              </p>
            </Callout>
          </div>

          {/* Auto-lock */}
          <div class="rounded-lg border border-gray-700 bg-[#15203a] p-6">
            <h3 class="mb-2 text-lg font-semibold text-white">Auto-Lock</h3>
            <p class="mb-4 text-sm text-gray-400">
              Automatically lock the vault after a period of inactivity.
            </p>

            <select
              value={String(autoLockMinutes.value)}
              onChange$={async (e) => {
                const val = Number((e.target as HTMLSelectElement).value);
                autoLockMinutes.value = val;
                try {
                  await invoke("set_auto_lock_minutes", { minutes: val });
                } catch (err) {
                  console.error("Failed to save auto-lock setting:", err);
                }
              }}
              style={{ colorScheme: "dark" }}
              class="rounded-md border border-gray-600 bg-gray-800 px-4 py-2.5 text-sm text-gray-200 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
            >
              <option value="5" selected={autoLockMinutes.value === 5}>5 minutes</option>
              <option value="15" selected={autoLockMinutes.value === 15}>15 minutes</option>
              <option value="30" selected={autoLockMinutes.value === 30}>30 minutes</option>
              <option value="60" selected={autoLockMinutes.value === 60}>1 hour</option>
              <option value="0" selected={autoLockMinutes.value === 0}>Never</option>
            </select>
          </div>

          {/* Reset Vault */}
          <div class="rounded-lg border border-red-900/50 bg-red-950/20 p-6">
            <h3 class="mb-2 text-lg font-semibold text-white">Reset Vault</h3>
            <p class="mb-4 text-sm text-gray-400">
              Erases everything stored on this device — your identity keys,
              conductor data, and every connected app's links and saved
              backups. Your identity and signatures come back when you set up
              again with your recovery phrase. Your Flowsta account is not
              affected.
            </p>

            {!showResetConfirm.value ? (
              <GlassButton
                variant="danger"
                onClick$={() => {
                  showResetConfirm.value = true;
                }}
              >
                Reset Vault
              </GlassButton>
            ) : (
              <div>
                <p class="mb-3 text-sm font-medium text-red-400">
                  This permanently erases this device — including connected apps
                  and their backups — and cannot be undone. Only your recovery
                  phrase can restore your identity.
                </p>
                <div class="flex gap-3">
                  <GlassButton
                    variant="danger"
                    disabled={resetting.value}
                    onClick$={handleResetVault}
                  >
                    {resetting.value ? "Erasing..." : "Yes, erase everything"}
                  </GlassButton>
                  <GlassButton
                    variant="secondary"
                    onClick$={() => {
                      showResetConfirm.value = false;
                    }}
                  >
                    Cancel
                  </GlassButton>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* About tab */}
      {activeTab.value === "about" && (
        <div class="rounded-lg border border-gray-700 bg-[#15203a] p-6">
          <h3 class="mb-4 text-lg font-semibold text-white">
            About Flowsta Vault
          </h3>

          <div class="space-y-3 text-sm">
            <div class="flex justify-between">
              <span class="text-gray-400">Version</span>
              <span class="text-white">{__APP_VERSION__}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-gray-400">Framework</span>
              <span class="text-white">Tauri v2</span>
            </div>
            <div class="flex justify-between">
              <span class="text-gray-400">Network</span>
              <span class="text-white">Holochain 0.6.0</span>
            </div>
            <div class="flex justify-between">
              <span class="text-gray-400">Encryption</span>
              <span class="text-white">AES-256-GCM + Argon2id</span>
            </div>
          </div>

          <div class="mt-6 space-y-3 rounded-lg border border-sky-800/50 bg-sky-900/10 p-5">
            <h4 class="text-sm font-semibold text-sky-300">
              How your identity stays safe
            </h4>
            <p class="text-sm leading-relaxed text-gray-300">
              Your <span class="text-white font-medium">recovery phrase</span> is
              like a master key that can create other keys. During setup, your
              Vault used it to generate a unique{" "}
              <span class="text-white font-medium">device key</span> — a
              cryptographic identity that only your device holds.
            </p>
            <p class="text-sm leading-relaxed text-gray-300">
              Once that device key was created, your recovery phrase was
              discarded from memory. It is never saved to disk. Only the device
              key remains, locked behind your password using strong encryption.
            </p>
            <p class="text-sm leading-relaxed text-gray-300">
              This means even if someone accessed your computer, they would
              need your password to unlock the key — and they would never find
              your recovery phrase, because it simply isn't here.
            </p>
          </div>
        </div>
      )}
    </div>
  );
});

export const head: DocumentHead = {
  title: "Settings - Flowsta Vault",
};
