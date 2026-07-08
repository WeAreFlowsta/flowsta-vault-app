import { component$, useSignal, useContext, $ } from "@builder.io/qwik";
import Callout from "~/components/dashboard/Callout";
import type { DocumentHead } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { GlassButton } from "~/components/common/GlassButton";
import { autoLockContext } from "~/lib/context";
import { clearSignaturesCache } from "~/lib/signatures-cache";

declare const __APP_VERSION__: string;

export default component$(() => {
  const autoLockMinutes = useContext(autoLockContext);

  const activeTab = useSignal<"general" | "about">("general");

  // Change password state
  const currentPassword = useSignal("");
  const newPassword = useSignal("");
  const confirmPassword = useSignal("");
  const changing = useSignal(false);
  const changeError = useSignal("");
  const changeSuccess = useSignal("");

  const showResetConfirm = useSignal(false);
  const resetting = useSignal(false);

  const passwordValid = newPassword.value.length >= 10;
  const passwordsMatch =
    newPassword.value.length > 0 &&
    newPassword.value === confirmPassword.value;
  const notSameAsOld =
    newPassword.value.length > 0 &&
    newPassword.value !== currentPassword.value;
  const canSubmit =
    !changing.value &&
    currentPassword.value.length > 0 &&
    passwordValid &&
    passwordsMatch &&
    notSameAsOld;

  const handleChangePassword = $(async () => {
    changeError.value = "";
    changeSuccess.value = "";
    changing.value = true;

    try {
      await invoke("change_vault_password", {
        currentPassword: currentPassword.value,
        newPassword: newPassword.value,
      });

      changeSuccess.value =
        "Password changed and your Vault reconnected with the new password.";
      currentPassword.value = "";
      newPassword.value = "";
      confirmPassword.value = "";
    } catch (e) {
      changeError.value = String(e);
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
            <p class="mb-4 text-sm text-gray-400">
              Your password protects this vault on this device. Changing it
              happens entirely locally — no server is involved — and your
              Vault briefly restarts its network connection to apply it.
            </p>

            <div class="max-w-md space-y-4">
              <div>
                <label class="mb-1 block text-sm font-medium text-gray-300">
                  Current password
                </label>
                <input
                  type="password"
                  class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                  placeholder="Your current password"
                  value={currentPassword.value}
                  onInput$={(e) => {
                    currentPassword.value = (e.target as HTMLInputElement).value;
                    changeError.value = "";
                  }}
                />
              </div>
              <div>
                <label class="mb-1 block text-sm font-medium text-gray-300">
                  New password
                </label>
                <input
                  type="password"
                  class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                  placeholder="At least 10 characters"
                  value={newPassword.value}
                  onInput$={(e) => {
                    newPassword.value = (e.target as HTMLInputElement).value;
                    changeError.value = "";
                  }}
                />
                {newPassword.value.length > 0 && !passwordValid && (
                  <p class="mt-1 text-xs text-gray-500">
                    Must be at least 10 characters.
                  </p>
                )}
                {newPassword.value.length > 0 && !notSameAsOld && (
                  <p class="mt-1 text-xs text-gray-500">
                    Must be different from your current password.
                  </p>
                )}
              </div>
              <div>
                <label class="mb-1 block text-sm font-medium text-gray-300">
                  Confirm new password
                </label>
                <input
                  type="password"
                  class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                  placeholder="Repeat your new password"
                  value={confirmPassword.value}
                  onInput$={(e) => {
                    confirmPassword.value = (e.target as HTMLInputElement).value;
                    changeError.value = "";
                  }}
                />
                {confirmPassword.value.length > 0 && !passwordsMatch && (
                  <p class="mt-1 text-xs text-gray-500">
                    Passwords don't match.
                  </p>
                )}
              </div>

              {changeError.value && (
                <Callout intent="danger">{changeError.value}</Callout>
              )}
              {changeSuccess.value && (
                <Callout intent="success">{changeSuccess.value}</Callout>
              )}

              <GlassButton
                variant="primary"
                disabled={!canSubmit}
                onClick$={handleChangePassword}
              >
                {changing.value ? "Changing..." : "Change Password"}
              </GlassButton>

              <p class="text-xs text-gray-500">
                Your recovery phrase is unaffected — it can always restore
                this identity, whatever the password.
              </p>
            </div>
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
