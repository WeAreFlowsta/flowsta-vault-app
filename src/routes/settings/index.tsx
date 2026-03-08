import { component$, useSignal, useContext, $ } from "@builder.io/qwik";
import type { DocumentHead } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { GlassButton } from "~/components/common/GlassButton";
import { connectionStatusContext, autoLockContext } from "~/lib/context";

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
          <div class="rounded-lg border border-gray-700 bg-gray-900 p-6">
            <h3 class="mb-2 text-lg font-semibold text-white">
              Change Password
            </h3>
            <p class="mb-4 text-sm text-gray-400">
              Changes your Flowsta account password and re-encrypts the local
              vault. Requires an internet connection.
            </p>

            {!isOnline && (
              <div class="mb-4 rounded-lg border border-yellow-700/50 bg-yellow-900/20 p-3">
                <p class="text-sm text-yellow-400">
                  You must be online to change your password.
                </p>
              </div>
            )}

            <form
              preventdefault:submit
              onSubmit$={handleChangePassword}
              class="max-w-sm space-y-3"
            >
              {needsEmail.value && (
                <div>
                  <p class="mb-2 text-xs text-yellow-400">
                    Your vault needs a one-time update. Enter your Flowsta email
                    or username to continue.
                  </p>
                  <input
                    type="text"
                    placeholder="Email or username"
                    value={emailOverride.value}
                    disabled={changing.value}
                    onInput$={(e) => {
                      emailOverride.value = (
                        e.target as HTMLInputElement
                      ).value;
                      changeError.value = "";
                    }}
                    class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-2.5 text-sm text-white placeholder-gray-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 disabled:opacity-50"
                  />
                </div>
              )}
              <input
                type="password"
                placeholder="Current password"
                value={currentPassword.value}
                disabled={!isOnline || changing.value}
                onInput$={(e) => {
                  currentPassword.value = (e.target as HTMLInputElement).value;
                  changeError.value = "";
                  changeSuccess.value = "";
                }}
                class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-2.5 text-sm text-white placeholder-gray-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 disabled:opacity-50"
              />
              <input
                type="password"
                placeholder="New password"
                value={newPassword.value}
                disabled={!isOnline || changing.value}
                onInput$={(e) => {
                  newPassword.value = (e.target as HTMLInputElement).value;
                  changeError.value = "";
                  changeSuccess.value = "";
                }}
                class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-2.5 text-sm text-white placeholder-gray-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 disabled:opacity-50"
              />
              <input
                type="password"
                placeholder="Confirm new password"
                value={confirmPassword.value}
                disabled={!isOnline || changing.value}
                onInput$={(e) => {
                  confirmPassword.value = (e.target as HTMLInputElement).value;
                  changeError.value = "";
                  changeSuccess.value = "";
                }}
                class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-2.5 text-sm text-white placeholder-gray-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 disabled:opacity-50"
              />

              {/* Validation hints — only show once user starts typing new password */}
              {newPassword.value.length > 0 && (
                <div class="space-y-1 text-xs">
                  {PASSWORD_RULES.map((rule) => (
                    <div
                      key={rule.label}
                      class={
                        rule.test(newPassword.value)
                          ? "text-green-400"
                          : "text-gray-500"
                      }
                    >
                      {rule.test(newPassword.value) ? "\u2713" : "\u2022"}{" "}
                      {rule.label}
                    </div>
                  ))}
                  {!notSameAsOld && currentPassword.value.length > 0 && (
                    <div class="text-red-400">
                      New password must differ from current
                    </div>
                  )}
                  {confirmPassword.value.length > 0 && !passwordsMatch && (
                    <div class="text-red-400">Passwords don't match</div>
                  )}
                </div>
              )}

              {changeError.value && (
                <p class="text-sm text-red-400">{changeError.value}</p>
              )}
              {changeSuccess.value && (
                <p class="text-sm text-green-400">{changeSuccess.value}</p>
              )}

              <GlassButton type="submit" disabled={!canSubmit}>
                {changing.value ? "Changing..." : "Change Password"}
              </GlassButton>
            </form>
          </div>

          {/* Auto-lock */}
          <div class="rounded-lg border border-gray-700 bg-gray-900 p-6">
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
              class="rounded-md border border-gray-600 bg-gray-800 px-4 py-2.5 text-sm text-gray-200 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
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
              Remove all local keys and data. You'll need your recovery phrase
              to set up again. Your Flowsta account is not affected.
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
                  Are you sure? This cannot be undone.
                </p>
                <div class="flex gap-3">
                  <GlassButton
                    variant="danger"
                    disabled={resetting.value}
                    onClick$={handleResetVault}
                  >
                    {resetting.value ? "Resetting..." : "Yes, Reset Vault"}
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
        <div class="rounded-lg border border-gray-700 bg-gray-900 p-6">
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

          <div class="mt-6 rounded-lg bg-blue-900/20 border border-blue-800 p-4">
            <p class="text-sm text-blue-300">
              Flowsta Vault keeps your identity keys on your device. Your
              recovery phrase is never stored — only the encrypted derived key
              persists in the vault.
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
