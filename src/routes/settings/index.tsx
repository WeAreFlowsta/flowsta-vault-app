import { component$, useSignal, useContext, useVisibleTask$, $ } from "@builder.io/qwik";
import Callout from "~/components/dashboard/Callout";
import type { DocumentHead } from "@builder.io/qwik-city";
import { invoke } from "@tauri-apps/api/core";
import { GlassButton } from "~/components/common/GlassButton";
import { autoLockContext } from "~/lib/context";
import { clearSignaturesCache } from "~/lib/signatures-cache";
import { PasswordStrength } from "~/components/vault/PasswordStrength";
import { checkVaultPassword } from "~/lib/password-strength";
import { normalizeEmail, isValidEmail, emailsMatch, EMAIL_INVALID, EMAIL_MISMATCH } from "~/lib/email";

declare const __API_URL__: string;

interface EmailChangeState {
  status: "pending" | "applied" | "current" | "expired" | "cancelled";
  email: string | null;
  expires_at: string | null;
}

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

  // Change email (device-hosted identities only - the Vault IS the account).
  const identityHosting = useSignal<string | null>(null);
  const currentEmail = useSignal("");
  const pendingEmail = useSignal<string | null>(null);
  const newEmail = useSignal("");
  const newEmail2 = useSignal("");
  const emailBusy = useSignal(false);
  const emailError = useSignal("");
  const emailNotice = useSignal("");
  const loadEmailState = $(async () => {
    try {
      const id = await invoke<{ hosting_model: string | null; web_email: string | null; pending_email: string | null }>("get_identity");
      identityHosting.value = id.hosting_model;
      currentEmail.value = id.web_email ?? "";
      pendingEmail.value = id.pending_email;
    } catch (err) {
      console.error("Failed to read identity:", err);
    }
  });
  const checkEmailChange = $(async (quiet: boolean) => {
    try {
      const r = await invoke<EmailChangeState>("check_email_change", { apiUrl: __API_URL__ });
      if (r.status === "applied") {
        emailNotice.value = `Done - your account email is now ${r.email}. Apps you've shared your email with get the new address the next time they ask.`;
        emailError.value = "";
      } else if (r.status === "expired" && pendingEmail.value) {
        emailError.value = "The verification link expired. Start the change again.";
      } else if (r.status === "cancelled" && pendingEmail.value) {
        emailNotice.value = "The email change was cancelled.";
      } else if (r.status === "pending" && !quiet) {
        emailNotice.value = "Not confirmed yet - click the link in the email we sent to the new address.";
      }
      await loadEmailState();
    } catch (err) {
      if (!quiet) emailError.value = String(err);
    }
  });
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async ({ cleanup }) => {
    await loadEmailState();
    if (identityHosting.value !== "device-hosted") return;
    // One check on open (catches a link clicked while the Vault was closed
    // or a change made from the web), then a slow poll while one is pending.
    await checkEmailChange(true);
    const timer = setInterval(() => {
      if (pendingEmail.value) checkEmailChange(true);
    }, 30_000);
    cleanup(() => clearInterval(timer));
  });
  const emailValid = isValidEmail(newEmail.value);
  const emailsAgree = newEmail2.value.length > 0 && emailsMatch(newEmail.value, newEmail2.value);
  const emailDiffers = normalizeEmail(newEmail.value) !== normalizeEmail(currentEmail.value);
  const canRequestEmail = !emailBusy.value && emailValid && emailsAgree && emailDiffers;
  const handleRequestEmailChange = $(async () => {
    emailError.value = "";
    emailNotice.value = "";
    if (!isValidEmail(newEmail.value)) { emailError.value = EMAIL_INVALID; return; }
    if (!emailsMatch(newEmail.value, newEmail2.value)) { emailError.value = EMAIL_MISMATCH; return; }
    emailBusy.value = true;
    try {
      const r = await invoke<EmailChangeState>("request_email_change", { apiUrl: __API_URL__, newEmail: normalizeEmail(newEmail.value) });
      emailNotice.value = `We've emailed ${r.email ?? "the new address"}. Click the link there to confirm - your Vault notices on its own within a minute while it's open, or the next time you unlock it.`;
      newEmail.value = "";
      newEmail2.value = "";
      await loadEmailState();
    } catch (err) {
      emailError.value = String(err);
    } finally {
      emailBusy.value = false;
    }
  });
  const handleCancelEmailChange = $(async () => {
    emailBusy.value = true;
    emailError.value = "";
    try {
      await invoke("cancel_email_change", { apiUrl: __API_URL__ });
      emailNotice.value = "The email change was cancelled.";
      await loadEmailState();
    } catch (err) {
      emailError.value = String(err);
    } finally {
      emailBusy.value = false;
    }
  });

  // Start-at-login (default on for new installs). Optimistic default while
  // the real state loads.
  const autostartEnabled = useSignal(true);
  const autostartBusy = useSignal(false);
  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async () => {
    try {
      autostartEnabled.value = await invoke<boolean>("get_autostart_enabled");
    } catch (err) {
      console.error("Failed to read autostart state:", err);
    }
  });
  const toggleAutostart = $(async () => {
    autostartBusy.value = true;
    const next = !autostartEnabled.value;
    try {
      await invoke("set_autostart_enabled", { enabled: next });
      autostartEnabled.value = next;
    } catch (err) {
      console.error("Failed to change autostart:", err);
    } finally {
      autostartBusy.value = false;
    }
  });

  const passwordValid = checkVaultPassword(newPassword.value).valid;
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
      // Reset Vault means "wipe everything" from the user's perspective -
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
              happens entirely locally - no server is involved - and your
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
                  class="mb-2 w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                  placeholder="At least 10 characters"
                  value={newPassword.value}
                  onInput$={(e) => {
                    newPassword.value = (e.target as HTMLInputElement).value;
                    changeError.value = "";
                  }}
                />
                <PasswordStrength password={newPassword.value} />
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
                Your recovery phrase is unaffected - it can always restore
                this identity, whatever the password.
              </p>
            </div>
          </div>

          {/* Change email - device-hosted identities only */}
          {identityHosting.value === "device-hosted" && (
            <div class="rounded-lg border border-gray-700 bg-[#15203a] p-6">
              <h3 class="mb-2 text-lg font-semibold text-white">Change Email</h3>
              <p class="mb-4 text-sm text-gray-400">
                Flowsta keeps only a fingerprint of your email; this Vault holds
                the address itself. Changing it asks Flowsta to send a link to
                the new address - the change takes effect when you click it,
                and apps you've shared your email with get the new address the
                next time they ask.
              </p>

              <div class="max-w-md space-y-4">
                {currentEmail.value && (
                  <p class="text-sm text-gray-300">
                    Current email: <span class="font-medium text-white">{currentEmail.value}</span>
                  </p>
                )}

                {pendingEmail.value ? (
                  <div class="space-y-3">
                    <Callout intent="info">
                      Waiting for you to confirm <span class="font-medium">{pendingEmail.value}</span> -
                      click the link in the email we sent there. Links last 72 hours.
                    </Callout>
                    <div class="flex flex-wrap gap-2">
                      <GlassButton variant="secondary" disabled={emailBusy.value} onClick$={() => checkEmailChange(false)}>
                        Check now
                      </GlassButton>
                      <GlassButton variant="secondary" disabled={emailBusy.value} onClick$={handleCancelEmailChange}>
                        Cancel change
                      </GlassButton>
                    </div>
                  </div>
                ) : (
                  <>
                    <div>
                      <label class="mb-1 block text-sm font-medium text-gray-300">New email</label>
                      <input
                        type="email"
                        autocomplete="email"
                        class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                        placeholder="you@example.com"
                        value={newEmail.value}
                        onInput$={(e) => { newEmail.value = (e.target as HTMLInputElement).value; emailError.value = ""; }}
                      />
                      {newEmail.value.length > 0 && !emailDiffers && (
                        <p class="mt-1 text-xs text-gray-500">That is already the email on this account.</p>
                      )}
                    </div>
                    <div>
                      <label class="mb-1 block text-sm font-medium text-gray-300">Confirm new email</label>
                      <input
                        type="email"
                        autocomplete="off"
                        class="w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                        placeholder="Repeat your new email"
                        value={newEmail2.value}
                        onInput$={(e) => { newEmail2.value = (e.target as HTMLInputElement).value; emailError.value = ""; }}
                        onPaste$={(e) => e.preventDefault()}
                      />
                      {newEmail2.value.length > 0 && !emailsAgree && (
                        <p class="mt-1 text-xs text-gray-500">Email addresses don't match.</p>
                      )}
                    </div>
                    <GlassButton variant="primary" disabled={!canRequestEmail} onClick$={handleRequestEmailChange}>
                      {emailBusy.value ? "Sending..." : "Send Confirmation Link"}
                    </GlassButton>
                  </>
                )}

                {emailError.value && <Callout intent="danger">{emailError.value}</Callout>}
                {emailNotice.value && <Callout intent="success">{emailNotice.value}</Callout>}

                <p class="text-xs text-gray-500">
                  Your username, recovery phrase and everything in this Vault stay
                  the same - only the address Flowsta can reach you at changes.
                </p>
              </div>
            </div>
          )}

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

          {/* Start at login */}
          <div class="rounded-lg border border-gray-700 bg-[#15203a] p-6">
            <div class="flex items-start justify-between gap-4">
              <div>
                <h3 class="mb-2 text-lg font-semibold text-white">Start at Login</h3>
                <p class="text-sm text-gray-400">
                  Open Flowsta Vault automatically when you sign in to this
                  computer, so it's ready the moment a Flowsta app or website
                  needs it. It starts in the background, locked - nothing
                  unlocks until you enter your password.
                </p>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={autostartEnabled.value}
                disabled={autostartBusy.value}
                onClick$={toggleAutostart}
                class={{
                  "relative mt-1 inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full p-0 transition-colors": true,
                  "bg-amber-500": autostartEnabled.value,
                  "bg-gray-600": !autostartEnabled.value,
                  "opacity-60": autostartBusy.value,
                }}
              >
                <span
                  class={{
                    "inline-block h-4 w-4 transform rounded-full bg-white transition-transform": true,
                    "translate-x-6": autostartEnabled.value,
                    "translate-x-1": !autostartEnabled.value,
                  }}
                />
              </button>
            </div>
          </div>

          {/* Reset Vault */}
          <div class="rounded-lg border border-red-900/50 bg-red-950/20 p-6">
            <h3 class="mb-2 text-lg font-semibold text-white">Reset Vault</h3>
            <p class="mb-3 text-sm text-gray-400">
              Erases everything stored on this device - your identity keys,
              conductor data, your private data, and every connected app's
              links and saved backups. Your Flowsta account is not affected.
            </p>
            <p class="mb-4 text-sm text-gray-400">
              Two things bring your account back afterward:
              <span class="text-gray-200"> your recovery phrase</span> restores
              your identity and signatures, and
              <span class="text-gray-200"> a data export</span> restores your
              private data and your apps' backups. Before you reset, make sure
              you have your recovery phrase, and export your data from
              <a href="/your-data/" class="text-amber-400 hover:text-amber-300"> Your Data → Export All Data</a>
              (save the file somewhere outside this app). Without both, your
              private data and app backups can't be recovered.
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
                  This permanently erases this device - your private data,
                  connected apps, and their backups - and cannot be undone.
                  Your recovery phrase restores your identity and signatures;
                  your private data and app backups come back only from a data
                  export. Make sure you have both before you continue.
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
              <span class="text-white">Holochain 0.6.1</span>
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
              the root of your identity. During setup, your Vault used it to
              derive your{" "}
              <span class="text-white font-medium">device key</span> - the
              cryptographic identity that signs as you - along with the keys
              that encrypt your data. The same phrase always re-creates the
              same identity, which is how it can restore you on another device.
            </p>
            <p class="text-sm leading-relaxed text-gray-300">
              The phrase itself is never saved - not to disk, and not kept
              after setup. Only the keys it derived stay on this device, locked
              behind your password with strong encryption.
            </p>
            <p class="text-sm leading-relaxed text-gray-300">
              So even if someone reached this computer, they would still need
              your password to unlock anything - and they would never find your
              recovery phrase, because it isn't here. That is also why the
              phrase is yours to keep safe: it is the only way to recover your
              identity, and no one, including Flowsta, can bring it back for
              you.
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
