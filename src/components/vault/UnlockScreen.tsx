import {
  component$,
  useSignal,
  useVisibleTask$,
  $,
  type QRL,
} from "@builder.io/qwik";
import { invoke } from "@tauri-apps/api/core";
import { GlassButton } from "~/components/common/GlassButton";

declare const __API_URL__: string;

interface UnlockScreenProps {
  onUnlock$: QRL<(password: string) => void>;
  onResetVault$: QRL<() => void>;
  initialError?: string;
}

export const UnlockScreen = component$<UnlockScreenProps>((props) => {
  const password = useSignal("");
  const error = useSignal(props.initialError ?? "");
  const loading = useSignal(false);
  const displayEmail = useSignal("");

  // Password sync mode: user changed password on web, vault still has old
  const syncMode = useSignal(false);
  const oldPassword = useSignal("");
  const syncing = useSignal(false);

  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async () => {
    try {
      const info = await invoke<{ display_email: string | null }>(
        "get_vault_display_info"
      );
      if (info.display_email) {
        displayEmail.value = info.display_email;
      }
    } catch {
      // Non-critical
    }
  });

  const handleUnlock = $(async () => {
    error.value = "";
    loading.value = true;
    try {
      await props.onUnlock$(password.value);
    } catch (e) {
      // Unlock failed — check if the entered password works on the web
      // (meaning user changed password on web but vault has the old one)
      if (displayEmail.value) {
        try {
          const webOk = await invoke<boolean>("check_web_password", {
            apiUrl: __API_URL__,
            email: displayEmail.value,
            password: password.value,
          });
          if (webOk) {
            syncMode.value = true;
            loading.value = false;
            return;
          }
        } catch {
          // Offline or error — fall through to normal error
        }
      }
      error.value = String(e);
    } finally {
      loading.value = false;
    }
  });

  const handleSync = $(async () => {
    error.value = "";
    syncing.value = true;
    try {
      // Decrypt with old password
      await invoke("unlock_vault", { password: oldPassword.value });
      // Re-encrypt with new (web) password
      await invoke("re_encrypt_vault", { newPassword: password.value });
      // Now proceed with the normal unlock flow (fetches profile, etc.)
      await props.onUnlock$(password.value);
    } catch (e) {
      error.value = String(e);
    } finally {
      syncing.value = false;
    }
  });

  return (
    <div class="flex min-h-screen items-center justify-center bg-gray-900 p-8">
      <div class="w-full max-w-sm">
        <div class="mb-8 text-center">
          {/* Logo + VAULT badge */}
          <div class="mb-6 flex items-center justify-center">
            <img src="/logo-dark.svg" alt="Flowsta" class="h-10" />
            <div class="ml-2 rounded-md bg-white px-2 py-0.5 flex items-center justify-center">
              <span class="text-xs font-bold tracking-wider text-gray-900">
                VAULT
              </span>
            </div>
          </div>
          {displayEmail.value ? (
            <p class="mt-1 text-sm text-gray-400">
              Welcome back,{" "}
              <span class="text-gray-300">{displayEmail.value}</span>
            </p>
          ) : (
            <p class="mt-1 text-sm text-gray-400">
              Enter your Flowsta password to unlock
            </p>
          )}
        </div>

        <div class="rounded-lg border border-gray-700 bg-gray-800 p-6">
          {!syncMode.value ? (
            /* Normal unlock */
            <form preventdefault:submit onSubmit$={handleUnlock}>
              <input
                type="password"
                class="mb-4 w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                placeholder="Password"
                value={password.value}
                autoFocus
                disabled={loading.value}
                onInput$={(e) => {
                  password.value = (e.target as HTMLInputElement).value;
                  error.value = "";
                }}
              />

              {error.value && (
                <div class="mb-4">
                  <p class="text-sm text-red-400">{error.value}</p>
                </div>
              )}

              <GlassButton
                type="submit"
                class="w-full"
                disabled={loading.value || password.value.length === 0}
              >
                <span id="unlock-btn-text">
                  {loading.value ? "Unlocking..." : "Unlock"}
                </span>
              </GlassButton>
            </form>
          ) : (
            /* Sync mode: password was changed on web */
            <form preventdefault:submit onSubmit$={handleSync}>
              <div class="mb-4 rounded-lg border border-blue-800 bg-blue-900/20 p-3">
                <p class="text-sm text-sky-300">
                  Your password was changed on the web. Enter your previous
                  vault password to sync.
                </p>
              </div>

              <input
                type="password"
                class="mb-4 w-full rounded-md border border-gray-600 bg-gray-900 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400"
                placeholder="Previous vault password"
                value={oldPassword.value}
                autoFocus
                disabled={syncing.value}
                onInput$={(e) => {
                  oldPassword.value = (e.target as HTMLInputElement).value;
                  error.value = "";
                }}
              />

              {error.value && (
                <div class="mb-4">
                  <p class="text-sm text-red-400">{error.value}</p>
                </div>
              )}

              <GlassButton
                type="submit"
                class="w-full"
                disabled={syncing.value || oldPassword.value.length === 0}
              >
                {syncing.value ? "Syncing..." : "Sync & Unlock"}
              </GlassButton>

              <button
                type="button"
                class="mt-3 w-full text-xs text-gray-500 hover:text-gray-400 transition-colors"
                onClick$={() => {
                  syncMode.value = false;
                  password.value = "";
                  oldPassword.value = "";
                  error.value = "";
                }}
              >
                Back to normal unlock
              </button>
            </form>
          )}

          <div class="mt-4 text-center">
            <button
              type="button"
              class="text-xs text-gray-500 hover:text-gray-400 transition-colors"
              onClick$={props.onResetVault$}
            >
              Forgot password? Re-enter recovery phrase
            </button>
          </div>
        </div>
      </div>
    </div>
  );
});
