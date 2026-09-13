import {
  component$,
  useSignal,
  useVisibleTask$,
  $,
  type QRL,
} from "@builder.io/qwik";
import { invoke } from "@tauri-apps/api/core";
import { GlassButton } from "~/components/common/GlassButton";
import { PasswordField } from "~/components/common/PasswordField";

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
      error.value = String(e);
    } finally {
      loading.value = false;
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
          <form preventdefault:submit onSubmit$={handleUnlock}>
            <PasswordField
              class="mb-4"
              placeholder="Password"
              autocomplete="current-password"
              value={password.value}
              autoFocus
              disabled={loading.value}
              onInput$={(v) => {
                password.value = v;
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
