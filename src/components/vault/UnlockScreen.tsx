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
import Callout from "~/components/dashboard/Callout";

/** One identity this Vault holds (see src-tauri/src/identities.rs). */
interface IdentityEntry {
  key: string;
  root: string;
  active: boolean;
  label: {
    agent_pub_key: string;
    display_name: string | null;
    username: string | null;
    profile_picture: string | null;
    email: string | null;
  } | null;
  display_email: string | null;
}

function identityTitle(e: IdentityEntry): string {
  return (
    e.label?.display_name ||
    (e.label?.username ? `@${e.label.username}` : null) ||
    e.label?.email ||
    e.display_email ||
    (e.key === "legacy" ? "Identity on this device" : `Identity …${e.key.slice(-6)}`)
  );
}

function identitySubtitle(e: IdentityEntry): string {
  const parts: string[] = [];
  if (e.label?.display_name && e.label?.username) parts.push(`@${e.label.username}`);
  const email = e.label?.email || e.display_email;
  if (email && email !== identityTitle(e)) parts.push(email);
  return parts.join(" · ");
}

interface UnlockScreenProps {
  onUnlock$: QRL<(password: string) => void>;
  onResetVault$: QRL<() => void>;
  /** Restore another identity from its recovery phrase, beside this one. */
  onAddIdentity$?: QRL<() => void>;
  /** Something is waiting on the unlock (a page's sign-in, a relay code). */
  notice?: { title: string; body: string } | null;
  initialError?: string;
}

export const UnlockScreen = component$<UnlockScreenProps>((props) => {
  const password = useSignal("");
  const error = useSignal(props.initialError ?? "");
  const loading = useSignal(false);
  const displayEmail = useSignal("");
  // The identities this Vault holds; a picker shows when there are two or
  // more. Choosing one repoints the locked Vault, the password then unlocks
  // that one.
  const identities = useSignal<IdentityEntry[]>([]);
  const switching = useSignal(false);

  const loadDisplayInfo = $(async () => {
    try {
      const info = await invoke<{ display_email: string | null }>(
        "get_vault_display_info"
      );
      displayEmail.value = info.display_email || "";
    } catch {
      displayEmail.value = "";
    }
  });

  // eslint-disable-next-line qwik/no-use-visible-task
  useVisibleTask$(async () => {
    await loadDisplayInfo();
    try {
      identities.value = await invoke<IdentityEntry[]>("list_identities");
    } catch {
      identities.value = [];
    }
  });

  const chooseIdentity = $(async (key: string) => {
    if (switching.value || loading.value) return;
    const current = identities.value.find((e) => e.active);
    if (current?.key === key) return;
    switching.value = true;
    error.value = "";
    try {
      await invoke("select_identity", { key });
      identities.value = identities.value.map((e) => ({ ...e, active: e.key === key }));
      password.value = "";
      await loadDisplayInfo();
    } catch (e) {
      error.value = String(e);
    } finally {
      switching.value = false;
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

        {props.notice && (
          <Callout intent="warning" title={props.notice.title} class="mb-4">
            {props.notice.body}
          </Callout>
        )}

        {identities.value.length > 1 && (
          <div class="mb-4 rounded-lg border border-gray-700 bg-gray-800 p-3">
            <p class="mb-2 px-1 text-xs font-medium uppercase tracking-wide text-gray-500">
              Identities in your Vault
            </p>
            <div class="flex flex-col gap-1">
              {identities.value.map((e) => (
                <button
                  key={e.key}
                  type="button"
                  disabled={switching.value || loading.value}
                  onClick$={() => chooseIdentity(e.key)}
                  class={[
                    "flex w-full items-center gap-3 rounded-md px-3 py-2 text-left transition-colors",
                    e.active
                      ? "bg-sky-500/15 ring-1 ring-sky-500/60"
                      : "hover:bg-gray-700/60",
                  ].join(" ")}
                >
                  {e.label?.profile_picture ? (
                    <img
                      src={e.label.profile_picture}
                      alt=""
                      width={32}
                      height={32}
                      class="h-8 w-8 shrink-0 rounded-full object-cover"
                    />
                  ) : (
                    <span class="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gray-700 text-sm font-semibold text-gray-200">
                      {identityTitle(e).replace(/^@/, "").charAt(0).toUpperCase()}
                    </span>
                  )}
                  <span class="min-w-0 flex-1">
                    <span class="block truncate text-sm text-white">{identityTitle(e)}</span>
                    {identitySubtitle(e) && (
                      <span class="block truncate text-xs text-gray-400">{identitySubtitle(e)}</span>
                    )}
                  </span>
                  {e.active && (
                    <span class="text-xs text-sky-300">Unlocking</span>
                  )}
                </button>
              ))}
            </div>
          </div>
        )}

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

          <div class="mt-4 flex flex-col items-center gap-2 text-center">
            <button
              type="button"
              class="text-xs text-gray-500 hover:text-gray-400 transition-colors"
              onClick$={props.onResetVault$}
            >
              Forgot password? Re-enter recovery phrase
            </button>
            {props.onAddIdentity$ && (
              <button
                type="button"
                class="text-xs text-gray-500 hover:text-gray-400 transition-colors"
                onClick$={props.onAddIdentity$}
              >
                Add another identity from its recovery phrase
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
});
