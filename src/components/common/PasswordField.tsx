import { component$, useSignal, type PropFunction } from "@builder.io/qwik";

/**
 * A password input with a show/hide toggle. Every place the Vault asks for
 * a password uses it (setup, migration sign-in, unlock, change password) -
 * a user asked for the eye during migration, and typing a 16-character
 * passphrase blind is the same problem everywhere.
 */
export interface PasswordFieldProps {
  value: string;
  onInput$: PropFunction<(value: string) => void>;
  placeholder?: string;
  /** Extra classes on the wrapper (spacing). */
  class?: string;
  autoFocus?: boolean;
  disabled?: boolean;
  autocomplete?: "off" | "current-password" | "new-password";
  /** "amber" = the setup/settings recipe; "blue" = the dashboard-card recipe. */
  variant?: "amber" | "blue";
  id?: string;
}

const RECIPES = {
  amber:
    "w-full rounded-md border border-gray-600 bg-gray-900 py-3 pl-4 pr-11 text-sm text-white placeholder-gray-500 focus:border-amber-400 focus:outline-none focus:ring-1 focus:ring-amber-400",
  blue:
    "w-full rounded-md border border-white/10 bg-black/30 py-3 pl-4 pr-11 text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500",
};

export const PasswordField = component$<PasswordFieldProps>((props) => {
  const shown = useSignal(false);
  return (
    <div class={["relative", props.class ?? ""].join(" ")}>
      <input
        id={props.id}
        type={shown.value ? "text" : "password"}
        class={RECIPES[props.variant ?? "amber"]}
        placeholder={props.placeholder}
        value={props.value}
        autoFocus={props.autoFocus}
        disabled={props.disabled}
        autocomplete={props.autocomplete ?? "off"}
        onInput$={(e) => props.onInput$((e.target as HTMLInputElement).value)}
      />
      <button
        type="button"
        tabIndex={-1}
        aria-label={shown.value ? "Hide password" : "Show password"}
        aria-pressed={shown.value}
        class="absolute inset-y-0 right-0 flex w-11 items-center justify-center text-gray-500 hover:text-gray-300 focus:outline-none focus-visible:text-amber-300"
        onClick$={() => (shown.value = !shown.value)}
      >
        {shown.value ? (
          // eye-off
          <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2} aria-hidden="true">
            <path stroke-linecap="round" stroke-linejoin="round" d="M3 3l18 18M10.6 10.6a2 2 0 002.8 2.8M9.9 5.1A9.7 9.7 0 0112 5c5 0 8.6 3.6 9.7 7-.4 1.2-1.1 2.4-2 3.4M6.3 6.3C4.4 7.6 3 9.4 2.3 12c1.1 3.4 4.7 7 9.7 7 1.6 0 3.1-.4 4.4-1" />
          </svg>
        ) : (
          // eye
          <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width={2} aria-hidden="true">
            <path stroke-linecap="round" stroke-linejoin="round" d="M2.3 12C3.4 8.6 7 5 12 5s8.6 3.6 9.7 7c-1.1 3.4-4.7 7-9.7 7s-8.6-3.6-9.7-7z" />
            <circle cx="12" cy="12" r="3" />
          </svg>
        )}
      </button>
    </div>
  );
});
