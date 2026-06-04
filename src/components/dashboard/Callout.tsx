/**
 * Callout — the one notice surface for the Sign It / dashboard forms.
 *
 * Ported from the Website dashboard. Design rules:
 *   - Five intents, each ONE colour from the scheme (info + premium reuse the
 *     brand accents sky/indigo; success/warning/danger are the universals).
 *   - A vivid coloured LEFT ACCENT BAR is the thing the gray panels don't have,
 *     so a callout reads instantly as "notice" and pops off the panels.
 *   - Colour is carried by the bar + icon, NOT the body text (which stays a
 *     neutral gray for legibility). The optional CTA is an intent-matched
 *     GlassButton, so message-colour and button-colour always agree.
 *
 * Vault note: Vault's GlassButton has no `sky`/`indigo` variants, so the
 * info/premium intents map their button to `info`. These callouts carry no
 * action button today, so the variant only has to type-check.
 *
 *   <Callout intent="info" title="What 'Disconnect' Does"> …body… </Callout>
 */
import { component$, Slot, type QRL } from "@builder.io/qwik";
import { GlassButton } from "~/components/common/GlassButton";

export type CalloutIntent = "info" | "success" | "warning" | "danger" | "premium";

interface CalloutProps {
  intent: CalloutIntent;
  title?: string;
  /** Override the default per-intent icon with an outline-svg `d` path. */
  iconPath?: string;
  /** Top-of-page banner spacing (mb-6). Visual is otherwise identical. */
  banner?: boolean;
  /** Primary CTA — rendered as an intent-matched GlassButton. */
  actionLabel?: string;
  onAction$?: QRL<() => void>;
  /** Secondary "Later" / "Dismiss" text link. */
  dismissLabel?: string;
  /** Show a close (×) button top-right. Also fires onDismiss$. */
  dismissible?: boolean;
  onDismiss$?: QRL<() => void>;
  class?: string;
}

type BtnVariant = "info" | "success" | "warning" | "danger";

interface IntentCfg {
  /** bg tint + all-side border colour */
  wrap: string;
  /** left accent-bar colour */
  bar: string;
  /** icon colour */
  icon: string;
  /** matching GlassButton variant */
  btn: BtnVariant;
  /** default outline-svg `d` path */
  path: string;
}

// Full static class strings per intent — Tailwind only emits classes it can see
// literally, so these must NOT be built by interpolation.
const INTENT: Record<CalloutIntent, IntentCfg> = {
  info: {
    wrap: "bg-sky-500/10 border-sky-500/25",
    bar: "border-l-sky-400",
    icon: "text-sky-400",
    btn: "info",
    path: "M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z",
  },
  success: {
    wrap: "bg-emerald-500/10 border-emerald-500/25",
    bar: "border-l-emerald-400",
    icon: "text-emerald-400",
    btn: "success",
    path: "M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
  },
  warning: {
    wrap: "bg-amber-500/10 border-amber-500/25",
    bar: "border-l-amber-400",
    icon: "text-amber-400",
    btn: "warning",
    path: "M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z",
  },
  danger: {
    wrap: "bg-red-500/10 border-red-500/25",
    bar: "border-l-red-400",
    icon: "text-red-400",
    btn: "danger",
    path: "M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z",
  },
  premium: {
    wrap: "bg-indigo-500/10 border-indigo-500/25",
    bar: "border-l-indigo-400",
    icon: "text-indigo-400",
    btn: "info",
    path: "M11.48 3.499a.562.562 0 011.04 0l2.125 5.111a.563.563 0 00.475.345l5.518.442c.499.04.701.663.321.988l-4.204 3.602a.563.563 0 00-.182.557l1.285 5.385a.562.562 0 01-.84.61l-4.725-2.885a.563.563 0 00-.586 0L6.982 20.54a.562.562 0 01-.84-.61l1.285-5.386a.563.563 0 00-.182-.557l-4.204-3.602a.563.563 0 01.321-.988l5.518-.442a.563.563 0 00.475-.345L11.48 3.5z",
  },
};

export default component$<CalloutProps>((props) => {
  const {
    intent,
    title,
    iconPath,
    banner,
    actionLabel,
    onAction$,
    dismissLabel,
    dismissible,
    onDismiss$,
    class: className = "",
  } = props;
  const c = INTENT[intent];

  return (
    <div
      class={`rounded-lg border border-l-4 p-4 ${c.wrap} ${c.bar} ${banner ? "mb-6" : ""} ${className}`}
    >
      <div class="flex items-start gap-3">
        <svg
          class={`w-5 h-5 mt-0.5 shrink-0 ${c.icon}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d={iconPath || c.path}
          />
        </svg>

        <div class="min-w-0 flex-1">
          {title && <h3 class="font-semibold text-white">{title}</h3>}
          <div class={`text-sm text-gray-300 ${title ? "mt-1" : ""}`}>
            <Slot />
          </div>

          {(actionLabel || dismissLabel) && (
            <div class="mt-3 flex flex-wrap items-center gap-3">
              {actionLabel && (
                <GlassButton variant={c.btn} onClick$={onAction$} class="text-sm">
                  {actionLabel}
                </GlassButton>
              )}
              {dismissLabel && (
                <button
                  type="button"
                  onClick$={onDismiss$}
                  class="text-sm text-gray-400 hover:text-white transition-colors"
                >
                  {dismissLabel}
                </button>
              )}
            </div>
          )}
        </div>

        {dismissible && (
          <button
            type="button"
            onClick$={onDismiss$}
            aria-label="Dismiss"
            class="shrink-0 text-gray-400 hover:text-white transition-colors"
          >
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M6 18L18 6M6 6l12 12"
              />
            </svg>
          </button>
        )}
      </div>
    </div>
  );
});
