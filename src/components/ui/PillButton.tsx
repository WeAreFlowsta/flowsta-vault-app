/**
 * PillButton — the compact companion to GlassButton, canonicalized from
 * the Sign It row actions (Edit thumbnail / Amend / Revoke). Use
 * GlassButton for full-size actions; PillButton for inline, row-level
 * ones. Same primary/secondary hierarchy as GlassButton: primary is the
 * white glass pill, secondary the gray pill whose hover accent signals
 * intent (amber = edit, sky = view/act, red = destructive, green = grant).
 */
import { component$, Slot, type QRL } from "@builder.io/qwik";

interface PillButtonProps {
  variant?: "primary" | "secondary" | "danger";
  /** Hover accent for secondary pills. */
  accent?: "amber" | "sky" | "red" | "green" | "none";
  onClick$?: QRL<() => void>;
  class?: string;
  disabled?: boolean;
  title?: string;
  type?: "button" | "submit" | "reset";
}

const ACCENT_HOVER: Record<string, string> = {
  amber: "hover:border-amber-400 hover:text-amber-300",
  sky: "hover:border-sky-400 hover:text-sky-400",
  red: "hover:border-red-400 hover:text-red-400",
  green: "hover:border-green-400 hover:text-green-400",
  none: "hover:border-gray-400 hover:text-white",
};

export const PillButton = component$<PillButtonProps>(
  ({ variant = "secondary", accent = "none", onClick$, class: className = "", disabled = false, title, type = "button" }) => {
    const base =
      "inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-colors disabled:opacity-50 disabled:pointer-events-none";
    const look =
      variant === "primary"
        ? "border border-white/50 bg-white/85 text-gray-900 hover:border-amber-200/70 hover:bg-white/95"
        : variant === "danger"
          ? "border border-red-500/50 bg-red-500/10 text-red-400 hover:bg-red-500/20"
          : `border border-gray-600 bg-gray-700 text-gray-200 ${ACCENT_HOVER[accent]}`;
    return (
      <button
        type={type}
        title={title}
        disabled={disabled}
        class={`${base} ${look} ${className}`}
        onClick$={onClick$}
      >
        <Slot />
      </button>
    );
  },
);
