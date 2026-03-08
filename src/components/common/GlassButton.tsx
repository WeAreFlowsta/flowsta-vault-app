/**
 * Liquid Glass Button Component - iOS 26 Liquid Glass Effect
 *
 * Ported from Website/src/components/common/GlassButton.tsx
 * to maintain visual consistency across Flowsta apps.
 */

import { component$, Slot, type QRL } from "@builder.io/qwik";

interface GlassButtonProps {
  variant?:
    | "primary"
    | "secondary"
    | "success"
    | "danger"
    | "warning"
    | "info";
  onClick$?: QRL<() => void>;
  class?: string;
  disabled?: boolean;
  type?: "button" | "submit" | "reset";
}

export const GlassButton = component$<GlassButtonProps>(
  ({ variant = "primary", onClick$, class: className = "", disabled = false, type = "button" }) => {
    const baseClasses = `
      relative
      h-[36px] sm:h-[44px]
      px-4 sm:px-6
      rounded-full
      font-normal
      text-xs sm:text-sm
      transition-all
      duration-500
      ease-[cubic-bezier(0.34,1.56,0.64,1)]
      overflow-hidden
      group
      flex
      items-center
      justify-center
      ${className}
    `;

    const primaryClasses = `
      bg-white/85
      backdrop-blur-xl
      text-gray-900
      shadow-[0_8px_32px_rgba(255,255,255,0.25)]
      border border-white/50
      hover:shadow-[0_8px_32px_rgba(251,191,36,0.4),0_0_24px_rgba(251,191,36,0.3)]
      hover:border-amber-200/70
      hover:bg-white/95
      hover:scale-[1.03]
      active:scale-[0.97]
      active:shadow-[0_4px_16px_rgba(251,191,36,0.5)]
    `;

    const secondaryClasses = `
      bg-white/10
      backdrop-blur-xl
      text-white
      border-2 border-white/70
      shadow-[0_8px_32px_rgba(255,255,255,0.15),inset_0_1px_0_rgba(255,255,255,0.3)]
      hover:bg-white/20
      hover:border-amber-200/90
      hover:shadow-[0_8px_32px_rgba(251,191,36,0.4),0_0_24px_rgba(251,191,36,0.3),inset_0_1px_0_rgba(255,255,255,0.5)]
      hover:scale-[1.03]
      active:scale-[0.97]
      active:shadow-[0_4px_16px_rgba(251,191,36,0.5)]
    `;

    const successClasses = `
      bg-green-600/85
      backdrop-blur-xl
      text-white
      shadow-[0_8px_32px_rgba(34,197,94,0.25)]
      border border-green-500/50
      hover:shadow-[0_8px_32px_rgba(34,197,94,0.4),0_0_24px_rgba(34,197,94,0.3)]
      hover:border-green-400/70
      hover:bg-green-600/95
      hover:scale-[1.03]
      active:scale-[0.97]
      active:shadow-[0_4px_16px_rgba(34,197,94,0.5)]
    `;

    const dangerClasses = `
      bg-red-600/85
      backdrop-blur-xl
      text-white
      shadow-[0_8px_32px_rgba(239,68,68,0.25)]
      border border-red-500/50
      hover:shadow-[0_8px_32px_rgba(239,68,68,0.4),0_0_24px_rgba(239,68,68,0.3)]
      hover:border-red-400/70
      hover:bg-red-600/95
      hover:scale-[1.03]
      active:scale-[0.97]
      active:shadow-[0_4px_16px_rgba(239,68,68,0.5)]
    `;

    const warningClasses = `
      bg-yellow-600/85
      backdrop-blur-xl
      text-white
      shadow-[0_8px_32px_rgba(234,179,8,0.25)]
      border border-yellow-500/50
      hover:shadow-[0_8px_32px_rgba(234,179,8,0.4),0_0_24px_rgba(234,179,8,0.3)]
      hover:border-yellow-400/70
      hover:bg-yellow-600/95
      hover:scale-[1.03]
      active:scale-[0.97]
      active:shadow-[0_4px_16px_rgba(234,179,8,0.5)]
    `;

    const infoClasses = `
      bg-purple-600/85
      backdrop-blur-xl
      text-white
      shadow-[0_8px_32px_rgba(147,51,234,0.25)]
      border border-purple-500/50
      hover:shadow-[0_8px_32px_rgba(147,51,234,0.4),0_0_24px_rgba(147,51,234,0.3)]
      hover:border-purple-400/70
      hover:bg-purple-600/95
      hover:scale-[1.03]
      active:scale-[0.97]
      active:shadow-[0_4px_16px_rgba(147,51,234,0.5)]
    `;

    const disabledClasses = `
      opacity-50
      cursor-not-allowed
      pointer-events-none
    `;

    const getVariantClasses = () => {
      switch (variant) {
        case "primary":
          return primaryClasses;
        case "secondary":
          return secondaryClasses;
        case "success":
          return successClasses;
        case "danger":
          return dangerClasses;
        case "warning":
          return warningClasses;
        case "info":
          return infoClasses;
        default:
          return primaryClasses;
      }
    };

    const buttonClasses = `${baseClasses} ${getVariantClasses()} ${disabled ? disabledClasses : ""}`;

    return (
      <button
        onClick$={onClick$}
        type={type}
        class={buttonClasses}
        disabled={disabled}
      >
        {/* Layer 1: Bottom glass layer - refracts content behind */}
        <span
          class="absolute inset-0 rounded-full backdrop-blur-sm"
          style={{
            background:
              "linear-gradient(135deg, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0.05) 100%)",
          }}
        />

        {/* Layer 2: Gold liquid glow - appears on hover */}
        <span
          class="absolute inset-0 rounded-full opacity-0 group-hover:opacity-100 transition-all duration-700 ease-out group-hover:scale-110"
          style={{
            background:
              "radial-gradient(circle at 50% 50%, rgba(251, 191, 36, 0.25) 0%, rgba(251, 146, 60, 0.15) 40%, transparent 70%)",
            filter: "blur(12px)",
          }}
        />

        {/* Layer 3: Top glass reflection */}
        <span
          class="absolute top-0 left-0 right-0 h-1/2 rounded-t-full opacity-50 group-hover:opacity-70 transition-all duration-500"
          style={{
            background:
              "linear-gradient(to bottom, rgba(255, 255, 255, 0.4) 0%, rgba(255, 255, 255, 0.1) 50%, transparent 100%)",
          }}
        />

        {/* Layer 4: Shimmer reflection */}
        <span
          class="absolute inset-0 rounded-full opacity-0 group-hover:opacity-100 transition-all duration-700"
          style={{
            background:
              "linear-gradient(110deg, transparent 30%, rgba(255, 255, 255, 0.4) 50%, transparent 70%)",
            transform: "translateX(-100%)",
            animation: "shimmer 2s ease-in-out infinite",
          }}
        />

        {/* Layer 5: Inner highlight */}
        <span
          class="absolute inset-0 rounded-full pointer-events-none"
          style={{
            background:
              "linear-gradient(to bottom, rgba(255, 255, 255, 0.15), transparent 25%)",
          }}
        />

        {/* Button content */}
        <span
          class="relative z-20 flex items-center group-hover:scale-[0.9709] transition-transform duration-500 ease-[cubic-bezier(0.34,1.56,0.64,1)]"
          style={{
            filter: "none",
            backfaceVisibility: "hidden",
            WebkitFontSmoothing: "antialiased",
            transform: "translateZ(0)",
            textRendering: "optimizeLegibility",
            isolation: "isolate",
          }}
        >
          <Slot />
        </span>

        <style>{`
          @keyframes shimmer {
            0% { transform: translateX(-100%); }
            50% { transform: translateX(100%); }
            100% { transform: translateX(100%); }
          }
        `}</style>
      </button>
    );
  },
);
