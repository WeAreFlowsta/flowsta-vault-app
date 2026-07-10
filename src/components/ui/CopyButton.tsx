import { component$, useSignal } from "@builder.io/qwik";

interface CopyButtonProps {
  text: string;
  label?: string;
  class?: string;
}

export const CopyButton = component$<CopyButtonProps>((props) => {
  const copied = useSignal(false);

  return (
    <button
      type="button"
      title={props.label ?? "Copy"}
      class={[
        // PillButton secondary look - kept in sync with ui/PillButton.tsx
        "inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium",
        "border border-gray-600 bg-gray-700 text-gray-200",
        "hover:border-gray-400 hover:text-white",
        "transition-colors duration-200",
        props.class,
      ]
        .filter(Boolean)
        .join(" ")}
      onClick$={async () => {
        await navigator.clipboard.writeText(props.text);
        copied.value = true;
        setTimeout(() => {
          copied.value = false;
        }, 2000);
      }}
    >
      {copied.value ? (
        <>
          <svg
            class="h-3.5 w-3.5 text-green-400"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            stroke-width={2}
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              d="M5 13l4 4L19 7"
            />
          </svg>
          <span>Copied!</span>
        </>
      ) : (
        <>
          <svg
            class="h-3.5 w-3.5"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            stroke-width={2}
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
            />
          </svg>
          <span>{props.label ?? "Copy"}</span>
        </>
      )}
    </button>
  );
});
