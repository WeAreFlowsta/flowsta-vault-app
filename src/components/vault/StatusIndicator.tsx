import { component$ } from "@builder.io/qwik";

export type ConnectionStatus = "online" | "dht-only" | "offline";

interface StatusIndicatorProps {
  status: ConnectionStatus;
}

const statusConfig: Record<
  ConnectionStatus,
  { color: string; label: string; pulse: boolean }
> = {
  online: { color: "bg-green-400", label: "Online", pulse: true },
  "dht-only": { color: "bg-amber-400", label: "DHT Only", pulse: false },
  offline: { color: "bg-red-400", label: "Offline", pulse: false },
};

export const StatusIndicator = component$<StatusIndicatorProps>((props) => {
  const config = statusConfig[props.status];

  return (
    <div class="flex items-center gap-2">
      <span class="relative flex h-2.5 w-2.5">
        {config.pulse && (
          <span
            class={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-75 ${config.color}`}
          />
        )}
        <span
          class={`relative inline-flex h-2.5 w-2.5 rounded-full ${config.color}`}
        />
      </span>
      <span class="text-xs text-gray-400">{config.label}</span>
    </div>
  );
});
