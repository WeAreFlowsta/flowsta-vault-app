import { component$, Slot } from "@builder.io/qwik";

interface StatCardProps {
  label: string;
  value: string;
  subtitle?: string;
}

export const StatCard = component$<StatCardProps>((props) => {
  return (
    <div class="rounded-lg border border-gray-700 bg-gray-900 p-6">
      <div class="mb-2 flex items-center gap-2 text-gray-400">
        <Slot name="icon" />
        <span class="text-sm font-medium">{props.label}</span>
      </div>
      <div class="text-3xl font-bold text-white">{props.value}</div>
      {props.subtitle && (
        <div class="mt-1 text-sm text-gray-400">{props.subtitle}</div>
      )}
    </div>
  );
});
