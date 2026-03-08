import { component$, useSignal } from "@builder.io/qwik";
import { CopyButton } from "~/components/ui/CopyButton";

interface IdentityCardProps {
  agentPubKey: string;
  did: string;
}

export const IdentityCard = component$<IdentityCardProps>((props) => {
  const showFull = useSignal(false);

  const truncate = (value: string, len = 40) =>
    value.length > len ? value.slice(0, len) + "..." : value;

  return (
    <div class="rounded-lg border border-gray-700 bg-gray-900 p-6">
      <div class="mb-4 flex items-center justify-between">
        <h3 class="text-lg font-semibold text-white">Your Identity</h3>
        <button
          type="button"
          class="text-xs text-gray-400 hover:text-gray-300 transition-colors"
          onClick$={() => {
            showFull.value = !showFull.value;
          }}
        >
          {showFull.value ? "Hide full" : "Show full"}
        </button>
      </div>

      {/* DID */}
      <div class="mb-4">
        <label class="mb-1 block text-xs font-medium text-gray-400">DID</label>
        <div class="flex items-center gap-2">
          <code class="flex-1 rounded bg-gray-900 px-3 py-2 text-sm text-blue-400 font-mono break-all">
            {showFull.value ? props.did : truncate(props.did)}
          </code>
          <CopyButton text={props.did} label="Copy DID" />
        </div>
      </div>

      {/* Agent Public Key */}
      <div>
        <label class="mb-1 block text-xs font-medium text-gray-400">
          Agent Public Key
        </label>
        <div class="flex items-center gap-2">
          <code class="flex-1 rounded bg-gray-900 px-3 py-2 text-sm text-gray-300 font-mono break-all">
            {showFull.value
              ? props.agentPubKey
              : truncate(props.agentPubKey, 30)}
          </code>
          <CopyButton text={props.agentPubKey} label="Copy Key" />
        </div>
      </div>
    </div>
  );
});
