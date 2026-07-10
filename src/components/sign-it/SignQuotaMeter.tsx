/**
 * SignQuotaMeter - Vault edition.
 *
 * Mirrors the Website component but links out to the web dashboard for upgrades
 * (Vault is local-first; subscription management lives on flowsta.com).
 */
import { component$ } from "@builder.io/qwik";

export interface SignQuotaState {
  tier: string;
  used: number;
  limit: number;
  period_end: string | null;
  /** "online" = freshly fetched from API; "cache" = HMAC-signed local cache only (offline). */
  source: "online" | "cache";
}

interface Props {
  quota: SignQuotaState | null;
  loading?: boolean;
}

const tierLabel: Record<string, string> = {
  free: "Free",
  premium: "Premium",
  premium_plus: "Premium Plus",
};

const upgradeLabel: Record<string, string> = {
  free: "Upgrade to Premium for 100 signatures/month",
  premium: "Upgrade to Premium Plus for 1,000 signatures/month",
};

const WEB_DASHBOARD = "https://flowsta.com/dashboard/premium";

function formatResetsAt(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  return `${d.getDate()} ${d.toLocaleString("en-US", { month: "short" })}`;
}

export const SignQuotaMeter = component$<Props>(({ quota, loading }) => {
  if (loading) {
    return (
      <div class="bg-gray-900 rounded-lg p-4 border border-gray-700 animate-pulse">
        <div class="h-4 bg-gray-800 rounded w-1/3 mb-3"></div>
        <div class="h-2 bg-gray-800 rounded w-full"></div>
      </div>
    );
  }
  if (!quota) return null;

  const isUnlimited = !Number.isFinite(quota.limit);
  const pct = isUnlimited ? 0 : Math.min(100, (quota.used / quota.limit) * 100);
  const exhausted = !isUnlimited && quota.used >= quota.limit;
  const low = !isUnlimited && !exhausted && pct >= 75;
  const upgradeCta = upgradeLabel[quota.tier];

  const barColor = exhausted ? "bg-red-500" : low ? "bg-amber-500" : "bg-green-500";
  const containerColor = exhausted
    ? "bg-red-900/10 border-red-500/40"
    : low
    ? "bg-amber-900/10 border-amber-500/40"
    : "bg-gray-900 border-gray-700";

  return (
    <div class={`rounded-lg p-4 border ${containerColor}`}>
      <div class="flex items-center justify-between mb-2">
        <div>
          <p class="text-sm text-gray-400">
            Sign It quota - {tierLabel[quota.tier] || quota.tier}
            {quota.source === "cache" && (
              <span class="ml-2 text-xs text-gray-500">(offline cache)</span>
            )}
          </p>
          <p class="text-white font-semibold">
            {isUnlimited ? `${quota.used} signatures used` : `${quota.used} / ${quota.limit} signatures`}
          </p>
        </div>
        {quota.period_end && !isUnlimited && (
          <div class="text-right text-xs text-gray-400">
            Resets {formatResetsAt(quota.period_end)}
          </div>
        )}
      </div>

      {!isUnlimited && (
        <div class="w-full bg-gray-800 rounded-full h-2 mb-3 overflow-hidden">
          <div class={`h-full ${barColor} transition-all`} style={{ width: `${pct}%` }}></div>
        </div>
      )}

      {exhausted && (
        <div class="mt-2">
          <p class="text-red-300 text-sm font-medium">
            You've used all {quota.limit} signature{quota.limit === 1 ? "" : "s"} for this period.
          </p>
          {upgradeCta && (
            <a
              href={WEB_DASHBOARD}
              target="_blank"
              rel="noopener"
              class="inline-block mt-2 px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-md text-sm font-medium"
            >
              {upgradeCta} →
            </a>
          )}
        </div>
      )}

      {low && !exhausted && upgradeCta && (
        <p class="text-amber-300 text-xs mt-1">
          Running low?{" "}
          <a href={WEB_DASHBOARD} target="_blank" rel="noopener" class="underline hover:text-amber-200">
            {upgradeCta}
          </a>
        </p>
      )}
    </div>
  );
});
