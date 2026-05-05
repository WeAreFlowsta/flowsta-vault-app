// localStorage cache for the recent-signatures list. Hydrating from cache
// lets returning users see their signatures instantly while a background
// fetch refreshes the list. The cache is cleared on Lock Vault to avoid
// leaking sig metadata across identities sharing a machine.

export const SIGNATURES_CACHE_KEY = "flowsta_vault_recent_signatures_v1";

export function persistSignaturesCache(sigs: unknown[]): void {
  try {
    localStorage.setItem(SIGNATURES_CACHE_KEY, JSON.stringify(sigs));
  } catch {
    // localStorage may be full or disabled — non-fatal
  }
}

export function hydrateSignaturesCache<T = unknown>(): T[] {
  try {
    const cached = localStorage.getItem(SIGNATURES_CACHE_KEY);
    if (!cached) return [];
    const parsed = JSON.parse(cached);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function clearSignaturesCache(): void {
  try {
    localStorage.removeItem(SIGNATURES_CACHE_KEY);
  } catch {
    // non-fatal
  }
}
