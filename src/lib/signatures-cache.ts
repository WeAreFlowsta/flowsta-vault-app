// localStorage cache for the recent-signatures list. Hydrating from cache
// lets returning users see their signatures instantly while a background
// fetch refreshes the list.
//
// Cache is keyed by the unlocked agent_pub_key (PREFIX + agent) so that
// identity transitions (Reset Vault then new identity, restore from a
// different recovery phrase, multiple users on one machine) never leak
// the previous user's signature metadata into the new user's UI. A
// missing or mismatched agent reads as a clean miss; the new agent's
// signatures populate from the conductor on first refresh.
//
// Lock Vault deliberately does NOT clear the cache - same-user re-unlock
// is the most common path and benefits from the instant load. Reset
// Vault DOES clear because the user expects "reset" to wipe state.

const PREFIX = "flowsta_vault_sigs_v2_";
const LEGACY_KEY = "flowsta_vault_recent_signatures_v1";

// Module-level current-identity tag. Set when the vault unlocks (or app
// starts already-unlocked); cleared on reset. persist/hydrate read this
// to scope cache reads/writes to the active identity without each call
// site needing to know about the agent_pub_key.
let activeAgent: string | null = null;

/**
 * Register the currently-unlocked identity. Subsequent persist/hydrate
 * calls scope to this agent until it changes or is cleared.
 *
 * Also opportunistically drops the legacy v1 cache key (which wasn't
 * keyed by agent and is no longer used) so machines that ever ran the
 * old build don't carry that artifact forever.
 */
export function setActiveSignatureAgent(agentKey: string): void {
  activeAgent = agentKey;
  try {
    localStorage.removeItem(LEGACY_KEY);
  } catch {
    // localStorage disabled - fine, nothing else to clean up
  }
}

export function persistSignaturesCache(sigs: unknown[]): void {
  if (!activeAgent) return; // no identity registered - don't cache
  try {
    localStorage.setItem(`${PREFIX}${activeAgent}`, JSON.stringify(sigs));
  } catch {
    // localStorage may be full or disabled - non-fatal
  }
}

export function hydrateSignaturesCache<T = unknown>(): T[] {
  if (!activeAgent) return [];
  try {
    const cached = localStorage.getItem(`${PREFIX}${activeAgent}`);
    if (!cached) return [];
    const parsed = JSON.parse(cached);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/**
 * Wipe every per-agent signature cache + the legacy v1 key + the active
 * agent registration. Use on Reset Vault, never on Lock Vault.
 */
export function clearSignaturesCache(): void {
  activeAgent = null;
  try {
    const toRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && (k.startsWith(PREFIX) || k === LEGACY_KEY)) {
        toRemove.push(k);
      }
    }
    for (const k of toRemove) {
      localStorage.removeItem(k);
    }
  } catch {
    // non-fatal
  }
}
