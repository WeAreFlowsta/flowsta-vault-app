/**
 * Display-side de-duplication of linked third-party apps.
 *
 * A Holochain app (e.g. ProofPoll) generates a fresh conductor agent key on
 * every install/reinstall, and each one links to the Vault - so the raw list
 * from `get_linked_third_party_apps` can hold many entries for ONE app (same
 * `client_id`, different `app_agent_pub_key`). The Connected Apps overview
 * should show the app once, not once per device/reinstall.
 *
 * This is display-only: the underlying storage keeps every per-agent entry,
 * because origin → client_id → scope mapping and per-agent revocation depend
 * on it. We only collapse for what the user sees.
 */
export interface RawLinkedApp {
  app_name: string;
  app_agent_pub_key: string;
  linked_at: number;
  client_id?: string | null;
}

export interface DedupedLinkedApp {
  app_name: string;
  client_id: string | null;
  /** Most recent link time across all of this app's agents. */
  linked_at: number;
  /** Every agent key linked for this app - used to revoke them all at once. */
  agent_keys: string[];
}

/**
 * Group linked apps by `client_id` (the stable per-app id from dev.flowsta.com),
 * falling back to `app_name` for legacy entries with no client_id. Newest first.
 */
export function dedupeLinkedApps(apps: RawLinkedApp[]): DedupedLinkedApp[] {
  const groups = new Map<string, DedupedLinkedApp>();
  for (const a of apps) {
    const key = a.client_id ?? `name:${a.app_name}`;
    const existing = groups.get(key);
    if (existing) {
      existing.agent_keys.push(a.app_agent_pub_key);
      if (a.linked_at > existing.linked_at) existing.linked_at = a.linked_at;
    } else {
      groups.set(key, {
        app_name: a.app_name,
        client_id: a.client_id ?? null,
        linked_at: a.linked_at,
        agent_keys: [a.app_agent_pub_key],
      });
    }
  }
  return [...groups.values()].sort((a, b) => b.linked_at - a.linked_at);
}
