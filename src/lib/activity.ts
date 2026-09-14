/**
 * The activity feed shown on the Overview (latest few) and the Activity
 * page (everything). Four sources merge into one list, newest first:
 *   - the Vault's own log (activity.json via `get_activity`): sign-ins,
 *     email grants, remembered sites, unlinks, email/password changes,
 *     identity setup;
 *   - signatures (the signing network, via the shared signatures store);
 *   - backups (per-app stats, latest per app);
 *   - linked apps (their link time).
 * The last three predate the log and keep their own records, so they are
 * derived here rather than logged twice.
 */

export interface ActivityLogEntry {
  at: number; // unix seconds
  kind: string;
  label: string;
  detail?: string | null;
  origin?: string | null;
  app_name?: string | null;
}

export interface BackupRecordSummary {
  counts_by_entry_type: Record<string, number>;
  total_records: number;
}

export interface BackupStatsLike {
  apps: { app_name: string; last_backup_at: number; latest_summary?: BackupRecordSummary | null }[];
}

export interface LinkedAppLike {
  app_name: string;
  linked_at: number;
}

export type FeedIcon = "signature" | "backup" | "link" | "signin" | "email" | "site" | "identity" | "password" | "device";

export interface FeedItem {
  key: string;
  icon: FeedIcon;
  /** Unix seconds. */
  timestamp: number;
  /** First line; `strong` is rendered bold inside it when present. */
  text: string;
  strong?: string | null;
  /** Second line, muted, before the time. */
  detail?: string | null;
}

/** "12 polls, 38 votes" or null if nothing to show. */
export function formatSummary(s: BackupRecordSummary | null | undefined): string | null {
  if (!s || s.total_records === 0) return null;
  const parts = Object.entries(s.counts_by_entry_type)
    .filter(([, n]) => n > 0)
    .map(([t, n]) => {
      const lower = t.toLowerCase();
      const plural = n === 1 ? lower : `${lower}s`;
      return `${n} ${plural}`;
    });
  return parts.length > 0 ? parts.join(", ") : null;
}

export function timeAgo(unixSecs: number): string {
  const now = Math.floor(Date.now() / 1000);
  const diff = now - unixSecs;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
  return new Date(unixSecs * 1000).toLocaleDateString();
}

/** "Today", "Yesterday", or a date - for the Activity page's day groups. */
export function dayLabel(unixSecs: number): string {
  const d = new Date(unixSecs * 1000);
  const today = new Date();
  const sameDay = (a: Date, b: Date) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  if (sameDay(d, today)) return "Today";
  const y = new Date(today);
  y.setDate(today.getDate() - 1);
  if (sameDay(d, y)) return "Yesterday";
  return d.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long", year: d.getFullYear() === today.getFullYear() ? undefined : "numeric" });
}

export function timeOfDay(unixSecs: number): string {
  return new Date(unixSecs * 1000).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
}

const KIND_ICON: Record<string, FeedIcon> = {
  sign_in: "signin",
  relay_approved: "device",
  email_shared: "email",
  email_unshared: "email",
  site_remembered: "site",
  site_forgotten: "site",
  app_unlinked: "link",
  email_changed: "identity",
  email_added: "identity",
  password_changed: "password",
  identity_created: "identity",
  identity_restored: "identity",
};

export function buildFeed(input: {
  log: ActivityLogEntry[];
  sigs: any[];
  sigsLoaded: boolean;
  stats: BackupStatsLike | null | undefined;
  linkedApps: LinkedAppLike[];
}): FeedItem[] {
  const items: FeedItem[] = [];
  input.log.forEach((e, i) => {
    if (!(e.at > 0)) return;
    // The label carries the app name for sign-ins ("Signed in to X"); bold it.
    const strong = e.app_name && e.label.endsWith(e.app_name) ? e.app_name : e.origin && e.label.endsWith(e.origin) ? e.origin : null;
    const text = strong ? e.label.slice(0, e.label.length - strong.length) : e.label;
    items.push({ key: `a${e.at}-${i}`, icon: KIND_ICON[e.kind] || "identity", timestamp: e.at, text, strong, detail: e.detail || null });
  });
  // Only surface sigs once the store has settled - otherwise the feed
  // would show the same partial count the Signatures tile hides behind
  // "Syncing from the network…".
  if (input.sigsLoaded) {
    input.sigs.forEach((sig: any, i: number) => {
      if (typeof sig.signed_at === "number" && sig.signed_at > 0) {
        const label =
          sig.fileName ||
          (typeof sig.file_hash === "string" && sig.file_hash.length >= 8 ? `${sig.file_hash.slice(0, 8)}…` : "a file");
        // `signed_at` is committed by the signing DNA in milliseconds; the
        // rest of the feed deals in seconds.
        items.push({ key: `s${i}`, icon: "signature", timestamp: Math.floor(sig.signed_at / 1000), text: "Signed ", strong: label });
      }
    });
  }
  for (const app of input.stats?.apps ?? []) {
    if (app.last_backup_at > 0) {
      const summary = formatSummary(app.latest_summary);
      items.push({ key: `b${app.app_name}`, icon: "backup", timestamp: app.last_backup_at, text: "", strong: app.app_name, detail: summary ? `backed up ${summary}` : "backed up data" });
    }
  }
  input.linkedApps.forEach((app, i) => {
    if (app.linked_at > 0) {
      items.push({ key: `l${i}`, icon: "link", timestamp: app.linked_at, text: "", strong: app.app_name, detail: "linked identity" });
    }
  });
  items.sort((a, b) => b.timestamp - a.timestamp);
  return items;
}
