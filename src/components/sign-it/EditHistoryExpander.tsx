import { component$, useSignal } from "@builder.io/qwik";

/**
 * Edit history expander for an amended signature chain.
 *
 * The API returns ALL signatures (including superseded versions) with a
 * `superseded_by` annotation. Surfaces display only the chain heads
 * (superseded_by === null) by default; this expander lets users walk
 * backward through the chain via the `supersedes` pointers on each
 * record. Renders nothing when the chain is a single version.
 *
 * Walks the chain client-side — no extra fetch. All the data is already
 * loaded; the older versions are just hidden by the default filter.
 *
 * The diff summary compares consecutive versions field-by-field and
 * lists only what changed, so users can see the meaningful difference
 * at a glance rather than re-reading the full metadata each time.
 */

interface Sig {
  action_hash?: string | null;
  signed_at?: number;
  intent?: string | null;
  ai_generation?: string | null;
  content_rights?: {
    license?: string;
    commercial_licensing?: string;
    ai_training?: string;
    contact_preference?: string;
  } | null;
  comment?: string | null;
  supersedes?: string | null;
  superseded_by?: string | null;
}

interface Props {
  current: Sig;
  allSigs: Sig[];
}

/** Walk from `head` back through `supersedes` pointers. Returns the
 * chain oldest-first (root → … → head). Defensive against cycles
 * (cap at 20 versions). */
function buildChain(head: Sig, all: Sig[]): Sig[] {
  const byHash = new Map<string, Sig>();
  for (const s of all) {
    if (s.action_hash) byHash.set(s.action_hash, s);
  }
  const chain: Sig[] = [head];
  let cursor = head;
  let guard = 20;
  while (cursor.supersedes && guard-- > 0) {
    const prev = byHash.get(cursor.supersedes);
    if (!prev) break;
    chain.unshift(prev);
    cursor = prev;
  }
  return chain;
}

function formatDateTime(ms: number | undefined): string {
  if (!ms) return "";
  return new Date(ms).toLocaleString("en-GB", {
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Compare two consecutive versions and return the changed-field
 * descriptions. Old→new for set→different; "added", "removed", or
 * "cleared" for transitions to/from null. */
function diffSummary(prev: Sig, next: Sig): string[] {
  const out: string[] = [];

  // Comment
  if (prev.comment !== next.comment) {
    if (!prev.comment && next.comment) out.push("Note added");
    else if (prev.comment && !next.comment) out.push("Note removed");
    else out.push("Note changed");
  }

  // License
  const pl = prev.content_rights?.license;
  const nl = next.content_rights?.license;
  if (pl !== nl) {
    if (!pl && nl) out.push(`License: ${nl}`);
    else if (pl && !nl) out.push(`License: ${pl} → not declared`);
    else out.push(`License: ${pl} → ${nl}`);
  }

  // AI generation
  if (prev.ai_generation !== next.ai_generation) {
    out.push(`AI generation: ${prev.ai_generation || "—"} → ${next.ai_generation || "—"}`);
  }

  // Commercial licensing
  const pc = prev.content_rights?.commercial_licensing;
  const nc = next.content_rights?.commercial_licensing;
  if (pc !== nc) {
    out.push(`Commercial: ${pc || "—"} → ${nc || "—"}`);
  }

  // AI training
  const pt = prev.content_rights?.ai_training;
  const nt = next.content_rights?.ai_training;
  if (pt !== nt) {
    out.push(`AI training: ${pt || "—"} → ${nt || "—"}`);
  }

  // Contact preference
  const pcp = prev.content_rights?.contact_preference;
  const ncp = next.content_rights?.contact_preference;
  if (pcp !== ncp) {
    out.push(`Contact: ${pcp || "—"} → ${ncp || "—"}`);
  }

  // Intent
  if (prev.intent !== next.intent) {
    out.push(`Intent: ${prev.intent || "—"} → ${next.intent || "—"}`);
  }

  return out;
}

export default component$<Props>(({ current, allSigs }) => {
  const expanded = useSignal(false);

  // Build the chain; bail out if there's only the current version (no
  // history to show).
  const chain = buildChain(current, allSigs);
  if (chain.length <= 1) return null;

  // Render history oldest-first below the link, with the current
  // version implicit (it's the card being displayed).
  // Diff is between each version and the one before it.
  const historicalVersions = chain.slice(0, -1); // exclude current

  return (
    <div class="mt-2 border-t border-slate-700/40 pt-2">
      <button
        type="button"
        class="text-[11px] text-slate-500 hover:text-slate-300 transition-colors inline-flex items-center gap-1"
        // Stop propagation: some surfaces (profile signature card) wrap
        // the whole row in an <a>; without this the click would navigate
        // instead of toggling.
        preventdefault:click
        onClick$={(e) => { e.stopPropagation(); expanded.value = !expanded.value; }}
      >
        <span class="inline-block transition-transform" style={{ transform: expanded.value ? "rotate(90deg)" : "rotate(0)" }}>▸</span>
        Edit history ({chain.length} versions)
      </button>
      {expanded.value && (
        <ol class="mt-2 space-y-2 pl-3 border-l border-slate-700/40">
          {historicalVersions.map((version, i) => {
            const next = chain[i + 1];
            const diffs = diffSummary(version, next);
            return (
              <li key={version.action_hash || i} class="text-[11px] text-slate-500">
                <div class="text-slate-400">
                  v{i + 1} · {formatDateTime(version.signed_at)}
                </div>
                {version.comment && (
                  <div class="mt-0.5 italic text-slate-500">{version.comment}</div>
                )}
                {diffs.length > 0 && (
                  <div class="mt-0.5">
                    <span class="text-slate-600">Changed in next version: </span>
                    {diffs.join(" · ")}
                  </div>
                )}
              </li>
            );
          })}
          <li class="text-[11px] text-slate-500">
            <div class="text-slate-400">
              v{chain.length} · {formatDateTime(current.signed_at)} <span class="text-slate-600">(current)</span>
            </div>
          </li>
        </ol>
      )}
    </div>
  );
});
