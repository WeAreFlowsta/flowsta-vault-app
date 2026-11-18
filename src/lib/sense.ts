// What a person would call "that does not make sense": two things on the
// screen that cannot both be true, or a sentence no person would write.
// It reads only what is SHOWN (the words on the Overview card, the rows of
// Settings > Devices, the sidebar's device count), so the same checks run
// over every combination the rules can produce (sense.test.ts) and over the
// real window in the UI suite (e2e/specs/_helpers.ts), where the card and
// the rows are drawn from separate reads and can disagree.
//
// Each check came from something a person saw. Add to it the same way.

export interface ShownBar {
  label: string;
  done: number;
  of: number;
}

export interface ShownCard {
  title: string;
  line: string;
  bars: ShownBar[];
  /** "Continue without it" is offered. */
  canContinue: boolean;
  /** "Lost that device? Remove it..." is shown. */
  lostHint: boolean;
}

export interface ShownRow {
  name: string;
  presence: string;
  sync: string | null;
}

export interface Shown {
  /** The Overview's setup card; null when none is up; undefined when this screen does not show the Overview. */
  card?: ShownCard | null;
  /** The identity's OTHER devices as listed; undefined when this screen does not list them. */
  rows?: ShownRow[];
  /** The sidebar's count ("3 devices"). */
  chipLabel?: string;
}

const isOnline = (r: ShownRow) => /^Online\b/.test(r.presence);
const isGone = (r: ShownRow) => /^Remov/.test(r.presence);
const names = (rows: ShownRow[]) => rows.map((r) => r.name).join(", ");

/** Sentences no person would write, in any text on the screen. */
const ODD_TEXT: [RegExp, string][] = [
  [/\b1 (records|devices|days|backups|copies)\b/, "a plural after 1"],
  [/\b0 of 0\b/, '"0 of 0"'],
  [/(^|[^\w.])-\d/, "a negative number"],
  [/\bof 0\b/, '"of 0"'],
  [/Invalid Date|\bnull\b|\bundefined\b|\bNaN\b/, "a programming leftover"],
  [/ {2,}/, "a doubled space"],
  [/\b(on|from|and|,)\s*$/, "a sentence that ends where a name should be"],
  [/\b(\d[\d,.]*) of \1\b.*\b(on its way|Receiving)\b|\b(on its way|Receiving)\b.*\b(\d[\d,.]*) of \4\b/, "all of it counted, and still said to be arriving"],
];

export function senseProblems(s: Shown): string[] {
  const out: string[] = [];
  const rows = s.rows?.filter((r) => !isGone(r));
  const online = rows?.filter(isOnline) ?? [];
  const card = s.card;

  if (card && rows) {
    const notReached = /^Looking for your other devices|^Your things are on /.test(card.title);
    if (notReached && online.length > 0) {
      out.push(`the card says no device has been reached ("${card.title}") while ${names(online)} shows as online`);
    }
    if (/^Open Flowsta Vault/.test(card.line) && online.length > 0) {
      out.push(`the card tells the person to open Flowsta Vault on another device while ${names(online)} shows as online`);
    }
    if (card.lostHint && rows.length > 0 && online.length === rows.length) {
      out.push("the card asks whether a device is lost while every other device shows as online");
    }
    if (/is here$/.test(card.title)) {
      const more = online.filter((r) => /^This device is getting/.test(r.sync ?? ""));
      if (more.length > 0) out.push(`the card says the private data is here while ${names(more)} is shown as still sending records`);
    }
  }
  if (card && /on its way$/.test(card.title)) {
    const full = card.bars.length > 0 && card.bars.every((b) => b.of > 0 && b.done >= b.of);
    const nothingToCome = rows ? online.length > 0 && online.every((r) => r.sync === "In sync") : true;
    if (full && nothingToCome) out.push("the card says the private data is on its way while everything it counts has arrived");
  }
  if (card && card.canContinue && /is here$/.test(card.title)) {
    out.push('the card offers "Continue without it" while it says the private data is here');
  }

  for (const r of rows ?? []) {
    if (!isOnline(r) && /^(Receiving|Getting|This device is getting)\b/.test(r.sync ?? "")) {
      out.push(`${r.name} is shown as exchanging records now ("${r.sync}") while it is not online ("${r.presence}")`);
    }
    if (isOnline(r) && /^Heard |^Not heard/.test(r.sync ?? "")) {
      out.push(`${r.name} is shown as online and as not heard`);
    }
  }

  if (s.chipLabel && rows) {
    const said = /^(\d+) devices?$/.exec(s.chipLabel);
    if (said && Number(said[1]) !== rows.length + 1) {
      out.push(`the sidebar says "${s.chipLabel}" while the list shows ${rows.length + 1}`);
    }
  }

  const texts: string[] = [];
  // (A card whose bars are all full is checked above; one bar may be full while another fills.)
  if (card) texts.push(card.title, card.line, ...card.bars.map((b) => `${b.label} ${b.done} of ${b.of}`));
  for (const r of s.rows ?? []) texts.push(r.name ? `${r.name}: ${r.presence}` : "", r.sync ?? "");
  if (s.chipLabel) texts.push(s.chipLabel);
  for (const t of texts) {
    for (const [re, what] of ODD_TEXT) {
      if (re.test(t)) out.push(`${what}: "${t}"`);
    }
  }
  if ((s.rows ?? []).some((r) => !r.name.trim())) out.push("a device is listed without a name");
  return [...new Set(out)];
}
