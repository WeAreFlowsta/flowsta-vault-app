// What the Vault says about the identity's devices, as rules that can be
// tested. One principle: nothing is said that this device does not know.
//
//   - Whether the person HAS another device is theirs to say (asked once at a
//     phrase restore; adding by code answers it). No network read can tell
//     "it is off" from "there is none": the list of devices lives only on
//     the identity's own devices.
//   - "Online" and "heard N ago" come only from a message that device sent
//     this one directly, stamped by this device's clock. Never from the
//     time a device wrote its own record (its clock, and it may have closed
//     since).
//   - "In sync" comes only from what a device said it holds.
//   - No timer changes a state. Time may change a sentence.

/** The person's answer to "is this identity on another device you still have?". */
export type OtherDevice = "yes" | "no" | null;

/** Another of the identity's devices, as this device knows it right now. */
export interface KnownDevice {
  name: string;
  /** When it last sent this device a message (ms, this device's clock), or null: not since this Vault opened. */
  heardAt: number | null;
  /** When it last wrote its own record (ms, ITS clock). Shown as a date, never as presence. */
  recordAt: number;
  /** Records it said it holds, or null: it has not said. */
  holds: number | null;
  /** It is itself being set up. */
  settingUp: boolean;
  /** Which side runs the older Vault, when the two cannot sync as they are. */
  needsUpdate: "it" | "this" | null;
  /** The two are exchanging records on the older network meanwhile. */
  syncingOnOlder: boolean;
  removed: "removed" | "removing" | null;
  /** It heard from this device while locked and still syncing. */
  locked: boolean;
}

export const ONLINE_MS = 5 * 60 * 1000;
export const SLOW_SECS = 5 * 60;
export const LONG_QUIET_DAYS = 3;

export function isOnline(d: KnownDevice, now: number): boolean {
  return d.heardAt !== null && now - d.heardAt <= ONLINE_MS;
}

// ── When setup is done ──────────────────────────────────────────────────

export interface SetupFacts {
  answer: OtherDevice;
  /** The person pressed "Continue without it". */
  continued: boolean;
  /** A full round finished with nothing failing. */
  roundComplete: boolean;
  /** Records held here. */
  mine: number;
  /** Devices heard directly this session that are not themselves being set up, with what each said it holds (null: not said). */
  heardSettled: (number | null)[];
  /** Records are still arriving from a device that was heard. */
  stillArriving: boolean;
}

/** Setup is done for one of three reasons, and for no other. No time is an input. */
export function setupDone(f: SetupFacts): "said_only_device" | "has_what_heard_devices_hold" | "continued_without" | null {
  if (f.continued) return "continued_without";
  if (!f.roundComplete) return null;
  if (f.answer === "no") return "said_only_device";
  if (f.stillArriving) return null;
  const said = f.heardSettled.filter((h): h is number => h !== null);
  // Every device heard must have said what it holds, and hold no more than this one.
  if (said.length > 0 && said.length === f.heardSettled.length && said.every((h) => h <= f.mine)) return "has_what_heard_devices_hold";
  return null;
}

// ── The Overview card ───────────────────────────────────────────────────

export interface CardFacts {
  /** Added as a device, or restored from the phrase. */
  joined: boolean;
  /** Setup is not done yet. */
  settingUp: boolean;
  /** The setup state has been read at least once this session. */
  known: boolean;
  answer: OtherDevice;
  /** This device reaches the network: true, false, or null when not yet known. */
  online: boolean | null;
  others: KnownDevice[];
  /** Records are arriving from a heard device that holds more than this one. */
  arriving: boolean;
  /** Seconds since the count of records here last moved while a device was online; null when nothing is expected. */
  quietSecs: number | null;
  now: number;
}

export type Card =
  | { kind: "ask" }
  | { kind: "offline" }
  | { kind: "looking" }
  | { kind: "on_device"; names: string[] }
  | { kind: "progress" }
  | { kind: "slow" }
  | { kind: "back"; names: string[] }
  | null;

export function overviewCard(f: CardFacts): Card {
  if (!f.joined || !f.known) return null;
  const live = f.others.filter((d) => !d.removed);
  const online = live.filter((d) => isOnline(d, f.now));
  if (!f.settingUp) {
    // Done, by the person's word or because everything heard had arrived: a
    // device that turns up later holding more is said plainly.
    return f.arriving && online.length > 0 ? { kind: "back", names: online.map((d) => d.name) } : null;
  }
  if (f.answer === null) return { kind: "ask" };
  if (f.answer === "no") return null;
  if (f.online === false) return { kind: "offline" };
  if (online.length > 0) return (f.quietSecs ?? 0) >= SLOW_SECS ? { kind: "slow" } : { kind: "progress" };
  if (live.length > 0) return { kind: "on_device", names: live.map((d) => d.name) };
  return { kind: "looking" };
}

const listed = (names: string[]) => (names.length === 1 ? names[0] : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`);

/** The card's words. `canContinue`: the "Continue without it" link shows. */
export function cardWords(c: NonNullable<Card>): { title: string; line: string; canContinue: boolean } {
  switch (c.kind) {
    case "ask":
      return { title: "Do you have Flowsta Vault on another device with this identity?", line: "Not sure? Choose Yes. You can continue without it at any time.", canContinue: false };
    case "offline":
      return { title: "This device is offline", line: "Your things arrive when it is back online.", canContinue: false };
    case "looking":
      return { title: "Looking for your other devices", line: "Open Flowsta Vault on your other device and leave it running.", canContinue: true };
    case "on_device":
      return { title: `Your things are on ${listed(c.names)}`, line: "Open Flowsta Vault there and leave it running.", canContinue: true };
    case "progress":
      return { title: "Your private data is on its way", line: "", canContinue: false };
    case "slow":
      return { title: "Your private data is on its way", line: "Arriving slowly. Keep both devices on.", canContinue: true };
    case "back":
      return { title: `${listed(c.names)} is back`, line: "Your things are arriving.", canContinue: false };
  }
}

export const CONTINUE_HINT = "Lost that device? Remove it in Settings, Devices, so it can no longer sign in.";

/** The email is asked for only once setup is done and none arrived, or on a device that never joined. */
export function asksForEmail(f: { webEmail: string | null; joined: boolean; settingUp: boolean; known: boolean }): boolean {
  if (f.webEmail) return false;
  if (!f.joined) return true;
  return f.known && !f.settingUp;
}

// ── A row of Settings, Devices ──────────────────────────────────────────

const ago = (ms: number) => {
  const min = Math.max(1, Math.round(ms / 60000));
  return min < 60 ? `${min} min` : `${Math.round(min / 60)} h`;
};
const day = (ms: number) => new Date(ms).toLocaleDateString(undefined, { day: "numeric", month: "short" });

export type RowColor = "green" | "grey" | "amber";

/** What one row says of another device: where it is, then whether the two hold the same. */
export function deviceRow(d: KnownDevice, mine: number, now: number): { presence: string; sync: string | null; color: RowColor; offerRemove: boolean } {
  if (d.removed) return { presence: d.removed === "removing" ? "Removing…" : "Removed", sync: null, color: "grey", offerRemove: false };
  if (d.needsUpdate === "it") return { presence: "Needs the Vault update to sync", sync: d.syncingOnOlder ? "Syncing on the older network until then" : null, color: "amber", offerRemove: false };
  if (d.needsUpdate === "this") return { presence: "This device needs the Vault update to sync with it", sync: d.syncingOnOlder ? "Syncing on the older network until then" : null, color: "amber", offerRemove: false };

  let presence: string;
  let color: RowColor = "grey";
  let offerRemove = false;
  if (isOnline(d, now)) {
    presence = d.locked ? "Online (locked)" : "Online";
    color = "green";
  } else if (d.heardAt !== null) {
    presence = `Heard ${ago(now - d.heardAt)} ago`;
  } else {
    const days = Math.floor((now - d.recordAt) / 86_400_000);
    if (days >= LONG_QUIET_DAYS) {
      presence = `Not heard for ${days} days. No longer have it? Remove it.`;
      color = "amber";
      offerRemove = true;
    } else {
      presence = `Not heard since this Vault opened. Its record is from ${day(d.recordAt)}.`;
    }
  }

  let sync: string | null = null;
  if (d.settingUp) {
    sync = d.holds === null ? "Receiving your private data" : `Receiving your private data, ${Math.min(d.holds, mine)} of ${mine}`;
    color = "amber";
  } else if (d.holds !== null) {
    if (d.holds === mine) sync = "In sync";
    else if (d.holds < mine) sync = `Getting ${mine - d.holds} records from this device`;
    else sync = `This device is getting ${d.holds - mine} records from it`;
  }
  return { presence, sync, color, offerRemove };
}

/** This device's own row. */
export function ownRow(settingUp: boolean): string {
  return settingUp ? "This device, receiving your private data" : "This device";
}

// ── The sidebar chip ────────────────────────────────────────────────────

export function chip(f: { joined: boolean; answer: OtherDevice; listRead: boolean; settingUp: boolean; others: KnownDevice[]; mine: number; now: number }): { label: string; color: RowColor; title: string } {
  const live = f.others.filter((d) => !d.removed);
  if (live.length === 0) {
    // Only this device is listed. That is a fact only when the list has
    // been read and either this device never joined or the person said so.
    const certain = f.listRead && (!f.joined || f.answer === "no" || !f.settingUp);
    return certain
      ? { label: "1 device", color: "grey", title: "Only on this device" }
      : { label: "Checking devices", color: "grey", title: "Looking for your other devices" };
  }
  const rows = live.map((d) => ({ d, r: deviceRow(d, f.mine, f.now) }));
  const amber = f.settingUp || rows.some(({ r }) => r.color === "amber");
  const allInSync = rows.every(({ r }) => r.sync === "In sync");
  return {
    label: `${live.length + 1} devices`,
    color: amber ? "amber" : allInSync ? "green" : "grey",
    title: (f.settingUp ? `${ownRow(true)}\n` : "") + rows.map(({ d, r }) => `${d.name}: ${[r.presence, r.sync].filter(Boolean).join(" ")}`).join("\n"),
  };
}

// ── From what the backend answers ───────────────────────────────────────

/** A row of `devices_list`, as far as these rules read it. */
export interface ListedDevice {
  install_id: string;
  name: string;
  state: string;
  removing?: boolean;
  record_at?: number;
  heard_at?: number;
  needs_update_side?: "it" | "this";
  syncing_on_older?: boolean;
  locked?: boolean;
}

/** What a device said it holds (`devices_progress`). */
export interface SaidHolds {
  install_id: string;
  holds: { records: number; setting_up: boolean };
}

export const isThisDevice = (d: ListedDevice) => d.state === "this_device" || d.state === "this_device_setting_up";

/** The identity's OTHER devices as these rules know them: the list gives
 *  names, record dates and contact; what each holds comes only from what it
 *  said. A device that has said nothing has `holds: null`, whatever the
 *  list's own state word says. */
export function knownDevices(list: ListedDevice[], said: SaidHolds[]): KnownDevice[] {
  return list.filter((d) => !isThisDevice(d)).map((d) => {
    const s = said.find((x) => x.install_id === d.install_id);
    return {
      name: d.name,
      heardAt: d.heard_at ?? null,
      recordAt: d.record_at ?? 0,
      holds: s ? s.holds.records : null,
      settingUp: s ? s.holds.setting_up : d.state === "setting_up",
      needsUpdate: d.state === "needs_update" ? d.needs_update_side ?? "it" : null,
      syncingOnOlder: !!d.syncing_on_older,
      removed: d.state === "removed" ? (d.removing ? "removing" : "removed") : null,
      locked: !!d.locked,
    };
  });
}

/** Records are arriving from a device heard in the last five minutes that said it holds more than this one. */
export function arrivingFrom(others: KnownDevice[], mine: number, now: number): boolean {
  return others.some((d) => !d.removed && !d.settingUp && isOnline(d, now) && d.holds !== null && d.holds > mine);
}

/** The most records any heard device said it holds: the progress bar's end. Null when none has said. */
export function recordsTarget(others: KnownDevice[]): number | null {
  const said = others.filter((d) => !d.removed && d.holds !== null).map((d) => d.holds as number);
  return said.length ? Math.max(...said) : null;
}
