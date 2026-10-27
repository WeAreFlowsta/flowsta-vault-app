// Which Overview cards a device shows while it is being set up as one of an
// identity's devices, and when the email is asked for. Pure functions, so the
// rules are tested: both 10-27 findings (the card that never left, the
// ten-minute card after the bars were full) were rule mistakes that nothing
// checked. The Overview reads these; nothing else decides.
import type { DeviceRow } from "~/components/vault/DevicesTab";

/** What the `sibling_sync` command answers. */
export interface SiblingSync {
  joined: boolean;
  other_devices: string[];
  records_arrived: boolean;
  asked_for_secs: number | null;
}

export interface SetupView {
  /** The identity was joined: added as a device, or restored from the phrase. */
  joined: boolean;
  /** The round's answer: this device is still being set up (no marker yet). */
  settingUp: boolean;
  /** The round has answered at least once this session. */
  setupKnown: boolean;
  webEmail: string | null;
  sync: SiblingSync | null;
}

/** Ten quiet minutes with no other device heard and nothing arrived. */
export const SILENCE_SECS = 600;

export function longSilence(ss: SiblingSync | null): boolean {
  return !!ss && ss.other_devices.length === 0 && !ss.records_arrived && (ss.asked_for_secs ?? 0) >= SILENCE_SECS;
}

/** "progress": "Your private data is on its way" with its rows; "silence":
 *  "No other device has answered yet"; null: no card. */
export type SetupCard = "progress" | "silence" | null;

export function setupCard(v: SetupView): SetupCard {
  // The card follows the round alone: it is there exactly while this device
  // is being set up, whatever else is known or missing.
  if (!v.joined || !v.settingUp) return null;
  return longSilence(v.sync) ? "silence" : "progress";
}

/** The "Add the email you registered with" callout. A device that joined
 *  waits for setup first (the other devices' profile record usually brings
 *  the email), and for the round's first answer, so it never flashes. */
export function asksForEmail(v: SetupView): boolean {
  if (v.webEmail) return false;
  if (!v.joined) return true;
  return v.setupKnown && !v.settingUp;
}

/** One line per other device while nothing has arrived from it: where the
 *  things are and what would make them come (the 10-23 spec). The other
 *  device's own choice to stop syncing while locked is not in its record
 *  yet, so that case reads as "last seen". */
export function whereThingsAre(d: DeviceRow, now = Date.now()): string {
  const when = (ms: number) => new Date(ms).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  const recent = (d.at ?? 0) > now - 10 * 60 * 1000;
  switch (d.state) {
    case "needs_update": return `${d.name} needs the Vault update to sync.`;
    case "not_seen_since": return `Your things are on ${d.name}, last seen ${when(d.at ?? 0)}. Open Flowsta Vault there (it can stay locked) and they arrive.`;
    case "setting_up": return `${d.name} is still being set up itself.`;
    default: return recent
      ? `${d.name} is online. Your things are on their way...`
      : `Your things are on ${d.name}, last seen ${when(d.at ?? 0)}. Open Flowsta Vault there (it can stay locked) and they arrive.`;
  }
}
