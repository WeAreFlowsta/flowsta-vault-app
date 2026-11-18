// Every combination of facts the rules can be given, through the words the
// Overview card, the Devices rows and the sidebar would show for it: none
// may contradict another or read as nonsense (sense.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import { arrivingFrom, cardBars, cardWords, chip, deviceRow, overviewCard, type KnownDevice, type OtherDevice } from "./device-rules";
import { senseProblems, type Shown } from "./sense";

const NOW = 1_800_000_000_000;
const MIN = 60_000;
const DAY = 86_400_000;

function devicesFor(mine: number): KnownDevice[] {
  const out: KnownDevice[] = [];
  const base = { recordAt: NOW - DAY, needsUpdate: null, syncingOnOlder: false, removed: null, locked: false } as const;
  const holds = [...new Set([null, 0, mine - 1, mine, mine + 1, mine + 5].filter((h) => h === null || h >= 0))];
  for (const heardAt of [null, NOW - MIN, NOW - 20 * MIN, NOW - 3 * 60 * MIN]) {
    for (const h of holds) {
      for (const settingUp of [false, true]) out.push({ ...base, name: "", heardAt, holds: h, settingUp });
    }
  }
  out.push({ ...base, name: "", heardAt: null, holds: null, settingUp: false, recordAt: NOW - 5 * DAY });
  out.push({ ...base, name: "", heardAt: null, holds: null, settingUp: false, recordAt: NOW - 4 * DAY - 1 });
  out.push({ ...base, name: "", heardAt: NOW - MIN, holds: mine, settingUp: false, locked: true });
  out.push({ ...base, name: "", heardAt: NOW - MIN, holds: mine, settingUp: false, removed: "removed" });
  out.push({ ...base, name: "", heardAt: null, holds: null, settingUp: false, removed: "removing" });
  out.push({ ...base, name: "", heardAt: NOW - MIN, holds: null, settingUp: false, needsUpdate: "it", syncingOnOlder: true });
  out.push({ ...base, name: "", heardAt: null, holds: null, settingUp: false, needsUpdate: "this" });
  return out;
}

function shown(f: { answer: OtherDevice; settingUp: boolean; online: boolean | null; others: KnownDevice[]; mine: number; quietSecs: number | null; backupsWanted: number; backupsPending: number; sessionSecs: number | null }): Shown {
  const card = overviewCard({ joined: true, known: true, now: NOW, arriving: arrivingFrom(f.others, f.mine, NOW), ...f });
  const words = card ? cardWords(card) : null;
  return {
    card: card && words ? { title: words.title, line: words.line, bars: cardBars(card, f), canContinue: words.canContinue, lostHint: words.lostHint } : null,
    rows: f.others.map((d) => { const r = deviceRow(d, f.mine, NOW); return { name: d.name, presence: r.presence, sync: r.sync }; }),
    chipLabel: chip({ joined: true, answer: f.answer, listRead: true, settingUp: f.settingUp, others: f.others, mine: f.mine, now: NOW }).label,
  };
}

test("no combination of facts shows something that does not make sense", () => {
  const found = new Map<string, string>();
  let checked = 0;
  const seen = new Set<string>();
  for (const mine of [0, 1, 431]) {
    const pool = devicesFor(mine);
    const sets: KnownDevice[][] = [[], ...pool.map((d) => [{ ...d, name: "Laptop" }])];
    // Pairs from the devices a person usually has: on, heard a while ago, or not heard; behind, level or ahead.
    const usual = pool.filter((d) => !d.removed && !d.needsUpdate && !d.locked && d.recordAt === NOW - DAY && d.heardAt !== NOW - 3 * 60 * MIN && (d.holds === null || d.holds === mine || d.holds === mine + 5 || d.holds === mine - 1));
    for (const a of usual) for (const b of usual) sets.push([{ ...a, name: "Laptop" }, { ...b, name: "Desk" }]);
    for (const others of sets) {
      for (const answer of [null, "yes", "no"] as OtherDevice[]) {
        for (const settingUp of [true, false]) {
          for (const online of [true, false]) {
            for (const quietSecs of [0, 600]) {
              for (const [backupsWanted, backupsPending] of [[0, 0], [2000, 0], [2000, 1500]]) {
                for (const sessionSecs of [60, 3600]) {
                  checked++;
                  const f = { answer, settingUp, online, others, mine, quietSecs, backupsWanted, backupsPending, sessionSecs };
                  const screen = shown(f);
                  const key = JSON.stringify(screen);
                  if (seen.has(key)) continue;
                  seen.add(key);
                  for (const problem of senseProblems(screen)) {
                    // One example of each kind of problem is enough to read.
                    const kind = problem.replace(/\d+/g, "N").replace(/"[^"]*"/g, '""');
                    if (!found.has(kind)) found.set(kind, `${problem}\n    from ${JSON.stringify({ ...f, others: others.map((d) => ({ ...d, heardAt: d.heardAt && `${(NOW - d.heardAt) / MIN} min ago`, recordAt: undefined })) })}`);
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  assert.ok(checked > 50_000);
  assert.deepEqual([...found.values()], []);
});

test("the checks catch what a person saw on 11-19", () => {
  // The Mac: all 431 counted, "on its way", "Continue without it", "Lost that device?", beside a device shown in sync.
  const mac = senseProblems({
    card: { title: "Your private data is on its way", line: "Arriving slowly. Keep both devices on.", bars: [{ label: "Records", done: 431, of: 431 }], canContinue: true, lostHint: true },
    rows: [{ name: "LinuxLappy", presence: "Online", sync: "In sync" }],
    chipLabel: "2 devices",
  });
  assert.ok(mac.some((p) => /on its way while everything it counts has arrived/.test(p)), mac.join("\n"));
  assert.ok(mac.some((p) => /lost while every other device shows as online/.test(p)), mac.join("\n"));
  // The Mac earlier: told to open the Vault on a device that was on.
  const open = senseProblems({
    card: { title: "Your things are on LinuxLappy", line: "Open Flowsta Vault there and leave it running.", bars: [], canContinue: true, lostHint: true },
    rows: [{ name: "LinuxLappy", presence: "Online", sync: "In sync" }],
  });
  assert.ok(open.some((p) => /open Flowsta Vault on another device while LinuxLappy shows as online/.test(p)), open.join("\n"));
  // LinuxLappy: a device not heard for 20 minutes, "receiving", with all of it counted.
  const lappy = senseProblems({ rows: [{ name: "Mac", presence: "Heard 20 min ago", sync: "Receiving your private data, 431 of 431" }] });
  assert.ok(lappy.some((p) => /exchanging records now/.test(p)), lappy.join("\n"));
  assert.ok(lappy.some((p) => /all of it counted/.test(p)), lappy.join("\n"));
  // And a screen that makes sense passes.
  assert.deepEqual(senseProblems({ card: null, rows: [{ name: "Mac", presence: "Online", sync: "In sync" }], chipLabel: "2 devices" }), []);
});
