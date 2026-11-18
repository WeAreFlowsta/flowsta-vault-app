// node --import tsx --test src/lib/*.test.ts  (npm run test:unit)
// One test for each row of the tables in the design
// (the Vault says only what it knows about devices).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  arrivingFrom, asksForEmail, cardWords, chip, deviceRow, knownDevices, overviewCard, ownRow, recordsTarget, setupDone,
  CONTINUE_HINT, ONLINE_MS, SLOW_SECS,
  type CardFacts, type KnownDevice, type SetupFacts,
} from "./device-rules";

const NOW = Date.UTC(2026, 10, 18, 12, 0, 0);
const MIN = 60_000;
const DAY = 86_400_000;

const device = (over: Partial<KnownDevice> = {}): KnownDevice => ({
  name: "Mac", heardAt: null, recordAt: NOW - 2 * 3_600_000, holds: null, settingUp: false,
  needsUpdate: null, syncingOnOlder: false, removed: null, locked: false, ...over,
});
const heardNow = (over: Partial<KnownDevice> = {}) => device({ heardAt: NOW - MIN, ...over });

describe("when setup is done", () => {
  const facts = (over: Partial<SetupFacts>): SetupFacts => ({ answer: "yes", continued: false, roundComplete: true, mine: 40, heardSettled: [], stillArriving: false, ...over });

  it("the person said this is the only device: at the first complete round", () => {
    assert.equal(setupDone(facts({ answer: "no" })), "said_only_device");
    assert.equal(setupDone(facts({ answer: "no", roundComplete: false })), null, "not before a round has finished");
  });
  it("every device heard holds no more than this one", () => {
    assert.equal(setupDone(facts({ heardSettled: [40] })), "has_what_heard_devices_hold");
    assert.equal(setupDone(facts({ heardSettled: [12, 40] })), "has_what_heard_devices_hold");
    assert.equal(setupDone(facts({ heardSettled: [41] })), null, "one holds more");
    assert.equal(setupDone(facts({ heardSettled: [40, null] })), null, "one was heard and has not said what it holds");
    assert.equal(setupDone(facts({ heardSettled: [40], stillArriving: true })), null, "records are still arriving");
  });
  it("the person pressed Continue without it, whatever else", () => {
    assert.equal(setupDone(facts({ continued: true })), "continued_without");
    assert.equal(setupDone(facts({ continued: true, roundComplete: false, heardSettled: [900] })), "continued_without");
  });
  it("nobody heard and no answer of 'no': it waits, for any length of time", () => {
    // The rule this replaces finished here after ten minutes and told the
    // other devices this one had everything.
    assert.equal(setupDone(facts({ heardSettled: [] })), null);
    assert.equal(setupDone(facts({ answer: null })), null);
    // And there is no time to give it: SetupFacts has no clock.
    assert.deepEqual(Object.keys(facts({})).sort(), ["answer", "continued", "heardSettled", "mine", "roundComplete", "stillArriving"]);
  });
});

describe("the Overview card", () => {
  const facts = (over: Partial<CardFacts>): CardFacts => ({ joined: true, settingUp: true, known: true, answer: "yes", online: true, others: [], arriving: false, quietSecs: null, now: NOW, ...over });

  it("no answer yet: it asks, once", () => {
    const c = overviewCard(facts({ answer: null }));
    assert.deepEqual(c, { kind: "ask" });
    assert.equal(cardWords(c!).title, "Do you have Flowsta Vault on another device with this identity?");
    assert.equal(cardWords(c!).canContinue, false);
  });
  it("answer Yes, no device listed: looking, with what to do and the way out", () => {
    const c = overviewCard(facts({}));
    assert.deepEqual(c, { kind: "looking" });
    assert.deepEqual(cardWords(c!), { title: "Looking for your other devices", line: "Open Flowsta Vault on your other device and leave it running.", canContinue: true });
  });
  it("a device listed and not heard: its name, and no claim that it is online or asleep", () => {
    const c = overviewCard(facts({ others: [device()] }));
    assert.deepEqual(c, { kind: "on_device", names: ["Mac"] });
    const w = cardWords(c!);
    assert.equal(w.title, "Your things are on Mac");
    assert.equal(w.canContinue, true);
    assert.doesNotMatch(w.title + w.line, /online|last seen|locked/i);
    assert.equal(cardWords(overviewCard(facts({ others: [device(), device({ name: "Windows PC" })] }))!).title, "Your things are on Mac and Windows PC");
  });
  it("a device heard: progress", () => {
    assert.deepEqual(overviewCard(facts({ others: [heardNow()], quietSecs: 10 })), { kind: "progress" });
  });
  it("a device heard and nothing moved for five minutes: it says slowly, and still waits", () => {
    assert.deepEqual(overviewCard(facts({ others: [heardNow()], quietSecs: SLOW_SECS - 1 })), { kind: "progress" });
    const c = overviewCard(facts({ others: [heardNow()], quietSecs: SLOW_SECS }));
    assert.deepEqual(c, { kind: "slow" });
    assert.equal(cardWords(c!).line, "Arriving slowly. Keep both devices on.");
    assert.deepEqual(overviewCard(facts({ others: [heardNow()], quietSecs: 86_400 })), { kind: "slow" }, "a day later it is the same card: time changed a sentence, never the state");
  });
  it("this device cannot reach the network: it says that, and blames no other device", () => {
    const c = overviewCard(facts({ online: false, others: [device()] }));
    assert.deepEqual(c, { kind: "offline" });
    assert.doesNotMatch(cardWords(c!).title + cardWords(c!).line, /Mac/);
    assert.deepEqual(overviewCard(facts({ online: null })), { kind: "looking" }, "not known yet is not offline");
  });
  it("answer No: no card", () => {
    assert.equal(overviewCard(facts({ answer: "no" })), null);
  });
  it("done: no card", () => {
    assert.equal(overviewCard(facts({ settingUp: false, others: [heardNow({ holds: 40 })] })), null);
  });
  it("done, and a device turns up later holding more: it is back", () => {
    const c = overviewCard(facts({ settingUp: false, answer: "no", arriving: true, others: [heardNow()] }));
    assert.deepEqual(c, { kind: "back", names: ["Mac"] });
    assert.equal(cardWords(c!).title, "Mac is back");
    assert.equal(overviewCard(facts({ settingUp: false, arriving: true, others: [device()] })), null, "not heard: nothing is arriving from it");
  });
  it("a first device, or a state not read yet: no card", () => {
    assert.equal(overviewCard(facts({ joined: false })), null);
    assert.equal(overviewCard(facts({ known: false })), null);
  });
  it("a removed device is not something to wait for", () => {
    assert.deepEqual(overviewCard(facts({ others: [device({ removed: "removed" })] })), { kind: "looking" });
  });
  it("the words never promise what cannot be known", () => {
    for (const kind of ["ask", "offline", "looking", "progress", "slow"] as const) {
      const w = cardWords({ kind });
      assert.doesNotMatch(w.title + " " + w.line, /Nothing to do|it can stay locked|No other device has answered/);
    }
    assert.match(CONTINUE_HINT, /Remove it in Settings, Devices/);
  });
});

describe("asking for the email", () => {
  it("never while setup is under way, at once when it is done or was never needed", () => {
    assert.equal(asksForEmail({ webEmail: null, joined: true, settingUp: true, known: true }), false);
    assert.equal(asksForEmail({ webEmail: null, joined: true, settingUp: false, known: true }), true);
    assert.equal(asksForEmail({ webEmail: null, joined: true, settingUp: false, known: false }), false, "not before the state is read");
    assert.equal(asksForEmail({ webEmail: null, joined: false, settingUp: false, known: false }), true);
    assert.equal(asksForEmail({ webEmail: "a@example.com", joined: true, settingUp: false, known: true }), false);
  });
});

describe("a row of Settings, Devices", () => {
  it("heard in the last five minutes: Online, green", () => {
    const r = deviceRow(device({ heardAt: NOW - ONLINE_MS }), 40, NOW);
    assert.equal(r.presence, "Online");
    assert.equal(r.color, "green");
    assert.notEqual(deviceRow(device({ heardAt: NOW - ONLINE_MS - 1 }), 40, NOW).presence, "Online");
  });
  it("heard earlier since this Vault opened: how long ago", () => {
    assert.equal(deviceRow(device({ heardAt: NOW - 40 * MIN }), 40, NOW).presence, "Heard 40 min ago");
    assert.equal(deviceRow(device({ heardAt: NOW - 3 * 60 * MIN }), 40, NOW).presence, "Heard 3 h ago");
  });
  it("not heard: says so and dates its record; a fresh record is never 'online'", () => {
    // Its record was written a minute ago by its own clock: that is not contact.
    const r = deviceRow(device({ recordAt: NOW - MIN }), 40, NOW);
    assert.match(r.presence, /^Not heard since this Vault opened\. Its record is from /);
    assert.equal(r.color, "grey");
    assert.doesNotMatch(r.presence, /Online|last seen|Up to date/);
  });
  it("not heard and its record three days old: the days, and the way to remove it", () => {
    const r = deviceRow(device({ recordAt: NOW - 3 * DAY }), 40, NOW);
    assert.equal(r.presence, "Not heard for 3 days. No longer have it? Remove it.");
    assert.equal(r.color, "amber");
    assert.equal(r.offerRemove, true);
    assert.equal(deviceRow(device({ recordAt: NOW - 3 * DAY + 1000 }), 40, NOW).offerRemove, false);
  });
  it("a device that is on and locked reads Online (locked), however old its record", () => {
    const r = deviceRow(device({ heardAt: NOW - MIN, locked: true, recordAt: NOW - 9 * DAY }), 40, NOW);
    assert.equal(r.presence, "Online (locked)");
    assert.equal(r.color, "green");
  });
  it("what it holds, only when it said so", () => {
    assert.equal(deviceRow(heardNow({ holds: 40 }), 40, NOW).sync, "In sync");
    assert.equal(deviceRow(heardNow({ holds: 31 }), 40, NOW).sync, "Getting 9 records from this device");
    assert.equal(deviceRow(heardNow({ holds: 52 }), 40, NOW).sync, "This device is getting 12 records from it");
    assert.equal(deviceRow(heardNow({ holds: null }), 40, NOW).sync, null, "it has not said: nothing is claimed");
    assert.equal(deviceRow(device({ holds: null, recordAt: NOW - MIN }), 40, NOW).sync, null, "a device that gave up and wrote a newer record is not 'up to date'");
  });
  it("being set up: receiving, with the count when it said one", () => {
    assert.equal(deviceRow(heardNow({ settingUp: true }), 40, NOW).sync, "Receiving your private data");
    const r = deviceRow(heardNow({ settingUp: true, holds: 12 }), 40, NOW);
    assert.equal(r.sync, "Receiving your private data, 12 of 40");
    assert.equal(r.color, "amber");
  });
  it("the update is named on the side that needs it", () => {
    assert.equal(deviceRow(device({ needsUpdate: "it" }), 40, NOW).presence, "Needs the Vault update to sync");
    assert.equal(deviceRow(device({ needsUpdate: "this" }), 40, NOW).presence, "This device needs the Vault update to sync with it");
    assert.equal(deviceRow(device({ needsUpdate: "it", syncingOnOlder: true }), 40, NOW).sync, "Syncing on the older network until then");
    assert.equal(deviceRow(device({ needsUpdate: "it" }), 40, NOW).sync, null);
  });
  it("removed and removing", () => {
    assert.equal(deviceRow(device({ removed: "removed" }), 40, NOW).presence, "Removed");
    assert.equal(deviceRow(device({ removed: "removing" }), 40, NOW).presence, "Removing…");
  });
  it("this device's own row says it is receiving until setup is done", () => {
    assert.equal(ownRow(true), "This device, receiving your private data");
    assert.equal(ownRow(false), "This device");
  });
});

describe("the sidebar chip", () => {
  const facts = (over: Partial<Parameters<typeof chip>[0]>) => ({ joined: true, answer: "yes" as const, listRead: true, settingUp: true, others: [] as KnownDevice[], mine: 40, now: NOW, ...over });

  it("a device that joined and has no list yet is checking, never 'only on this device'", () => {
    assert.equal(chip(facts({})).label, "Checking devices");
    // A device that made the identity is its only device until it adds one
    // (the page shows the count it last knew when that is more than one).
    assert.equal(chip(facts({ listRead: false, joined: false })).label, "1 device");
  });
  it("'1 device' only when that is known", () => {
    assert.deepEqual(chip(facts({ joined: false, settingUp: false })), { label: "1 device", color: "grey", title: "Only on this device" });
    assert.equal(chip(facts({ answer: "no" })).label, "1 device");
    assert.equal(chip(facts({ settingUp: false })).label, "1 device", "setup done with nobody else listed");
  });
  it("amber while this device is receiving, green only when every device said it holds the same", () => {
    assert.equal(chip(facts({ others: [heardNow({ holds: 40 })] })).color, "amber");
    assert.equal(chip(facts({ settingUp: false, others: [heardNow({ holds: 40 })] })).color, "green");
    assert.equal(chip(facts({ settingUp: false, others: [heardNow({ holds: null })] })).color, "grey", "it has not said: not green");
    assert.equal(chip(facts({ settingUp: false, others: [heardNow({ holds: 40 })] })).label, "2 devices");
    assert.match(chip(facts({ others: [heardNow({ holds: 12 })] })).title, /^This device, receiving your private data\nMac: Online /);
  });
});

describe("the chip before the list is read", () => {
  const base = { answer: null as null, settingUp: true, others: [], mine: 0, now: NOW };
  it("says 1 device at once on a device that made the identity", () => {
    assert.equal(chip({ ...base, joined: false, listRead: false }).label, "1 device");
  });
  it("says Checking devices on a device that joined, until the list is read and setup is done or the person said so", () => {
    assert.equal(chip({ ...base, joined: true, listRead: false }).label, "Checking devices");
    assert.equal(chip({ ...base, joined: true, listRead: true }).label, "Checking devices");
    assert.equal(chip({ ...base, joined: true, listRead: true, answer: "no" }).label, "1 device");
    assert.equal(chip({ ...base, joined: true, listRead: true, settingUp: false }).label, "1 device");
  });
});

describe("from what the backend answers", () => {
  const list = [
    { install_id: "me", name: "Linux", state: "this_device_setting_up" },
    { install_id: "a", name: "Mac", state: "up_to_date", record_at: NOW - DAY, heard_at: NOW - MIN },
    { install_id: "b", name: "PC", state: "up_to_date", record_at: NOW - DAY },
    { install_id: "c", name: "Old", state: "removed", removing: true, record_at: NOW - 9 * DAY },
    { install_id: "d", name: "Tablet", state: "needs_update", needs_update_side: "this" as const, record_at: NOW - DAY },
  ];
  const said = [{ install_id: "a", holds: { records: 40, setting_up: false } }];
  const known = knownDevices(list, said);

  it("leaves this device out and keeps the others by name", () => {
    assert.deepEqual(known.map((d) => d.name), ["Mac", "PC", "Old", "Tablet"]);
  });
  it("takes what a device holds only from what it said", () => {
    assert.equal(known[0].holds, 40);
    assert.equal(known[1].holds, null, "the list's own word 'up_to_date' is not a statement of what it holds");
    assert.equal(deviceRow(known[1], 40, NOW).sync, null);
  });
  it("takes contact only from a message heard here", () => {
    assert.equal(known[0].heardAt, NOW - MIN);
    assert.equal(known[1].heardAt, null);
  });
  it("carries removal and which side needs the update", () => {
    assert.equal(known[2].removed, "removing");
    assert.equal(known[3].needsUpdate, "this");
    assert.equal(knownDevices([{ install_id: "e", name: "X", state: "needs_update" }], [])[0].needsUpdate, "it");
  });
  it("says records are arriving only from a device online now that said it holds more", () => {
    assert.equal(arrivingFrom(known, 12, NOW), true);
    assert.equal(arrivingFrom(known, 40, NOW), false, "it holds no more than this one");
    assert.equal(arrivingFrom(known, 12, NOW + ONLINE_MS + MIN), false, "no longer online");
    assert.equal(arrivingFrom([device({ heardAt: NOW, holds: null })], 12, NOW), false, "it has not said");
  });
  it("ends the progress bar at the most any device said, and has no end when none has said", () => {
    assert.equal(recordsTarget(known), 40);
    assert.equal(recordsTarget([device()]), null);
  });
});
