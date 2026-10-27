// node --import tsx --test src/lib/*.test.ts  (npm run test:unit)
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { asksForEmail, longSilence, setupCard, whereThingsAre, type SetupView, type SiblingSync } from "./overview-cards";
import type { DeviceRow } from "~/components/vault/DevicesTab";

const quiet: SiblingSync = { joined: true, other_devices: [], records_arrived: false, asked_for_secs: 0 };
const heard: SiblingSync = { joined: true, other_devices: ["mac"], records_arrived: true, asked_for_secs: 30 };
const view = (over: Partial<SetupView>): SetupView => ({ joined: true, settingUp: true, setupKnown: true, webEmail: null, sync: heard, ...over });

describe("the setup card", () => {
  it("shows while a joined device is being set up, and only then", () => {
    assert.equal(setupCard(view({})), "progress");
    assert.equal(setupCard(view({ settingUp: false })), null, "the round said it has everything: the card leaves");
    assert.equal(setupCard(view({ joined: false })), null, "the first device is never being set up");
  });
  it("stays exactly as long as the round says, whatever the email", () => {
    // 10-27: an identity whose first device never wrote a profile record
    // kept the card for good because the email was still missing.
    assert.equal(setupCard(view({ settingUp: false, webEmail: null })), null);
    assert.equal(setupCard(view({ settingUp: true, webEmail: "a@example.com" })), "progress");
  });
  it("says no device has answered after ten quiet minutes, not before", () => {
    assert.equal(setupCard(view({ sync: { ...quiet, asked_for_secs: 599 } })), "progress");
    assert.equal(setupCard(view({ sync: { ...quiet, asked_for_secs: 600 } })), "silence");
    assert.equal(setupCard(view({ sync: null })), "progress", "the cells have not answered yet: still on its way");
    assert.equal(setupCard(view({ sync: { ...quiet, other_devices: ["mac"], asked_for_secs: 900 } })), "progress", "a device is known: not silence");
    assert.equal(setupCard(view({ sync: { ...quiet, records_arrived: true, asked_for_secs: 900 } })), "progress", "records came: not silence");
  });
  it("the silence rule on its own", () => {
    assert.equal(longSilence(null), false);
    assert.equal(longSilence({ ...quiet, asked_for_secs: null }), false);
    assert.equal(longSilence({ ...quiet, asked_for_secs: 600 }), true);
  });
});

describe("asking for the email", () => {
  it("a device that knows its email is never asked", () => {
    assert.equal(asksForEmail(view({ webEmail: "a@example.com", settingUp: false })), false);
    assert.equal(asksForEmail(view({ webEmail: "a@example.com", joined: false })), false);
  });
  it("the first device without an email is asked at once", () => {
    assert.equal(asksForEmail(view({ joined: false, setupKnown: false, settingUp: false })), true);
  });
  it("a joined device is asked once setup is done, not while the card is up, not before the round answered", () => {
    assert.equal(asksForEmail(view({ settingUp: true })), false, "the card is up: the email may still arrive");
    assert.equal(asksForEmail(view({ setupKnown: false, settingUp: false })), false, "no answer yet: do not flash");
    assert.equal(asksForEmail(view({ setupKnown: true, settingUp: false })), true, "setup done, still no email: ask");
  });
  it("the card and the callout never show together", () => {
    for (const settingUp of [true, false]) for (const setupKnown of [true, false]) for (const joined of [true, false]) {
      const v = view({ settingUp, setupKnown, joined, webEmail: null });
      assert.ok(!(setupCard(v) && asksForEmail(v)), JSON.stringify(v));
    }
  });
});

describe("where the things are", () => {
  const now = Date.UTC(2026, 9, 27, 10, 0, 0);
  const row = (over: Partial<DeviceRow>): DeviceRow => ({ install_id: "a1", name: "Erics-MacBook-Air.local", platform: "macos", added_at: now - 86_400_000, state: "up_to_date", at: now - 60_000, ...over });
  it("a device heard in the last ten minutes is online, never read as offline", () => {
    const line = whereThingsAre(row({}), now);
    assert.equal(line, "Erics-MacBook-Air.local is online. Your things are on their way...");
    assert.ok(!/Waiting for/.test(line));
  });
  it("a device not heard for ten minutes says when it was last seen and what to do", () => {
    const line = whereThingsAre(row({ at: now - 11 * 60_000 }), now);
    assert.match(line, /^Your things are on Erics-MacBook-Air.local, last seen .*Open Flowsta Vault there/);
  });
  it("the other states keep their own lines", () => {
    assert.match(whereThingsAre(row({ state: "needs_update" }), now), /needs the Vault update/);
    assert.match(whereThingsAre(row({ state: "setting_up" }), now), /still being set up itself/);
    assert.match(whereThingsAre(row({ state: "not_seen_since", at: now - 60_000 }), now), /last seen/);
  });
});
