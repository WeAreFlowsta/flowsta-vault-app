// node --import tsx --test src/lib/*.test.ts  (npm run test:unit)
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { backupsTotal } from "./overview-cards";

describe("the Backups card's number", () => {
  it("waits for both parts, so a partial sum never shows", () => {
    assert.equal(backupsTotal(null, null), null, "nothing loaded yet");
    assert.equal(backupsTotal(1815, null), null, "the copies kept from the other device are not in yet");
    assert.equal(backupsTotal(null, 8), null, "this device's own backups are not in yet");
  });
  it("adds the two once both are known", () => {
    assert.equal(backupsTotal(1815, 8), 1823);
    assert.equal(backupsTotal(8, 1815), 1823);
    assert.equal(backupsTotal(0, 0), 0, "a device with none says so, as a number");
  });
});
