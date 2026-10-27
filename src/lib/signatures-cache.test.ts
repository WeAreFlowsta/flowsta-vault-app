// node --import tsx --test src/lib/*.test.ts  (npm run test:unit)
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { dropCarriedOriginals, oneCopyPerOriginal } from "./signatures-cache";

type Row = { action_hash: string; original_action_hash?: string; supersedes: string | null; superseded_by?: string | null; file_hash?: string };

// Team Flowsta on beta13 (three devices): one file's rows as the page held
// them - the original carried three times, its amendment three times.
const teamFlowsta: Row[] = [
  { action_hash: "84292418b2", original_action_hash: "8429245302", supersedes: null, file_hash: "0f9064" },
  { action_hash: "8429244288", original_action_hash: "8429248055", supersedes: "8429248917", file_hash: "0f9064" },
  { action_hash: "8429248917", original_action_hash: "8429245302", supersedes: null, file_hash: "0f9064" },
  { action_hash: "8429243efc", original_action_hash: "8429248055", supersedes: "8429248917", file_hash: "0f9064" },
  { action_hash: "8429245baf", original_action_hash: "8429248055", supersedes: "8429248917", file_hash: "0f9064" },
];

describe("one copy per original", () => {
  it("collapses the carried copies of a three-device identity to one original and one amendment", () => {
    const out = oneCopyPerOriginal(teamFlowsta);
    assert.deepEqual(out.map((s) => s.action_hash), ["84292418b2", "8429244288"]);
    assert.equal(out[1].supersedes, "84292418b2", "the amendment names the kept copy of the original");
    assert.equal(out[0].superseded_by, "8429244288", "the original reads as amended, not current");
    assert.equal(out[1].superseded_by ?? null, null);
  });
  it("leaves native rows and a list without copies alone", () => {
    const native: Row[] = [{ action_hash: "n1", supersedes: null }, { action_hash: "n2", supersedes: "n1" }];
    assert.equal(oneCopyPerOriginal(native), native, "same array when nothing was dropped");
    const one: Row[] = [{ action_hash: "c1", original_action_hash: "o1", supersedes: null }];
    assert.deepEqual(oneCopyPerOriginal(one), one);
  });
  it("works after the 0.6 originals are dropped, as the page applies it", () => {
    const withOriginal: Row[] = [{ action_hash: "8429245302", supersedes: null, file_hash: "0f9064" }, ...teamFlowsta];
    const out = oneCopyPerOriginal(dropCarriedOriginals(withOriginal));
    assert.equal(out.length, 2);
    assert.ok(out.every((s) => s.action_hash !== "8429245302"));
  });
});
