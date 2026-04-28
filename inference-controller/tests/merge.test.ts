import { describe, it, expect } from "vitest";
import { BeliefGraph } from "../src/graph/belief-graph.js";
import { MergeService } from "../src/graph/merge.js";
import { makeHypothesis } from "./_helpers.js";

describe("merge approval and reversibility", () => {
  function setup() {
    const g = new BeliefGraph();
    const primary = makeHypothesis({ statement: "primary" });
    const subsumed = makeHypothesis({ statement: "subsumed" });
    g.addHypothesis(primary);
    g.addHypothesis(subsumed);
    return { g, primary, subsumed, ms: new MergeService(g) };
  }

  it("propose moves the subsumed hypothesis to merged lifecycle", () => {
    const { g, primary, subsumed, ms } = setup();
    const m = ms.propose({
      investigationId: "inv_1",
      kind: "exact_equivalence",
      primaryHypothesisId: primary.id,
      subsumedHypothesisId: subsumed.id,
    });
    expect(g.getHypothesis(subsumed.id)!.lifecycle).toBe("merged");
    expect(m.finalized).toBe(false);
  });

  it("revert restores the prior lifecycle and removes the merge id from history", () => {
    const { g, primary, subsumed, ms } = setup();
    const m = ms.propose({
      investigationId: "inv_1",
      kind: "subtype",
      primaryHypothesisId: primary.id,
      subsumedHypothesisId: subsumed.id,
    });
    ms.revert(m.id);
    expect(g.getHypothesis(subsumed.id)!.lifecycle).toBe("active");
    expect(g.getHypothesis(subsumed.id)!.mergeHistory).not.toContain(m.id);
  });

  it("finalize requires approval=true", () => {
    const { primary, subsumed, ms } = setup();
    const m = ms.propose({
      investigationId: "inv_1",
      kind: "parent_child",
      primaryHypothesisId: primary.id,
      subsumedHypothesisId: subsumed.id,
    });
    expect(() => ms.finalize(m.id, false)).toThrow(/approval/);
    const finalized = ms.finalize(m.id, true);
    expect(finalized.finalized).toBe(true);
  });

  it("finalized merges cannot be reverted", () => {
    const { primary, subsumed, ms } = setup();
    const m = ms.propose({
      investigationId: "inv_1",
      kind: "parent_child",
      primaryHypothesisId: primary.id,
      subsumedHypothesisId: subsumed.id,
    });
    ms.finalize(m.id, true);
    expect(() => ms.revert(m.id)).toThrow(/finalized/);
  });
});
