import { describe, it, expect } from "vitest";
import { BeliefGraph } from "../src/graph/belief-graph.js";
import { ContradictionService } from "../src/graph/contradictions.js";
import { makeHypothesis } from "./_helpers.js";

describe("contradiction vs low probability", () => {
  it("a low posterior alone does not create a contradiction record", () => {
    const g = new BeliefGraph();
    const h = makeHypothesis();
    g.addHypothesis(h);
    g.setBelief({
      hypothesisId: h.id,
      posterior: 0.05,
      updateTrace: [],
      agendaPriority: 0,
      lastUpdatedAt: new Date(0).toISOString(),
    });
    expect(g.contradictionsFor(h.id)).toHaveLength(0);
  });

  it("contradictions are first-class state with a typed reason", () => {
    const g = new BeliefGraph();
    const h1 = makeHypothesis();
    const h2 = makeHypothesis();
    g.addHypothesis(h1);
    g.addHypothesis(h2);
    const cs = new ContradictionService(g);
    const c = cs.record({
      investigationId: "inv_1",
      affected: { kind: "hypothesis", refId: h1.id },
      conflicting: { kind: "hypothesis", refId: h2.id },
      contradictionType: "logical_defeat",
      rule: "mutual exclusion of attributions",
    });
    expect(c.contradictionType).toBe("logical_defeat");
    expect(c.resolution).toBe("open");
    expect(g.contradictionsFor(h1.id)).toHaveLength(1);
  });

  it("resolution state is independent of belief value", () => {
    const g = new BeliefGraph();
    const h1 = makeHypothesis();
    const h2 = makeHypothesis();
    g.addHypothesis(h1);
    g.addHypothesis(h2);
    const cs = new ContradictionService(g);
    const c = cs.record({
      investigationId: "inv_1",
      affected: { kind: "hypothesis", refId: h1.id },
      conflicting: { kind: "hypothesis", refId: h2.id },
      contradictionType: "evidence_conflict",
    });
    const resolved = cs.resolve(c.id, "deprioritized");
    expect(resolved.resolution).toBe("deprioritized");
    // Setting a low belief value does not change resolution state.
    g.setBelief({
      hypothesisId: h1.id,
      posterior: 0.001,
      updateTrace: [],
      agendaPriority: 0,
      lastUpdatedAt: new Date(0).toISOString(),
    });
    expect(g.getContradiction(c.id)!.resolution).toBe("deprioritized");
  });
});
