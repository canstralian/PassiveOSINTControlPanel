import { describe, it, expect } from "vitest";
import { BeliefGraph, GraphValidationError } from "../src/graph/belief-graph.js";
import { makeEvidence, makeHypothesis } from "./_helpers.js";

describe("BeliefGraph node/edge validation", () => {
  it("rejects duplicate hypothesis ids", () => {
    const g = new BeliefGraph();
    const h = makeHypothesis();
    g.addHypothesis(h);
    expect(() => g.addHypothesis(h)).toThrow(GraphValidationError);
  });

  it("rejects evidence linked to unknown hypothesis", () => {
    const g = new BeliefGraph();
    const ev = makeEvidence({
      affects: [{ hypothesisId: "hyp_does_not_exist", polarityHint: "supports" }],
    });
    expect(() => g.addEvidence(ev)).toThrow(GraphValidationError);
  });

  it("rejects belief on unknown hypothesis", () => {
    const g = new BeliefGraph();
    expect(() =>
      g.setBelief({
        hypothesisId: "hyp_unknown",
        posterior: 0.5,
        updateTrace: [],
        agendaPriority: 0,
        lastUpdatedAt: new Date(0).toISOString(),
      })
    ).toThrow(GraphValidationError);
  });

  it("evidenceFor returns only evidence affecting the requested hypothesis", () => {
    const g = new BeliefGraph();
    const h1 = makeHypothesis();
    const h2 = makeHypothesis();
    g.addHypothesis(h1);
    g.addHypothesis(h2);
    g.addEvidence(
      makeEvidence({
        affects: [{ hypothesisId: h1.id, polarityHint: "supports" }],
      })
    );
    g.addEvidence(
      makeEvidence({
        affects: [{ hypothesisId: h2.id, polarityHint: "opposes" }],
      })
    );
    expect(g.evidenceFor(h1.id)).toHaveLength(1);
    expect(g.evidenceFor(h2.id)).toHaveLength(1);
  });
});
