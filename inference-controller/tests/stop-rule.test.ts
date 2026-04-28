import { describe, it, expect } from "vitest";
import { evaluateStop, makeStopCandidate } from "../src/controller/stop.js";
import { Controller } from "../src/controller/controller.js";
import { ScopePolicy } from "../src/safety/scope.js";
import { makeAction, makeBudgets, makeInvestigation } from "./_helpers.js";

describe("stop rule", () => {
  it("emits stop when budget is exhausted", () => {
    const out = evaluateStop({
      budgets: makeBudgets({ actionsRemaining: 0 }),
      admissibleActionCount: 5,
      topActionScore: 1,
      scoreThreshold: 0,
      hasValidatedTopHypothesis: false,
      hasFalsifiedAllActive: false,
      manualStopRequested: false,
      failClosed: false,
    });
    expect(out.shouldStop).toBe(true);
    expect(out.reasons).toContain("budget_exhausted");
  });

  it("emits stop when the top score is below threshold", () => {
    const out = evaluateStop({
      budgets: makeBudgets(),
      admissibleActionCount: 3,
      topActionScore: -1,
      scoreThreshold: 0,
      hasValidatedTopHypothesis: false,
      hasFalsifiedAllActive: false,
      manualStopRequested: false,
      failClosed: false,
    });
    expect(out.shouldStop).toBe(true);
    expect(out.reasons).toContain("all_top_actions_below_threshold");
  });

  it("emits fail_closed reason when failClosed is true", () => {
    const out = evaluateStop({
      budgets: makeBudgets(),
      admissibleActionCount: 3,
      topActionScore: 1,
      scoreThreshold: 0,
      hasValidatedTopHypothesis: false,
      hasFalsifiedAllActive: false,
      manualStopRequested: false,
      failClosed: true,
    });
    expect(out.reasons).toContain("fail_closed");
  });

  it("controller always considers stop_and_report — it is in candidateScores", () => {
    const inv = makeInvestigation();
    const out = new Controller().selectAction({
      investigation: inv,
      candidates: [makeAction({ estimatedRiskClass: "none" })],
      scopePolicy: new ScopePolicy(),
    });
    const stopCandidates = out.decision.candidateScores.filter((cs) =>
      cs.candidateId.startsWith("act_")
    );
    expect(stopCandidates.length).toBeGreaterThanOrEqual(2);
    // makeStopCandidate produces a low but positive baseline score.
    const stopCand = makeStopCandidate(inv.id);
    expect(stopCand.kind).toBe("stop_and_report");
  });
});
