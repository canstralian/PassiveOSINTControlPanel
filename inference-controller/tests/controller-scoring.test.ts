import { describe, it, expect } from "vitest";
import { Controller } from "../src/controller/controller.js";
import { ScopePolicy } from "../src/safety/scope.js";
import { scoreCandidate } from "../src/controller/scoring.js";
import { makeAction, makeBudgets, makeInvestigation } from "./_helpers.js";

describe("controller score decomposition", () => {
  it("persists the full decomposition for the selected action", () => {
    const inv = makeInvestigation();
    const a1 = makeAction({
      estimatedExpectedPosteriorChange: 0.6,
      estimatedDecisionCriticality: 0.5,
      estimatedMissionValue: 0.8,
      estimatedCost: 1,
      estimatedLatencyMs: 10,
    });
    const c = new Controller();
    const out = c.selectAction({
      investigation: inv,
      candidates: [a1],
      scopePolicy: new ScopePolicy(),
    });
    const s = out.decision.score;
    expect(s.expectedPosteriorChange).toBe(0.6);
    expect(s.decisionCriticality).toBe(0.5);
    expect(s.missionValue).toBe(0.8);
    expect(s.finalScore).toBeCloseTo(
      0.6 * 0.5 * 0.8 - 1 * 0.01 - 10 * 0.0001 - 0 - s.budgetPressurePenalty,
      9
    );
    expect(s.explanation).toMatch(/epc/);
  });

  it("selects the highest-score admissible action by default", () => {
    const inv = makeInvestigation();
    const a1 = makeAction({
      estimatedExpectedPosteriorChange: 0.2,
      estimatedDecisionCriticality: 0.2,
      estimatedMissionValue: 0.2,
    });
    const a2 = makeAction({
      estimatedExpectedPosteriorChange: 0.9,
      estimatedDecisionCriticality: 0.9,
      estimatedMissionValue: 0.9,
    });
    const out = new Controller().selectAction({
      investigation: inv,
      candidates: [a1, a2],
      scopePolicy: new ScopePolicy(),
    });
    expect(out.decision.selectedActionId).toBe(a2.id);
    expect(out.decision.overrideReason).toBeUndefined();
  });

  it("override requires overrideReason, recorded on the decision", () => {
    const inv = makeInvestigation();
    const a1 = makeAction({
      estimatedExpectedPosteriorChange: 0.9,
      estimatedDecisionCriticality: 0.9,
      estimatedMissionValue: 0.9,
    });
    const a2 = makeAction({
      estimatedExpectedPosteriorChange: 0.1,
      estimatedDecisionCriticality: 0.1,
      estimatedMissionValue: 0.1,
    });
    const out = new Controller().selectAction({
      investigation: inv,
      candidates: [a1, a2],
      scopePolicy: new ScopePolicy(),
      override: { actionId: a2.id, reason: "operator policy override" },
    });
    expect(out.decision.selectedActionId).toBe(a2.id);
    expect(out.decision.overrideReason).toBe("operator policy override");
  });

  it("always considers stop_and_report (it appears in candidateScores)", () => {
    const inv = makeInvestigation();
    const a1 = makeAction();
    const out = new Controller().selectAction({
      investigation: inv,
      candidates: [a1],
      scopePolicy: new ScopePolicy(),
    });
    // candidateScores includes the synthetic stop candidate.
    expect(out.decision.candidateScores.length).toBe(2);
  });

  it("budget pressure penalises scores under heavy load", () => {
    const inv = makeInvestigation({
      budgets: makeBudgets({ actionsRemaining: 1, toolCallsRemaining: 0, memoryPressure: 0.9 }),
    });
    const action = makeAction({
      estimatedExpectedPosteriorChange: 0.5,
      estimatedDecisionCriticality: 0.5,
      estimatedMissionValue: 0.5,
    });
    const lowPressure = scoreCandidate(action, makeBudgets());
    const highPressure = scoreCandidate(action, inv.budgets);
    expect(highPressure.budgetPressurePenalty).toBeGreaterThan(
      lowPressure.budgetPressurePenalty
    );
    expect(highPressure.finalScore).toBeLessThan(lowPressure.finalScore);
  });
});
