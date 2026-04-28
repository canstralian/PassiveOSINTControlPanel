/**
 * Stop conditions.
 *
 * Every controller cycle must consider `stop_and_report`. Stop conditions
 * are implemented BEFORE any autonomous loop is allowed to run.
 */
import type { Budgets, CandidateAction } from "../domain/types.js";
import { budgetPressure } from "./scoring.js";
import { newActionId } from "../domain/ids.js";

export type StopReason =
  | "budget_exhausted"
  | "no_admissible_actions"
  | "all_top_actions_below_threshold"
  | "validated_top_hypothesis"
  | "falsified_all_active_hypotheses"
  | "manual_stop_requested"
  | "fail_closed";

export type StopSignal = {
  shouldStop: boolean;
  reasons: StopReason[];
};

export type StopInputs = {
  budgets: Budgets;
  admissibleActionCount: number;
  topActionScore: number;
  scoreThreshold: number;
  hasValidatedTopHypothesis: boolean;
  hasFalsifiedAllActive: boolean;
  manualStopRequested: boolean;
  failClosed: boolean;
};

export function evaluateStop(inputs: StopInputs): StopSignal {
  const reasons: StopReason[] = [];
  if (inputs.failClosed) reasons.push("fail_closed");
  if (inputs.manualStopRequested) reasons.push("manual_stop_requested");
  if (
    inputs.budgets.actionsRemaining <= 0 ||
    budgetPressure(inputs.budgets) >= 0.99
  ) {
    reasons.push("budget_exhausted");
  }
  if (inputs.admissibleActionCount === 0) {
    reasons.push("no_admissible_actions");
  } else if (inputs.topActionScore < inputs.scoreThreshold) {
    reasons.push("all_top_actions_below_threshold");
  }
  if (inputs.hasValidatedTopHypothesis) reasons.push("validated_top_hypothesis");
  if (inputs.hasFalsifiedAllActive) reasons.push("falsified_all_active_hypotheses");
  return { shouldStop: reasons.length > 0, reasons };
}

/** Generate a `stop_and_report` candidate action so it is always considered. */
export function makeStopCandidate(investigationId: string, now: Date = new Date()): CandidateAction {
  return {
    id: newActionId(),
    investigationId,
    kind: "stop_and_report",
    description: "stop and emit final report",
    targets: [],
    estimatedExpectedPosteriorChange: 0,
    estimatedDecisionCriticality: 0.1,
    estimatedMissionValue: 0.1,
    estimatedCost: 0,
    estimatedLatencyMs: 0,
    estimatedRiskClass: "none",
    createdAt: now.toISOString(),
  };
}
