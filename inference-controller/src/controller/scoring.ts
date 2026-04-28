/**
 * Score decomposition for action selection.
 *
 * MVP formula (per spec):
 *   score = (expectedPosteriorChange * decisionCriticality * missionValue)
 *         - costPenalty
 *         - latencyPenalty
 *         - riskPenalty
 *         - budgetPressurePenalty
 *
 * The selected action MUST persist its full score decomposition. Selecting
 * a lower-scored action requires an `overrideReason`.
 */
import type {
  Budgets,
  CandidateAction,
  RiskClass,
  ScoreDecomposition,
} from "../domain/types.js";

export type ScoringWeights = {
  costPerUnit: number;
  latencyPerMs: number;
  riskPerLevel: Record<RiskClass, number>;
  budgetPressure: number;
};

export const DEFAULT_WEIGHTS: ScoringWeights = {
  costPerUnit: 0.01,
  latencyPerMs: 0.0001,
  riskPerLevel: {
    none: 0,
    low: 0.05,
    medium: 0.2,
    high: 0.5,
    destructive: 1.0,
  },
  budgetPressure: 0.5,
};

/**
 * Estimates overall budget pressure as a normalized value in [0, 1].
 *
 * Computes the average of multiple normalized "pressure" axes derived from remaining
 * budget fields (actions, tool calls, recursion depth, branch count, cost, latency)
 * plus `memoryPressure`, then caps the result at 1.
 *
 * @param b - Budget metrics used to compute pressure
 * @returns A number between 0 and 1 indicating aggregated budget pressure (higher is more constrained)
 */
export function budgetPressure(b: Budgets): number {
  // Pressure rises as remaining budgets fall, normalized into [0, 1].
  // Memory pressure already lives on [0,1]. Other axes are normalized
  // against generous defaults.
  const axes = [
    Math.max(0, 1 - b.actionsRemaining / 50),
    Math.max(0, 1 - b.toolCallsRemaining / 25),
    Math.max(0, 1 - b.recursionDepthRemaining / 10),
    Math.max(0, 1 - b.branchCountRemaining / 10),
    Math.max(0, 1 - b.costRemaining / 100),
    Math.max(0, 1 - b.latencyMsRemaining / 60_000),
    b.memoryPressure,
  ];
  const sum = axes.reduce((a, x) => a + x, 0);
  return Math.min(1, sum / axes.length);
}

/**
 * Compute a score decomposition for a candidate action using weighted penalties and value estimates.
 *
 * @param action - Candidate action containing estimatedPosteriorChange, estimatedDecisionCriticality, estimatedMissionValue, estimatedCost, estimatedLatencyMs, and estimatedRiskClass
 * @param budgets - Current budgets used to compute budget pressure
 * @param weights - Scoring coefficients to convert estimates into penalties (defaults to DEFAULT_WEIGHTS)
 * @returns A ScoreDecomposition with the input value components, computed penalties (`costPenalty`, `latencyPenalty`, `riskPenalty`, `budgetPressurePenalty`), the resulting `finalScore`, and a human-readable `explanation` string
 */
export function scoreCandidate(
  action: CandidateAction,
  budgets: Budgets,
  weights: ScoringWeights = DEFAULT_WEIGHTS
): ScoreDecomposition {
  const expectedPosteriorChange = action.estimatedExpectedPosteriorChange;
  const decisionCriticality = action.estimatedDecisionCriticality;
  const missionValue = action.estimatedMissionValue;
  const costPenalty = action.estimatedCost * weights.costPerUnit;
  const latencyPenalty = action.estimatedLatencyMs * weights.latencyPerMs;
  const riskPenalty = weights.riskPerLevel[action.estimatedRiskClass];
  const budgetPressurePenalty = budgetPressure(budgets) * weights.budgetPressure;

  const finalScore =
    expectedPosteriorChange * decisionCriticality * missionValue -
    costPenalty -
    latencyPenalty -
    riskPenalty -
    budgetPressurePenalty;

  const explanation =
    `epc(${expectedPosteriorChange.toFixed(3)}) * crit(${decisionCriticality.toFixed(3)}) * mission(${missionValue.toFixed(3)}) ` +
    `- cost(${costPenalty.toFixed(3)}) - latency(${latencyPenalty.toFixed(3)}) ` +
    `- risk(${riskPenalty.toFixed(3)}) - budget(${budgetPressurePenalty.toFixed(3)}) ` +
    `= ${finalScore.toFixed(3)}`;

  return {
    expectedPosteriorChange,
    decisionCriticality,
    missionValue,
    costPenalty,
    latencyPenalty,
    riskPenalty,
    budgetPressurePenalty,
    finalScore,
    explanation,
  };
}
