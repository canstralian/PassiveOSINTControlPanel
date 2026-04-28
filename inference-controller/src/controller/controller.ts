/**
 * Controller.
 *
 * Selects the next action over a candidate set using explicit score
 * decomposition. Persists the decomposition. Honors override reasons.
 * Always considers `stop_and_report`.
 */
import type {
  ActionDecision,
  Budgets,
  CandidateAction,
  Investigation,
  ScoreDecomposition,
} from "../domain/types.js";
import { scoreCandidate, DEFAULT_WEIGHTS, type ScoringWeights } from "./scoring.js";
import { newActionDecisionId } from "../domain/ids.js";
import { evaluateStop, makeStopCandidate } from "./stop.js";
import type { ScopePolicy } from "../safety/scope.js";

export type CycleInput = {
  investigation: Investigation;
  candidates: CandidateAction[];
  scopePolicy: ScopePolicy;
  scoreThreshold?: number;
  manualStopRequested?: boolean;
  failClosed?: boolean;
  override?: { actionId: string; reason: string };
  weights?: ScoringWeights;
  now?: Date;
  // Signals required for stop evaluation but produced outside the
  // controller (validated/falsified hypothesis state).
  hasValidatedTopHypothesis?: boolean;
  hasFalsifiedAllActive?: boolean;
};

export type CycleOutput = {
  decision: ActionDecision;
  stopSignal: ReturnType<typeof evaluateStop>;
};

export class Controller {
  selectAction(input: CycleInput): CycleOutput {
    const now = input.now ?? new Date();
    const weights = input.weights ?? DEFAULT_WEIGHTS;
    const stopCandidate = makeStopCandidate(input.investigation.id, now);
    const candidatePool: CandidateAction[] = [...input.candidates, stopCandidate];

    const admissible = candidatePool.filter((c) => {
      const dec = input.scopePolicy.evaluate(c, input.investigation.scope);
      return dec.allowed;
    });

    const scored = admissible.map((c) => ({
      candidate: c,
      score: scoreCandidate(c, input.investigation.budgets, weights),
    }));

    // Highest finalScore wins. Tiebreak deterministically by id.
    scored.sort((a, b) => {
      if (b.score.finalScore !== a.score.finalScore) {
        return b.score.finalScore - a.score.finalScore;
      }
      return a.candidate.id.localeCompare(b.candidate.id);
    });

    const top = scored[0];
    if (!top) {
      throw new Error(
        "no admissible actions even with stop_and_report; controller is misconfigured"
      );
    }

    let selected: { candidate: CandidateAction; score: ScoreDecomposition };
    let overrideReason: string | undefined;
    if (input.override) {
      const found = scored.find((s) => s.candidate.id === input.override!.actionId);
      if (!found) {
        throw new Error(
          `override targets non-admissible/non-existent action: ${input.override.actionId}`
        );
      }
      selected = found;
      overrideReason = input.override.reason;
    } else {
      selected = top;
    }

    const stopSignal = evaluateStop({
      budgets: input.investigation.budgets,
      admissibleActionCount: admissible.length - 1, // exclude stop itself
      topActionScore: top.score.finalScore,
      scoreThreshold: input.scoreThreshold ?? 0,
      hasValidatedTopHypothesis: input.hasValidatedTopHypothesis ?? false,
      hasFalsifiedAllActive: input.hasFalsifiedAllActive ?? false,
      manualStopRequested: input.manualStopRequested ?? false,
      failClosed: input.failClosed ?? false,
    });

    const decision: ActionDecision = {
      id: newActionDecisionId(),
      investigationId: input.investigation.id,
      selectedActionId: selected.candidate.id,
      score: selected.score,
      candidateScores: scored.map((s) => ({
        candidateId: s.candidate.id,
        score: s.score,
      })),
      ...(overrideReason !== undefined ? { overrideReason } : {}),
      mode: input.investigation.mode,
      decidedAt: now.toISOString(),
    };
    return { decision, stopSignal };
  }
}

export function debitForAction(
  budgets: Budgets,
  action: CandidateAction
): Budgets {
  return {
    ...budgets,
    costRemaining: Math.max(0, budgets.costRemaining - action.estimatedCost),
    latencyMsRemaining: Math.max(
      0,
      budgets.latencyMsRemaining - action.estimatedLatencyMs
    ),
    actionsRemaining: Math.max(0, budgets.actionsRemaining - 1),
    toolCallsRemaining:
      action.kind === "external_tool_call"
        ? Math.max(0, budgets.toolCallsRemaining - 1)
        : budgets.toolCallsRemaining,
  };
}
