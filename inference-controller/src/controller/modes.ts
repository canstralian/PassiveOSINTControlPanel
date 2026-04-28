/**
 * Controller modes — explicit policy configurations with hysteresis.
 *
 * Modes are not hidden mood states. They are switched on explicit thresholds
 * with deadbands to avoid oscillation.
 */
import type { Investigation } from "../domain/types.js";
import { budgetPressure } from "./scoring.js";

export type ControllerMode = Investigation["mode"];

export type ModeSignals = {
  openContradictionCount: number;
  unsupportedHypothesisCount: number;
  hasFalsifiedAll: boolean;
  hasValidatedTop: boolean;
  budgetPressure: number;
  recoveryRequested: boolean;
};

const ENTER = {
  triage: { contradictions: 3 },
  recovery: {},
  exploitation: { unsupported: 1 },
  stop_review: { budgetPressure: 0.85 },
} as const;

const EXIT = {
  triage: { contradictions: 1 },
  exploitation: { unsupported: 0 },
  stop_review: { budgetPressure: 0.7 },
} as const;

/**
 * Selects the next controller mode using prioritized signals and configured hysteresis thresholds.
 *
 * Evaluates signals in priority order (recovery, stop_review, triage, exploitation, then exploration)
 * and applies enter/exit deadbands so modes are held or entered according to the configured thresholds.
 *
 * @param current - The controller's current mode
 * @param signals - Mode-related measurements:
 *   - openContradictionCount: number of unresolved contradictions
 *   - unsupportedHypothesisCount: number of hypotheses lacking required support/evidence
 *   - hasFalsifiedAll: true when all hypotheses have been falsified
 *   - hasValidatedTop: true when a top hypothesis has been validated
 *   - budgetPressure: normalized budget usage pressure (0–1)
 *   - recoveryRequested: true when recovery mode should be forced
 * @returns The chosen `ControllerMode`: one of "recovery", "stop_review", "triage", "exploitation", or "exploration"
 */
export function nextMode(current: ControllerMode, signals: ModeSignals): ControllerMode {
  // Recovery is highest-priority while requested.
  if (signals.recoveryRequested) return "recovery";

  // Stop review on heavy budget pressure or terminal results.
  if (signals.hasFalsifiedAll || signals.hasValidatedTop) return "stop_review";
  if (current === "stop_review" && signals.budgetPressure >= EXIT.stop_review.budgetPressure)
    return "stop_review";
  if (signals.budgetPressure >= ENTER.stop_review.budgetPressure) return "stop_review";

  // Triage on lots of unresolved contradictions.
  if (current === "triage") {
    if (signals.openContradictionCount > EXIT.triage.contradictions) return "triage";
  } else {
    if (signals.openContradictionCount >= ENTER.triage.contradictions) return "triage";
  }

  // Exploitation when at least one supported hypothesis is awaiting evidence.
  if (current === "exploitation") {
    if (signals.unsupportedHypothesisCount > EXIT.exploitation.unsupported) return "exploitation";
  } else {
    if (signals.unsupportedHypothesisCount >= ENTER.exploitation.unsupported) return "exploitation";
  }

  return "exploration";
}

/**
 * Compute a numeric budget-pressure signal from the given budget inputs.
 *
 * @param budgets - The budget descriptor (remaining/allocated resources and related fields) used to derive pressure
 * @returns A number between 0 and 1 representing budget pressure, where higher values indicate greater pressure
 */
export function deriveBudgetPressureSignal(
  budgets: Parameters<typeof budgetPressure>[0]
): number {
  return budgetPressure(budgets);
}
