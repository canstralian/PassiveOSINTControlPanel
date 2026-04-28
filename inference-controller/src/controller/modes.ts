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

export function deriveBudgetPressureSignal(
  budgets: Parameters<typeof budgetPressure>[0]
): number {
  return budgetPressure(budgets);
}
