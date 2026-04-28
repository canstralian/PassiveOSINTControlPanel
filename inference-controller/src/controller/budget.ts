/**
 * Budget bookkeeping.
 *
 * Budgets are explicit and must be checked before each cycle and decremented
 * after each action attempt (regardless of success).
 */
import type { Budgets } from "../domain/types.js";

export class BudgetExhaustedError extends Error {
  constructor(public readonly axis: keyof Budgets) {
    super(`budget exhausted on axis: ${String(axis)}`);
    this.name = "BudgetExhaustedError";
  }
}

export function ensureBudgetAvailable(b: Budgets): void {
  if (b.actionsRemaining <= 0) throw new BudgetExhaustedError("actionsRemaining");
  if (b.toolCallsRemaining < 0) throw new BudgetExhaustedError("toolCallsRemaining");
  if (b.recursionDepthRemaining <= 0)
    throw new BudgetExhaustedError("recursionDepthRemaining");
  if (b.branchCountRemaining < 0) throw new BudgetExhaustedError("branchCountRemaining");
  if (b.costRemaining < 0) throw new BudgetExhaustedError("costRemaining");
  if (b.latencyMsRemaining < 0) throw new BudgetExhaustedError("latencyMsRemaining");
  if (b.riskRemaining < 0) throw new BudgetExhaustedError("riskRemaining");
  if (b.memoryPressure >= 1) throw new BudgetExhaustedError("memoryPressure");
}

export function debit(
  b: Budgets,
  patch: Partial<Pick<
    Budgets,
    | "costRemaining"
    | "latencyMsRemaining"
    | "actionsRemaining"
    | "toolCallsRemaining"
    | "branchCountRemaining"
    | "recursionDepthRemaining"
    | "riskRemaining"
  >>
): Budgets {
  return {
    ...b,
    costRemaining: Math.max(0, b.costRemaining - (patch.costRemaining ?? 0)),
    latencyMsRemaining: Math.max(
      0,
      b.latencyMsRemaining - (patch.latencyMsRemaining ?? 0)
    ),
    actionsRemaining: Math.max(0, b.actionsRemaining - (patch.actionsRemaining ?? 0)),
    toolCallsRemaining: Math.max(
      0,
      b.toolCallsRemaining - (patch.toolCallsRemaining ?? 0)
    ),
    branchCountRemaining: Math.max(
      0,
      b.branchCountRemaining - (patch.branchCountRemaining ?? 0)
    ),
    recursionDepthRemaining: Math.max(
      0,
      b.recursionDepthRemaining - (patch.recursionDepthRemaining ?? 0)
    ),
    riskRemaining: Math.max(0, b.riskRemaining - (patch.riskRemaining ?? 0)),
  };
}
