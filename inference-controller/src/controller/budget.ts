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

/**
 * Validates that all budget axes are within allowed ranges and throws if any are exhausted or invalid.
 *
 * @param b - The budgets object to validate
 * @throws BudgetExhaustedError when a specific budget axis is exhausted or out of range:
 * - `actionsRemaining` if <= 0
 * - `toolCallsRemaining` if < 0
 * - `recursionDepthRemaining` if <= 0
 * - `branchCountRemaining` if < 0
 * - `costRemaining` if < 0
 * - `latencyMsRemaining` if < 0
 * - `riskRemaining` if < 0
 * - `memoryPressure` if >= 1
 */
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

/**
 * Produce a new Budgets object with selected remaining-budget axes decremented by the provided patch amounts.
 *
 * @param b - The current budgets to debit from
 * @param patch - Partial set of budget axes and the amounts to subtract from each axis; unspecified axes are unchanged
 * @returns A new Budgets object where each patched axis has been reduced by the corresponding amount and clamped to a minimum of 0
 */
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
