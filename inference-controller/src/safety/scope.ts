/**
 * Scope policy.
 *
 * Decides whether a candidate action is in-scope for a given investigation.
 * The system must NEVER infer permission. Anything not explicitly authorized
 * is denied.
 */
import type {
  CandidateAction,
  InvestigationScope,
  ValidationResult,
} from "../domain/types.js";

export type ScopeDecision =
  | { allowed: true; reasons: string[] }
  | { allowed: false; reasons: string[]; errorCode: "scope_denied" };

export class ScopePolicy {
  evaluate(action: CandidateAction, scope: InvestigationScope): ScopeDecision {
    const reasons: string[] = [];

    // Rule 1: external tool calls require allowExternalActions.
    if (action.kind === "external_tool_call") {
      if (!scope.allowExternalActions) {
        return {
          allowed: false,
          reasons: ["external actions disabled by investigation scope"],
          errorCode: "scope_denied",
        };
      }
      if (!action.toolRef) {
        return {
          allowed: false,
          reasons: ["external_tool_call requires toolRef"],
          errorCode: "scope_denied",
        };
      }
      if (!scope.authorizedToolIds.includes(action.toolRef.toolId)) {
        return {
          allowed: false,
          reasons: [`tool ${action.toolRef.toolId} not in authorized tool list`],
          errorCode: "scope_denied",
        };
      }
      reasons.push(`tool ${action.toolRef.toolId} authorized`);
    }

    // Rule 2: any external_target referenced must be in authorizedTargets.
    for (const target of action.targets) {
      if (target.kind === "external_target") {
        if (!scope.authorizedTargets.includes(target.refId)) {
          return {
            allowed: false,
            reasons: [`external target ${target.refId} not authorized`],
            errorCode: "scope_denied",
          };
        }
        reasons.push(`external target ${target.refId} authorized`);
      }
    }

    // Rule 3: merge actions involving merge_pair are always in-scope at
    // this stage; the approval gate handles major-merge approval.
    if (reasons.length === 0) {
      reasons.push("no out-of-scope targets");
    }
    return { allowed: true, reasons };
  }
}

/**
 * Convert a ScopeDecision into a ValidationResult.
 *
 * @param d - The scope decision produced by scope evaluation
 * @returns `{ ok: true }` when `d.allowed` is true; otherwise `{ ok: false, errorCode: "scope_denied", message }` where `message` is the decision reasons joined by `"; "`
 */
export function scopeDecisionToValidation(d: ScopeDecision): ValidationResult {
  if (d.allowed) return { ok: true };
  return {
    ok: false,
    errorCode: "scope_denied",
    message: d.reasons.join("; "),
  };
}
