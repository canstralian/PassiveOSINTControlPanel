/**
 * External-action control chain.
 *
 * ScopePolicy -> RiskClassifier -> ApprovalGate -> AuditLogger ->
 * ToolGateway -> ResultValidator -> EventLogger -> BeliefGraphUpdater
 *
 * Each stage either passes through, denies, or causes fail-closed. No stage
 * may be bypassed. If audit logging fails, execution fails closed.
 */
import type {
  CandidateAction,
  Investigation,
  ValidationResult,
} from "../domain/types.js";
import type { ScopePolicy } from "../safety/scope.js";
import { scopeDecisionToValidation } from "../safety/scope.js";
import type { RiskClassifier } from "../safety/risk.js";
import type { ApprovalGate } from "../safety/approval.js";
import type { AuditLogger } from "../audit/logger.js";
import type { ToolGateway, ToolResultEnvelope } from "../tools/gateway.js";
import type { ResultValidator } from "../tools/validator.js";
import type { EventLogger } from "../audit/events.js";
import { newEventId } from "../domain/ids.js";

export type ExternalActionOutcome =
  | {
      ok: true;
      result: ToolResultEnvelope;
      validation: ValidationResult;
    }
  | {
      ok: false;
      stage:
        | "scope"
        | "risk"
        | "approval"
        | "audit"
        | "tool"
        | "result_validation"
        | "input";
      validation: ValidationResult;
      failClosed: boolean;
    };

export type ExternalActionDeps = {
  scopePolicy: ScopePolicy;
  riskClassifier: RiskClassifier;
  approvalGate: ApprovalGate;
  auditLogger: AuditLogger;
  toolGateway: ToolGateway;
  resultValidator: ResultValidator;
  eventLogger: EventLogger;
};

export type ExternalActionRequest = {
  investigation: Investigation;
  action: CandidateAction;
  actor: string;
};

export async function runExternalAction(
  deps: ExternalActionDeps,
  req: ExternalActionRequest
): Promise<ExternalActionOutcome> {
  const { investigation, action, actor } = req;

  if (action.kind !== "external_tool_call" || !action.toolRef) {
    return {
      ok: false,
      stage: "input",
      failClosed: false,
      validation: {
        ok: false,
        errorCode: "schema_invalid",
        message: "runExternalAction requires kind=external_tool_call with toolRef",
      },
    };
  }

  // 1. Scope.
  const scopeDec = deps.scopePolicy.evaluate(action, investigation.scope);
  const scopeOutcome = scopeDec.allowed ? "allowed" : "denied";
  if (!scopeDec.allowed) {
    try {
      await deps.auditLogger.record({
        actor,
        investigationId: investigation.id,
        operation: "scope_decision",
        inputRefs: [action.id],
        scopeDecision: "denied",
        riskDecision: "n/a",
      });
    } catch {
      return {
        ok: false,
        stage: "audit",
        failClosed: true,
        validation: {
          ok: false,
          errorCode: "audit_unavailable",
          message: "audit unavailable while logging scope denial",
        },
      };
    }
    return {
      ok: false,
      stage: "scope",
      failClosed: false,
      validation: scopeDecisionToValidation(scopeDec),
    };
  }

  // 2. Risk.
  const riskDec = deps.riskClassifier.classify(
    action,
    investigation.scope.maxRiskWithoutApproval
  );
  const needsApproval = "needsApproval" in riskDec && riskDec.needsApproval;

  // 3. Approval (only if needed).
  let approvalDecision: "granted" | "denied" | "not_required" = "not_required";
  let approvalReason: string | undefined;
  if (needsApproval) {
    const decision = deps.approvalGate.decide({
      investigationId: investigation.id,
      actionId: action.id,
      reason: riskDec.reason,
    });
    if (!decision.granted) {
      approvalDecision = "denied";
      approvalReason = decision.reason;
      try {
        await deps.auditLogger.record({
          actor,
          investigationId: investigation.id,
          operation: "approval_decision",
          inputRefs: [action.id],
          scopeDecision: "allowed",
          riskDecision: "needs_approval",
          approvalDecision: "denied",
        });
      } catch {
        return {
          ok: false,
          stage: "audit",
          failClosed: true,
          validation: {
            ok: false,
            errorCode: "audit_unavailable",
            message: "audit unavailable while logging approval denial",
          },
        };
      }
      return {
        ok: false,
        stage: "approval",
        failClosed: false,
        validation: {
          ok: false,
          errorCode: "approval_missing",
          message: approvalReason,
        },
      };
    }
    approvalDecision = "granted";
  }

  // 4. Audit (pre-execution). Must succeed before tool call.
  try {
    await deps.auditLogger.record({
      actor,
      investigationId: investigation.id,
      operation: "tool_call_attempted",
      inputRefs: [action.id, action.toolRef.toolId],
      scopeDecision: scopeOutcome,
      riskDecision: needsApproval ? "needs_approval" : "below_threshold",
      ...(needsApproval ? { approvalDecision } : {}),
    });
  } catch {
    return {
      ok: false,
      stage: "audit",
      failClosed: true,
      validation: {
        ok: false,
        errorCode: "audit_unavailable",
        message: "audit unavailable; refusing to execute tool",
      },
    };
  }

  // 5. Tool gateway.
  const envelope = await deps.toolGateway.invoke({
    toolId: action.toolRef.toolId,
    input: action.toolRef.input,
    context: {
      investigationId: investigation.id,
      actionId: action.id,
    },
  });

  // 6. Result validation.
  const validation = deps.resultValidator.validate(envelope);

  // 7. Audit (post-execution). Must succeed.
  try {
    await deps.auditLogger.record({
      actor,
      investigationId: investigation.id,
      operation: validation.ok ? "tool_call_validated" : "tool_call_executed",
      inputRefs: [action.id, action.toolRef.toolId],
      scopeDecision: scopeOutcome,
      riskDecision: needsApproval ? "needs_approval" : "below_threshold",
      ...(needsApproval ? { approvalDecision } : {}),
    });
  } catch {
    return {
      ok: false,
      stage: "audit",
      failClosed: true,
      validation: {
        ok: false,
        errorCode: "audit_unavailable",
        message: "audit unavailable while logging tool result",
      },
    };
  }

  // 8. Domain event (only on validated success). The caller is responsible
  // for invoking BeliefGraphUpdater with grounded evidence; we do not
  // synthesize evidence from raw tool output.
  if (validation.ok) {
    deps.eventLogger.emit({
      id: newEventId(),
      investigationId: investigation.id,
      kind: "graph_node_added",
      payload: { actionId: action.id, toolId: action.toolRef.toolId },
      timestamp: new Date().toISOString(),
    });
    return { ok: true, result: envelope, validation };
  }
  return {
    ok: false,
    stage: envelope.ok ? "result_validation" : "tool",
    failClosed: false,
    validation,
  };
}
