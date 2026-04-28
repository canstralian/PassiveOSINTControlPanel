/**
 * Public API surface.
 */
export * from "./domain/types.js";
export * as ids from "./domain/ids.js";
export * from "./domain/lifecycle.js";

export { AuditLogger, InMemoryAuditSink, JsonlFileAuditSink, verifyAuditChain } from "./audit/logger.js";
export type { AuditPayload, AuditSink } from "./audit/logger.js";
export { EventLogger } from "./audit/events.js";

export { ScopePolicy, scopeDecisionToValidation } from "./safety/scope.js";
export type { ScopeDecision } from "./safety/scope.js";
export { RiskClassifier } from "./safety/risk.js";
export type { RiskDecision } from "./safety/risk.js";
export { ApprovalGate } from "./safety/approval.js";
export type { ApprovalDecision, ApprovalRequest } from "./safety/approval.js";

export { ToolGateway } from "./tools/gateway.js";
export type { ToolHandler, ToolInvocation, ToolResultEnvelope } from "./tools/gateway.js";
export { ResultValidator } from "./tools/validator.js";

export { BeliefGraph, GraphValidationError } from "./graph/belief-graph.js";
export type { GraphEdge, EdgeKind } from "./graph/belief-graph.js";
export { BeliefGraphUpdater, bayesUpdate, CODE_VERSION } from "./graph/update.js";
export type { UpdateRequest, UpdateOutcome } from "./graph/update.js";
export { ContradictionService } from "./graph/contradictions.js";
export { MergeService } from "./graph/merge.js";
export type { MergeKind, MergeRecord } from "./graph/merge.js";

export {
  scoreCandidate,
  budgetPressure,
  DEFAULT_WEIGHTS,
} from "./controller/scoring.js";
export type { ScoringWeights } from "./controller/scoring.js";
export { Controller, debitForAction } from "./controller/controller.js";
export type { CycleInput, CycleOutput } from "./controller/controller.js";
export {
  ensureBudgetAvailable,
  debit,
  BudgetExhaustedError,
} from "./controller/budget.js";
export { evaluateStop, makeStopCandidate } from "./controller/stop.js";
export type { StopReason, StopSignal, StopInputs } from "./controller/stop.js";
export { nextMode, deriveBudgetPressureSignal } from "./controller/modes.js";
export type { ControllerMode, ModeSignals } from "./controller/modes.js";

export { runExternalAction } from "./chains/external-action.js";
export type {
  ExternalActionOutcome,
  ExternalActionDeps,
  ExternalActionRequest,
} from "./chains/external-action.js";
export { runStateMutation } from "./chains/state-mutation.js";
export type {
  StateMutationOutcome,
  StateMutationRequest,
} from "./chains/state-mutation.js";
