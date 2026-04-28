/**
 * Domain schemas for the inference controller.
 *
 * The schemas keep the following concepts separate, per spec:
 * Hypotheses, Evidence, Provenance, Source reliability, Observation models,
 * Belief states, Contradictions, Assumption contexts, Candidate actions,
 * Action decisions, Lifecycle states, Validation results, Audit events.
 *
 * These must NOT be collapsed into a single `confidence`/`score`/`status`
 * or free-form metadata field.
 */
import { z } from "zod";

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

export const LifecycleState = z.enum([
  "candidate",
  "active",
  "supported",
  "challenged",
  "inactive",
  "blocked",
  "merged",
  "soft_closed",
  "reactivated",
  "validated",
  "falsified",
  "archived",
]);
export type LifecycleState = z.infer<typeof LifecycleState>;

// ---------------------------------------------------------------------------
// Provenance, sources, observation models
// ---------------------------------------------------------------------------

export const SourceReliability = z.object({
  sourceId: z.string().min(1),
  // Reliability is heuristic — it gates participation in formal updates,
  // but it is NOT a posterior contribution by itself.
  reliabilityClass: z.enum(["A", "B", "C", "D", "E", "F"]),
  // Optional numeric prior on the source being correct, used in
  // observation models that consume it.
  reliabilityPrior: z.number().min(0).max(1).optional(),
  notes: z.string().optional(),
});
export type SourceReliability = z.infer<typeof SourceReliability>;

export const Provenance = z.object({
  sourceId: z.string().min(1),
  collectedAt: z.string().datetime(),
  collector: z.string().min(1),
  // Free-form locator (URL, hash, file id). Required so material operations
  // are reconstructable from audit + domain records.
  locator: z.string().min(1),
  // Whether the collection was authorized.
  authorized: z.boolean(),
  // Optional assumption context this provenance is valid under.
  assumptionContextId: z.string().optional(),
});
export type Provenance = z.infer<typeof Provenance>;

export const ObservationModel = z.object({
  observationModelId: z.string().min(1),
  // Closed enum of supported update primitives. Heuristic signals do NOT
  // use one of these — they go through the agenda layer instead.
  kind: z.enum([
    "bernoulli_likelihood",
    "categorical_likelihood",
    "gaussian_likelihood",
    "log_odds_increment",
  ]),
  version: z.string().min(1),
  // Free-form parameter object the update primitive understands.
  parameters: z.record(z.unknown()),
});
export type ObservationModel = z.infer<typeof ObservationModel>;

// ---------------------------------------------------------------------------
// Hypotheses
// ---------------------------------------------------------------------------

export const Hypothesis = z.object({
  id: z.string().min(1),
  investigationId: z.string().min(1),
  statement: z.string().min(1),
  lifecycle: LifecycleState,
  // Prior is required to drive formal posterior calculation. It can be a
  // declared default (e.g. 0.5) but it must be present and traceable.
  prior: z.number().min(0).max(1),
  priorRationale: z.string().min(1),
  createdAt: z.string().datetime(),
  // The assumption context under which this hypothesis is meaningful.
  assumptionContextId: z.string().optional(),
  // History of merges this hypothesis is part of (so reversibility is
  // explicit).
  mergeHistory: z.array(z.string()).default([]),
  // Whether soft-close wake conditions are armed.
  wakeConditions: z
    .array(
      z.object({
        kind: z.enum(["new_evidence_about", "evidence_threshold", "deadline"]),
        descriptor: z.string().min(1),
      })
    )
    .default([]),
});
export type Hypothesis = z.infer<typeof Hypothesis>;

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

export const Evidence = z.object({
  id: z.string().min(1),
  investigationId: z.string().min(1),
  observedAt: z.string().datetime(),
  // Provenance is OPTIONAL at the storage layer (per spec point 7:
  // "Evidence without provenance may be stored, but cannot drive formal
  // belief updates"). The belief updater enforces presence at update time.
  provenance: Provenance.optional(),
  observationType: z.enum([
    "primary_record",
    "derived_signal",
    "report",
    "statement",
    "measurement",
    "model_output",
  ]),
  // Free-form observed value; the observation model interprets it.
  observedValue: z.unknown(),
  // Hypotheses this evidence may bear on, plus the directional polarity
  // hint (this hint is heuristic; the formal contribution comes from the
  // observation model).
  affects: z.array(
    z.object({
      hypothesisId: z.string().min(1),
      polarityHint: z.enum(["supports", "opposes", "neutral"]).default("neutral"),
    })
  ),
  // Correlation group lets the updater avoid double-counting evidence
  // produced by the same upstream cause.
  correlationGroupId: z.string().optional(),
});
export type Evidence = z.infer<typeof Evidence>;

// ---------------------------------------------------------------------------
// Belief state
// ---------------------------------------------------------------------------

export const BeliefState = z.object({
  hypothesisId: z.string().min(1),
  // Posterior is ONLY produced by formal updates. Heuristic agendas do not
  // touch it.
  posterior: z.number().min(0).max(1),
  // Trace of the chain of updates that produced this posterior.
  updateTrace: z.array(
    z.object({
      evidenceId: z.string().min(1),
      observationModelId: z.string().min(1),
      modelVersion: z.string().min(1),
      codeVersion: z.string().min(1),
      priorBefore: z.number().min(0).max(1),
      posteriorAfter: z.number().min(0).max(1),
      correlationGroupId: z.string().optional(),
      timestamp: z.string().datetime(),
    })
  ),
  // Heuristic agenda priority (NOT the posterior).
  agendaPriority: z.number().min(0).max(1).default(0),
  lastUpdatedAt: z.string().datetime(),
});
export type BeliefState = z.infer<typeof BeliefState>;

// ---------------------------------------------------------------------------
// Contradictions
// ---------------------------------------------------------------------------

export const ContradictionType = z.enum([
  "logical_defeat",
  "evidence_conflict",
  "assumption_conflict",
  "policy_conflict",
  "scope_conflict",
  "temporal_conflict",
]);
export type ContradictionType = z.infer<typeof ContradictionType>;

export const ContradictionResolution = z.enum([
  "open",
  "blocked",
  "deprioritized",
  "marked_unsupported",
  "resolved_by_evidence",
  "resolved_by_assumption_change",
]);
export type ContradictionResolution = z.infer<typeof ContradictionResolution>;

export const Contradiction = z.object({
  id: z.string().min(1),
  investigationId: z.string().min(1),
  // The "owner" side of the contradiction.
  affected: z.object({
    kind: z.enum(["hypothesis", "evidence", "assumption", "context"]),
    refId: z.string().min(1),
  }),
  // The conflicting side.
  conflicting: z.object({
    kind: z.enum(["hypothesis", "evidence", "assumption", "context"]),
    refId: z.string().min(1),
  }),
  contradictionType: ContradictionType,
  // Defeat or block rule reference (optional).
  rule: z.string().optional(),
  resolution: ContradictionResolution,
  // Action(s) generated to disambiguate, if any.
  generatedActionIds: z.array(z.string()).default([]),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});
export type Contradiction = z.infer<typeof Contradiction>;

// ---------------------------------------------------------------------------
// Assumption contexts
// ---------------------------------------------------------------------------

export const AssumptionContext = z.object({
  id: z.string().min(1),
  investigationId: z.string().min(1),
  description: z.string().min(1),
  assumptions: z.array(z.string()),
  active: z.boolean(),
  createdAt: z.string().datetime(),
});
export type AssumptionContext = z.infer<typeof AssumptionContext>;

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export const ActionKind = z.enum([
  "inference",
  "observation",
  "experiment",
  "merge",
  "contradiction_resolution",
  "validation",
  "recovery",
  "stop_and_report",
  "external_tool_call",
]);
export type ActionKind = z.infer<typeof ActionKind>;

export const RiskClass = z.enum(["none", "low", "medium", "high", "destructive"]);
export type RiskClass = z.infer<typeof RiskClass>;

export const CandidateAction = z.object({
  id: z.string().min(1),
  investigationId: z.string().min(1),
  kind: ActionKind,
  // Human-readable description.
  description: z.string().min(1),
  // What this action would touch (used by ScopePolicy).
  targets: z.array(
    z.object({
      kind: z.enum([
        "hypothesis",
        "evidence",
        "context",
        "tool",
        "external_target",
        "merge_pair",
      ]),
      refId: z.string().min(1),
    })
  ),
  // Estimated values populated by the controller / scoring functions.
  estimatedExpectedPosteriorChange: z.number().min(0).max(1).default(0),
  estimatedDecisionCriticality: z.number().min(0).max(1).default(0),
  estimatedMissionValue: z.number().min(0).max(1).default(0),
  estimatedCost: z.number().nonnegative().default(0),
  estimatedLatencyMs: z.number().nonnegative().default(0),
  estimatedRiskClass: RiskClass.default("none"),
  // For external_tool_call only.
  toolRef: z
    .object({
      toolId: z.string().min(1),
      input: z.unknown(),
    })
    .optional(),
  createdAt: z.string().datetime(),
});
export type CandidateAction = z.infer<typeof CandidateAction>;

export const ScoreDecomposition = z.object({
  expectedPosteriorChange: z.number(),
  decisionCriticality: z.number(),
  missionValue: z.number(),
  costPenalty: z.number(),
  latencyPenalty: z.number(),
  riskPenalty: z.number(),
  budgetPressurePenalty: z.number(),
  finalScore: z.number(),
  explanation: z.string().min(1),
});
export type ScoreDecomposition = z.infer<typeof ScoreDecomposition>;

export const ActionDecision = z.object({
  id: z.string().min(1),
  investigationId: z.string().min(1),
  selectedActionId: z.string().min(1),
  // Persisted score decomposition for the selected action.
  score: ScoreDecomposition,
  // Score decompositions for all admissible candidates considered.
  candidateScores: z.array(
    z.object({
      candidateId: z.string().min(1),
      score: ScoreDecomposition,
    })
  ),
  // If a non-top action was chosen, this MUST be present.
  overrideReason: z.string().optional(),
  // Mode at the time of decision.
  mode: z.enum(["exploration", "triage", "exploitation", "recovery", "stop_review"]),
  decidedAt: z.string().datetime(),
});
export type ActionDecision = z.infer<typeof ActionDecision>;

// ---------------------------------------------------------------------------
// Validation results (returned by validators / ResultValidator)
// ---------------------------------------------------------------------------

export const ValidationResult = z.object({
  ok: z.boolean(),
  // Closed enum of error codes for machine-checkable failure cases.
  errorCode: z
    .enum([
      "schema_invalid",
      "scope_denied",
      "risk_threshold_exceeded",
      "approval_missing",
      "audit_unavailable",
      "tool_failure",
      "result_invalid",
      "lifecycle_invalid_transition",
      "provenance_missing",
      "merge_unauthorized",
      "budget_exceeded",
    ])
    .optional(),
  message: z.string().optional(),
  details: z.record(z.unknown()).optional(),
});
export type ValidationResult = z.infer<typeof ValidationResult>;

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

export const AuditOperation = z.enum([
  "investigation_created",
  "hypothesis_created",
  "hypothesis_lifecycle_changed",
  "evidence_added",
  "belief_updated",
  "contradiction_recorded",
  "contradiction_resolved",
  "merge_proposed",
  "merge_committed",
  "merge_reverted",
  "scope_decision",
  "risk_decision",
  "approval_decision",
  "tool_call_attempted",
  "tool_call_executed",
  "tool_call_validated",
  "action_selected",
  "controller_cycle",
  "stop_emitted",
  "fail_closed",
]);
export type AuditOperation = z.infer<typeof AuditOperation>;

export const AuditEvent = z.object({
  id: z.string().min(1),
  actor: z.string().min(1),
  investigationId: z.string().min(1),
  operation: AuditOperation,
  inputRefs: z.array(z.string()),
  scopeDecision: z.enum(["allowed", "denied", "n/a"]),
  riskDecision: z.enum(["below_threshold", "needs_approval", "denied", "n/a"]),
  approvalDecision: z.enum(["granted", "denied", "not_required", "pending"]).optional(),
  previousStateRef: z.string().optional(),
  newStateRef: z.string().optional(),
  timestamp: z.string().datetime(),
  // Hash of (previous integrity marker || canonical payload). Append-only
  // chain.
  integrityMarker: z.string().min(1),
});
export type AuditEvent = z.infer<typeof AuditEvent>;

// ---------------------------------------------------------------------------
// Domain events (lower-cost than audit; for graph deltas etc.)
// ---------------------------------------------------------------------------

export const DomainEvent = z.object({
  id: z.string().min(1),
  investigationId: z.string().min(1),
  kind: z.enum([
    "graph_node_added",
    "graph_edge_added",
    "graph_node_updated",
    "belief_updated",
    "contradiction_changed",
    "merge_changed",
    "mode_changed",
    "budget_changed",
    "stop_signal",
  ]),
  payload: z.record(z.unknown()),
  timestamp: z.string().datetime(),
});
export type DomainEvent = z.infer<typeof DomainEvent>;

// ---------------------------------------------------------------------------
// Budgets
// ---------------------------------------------------------------------------

export const Budgets = z.object({
  costRemaining: z.number().nonnegative(),
  latencyMsRemaining: z.number().nonnegative(),
  riskRemaining: z.number().nonnegative(),
  actionsRemaining: z.number().int().nonnegative(),
  recursionDepthRemaining: z.number().int().nonnegative(),
  branchCountRemaining: z.number().int().nonnegative(),
  toolCallsRemaining: z.number().int().nonnegative(),
  memoryPressure: z.number().min(0).max(1),
});
export type Budgets = z.infer<typeof Budgets>;

// ---------------------------------------------------------------------------
// Investigation
// ---------------------------------------------------------------------------

export const InvestigationScope = z.object({
  // Targets the investigation is permitted to interact with.
  authorizedTargets: z.array(z.string()),
  // Tools the investigation is permitted to use.
  authorizedToolIds: z.array(z.string()),
  // Whether external network actions are permitted at all.
  allowExternalActions: z.boolean(),
  // Maximum risk class allowed without approval.
  maxRiskWithoutApproval: RiskClass,
});
export type InvestigationScope = z.infer<typeof InvestigationScope>;

export const Investigation = z.object({
  id: z.string().min(1),
  description: z.string().min(1),
  createdAt: z.string().datetime(),
  scope: InvestigationScope,
  budgets: Budgets,
  mode: z.enum(["exploration", "triage", "exploitation", "recovery", "stop_review"]),
});
export type Investigation = z.infer<typeof Investigation>;
