import {
  type Budgets,
  type CandidateAction,
  type Evidence,
  type Hypothesis,
  type Investigation,
  type ObservationModel,
  type Provenance,
} from "../src/domain/types.js";
import {
  newActionId,
  newEvidenceId,
  newHypothesisId,
  newInvestigationId,
  newObservationModelId,
  newSourceId,
} from "../src/domain/ids.js";

export function makeBudgets(overrides: Partial<Budgets> = {}): Budgets {
  return {
    costRemaining: 100,
    latencyMsRemaining: 60_000,
    riskRemaining: 10,
    actionsRemaining: 50,
    recursionDepthRemaining: 10,
    branchCountRemaining: 10,
    toolCallsRemaining: 25,
    memoryPressure: 0,
    ...overrides,
  };
}

export function makeInvestigation(overrides: Partial<Investigation> = {}): Investigation {
  return {
    id: newInvestigationId(),
    description: "test investigation",
    createdAt: new Date(0).toISOString(),
    scope: {
      authorizedTargets: ["target.example"],
      authorizedToolIds: ["whois", "dns"],
      allowExternalActions: true,
      maxRiskWithoutApproval: "low",
    },
    budgets: makeBudgets(),
    mode: "exploration",
    ...overrides,
  };
}

export function makeHypothesis(overrides: Partial<Hypothesis> = {}): Hypothesis {
  return {
    id: newHypothesisId(),
    investigationId: "inv_test",
    statement: "the suspect controls target.example",
    lifecycle: "active",
    prior: 0.3,
    priorRationale: "default prior for unknown attribution",
    createdAt: new Date(0).toISOString(),
    mergeHistory: [],
    wakeConditions: [],
    ...overrides,
  };
}

export function makeProvenance(overrides: Partial<Provenance> = {}): Provenance {
  return {
    sourceId: newSourceId(),
    collectedAt: new Date(0).toISOString(),
    collector: "test-collector",
    locator: "test://locator",
    authorized: true,
    ...overrides,
  };
}

export function makeEvidence(overrides: Partial<Evidence> = {}): Evidence {
  return {
    id: newEvidenceId(),
    investigationId: "inv_test",
    observedAt: new Date(0).toISOString(),
    provenance: makeProvenance(),
    observationType: "primary_record",
    observedValue: { signal: 1 },
    affects: [{ hypothesisId: "hyp_test", polarityHint: "supports" }],
    ...overrides,
  };
}

export function makeObservationModel(
  overrides: Partial<ObservationModel> = {}
): ObservationModel {
  return {
    observationModelId: newObservationModelId(),
    kind: "bernoulli_likelihood",
    version: "1.0.0",
    parameters: {},
    ...overrides,
  };
}

export function makeAction(overrides: Partial<CandidateAction> = {}): CandidateAction {
  return {
    id: newActionId(),
    investigationId: "inv_test",
    kind: "inference",
    description: "infer",
    targets: [],
    estimatedExpectedPosteriorChange: 0.5,
    estimatedDecisionCriticality: 0.5,
    estimatedMissionValue: 0.5,
    estimatedCost: 0,
    estimatedLatencyMs: 0,
    estimatedRiskClass: "none",
    createdAt: new Date(0).toISOString(),
    ...overrides,
  };
}
