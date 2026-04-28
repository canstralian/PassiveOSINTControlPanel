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

/**
 * Create a Budgets object populated with sensible default limits.
 *
 * @param overrides - Partial budget fields to replace the defaults
 * @returns A Budgets object whose fields are the defaults with any provided overrides applied
 */
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

/**
 * Creates a deterministic test Investigation object populated with sensible defaults.
 *
 * The returned object includes a generated `id`, fixed `createdAt` timestamp, a default `scope`,
 * default `budgets`, and `mode` set to `"exploration"`. Any properties provided in `overrides`
 * replace the corresponding defaults.
 *
 * @param overrides - Partial fields to merge into the default Investigation; properties in this object override defaults
 * @returns An Investigation object with defaults applied and any `overrides` merged in
 */
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

/**
 * Create a Hypothesis object populated with deterministic test defaults.
 *
 * The returned object contains preset fields (including a generated `id`, fixed
 * `investigationId`, `statement`, `lifecycle`, `prior`, `priorRationale`,
 * `createdAt`, and empty `mergeHistory` and `wakeConditions`) that are useful
 * for tests and fixtures.
 *
 * @param overrides - Partial fields to replace or extend the default Hypothesis
 * @returns The constructed Hypothesis; any properties provided in `overrides`
 * replace the corresponding defaults
 */
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

/**
 * Create a Provenance object populated with deterministic test defaults.
 *
 * The returned object uses a generated `sourceId`, `collectedAt` set to the Unix epoch ISO timestamp, `collector` of `"test-collector"`, `locator` of `"test://locator"`, and `authorized: true`. Any fields provided in `overrides` replace the corresponding defaults.
 *
 * @param overrides - Partial fields to merge over the default Provenance
 * @returns A Provenance object with defaults applied and overridden by `overrides`
 */
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

/**
 * Create a deterministic Evidence object populated with sensible defaults for tests.
 *
 * The object includes a generated `id`, fixed `investigationId` and timestamps, a default `provenance`,
 * `observationType`, `observedValue`, and an `affects` entry; any properties provided in `overrides`
 * replace the corresponding defaults.
 *
 * @param overrides - Partial Evidence fields to merge over the defaults
 * @returns An Evidence object with defaults applied and `overrides` merged in
 */
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

/**
 * Create an ObservationModel with sensible defaults and apply any provided overrides.
 *
 * @param overrides - Partial properties to replace the defaults on the created ObservationModel
 * @returns An ObservationModel with a generated `observationModelId`, `kind` set to `"bernoulli_likelihood"`, `version` `"1.0.0"`, empty `parameters`, and any fields from `overrides` applied
 */
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

/**
 * Create a CandidateAction object populated with deterministic default fields for tests.
 *
 * Defaults include a generated `id`, fixed `investigationId` ("inv_test"), `kind` "inference",
 * default estimated metrics and timestamps; any properties provided in `overrides` replace the defaults.
 *
 * @param overrides - Partial fields to merge over the default CandidateAction
 * @returns The constructed CandidateAction with defaults merged with `overrides`
 */
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
