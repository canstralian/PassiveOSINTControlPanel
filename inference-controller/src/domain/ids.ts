import { randomUUID } from "node:crypto";

export type HypothesisId = string & { readonly __brand: "HypothesisId" };
export type EvidenceId = string & { readonly __brand: "EvidenceId" };
export type ContradictionId = string & { readonly __brand: "ContradictionId" };
export type AssumptionContextId = string & { readonly __brand: "AssumptionContextId" };
export type ActionId = string & { readonly __brand: "ActionId" };
export type ActionDecisionId = string & { readonly __brand: "ActionDecisionId" };
export type AuditEventId = string & { readonly __brand: "AuditEventId" };
export type EventId = string & { readonly __brand: "EventId" };
export type SourceId = string & { readonly __brand: "SourceId" };
export type ObservationModelId = string & { readonly __brand: "ObservationModelId" };
export type InvestigationId = string & { readonly __brand: "InvestigationId" };
export type MergeId = string & { readonly __brand: "MergeId" };
export type RunId = string & { readonly __brand: "RunId" };

const mk = <T extends string>(prefix: string): (() => T) =>
  () => `${prefix}_${randomUUID()}` as T;

export const newHypothesisId = mk<HypothesisId>("hyp");
export const newEvidenceId = mk<EvidenceId>("ev");
export const newContradictionId = mk<ContradictionId>("contra");
export const newAssumptionContextId = mk<AssumptionContextId>("ctx");
export const newActionId = mk<ActionId>("act");
export const newActionDecisionId = mk<ActionDecisionId>("dec");
export const newAuditEventId = mk<AuditEventId>("audit");
export const newEventId = mk<EventId>("evt");
export const newSourceId = mk<SourceId>("src");
export const newObservationModelId = mk<ObservationModelId>("obsmodel");
export const newInvestigationId = mk<InvestigationId>("inv");
export const newMergeId = mk<MergeId>("merge");
export const newRunId = mk<RunId>("run");
