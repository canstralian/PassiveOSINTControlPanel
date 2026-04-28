/**
 * Typed probabilistic evidence graph store.
 *
 * Hypotheses, evidence, contradictions, and edges are stored as separate
 * collections with cross-references. The store does not perform any belief
 * arithmetic — that is the BeliefGraphUpdater's job.
 */
import type {
  Hypothesis,
  Evidence,
  Contradiction,
  BeliefState,
  AssumptionContext,
  ObservationModel,
} from "../domain/types.js";

export type EdgeKind =
  | "evidence_affects_hypothesis"
  | "hypothesis_under_context"
  | "evidence_under_context"
  | "contradiction_links"
  | "merge_links";

export type GraphEdge = {
  id: string;
  kind: EdgeKind;
  fromKind: "hypothesis" | "evidence" | "contradiction" | "context" | "merge";
  fromId: string;
  toKind: "hypothesis" | "evidence" | "contradiction" | "context" | "merge";
  toId: string;
};

export class GraphValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GraphValidationError";
  }
}

export class BeliefGraph {
  private readonly hypotheses = new Map<string, Hypothesis>();
  private readonly evidence = new Map<string, Evidence>();
  private readonly contradictions = new Map<string, Contradiction>();
  private readonly contexts = new Map<string, AssumptionContext>();
  private readonly observationModels = new Map<string, ObservationModel>();
  private readonly beliefs = new Map<string, BeliefState>();
  private readonly edges = new Map<string, GraphEdge>();

  // -------- Hypotheses --------

  addHypothesis(h: Hypothesis): void {
    if (this.hypotheses.has(h.id)) {
      throw new GraphValidationError(`duplicate hypothesis id: ${h.id}`);
    }
    if (h.assumptionContextId && !this.contexts.has(h.assumptionContextId)) {
      throw new GraphValidationError(
        `hypothesis references unknown context: ${h.assumptionContextId}`
      );
    }
    this.hypotheses.set(h.id, h);
  }

  updateHypothesis(h: Hypothesis): void {
    if (!this.hypotheses.has(h.id)) {
      throw new GraphValidationError(`unknown hypothesis: ${h.id}`);
    }
    this.hypotheses.set(h.id, h);
  }

  getHypothesis(id: string): Hypothesis | undefined {
    return this.hypotheses.get(id);
  }

  allHypotheses(): readonly Hypothesis[] {
    return Array.from(this.hypotheses.values());
  }

  // -------- Evidence --------

  addEvidence(e: Evidence): void {
    if (this.evidence.has(e.id)) {
      throw new GraphValidationError(`duplicate evidence id: ${e.id}`);
    }
    for (const link of e.affects) {
      if (!this.hypotheses.has(link.hypothesisId)) {
        throw new GraphValidationError(
          `evidence ${e.id} references unknown hypothesis: ${link.hypothesisId}`
        );
      }
    }
    this.evidence.set(e.id, e);
  }

  getEvidence(id: string): Evidence | undefined {
    return this.evidence.get(id);
  }

  evidenceFor(hypothesisId: string): readonly Evidence[] {
    return Array.from(this.evidence.values()).filter((ev) =>
      ev.affects.some((a) => a.hypothesisId === hypothesisId)
    );
  }

  // -------- Contradictions --------

  upsertContradiction(c: Contradiction): void {
    this.contradictions.set(c.id, c);
  }

  getContradiction(id: string): Contradiction | undefined {
    return this.contradictions.get(id);
  }

  contradictionsFor(hypothesisId: string): readonly Contradiction[] {
    return Array.from(this.contradictions.values()).filter(
      (c) =>
        (c.affected.kind === "hypothesis" && c.affected.refId === hypothesisId) ||
        (c.conflicting.kind === "hypothesis" && c.conflicting.refId === hypothesisId)
    );
  }

  allContradictions(): readonly Contradiction[] {
    return Array.from(this.contradictions.values());
  }

  // -------- Contexts --------

  addContext(c: AssumptionContext): void {
    this.contexts.set(c.id, c);
  }

  getContext(id: string): AssumptionContext | undefined {
    return this.contexts.get(id);
  }

  // -------- Observation models --------

  registerObservationModel(m: ObservationModel): void {
    this.observationModels.set(m.observationModelId, m);
  }

  getObservationModel(id: string): ObservationModel | undefined {
    return this.observationModels.get(id);
  }

  // -------- Beliefs --------

  setBelief(b: BeliefState): void {
    if (!this.hypotheses.has(b.hypothesisId)) {
      throw new GraphValidationError(
        `belief references unknown hypothesis: ${b.hypothesisId}`
      );
    }
    this.beliefs.set(b.hypothesisId, b);
  }

  getBelief(hypothesisId: string): BeliefState | undefined {
    return this.beliefs.get(hypothesisId);
  }

  // -------- Edges --------

  addEdge(edge: GraphEdge): void {
    if (this.edges.has(edge.id)) {
      throw new GraphValidationError(`duplicate edge id: ${edge.id}`);
    }
    this.edges.set(edge.id, edge);
  }

  edgesFrom(fromId: string): readonly GraphEdge[] {
    return Array.from(this.edges.values()).filter((e) => e.fromId === fromId);
  }

  // -------- Snapshot (immutable copies for purity tests) --------

  snapshot(): {
    hypotheses: Hypothesis[];
    evidence: Evidence[];
    contradictions: Contradiction[];
    contexts: AssumptionContext[];
    beliefs: BeliefState[];
    edges: GraphEdge[];
  } {
    return {
      hypotheses: structuredClone(Array.from(this.hypotheses.values())),
      evidence: structuredClone(Array.from(this.evidence.values())),
      contradictions: structuredClone(Array.from(this.contradictions.values())),
      contexts: structuredClone(Array.from(this.contexts.values())),
      beliefs: structuredClone(Array.from(this.beliefs.values())),
      edges: structuredClone(Array.from(this.edges.values())),
    };
  }
}
