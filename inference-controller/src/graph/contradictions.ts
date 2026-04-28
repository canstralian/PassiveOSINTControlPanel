/**
 * Contradiction service.
 *
 * Contradictions are first-class state. Low posterior is NOT contradiction.
 * The service distinguishes:
 *   - logical_defeat
 *   - evidence_conflict
 *   - assumption_conflict
 *   - policy_conflict
 *   - scope_conflict
 *   - temporal_conflict
 *
 * And tracks resolution state independently of belief value.
 */
import type {
  Contradiction,
  ContradictionResolution,
  ContradictionType,
} from "../domain/types.js";
import { newContradictionId } from "../domain/ids.js";
import type { BeliefGraph } from "./belief-graph.js";

export type RecordContradictionRequest = {
  investigationId: string;
  affected: Contradiction["affected"];
  conflicting: Contradiction["conflicting"];
  contradictionType: ContradictionType;
  rule?: string;
  now?: Date;
};

export class ContradictionService {
  constructor(private readonly graph: BeliefGraph) {}

  record(req: RecordContradictionRequest): Contradiction {
    const now = (req.now ?? new Date()).toISOString();
    const c: Contradiction = {
      id: newContradictionId(),
      investigationId: req.investigationId,
      affected: req.affected,
      conflicting: req.conflicting,
      contradictionType: req.contradictionType,
      ...(req.rule !== undefined ? { rule: req.rule } : {}),
      resolution: "open",
      generatedActionIds: [],
      createdAt: now,
      updatedAt: now,
    };
    this.graph.upsertContradiction(c);
    return c;
  }

  resolve(
    contradictionId: string,
    resolution: ContradictionResolution,
    now: Date = new Date()
  ): Contradiction {
    const existing = this.graph.getContradiction(contradictionId);
    if (!existing) {
      throw new Error(`unknown contradiction: ${contradictionId}`);
    }
    if (existing.resolution === resolution) return existing;
    const next: Contradiction = {
      ...existing,
      resolution,
      updatedAt: now.toISOString(),
    };
    this.graph.upsertContradiction(next);
    return next;
  }
}
