/**
 * Merge service.
 *
 * Merges are first-class, typed, and reversible in MVP unless explicitly
 * finalized through approval. We never silently combine belief states; a
 * merge is a structured operator with a recorded trace.
 */
import { newMergeId } from "../domain/ids.js";
import type { Hypothesis, LifecycleState } from "../domain/types.js";
import { applyTransition } from "../domain/lifecycle.js";
import type { BeliefGraph } from "./belief-graph.js";

export type MergeKind =
  | "exact_equivalence"
  | "partial_overlap"
  | "subtype"
  | "parent_child"
  | "same_underlying_cause"
  | "abstraction_alias";

export type MergeRecord = {
  id: string;
  investigationId: string;
  kind: MergeKind;
  primaryHypothesisId: string;
  subsumedHypothesisId: string;
  // The lifecycle state of the subsumed hypothesis BEFORE merge (so we can
  // reverse it).
  subsumedLifecycleBefore: LifecycleState;
  finalized: boolean;
  createdAt: string;
  finalizedAt?: string;
  reversedAt?: string;
};

export class MergeService {
  private readonly merges = new Map<string, MergeRecord>();

  constructor(private readonly graph: BeliefGraph) {}

  /**
   * Record a merge proposal. The subsumed hypothesis is moved to `merged`
   * lifecycle. The merge is reversible until finalize().
   */
  propose(req: {
    investigationId: string;
    kind: MergeKind;
    primaryHypothesisId: string;
    subsumedHypothesisId: string;
    now?: Date;
  }): MergeRecord {
    const primary = this.graph.getHypothesis(req.primaryHypothesisId);
    const subsumed = this.graph.getHypothesis(req.subsumedHypothesisId);
    if (!primary) throw new Error(`unknown primary hypothesis: ${req.primaryHypothesisId}`);
    if (!subsumed) throw new Error(`unknown subsumed hypothesis: ${req.subsumedHypothesisId}`);
    if (primary.id === subsumed.id) throw new Error("cannot merge a hypothesis with itself");

    const id = newMergeId();
    const now = (req.now ?? new Date()).toISOString();
    const lifecycleBefore = subsumed.lifecycle;
    const next = applyTransition(subsumed.lifecycle, "merged");
    this.graph.updateHypothesis({
      ...subsumed,
      lifecycle: next,
      mergeHistory: [...subsumed.mergeHistory, id],
    });
    const record: MergeRecord = {
      id,
      investigationId: req.investigationId,
      kind: req.kind,
      primaryHypothesisId: req.primaryHypothesisId,
      subsumedHypothesisId: req.subsumedHypothesisId,
      subsumedLifecycleBefore: lifecycleBefore,
      finalized: false,
      createdAt: now,
    };
    this.merges.set(id, record);
    return record;
  }

  /**
   * Finalize a merge. Requires explicit approval (passed as a flag from the
   * approval gate). After finalize, the merge cannot be reversed.
   */
  finalize(mergeId: string, approved: boolean, now: Date = new Date()): MergeRecord {
    const m = this.merges.get(mergeId);
    if (!m) throw new Error(`unknown merge: ${mergeId}`);
    if (!approved) throw new Error("finalize requires approval");
    if (m.finalized) return m;
    const next: MergeRecord = { ...m, finalized: true, finalizedAt: now.toISOString() };
    this.merges.set(mergeId, next);
    return next;
  }

  /**
   * Reverse a not-yet-finalized merge. The subsumed hypothesis's lifecycle
   * is restored. We allow the reverse to perform the lifecycle change even
   * though `merged -> *` is otherwise restricted to `archived`, because the
   * reverse is itself an authorized merge operator.
   */
  revert(mergeId: string, now: Date = new Date()): MergeRecord {
    const m = this.merges.get(mergeId);
    if (!m) throw new Error(`unknown merge: ${mergeId}`);
    if (m.finalized) throw new Error("cannot revert a finalized merge");
    if (m.reversedAt) return m;
    const subsumed = this.graph.getHypothesis(m.subsumedHypothesisId);
    if (!subsumed) throw new Error("subsumed hypothesis missing");
    // Rewrite directly, bypassing the lifecycle machine, because revert is
    // the inverse operator. Clear the merge id from history.
    this.graph.updateHypothesis({
      ...subsumed,
      lifecycle: m.subsumedLifecycleBefore,
      mergeHistory: subsumed.mergeHistory.filter((x) => x !== m.id),
    });
    const next: MergeRecord = { ...m, reversedAt: now.toISOString() };
    this.merges.set(mergeId, next);
    return next;
  }

  get(mergeId: string): MergeRecord | undefined {
    return this.merges.get(mergeId);
  }
}
