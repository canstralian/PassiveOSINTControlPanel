/**
 * Deterministic hypothesis lifecycle state machine.
 *
 * Lifecycle states are control states, not display labels. Invalid
 * transitions MUST fail. Edges are intentionally narrow — broaden only with
 * a corresponding test.
 */
import type { LifecycleState } from "./types.js";

const TRANSITIONS: Readonly<Record<LifecycleState, ReadonlySet<LifecycleState>>> = {
  candidate: new Set(["active", "blocked", "merged", "archived"] as const),
  active: new Set([
    "supported",
    "challenged",
    "inactive",
    "blocked",
    "merged",
    "soft_closed",
    "validated",
    "falsified",
    "archived",
  ] as const),
  supported: new Set([
    "active",
    "challenged",
    "validated",
    "falsified",
    "soft_closed",
    "blocked",
    "merged",
    "archived",
  ] as const),
  challenged: new Set([
    "active",
    "supported",
    "falsified",
    "soft_closed",
    "blocked",
    "inactive",
    "merged",
    "archived",
  ] as const),
  inactive: new Set(["reactivated", "archived"] as const),
  blocked: new Set(["active", "soft_closed", "archived"] as const),
  // Merged is reversible only via merge revert (which writes a new
  // hypothesis lineage). The state itself only flows to archived.
  merged: new Set(["archived"] as const),
  soft_closed: new Set(["reactivated", "archived"] as const),
  reactivated: new Set(["active", "supported", "challenged", "archived"] as const),
  // Validated and falsified are thresholded decisions, not absolute. They
  // can be revisited if new contradicting/supporting evidence arrives.
  validated: new Set(["challenged", "soft_closed", "archived"] as const),
  falsified: new Set(["challenged", "soft_closed", "archived"] as const),
  archived: new Set([] as const),
};

export type LifecycleTransitionReason =
  | "evidence_update"
  | "contradiction_recorded"
  | "merge_committed"
  | "soft_close_decision"
  | "reactivation_wake"
  | "validation_threshold"
  | "falsification_threshold"
  | "scope_block"
  | "approval_decision"
  | "controller_decision"
  | "manual";

export type LifecycleTransition = {
  from: LifecycleState;
  to: LifecycleState;
  reason: LifecycleTransitionReason;
};

export class IllegalLifecycleTransitionError extends Error {
  constructor(public readonly from: LifecycleState, public readonly to: LifecycleState) {
    super(`Illegal lifecycle transition: ${from} -> ${to}`);
    this.name = "IllegalLifecycleTransitionError";
  }
}

/**
 * Determine whether a transition from one lifecycle state to another is allowed.
 *
 * Identical `from` and `to` states are not considered legal transitions.
 *
 * @param from - The current lifecycle state
 * @param to - The desired next lifecycle state
 * @returns `true` if `to` is an allowed next state from `from`, `false` otherwise.
 */
export function isLegalTransition(from: LifecycleState, to: LifecycleState): boolean {
  if (from === to) return false;
  return TRANSITIONS[from].has(to);
}

/**
 * List allowed next lifecycle states for a given current state.
 *
 * @param from - The current lifecycle state
 * @returns An array of lifecycle states that may follow `from`; empty if there are no allowed next states
 */
export function legalNextStates(from: LifecycleState): readonly LifecycleState[] {
  return Array.from(TRANSITIONS[from]);
}

/**
 * Validate and apply a lifecycle state transition.
 *
 * @param current - The current lifecycle state.
 * @param next - The desired next lifecycle state.
 * @returns The `next` lifecycle state when the transition is permitted.
 * @throws {IllegalLifecycleTransitionError} When the transition from `current` to `next` is not allowed.
 */
export function applyTransition(
  current: LifecycleState,
  next: LifecycleState
): LifecycleState {
  if (!isLegalTransition(current, next)) {
    throw new IllegalLifecycleTransitionError(current, next);
  }
  return next;
}
