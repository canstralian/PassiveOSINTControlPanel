import { describe, it, expect } from "vitest";
import {
  applyTransition,
  IllegalLifecycleTransitionError,
  isLegalTransition,
  legalNextStates,
} from "../src/domain/lifecycle.js";
import type { LifecycleState } from "../src/domain/types.js";

describe("lifecycle state machine", () => {
  it("permits all canonical happy-path transitions", () => {
    expect(isLegalTransition("candidate", "active")).toBe(true);
    expect(isLegalTransition("active", "supported")).toBe(true);
    expect(isLegalTransition("supported", "validated")).toBe(true);
    expect(isLegalTransition("active", "challenged")).toBe(true);
    expect(isLegalTransition("challenged", "falsified")).toBe(true);
    expect(isLegalTransition("active", "soft_closed")).toBe(true);
    expect(isLegalTransition("soft_closed", "reactivated")).toBe(true);
    expect(isLegalTransition("reactivated", "active")).toBe(true);
  });

  it("rejects identity transitions", () => {
    const states: LifecycleState[] = [
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
    ];
    for (const s of states) {
      expect(isLegalTransition(s, s)).toBe(false);
    }
  });

  it("rejects illegal transitions", () => {
    expect(isLegalTransition("candidate", "validated")).toBe(false);
    expect(isLegalTransition("archived", "active")).toBe(false);
    expect(isLegalTransition("merged", "active")).toBe(false);
    expect(isLegalTransition("inactive", "supported")).toBe(false);
  });

  it("applyTransition throws on illegal transitions", () => {
    expect(() => applyTransition("candidate", "validated")).toThrow(
      IllegalLifecycleTransitionError
    );
  });

  it("archived is terminal", () => {
    expect(legalNextStates("archived")).toHaveLength(0);
  });

  it("validated and falsified can be revisited via challenged", () => {
    expect(isLegalTransition("validated", "challenged")).toBe(true);
    expect(isLegalTransition("falsified", "challenged")).toBe(true);
  });

  it("merged only flows to archived (revert is via merge service, not state machine)", () => {
    const next = legalNextStates("merged");
    expect(next).toEqual(["archived"]);
  });

  it("soft_closed is recoverable via reactivated", () => {
    expect(isLegalTransition("soft_closed", "reactivated")).toBe(true);
  });
});
