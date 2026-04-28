import { describe, it, expect } from "vitest";
import { applyTransition } from "../src/domain/lifecycle.js";
import { makeHypothesis } from "./_helpers.js";

describe("soft-close and reactivation", () => {
  it("soft_closed retains wake conditions", () => {
    const h = makeHypothesis({
      lifecycle: "active",
      wakeConditions: [{ kind: "new_evidence_about", descriptor: "target.example" }],
    });
    const next = applyTransition(h.lifecycle, "soft_closed");
    expect(next).toBe("soft_closed");
    expect(h.wakeConditions).toHaveLength(1);
  });

  it("soft_closed -> reactivated -> active is a legal sequence", () => {
    const s1 = applyTransition("active", "soft_closed");
    const s2 = applyTransition(s1, "reactivated");
    const s3 = applyTransition(s2, "active");
    expect(s3).toBe("active");
  });
});
