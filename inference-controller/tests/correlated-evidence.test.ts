import { describe, it, expect } from "vitest";
import { BeliefGraphUpdater } from "../src/graph/update.js";
import { makeEvidence, makeHypothesis, makeObservationModel } from "./_helpers.js";

describe("correlated evidence double-count prevention", () => {
  it("rejects a second evidence in the same correlation group", () => {
    const updater = new BeliefGraphUpdater();
    const h = makeHypothesis({ prior: 0.5 });
    const out1 = updater.applyUpdate({
      hypothesis: h,
      prevBelief: undefined,
      evidence: makeEvidence({ correlationGroupId: "cg_1" }),
      observationModel: makeObservationModel(),
      likelihoodGivenH: 0.9,
      likelihoodGivenNotH: 0.1,
    });
    if (!out1.ok) throw new Error("first update failed");
    const out2 = updater.applyUpdate({
      hypothesis: h,
      prevBelief: out1.belief,
      evidence: makeEvidence({ correlationGroupId: "cg_1" }),
      observationModel: makeObservationModel(),
      likelihoodGivenH: 0.9,
      likelihoodGivenNotH: 0.1,
    });
    expect(out2.ok).toBe(false);
    if (!out2.ok) {
      expect(out2.validation.errorCode).toBe("result_invalid");
      expect(out2.validation.message).toMatch(/correlated|duplicate/i);
    }
  });

  it("accepts evidence in a DIFFERENT correlation group", () => {
    const updater = new BeliefGraphUpdater();
    const h = makeHypothesis({ prior: 0.5 });
    const out1 = updater.applyUpdate({
      hypothesis: h,
      prevBelief: undefined,
      evidence: makeEvidence({ correlationGroupId: "cg_1" }),
      observationModel: makeObservationModel(),
      likelihoodGivenH: 0.9,
      likelihoodGivenNotH: 0.1,
    });
    if (!out1.ok) throw new Error("first update failed");
    const out2 = updater.applyUpdate({
      hypothesis: h,
      prevBelief: out1.belief,
      evidence: makeEvidence({ correlationGroupId: "cg_2" }),
      observationModel: makeObservationModel(),
      likelihoodGivenH: 0.9,
      likelihoodGivenNotH: 0.1,
    });
    expect(out2.ok).toBe(true);
  });

  it("rejects re-applying the SAME evidence id even with no correlation group", () => {
    const updater = new BeliefGraphUpdater();
    const h = makeHypothesis({ prior: 0.5 });
    const ev = makeEvidence();
    const out1 = updater.applyUpdate({
      hypothesis: h,
      prevBelief: undefined,
      evidence: ev,
      observationModel: makeObservationModel(),
      likelihoodGivenH: 0.9,
      likelihoodGivenNotH: 0.1,
    });
    if (!out1.ok) throw new Error("first update failed");
    const out2 = updater.applyUpdate({
      hypothesis: h,
      prevBelief: out1.belief,
      evidence: ev,
      observationModel: makeObservationModel(),
      likelihoodGivenH: 0.9,
      likelihoodGivenNotH: 0.1,
    });
    expect(out2.ok).toBe(false);
  });
});
