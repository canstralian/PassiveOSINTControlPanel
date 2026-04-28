import { describe, it, expect } from "vitest";
import { BeliefGraphUpdater } from "../src/graph/update.js";
import { makeEvidence, makeHypothesis, makeObservationModel } from "./_helpers.js";

describe("evidence without provenance", () => {
  it("is excluded from formal posterior updates", () => {
    const updater = new BeliefGraphUpdater();
    const h = makeHypothesis();
    const ev = makeEvidence({ provenance: undefined });
    const out = updater.applyUpdate({
      hypothesis: h,
      prevBelief: undefined,
      evidence: ev,
      observationModel: makeObservationModel(),
      likelihoodGivenH: 0.9,
      likelihoodGivenNotH: 0.1,
    });
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.validation.errorCode).toBe("provenance_missing");
    }
  });

  it("evidence WITH provenance is admitted to the formal update", () => {
    const updater = new BeliefGraphUpdater();
    const h = makeHypothesis({ prior: 0.3 });
    const out = updater.applyUpdate({
      hypothesis: h,
      prevBelief: undefined,
      evidence: makeEvidence(),
      observationModel: makeObservationModel(),
      likelihoodGivenH: 0.9,
      likelihoodGivenNotH: 0.1,
    });
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.belief.posterior).toBeGreaterThan(0.3);
    }
  });
});
