import { describe, it, expect } from "vitest";
import { bayesUpdate, BeliefGraphUpdater, CODE_VERSION } from "../src/graph/update.js";
import { makeEvidence, makeHypothesis, makeObservationModel } from "./_helpers.js";

describe("belief update reproducibility", () => {
  it("bayesUpdate is deterministic on identical inputs", () => {
    const a = bayesUpdate(0.3, 0.9, 0.1);
    const b = bayesUpdate(0.3, 0.9, 0.1);
    expect(a).toEqual(b);
  });

  it("update trace records prior, posterior, model version, and code version", () => {
    const updater = new BeliefGraphUpdater();
    const h = makeHypothesis({ prior: 0.4 });
    const m = makeObservationModel({ version: "2.1.0" });
    const out = updater.applyUpdate({
      hypothesis: h,
      prevBelief: undefined,
      evidence: makeEvidence(),
      observationModel: m,
      likelihoodGivenH: 0.8,
      likelihoodGivenNotH: 0.2,
    });
    expect(out.ok).toBe(true);
    if (out.ok) {
      const trace = out.belief.updateTrace[0]!;
      expect(trace.priorBefore).toBe(0.4);
      expect(trace.posteriorAfter).toBeCloseTo(out.belief.posterior, 12);
      expect(trace.modelVersion).toBe("2.1.0");
      expect(trace.codeVersion).toBe(CODE_VERSION);
      expect(trace.observationModelId).toBe(m.observationModelId);
    }
  });

  it("subsequent updates chain priors from the previous posterior", () => {
    const updater = new BeliefGraphUpdater();
    const h = makeHypothesis({ prior: 0.5 });
    const ev1 = makeEvidence();
    const out1 = updater.applyUpdate({
      hypothesis: h,
      prevBelief: undefined,
      evidence: ev1,
      observationModel: makeObservationModel(),
      likelihoodGivenH: 0.9,
      likelihoodGivenNotH: 0.1,
    });
    if (!out1.ok) throw new Error("first update failed");
    const ev2 = makeEvidence();
    const out2 = updater.applyUpdate({
      hypothesis: h,
      prevBelief: out1.belief,
      evidence: ev2,
      observationModel: makeObservationModel(),
      likelihoodGivenH: 0.7,
      likelihoodGivenNotH: 0.3,
    });
    if (!out2.ok) throw new Error("second update failed");
    expect(out2.belief.updateTrace).toHaveLength(2);
    expect(out2.belief.updateTrace[1]!.priorBefore).toBeCloseTo(out1.belief.posterior, 12);
  });
});
