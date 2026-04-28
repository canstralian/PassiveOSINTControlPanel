/**
 * BeliefGraphUpdater — formal posterior updates only.
 *
 * Heuristic agenda priority is updated separately by the controller; this
 * module ONLY performs grounded updates that satisfy spec point 8:
 *
 *   - prior or declared default prior
 *   - evidence with provenance
 *   - observation model
 *   - likelihood contribution
 *   - persisted update trace including model + code version
 *   - correlation group dedup
 *
 * Updates are returned as new BeliefState records; they are NOT mutated in
 * place on the input objects, so the function is safe to call from a
 * pure-test context.
 */
import type {
  BeliefState,
  Evidence,
  Hypothesis,
  ObservationModel,
  ValidationResult,
} from "../domain/types.js";

export const CODE_VERSION = "0.0.1";

export type UpdateRequest = {
  hypothesis: Hypothesis;
  prevBelief: BeliefState | undefined;
  evidence: Evidence;
  observationModel: ObservationModel;
  // Likelihood the observation model assigns to the evidence under H true
  // and under H false. Required for log-odds / bernoulli updates.
  likelihoodGivenH: number;
  likelihoodGivenNotH: number;
  now?: Date;
};

export type UpdateOutcome =
  | {
      ok: true;
      belief: BeliefState;
    }
  | {
      ok: false;
      validation: ValidationResult;
    };

export class BeliefGraphUpdater {
  applyUpdate(req: UpdateRequest): UpdateOutcome {
    const now = (req.now ?? new Date()).toISOString();

    // Spec invariant 7: evidence without provenance cannot drive formal
    // belief updates.
    if (!req.evidence.provenance) {
      return {
        ok: false,
        validation: {
          ok: false,
          errorCode: "provenance_missing",
          message: "evidence has no provenance; refusing formal update",
        },
      };
    }

    // Numeric sanity. A zero-likelihood pair is undefined.
    if (req.likelihoodGivenH < 0 || req.likelihoodGivenH > 1) {
      return {
        ok: false,
        validation: {
          ok: false,
          errorCode: "result_invalid",
          message: "likelihoodGivenH out of range",
        },
      };
    }
    if (req.likelihoodGivenNotH < 0 || req.likelihoodGivenNotH > 1) {
      return {
        ok: false,
        validation: {
          ok: false,
          errorCode: "result_invalid",
          message: "likelihoodGivenNotH out of range",
        },
      };
    }

    const priorBefore = req.prevBelief?.posterior ?? req.hypothesis.prior;

    // Correlated-evidence dedup: if this evidence's correlation group has
    // already been incorporated (by id or by group), reject the update.
    if (req.prevBelief && req.evidence.correlationGroupId) {
      const seen = req.prevBelief.updateTrace.some(
        (t) =>
          t.correlationGroupId === req.evidence.correlationGroupId ||
          t.evidenceId === req.evidence.id
      );
      if (seen) {
        return {
          ok: false,
          validation: {
            ok: false,
            errorCode: "result_invalid",
            message:
              "correlated or duplicate evidence already incorporated; refusing double count",
          },
        };
      }
    } else if (req.prevBelief) {
      // Even with no correlation group, refuse to apply the same evidence twice.
      const seen = req.prevBelief.updateTrace.some(
        (t) => t.evidenceId === req.evidence.id
      );
      if (seen) {
        return {
          ok: false,
          validation: {
            ok: false,
            errorCode: "result_invalid",
            message: "evidence already applied",
          },
        };
      }
    }

    const posteriorAfter = bayesUpdate(
      priorBefore,
      req.likelihoodGivenH,
      req.likelihoodGivenNotH
    );
    if (!Number.isFinite(posteriorAfter)) {
      return {
        ok: false,
        validation: {
          ok: false,
          errorCode: "result_invalid",
          message: "posterior is not finite",
        },
      };
    }

    const trace = [
      ...(req.prevBelief?.updateTrace ?? []),
      {
        evidenceId: req.evidence.id,
        observationModelId: req.observationModel.observationModelId,
        modelVersion: req.observationModel.version,
        codeVersion: CODE_VERSION,
        priorBefore,
        posteriorAfter,
        ...(req.evidence.correlationGroupId !== undefined
          ? { correlationGroupId: req.evidence.correlationGroupId }
          : {}),
        timestamp: now,
      },
    ];

    const belief: BeliefState = {
      hypothesisId: req.hypothesis.id,
      posterior: posteriorAfter,
      updateTrace: trace,
      agendaPriority: req.prevBelief?.agendaPriority ?? 0,
      lastUpdatedAt: now,
    };
    return { ok: true, belief };
  }
}

/** Bayesian update on P(H) given P(E|H) and P(E|¬H). */
export function bayesUpdate(
  prior: number,
  likelihoodH: number,
  likelihoodNotH: number
): number {
  const num = likelihoodH * prior;
  const denom = num + likelihoodNotH * (1 - prior);
  if (denom === 0) return prior;
  const post = num / denom;
  // Clamp to [eps, 1 - eps] to keep log-odds well-defined downstream.
  if (post < 1e-9) return 1e-9;
  if (post > 1 - 1e-9) return 1 - 1e-9;
  return post;
}
