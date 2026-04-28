/**
 * Risk classifier.
 *
 * Maps a candidate action to a risk class and decides whether it can proceed
 * without approval. The risk class is a closed enum (see RiskClass).
 */
import type { CandidateAction, RiskClass } from "../domain/types.js";

const RISK_ORDER: Record<RiskClass, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  destructive: 4,
};

export type RiskDecision =
  | { class: RiskClass; needsApproval: false }
  | { class: RiskClass; needsApproval: true; reason: string }
  | { class: RiskClass; denied: true; reason: string };

export class RiskClassifier {
  classify(
    action: CandidateAction,
    maxWithoutApproval: RiskClass
  ): RiskDecision {
    const klass = action.estimatedRiskClass;
    const klassRank = RISK_ORDER[klass];
    const ceilingRank = RISK_ORDER[maxWithoutApproval];

    // Destructive actions ALWAYS require approval, even if the ceiling is
    // somehow set there. The spec considers these "irreversible / external
    // side effects".
    if (klass === "destructive") {
      return {
        class: klass,
        needsApproval: true,
        reason: "destructive actions always require approval",
      };
    }

    if (klassRank <= ceilingRank) {
      return { class: klass, needsApproval: false };
    }
    return {
      class: klass,
      needsApproval: true,
      reason: `risk class ${klass} exceeds threshold ${maxWithoutApproval}`,
    };
  }
}
