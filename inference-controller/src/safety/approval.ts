/**
 * Approval gate.
 *
 * The gate exposes a synchronous decide() that callers consult after the
 * RiskClassifier signals approval is required. In MVP, approvals are
 * pre-registered: callers (operators / tests) grant approvals out-of-band
 * and the gate consumes them. The gate never grants approval implicitly.
 */

export type ApprovalRequest = {
  investigationId: string;
  actionId: string;
  reason: string;
};

export type ApprovalDecision =
  | { granted: true; approver: string; grantedAt: string }
  | { granted: false; reason: string };

export class ApprovalGate {
  // Map<actionId, ApprovalDecision>
  private readonly registry = new Map<string, ApprovalDecision>();

  preApprove(actionId: string, approver: string, now: Date = new Date()): void {
    this.registry.set(actionId, {
      granted: true,
      approver,
      grantedAt: now.toISOString(),
    });
  }

  preDeny(actionId: string, reason: string): void {
    this.registry.set(actionId, { granted: false, reason });
  }

  decide(req: ApprovalRequest): ApprovalDecision {
    const existing = this.registry.get(req.actionId);
    if (existing) return existing;
    return { granted: false, reason: "no approval registered" };
  }
}
