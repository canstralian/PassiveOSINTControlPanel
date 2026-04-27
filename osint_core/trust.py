"""
osint_core.trust
================

Bounded trust scoring for the Passive OSINT Control Panel.

The first trust-fabric layer is intentionally small:

    observe -> score -> persist -> report

It does not expand authority. Trust may reduce authority automatically, but it
may not increase authority automatically.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Literal


ComponentType = Literal["model", "service", "module", "workflow", "hardware", "policy"]
TrustSource = Literal["verification", "drift", "constraint", "audit", "ci", "operator"]
RepairAction = Literal["none", "observe", "constrain", "rollback", "quarantine", "adapt"]
VerificationDepth = Literal["normal", "elevated", "strict", "quarantined"]
PermissionScope = Literal["passive", "conditional", "restricted", "blocked"]
SchedulerRoute = Literal["FAST", "DELIBERATIVE", "CONTAINMENT", "FAIL_CLOSED"]

TRUST_MIN = 0.0
TRUST_MAX = 1.0
DEFAULT_TRUST_SCORE = 0.6
COLLAPSED_TRUST_SCORE = 0.2
LOW_TRUST_SCORE = 0.4
HIGH_TRUST_SCORE = 0.8

NEGATIVE_MULTIPLIER = 1.0
POSITIVE_MULTIPLIER = 0.35


@dataclass(frozen=True)
class TrustDelta:
    """One evidence-backed trust movement for a component."""

    component_id: str
    component_type: ComponentType
    source: TrustSource
    score_delta: float
    reason: str
    evidence: dict[str, Any]
    repair_action: RepairAction = "none"
    timestamp: str = ""

    def normalized(self) -> "TrustDelta":
        """Clamp delta to [-1.0, 1.0] and attach a timestamp when missing."""
        bounded = max(-1.0, min(1.0, float(self.score_delta)))
        return replace(
            self,
            score_delta=bounded,
            timestamp=self.timestamp or datetime.now(timezone.utc).isoformat(),
        )


@dataclass(frozen=True)
class TrustState:
    """Rolling trust state for a component."""

    component_id: str
    component_type: ComponentType
    trust_score: float = DEFAULT_TRUST_SCORE
    verification_depth: VerificationDepth = "normal"
    permission_scope: PermissionScope = "passive"
    last_repair_action: RepairAction | None = None
    evidence_count: int = 0
    updated_at: str = ""

    def normalized(self) -> "TrustState":
        """Clamp score and derive safety fields from the current trust value."""
        score = clamp_score(self.trust_score)
        return replace(
            self,
            trust_score=score,
            verification_depth=derive_verification_depth(score),
            permission_scope=derive_permission_scope(score, self.permission_scope),
            updated_at=self.updated_at or datetime.now(timezone.utc).isoformat(),
        )


def clamp_score(value: float) -> float:
    """Clamp a trust score to [0.0, 1.0]."""
    return max(TRUST_MIN, min(TRUST_MAX, float(value)))


def calculate_trust_delta(
    *,
    component_id: str,
    component_type: ComponentType,
    drift_assessment: Any | None = None,
    reconciliation_result: dict[str, Any] | None = None,
    audit_result: dict[str, Any] | None = None,
    ci_result: dict[str, Any] | None = None,
) -> TrustDelta:
    """Calculate one trust delta from runtime evidence.

    Priority is conservative: policy, structural, behavioral, or adversarial
    drift dominates positive evidence. Clean evidence can only produce a small
    positive delta.
    """
    reasons: list[str] = []
    evidence: dict[str, Any] = {}
    source: TrustSource = "verification"
    repair_action: RepairAction = "observe"
    raw_delta = 0.0

    if drift_assessment is not None:
        source = "drift"
        correction = str(getattr(drift_assessment, "recommended_correction", "OBSERVE"))
        confidence = float(getattr(drift_assessment, "confidence", 0.0))
        dominant = getattr(drift_assessment, "dominant_type", None)
        dominant_value = getattr(dominant, "value", None) or str(dominant) if dominant else None
        signal_count = len(getattr(drift_assessment, "signals", []) or [])

        evidence.update(
            {
                "dominant_drift_type": dominant_value,
                "recommended_correction": correction,
                "confidence": confidence,
                "signal_count": signal_count,
            }
        )

        if correction in {"REVERT", "CONSTRAIN"}:
            raw_delta -= max(0.2, confidence)
            repair_action = "rollback" if correction == "REVERT" else "constrain"
            reasons.append(f"drift recommended {correction}")
        elif signal_count == 0:
            raw_delta += 0.12
            repair_action = "observe"
            reasons.append("no drift signals detected")
        elif correction == "ADAPT":
            raw_delta += 0.04
            repair_action = "adapt"
            reasons.append("adaptive drift signal observed")

    if reconciliation_result:
        source = "constraint"
        blocked = int(reconciliation_result.get("blocked_count", 0) or 0)
        violations = int(reconciliation_result.get("violation_count", 0) or 0)
        evidence["blocked_count"] = blocked
        evidence["violation_count"] = violations
        if violations or blocked:
            raw_delta -= min(0.6, 0.15 * max(blocked, violations))
            repair_action = "constrain"
            reasons.append("constraint reconciliation blocked actions")
        else:
            raw_delta += 0.06
            reasons.append("constraint reconciliation clean")

    if audit_result:
        source = "audit"
        audit_safe = bool(audit_result.get("audit_safe", False))
        evidence["audit_safe"] = audit_safe
        if not audit_safe:
            raw_delta -= 0.7
            repair_action = "quarantine"
            reasons.append("audit safety failed")
        else:
            raw_delta += 0.04
            reasons.append("audit safety passed")

    if ci_result:
        source = "ci"
        passed = bool(ci_result.get("passed", False))
        evidence["ci_passed"] = passed
        if passed:
            raw_delta += 0.08
            reasons.append("CI passed")
        else:
            raw_delta -= 0.5
            repair_action = "constrain"
            reasons.append("CI failed")

    if not reasons:
        reasons.append("no decisive trust evidence")

    return TrustDelta(
        component_id=component_id,
        component_type=component_type,
        source=source,
        score_delta=raw_delta,
        reason="; ".join(reasons),
        evidence=evidence,
        repair_action=repair_action,
    ).normalized()


def apply_trust_delta(state: TrustState, delta: TrustDelta) -> TrustState:
    """Apply asymmetric trust movement to a state.

    Negative deltas apply at full strength. Positive deltas recover slowly.
    Permission scope is derived conservatively and cannot become broader than
    the existing scope through this automatic path.
    """
    normalized_state = state.normalized()
    normalized_delta = delta.normalized()

    multiplier = NEGATIVE_MULTIPLIER if normalized_delta.score_delta < 0 else POSITIVE_MULTIPLIER
    next_score = clamp_score(
        normalized_state.trust_score + (normalized_delta.score_delta * multiplier)
    )
    next_scope = derive_permission_scope(next_score, normalized_state.permission_scope)

    return TrustState(
        component_id=normalized_state.component_id,
        component_type=normalized_state.component_type,
        trust_score=next_score,
        verification_depth=derive_verification_depth(next_score),
        permission_scope=next_scope,
        last_repair_action=normalized_delta.repair_action,
        evidence_count=normalized_state.evidence_count + 1,
        updated_at=datetime.now(timezone.utc).isoformat(),
    )


def derive_verification_depth(trust_score: float) -> VerificationDepth:
    """Map score to verification depth."""
    score = clamp_score(trust_score)
    if score <= COLLAPSED_TRUST_SCORE:
        return "quarantined"
    if score <= LOW_TRUST_SCORE:
        return "strict"
    if score < HIGH_TRUST_SCORE:
        return "elevated"
    return "normal"


def derive_permission_scope(
    trust_score: float,
    current_scope: PermissionScope = "passive",
) -> PermissionScope:
    """Map score to permission scope without automatic authority expansion."""
    score = clamp_score(trust_score)

    if score <= COLLAPSED_TRUST_SCORE:
        candidate: PermissionScope = "blocked"
    elif score <= LOW_TRUST_SCORE:
        candidate = "restricted"
    elif score < HIGH_TRUST_SCORE:
        candidate = "passive"
    else:
        candidate = current_scope

    return narrower_scope(current_scope, candidate)


def narrower_scope(current: PermissionScope, candidate: PermissionScope) -> PermissionScope:
    """Return the more restrictive permission scope."""
    rank: dict[PermissionScope, int] = {
        "conditional": 3,
        "passive": 2,
        "restricted": 1,
        "blocked": 0,
    }
    return current if rank[current] <= rank[candidate] else candidate


def derive_scheduler_route(
    *,
    risk: Literal["low", "medium", "high", "critical"],
    trust_state: TrustState,
) -> SchedulerRoute:
    """Route scheduler decisions using trust and risk."""
    state = trust_state.normalized()
    if state.permission_scope == "blocked" or state.verification_depth == "quarantined":
        return "FAIL_CLOSED"
    if state.permission_scope == "restricted" or risk in {"critical", "high"}:
        return "CONTAINMENT"
    if state.verification_depth == "elevated" or risk == "medium":
        return "DELIBERATIVE"
    return "FAST"
