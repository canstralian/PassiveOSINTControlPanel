"""
osint_core.trust
================

Self-healing trust fabric primitives.

Converts drift, reconciliation, audit, and CI signals into rolling
component-level trust state.

Rules:
- Trust may reduce authority automatically.
- Trust may not expand authority automatically.
- Trust loss is fast.
- Trust recovery is slow.
- Structural/policy/adversarial drift causes sharper trust loss.
- Statistical drift accumulates slowly.
- Raw indicators must never be stored in trust events.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Literal


ComponentType = Literal["model", "service", "module", "workflow", "hardware", "policy", "system"]
TrustSource = Literal["verification", "drift", "constraint", "audit", "ci", "operator", "reconciliation"]
RepairAction = Literal["none", "observe", "constrain", "rollback", "quarantine", "adapt"]
VerificationDepth = Literal["normal", "elevated", "strict", "quarantined"]
PermissionScope = Literal["passive", "conditional", "restricted", "blocked"]


class TrustReason(str, Enum):
    CLEAN_EXECUTION = "clean_execution"
    POLICY_VIOLATION = "policy_violation"
    STRUCTURAL_DRIFT = "structural_drift"
    BEHAVIORAL_DRIFT = "behavioral_drift"
    ADVERSARIAL_DRIFT = "adversarial_drift"
    OPERATIONAL_DRIFT = "operational_drift"
    STATISTICAL_DRIFT = "statistical_drift"
    OBSERVER_DISSENT = "observer_dissent"
    CI_PASSED = "ci_passed"
    CI_FAILED = "ci_failed"
    REPAIR_SUCCEEDED = "repair_succeeded"


@dataclass(frozen=True)
class TrustDelta:
    component_id: str
    component_type: ComponentType
    source: TrustSource
    score_delta: float
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)
    repair_action: RepairAction = "none"


@dataclass(frozen=True)
class TrustState:
    component_id: str
    component_type: ComponentType
    trust_score: float = 1.0
    verification_depth: VerificationDepth = "normal"
    permission_scope: PermissionScope = "passive"
    last_repair_action: RepairAction | None = None
    evidence_count: int = 0


@dataclass(frozen=True)
class TrustProfile:
    recovery_rate: float = 0.25
    decay_rate: float = 1.0
    statistical_weight: float = 0.10
    operational_weight: float = 0.25
    adversarial_weight: float = 0.60
    structural_weight: float = 0.90
    policy_weight: float = 0.90
    behavioral_weight: float = 0.70
    clean_run_reward: float = 0.02
    ci_pass_reward: float = 0.03
    repair_reward: float = 0.04
    minimum_score: float = 0.0
    maximum_score: float = 1.0


DEFAULT_PROFILE = TrustProfile()


def clamp_score(value: float, profile: TrustProfile = DEFAULT_PROFILE) -> float:
    return max(profile.minimum_score, min(profile.maximum_score, value))


def derive_verification_depth(trust_score: float) -> VerificationDepth:
    if trust_score < 0.10:
        return "quarantined"
    if trust_score < 0.40:
        return "strict"
    if trust_score < 0.75:
        return "elevated"
    return "normal"


def derive_permission_scope(trust_score: float) -> PermissionScope:
    if trust_score < 0.10:
        return "blocked"
    if trust_score < 0.40:
        return "restricted"
    if trust_score < 0.75:
        return "conditional"
    return "passive"


def apply_trust_delta(
    state: TrustState,
    delta: TrustDelta,
    profile: TrustProfile = DEFAULT_PROFILE,
) -> TrustState:
    if delta.score_delta >= 0:
        adjusted = delta.score_delta * profile.recovery_rate
    else:
        adjusted = delta.score_delta * profile.decay_rate

    new_score = clamp_score(state.trust_score + adjusted, profile)

    return replace(
        state,
        trust_score=new_score,
        verification_depth=derive_verification_depth(new_score),
        permission_scope=derive_permission_scope(new_score),
        last_repair_action=delta.repair_action,
        evidence_count=state.evidence_count + 1,
    )


def apply_trust_deltas(
    state: TrustState,
    deltas: tuple[TrustDelta, ...],
    profile: TrustProfile = DEFAULT_PROFILE,
) -> TrustState:
    next_state = state
    for delta in deltas:
        next_state = apply_trust_delta(next_state, delta, profile)
    return next_state


def get_vector_value(vector: Any, key: str) -> float:
    if isinstance(vector, dict):
        return float(vector.get(key, 0.0) or 0.0)
    return float(getattr(vector, key, 0.0) or 0.0)


def trust_delta_from_drift(
    *,
    component_id: str,
    component_type: ComponentType,
    drift_assessment: Any,
    profile: TrustProfile = DEFAULT_PROFILE,
) -> tuple[TrustDelta, ...]:
    vector = getattr(drift_assessment, "drift_vector", drift_assessment)

    values = {
        "policy": get_vector_value(vector, "policy"),
        "structural": get_vector_value(vector, "structural"),
        "behavioral": get_vector_value(vector, "behavioral"),
        "adversarial": get_vector_value(vector, "adversarial"),
        "operational": get_vector_value(vector, "operational"),
        "statistical": get_vector_value(vector, "statistical"),
    }

    deltas: list[TrustDelta] = []

    mappings = [
        ("policy", profile.policy_weight, TrustReason.POLICY_VIOLATION.value, "rollback"),
        ("structural", profile.structural_weight, TrustReason.STRUCTURAL_DRIFT.value, "rollback"),
        ("behavioral", profile.behavioral_weight, TrustReason.BEHAVIORAL_DRIFT.value, "constrain"),
        ("adversarial", profile.adversarial_weight, TrustReason.ADVERSARIAL_DRIFT.value, "constrain"),
        ("operational", profile.operational_weight, TrustReason.OPERATIONAL_DRIFT.value, "observe"),
        ("statistical", profile.statistical_weight, TrustReason.STATISTICAL_DRIFT.value, "adapt"),
    ]

    for drift_type, weight, reason, repair_action in mappings:
        value = values[drift_type]
        if value > 0:
            deltas.append(
                TrustDelta(
                    component_id=component_id,
                    component_type=component_type,
                    source="drift",
                    score_delta=-(value * weight),
                    reason=reason,
                    evidence={drift_type: value},
                    repair_action=repair_action,
                )
            )

    if not deltas:
        deltas.append(
            TrustDelta(
                component_id=component_id,
                component_type=component_type,
                source="verification",
                score_delta=profile.clean_run_reward,
                reason=TrustReason.CLEAN_EXECUTION.value,
                evidence={"drift": "none"},
                repair_action="none",
            )
        )

    return tuple(deltas)


def trust_delta_from_reconciliation(
    *,
    component_id: str,
    component_type: ComponentType,
    reconciliation_result: Any,
) -> TrustDelta:
    correction = str(getattr(reconciliation_result, "correction", "")).upper()

    if correction == "OBSERVE":
        return TrustDelta(component_id, component_type, "reconciliation", 0.02, TrustReason.CLEAN_EXECUTION.value, {"correction": correction}, "none")
    if correction == "ADAPT":
        return TrustDelta(component_id, component_type, "reconciliation", -0.02, TrustReason.STATISTICAL_DRIFT.value, {"correction": correction}, "adapt")
    if correction == "CONSTRAIN":
        return TrustDelta(component_id, component_type, "reconciliation", -0.20, TrustReason.OBSERVER_DISSENT.value, {"correction": correction}, "constrain")
    if correction == "REVERT":
        return TrustDelta(component_id, component_type, "reconciliation", -0.50, TrustReason.BEHAVIORAL_DRIFT.value, {"correction": correction}, "rollback")

    return TrustDelta(component_id, component_type, "reconciliation", -0.80, TrustReason.STRUCTURAL_DRIFT.value, {"correction": correction}, "quarantine")


def trust_delta_from_ci(
    *,
    workflow_id: str,
    passed: bool,
    profile: TrustProfile = DEFAULT_PROFILE,
) -> TrustDelta:
    if passed:
        return TrustDelta(workflow_id, "workflow", "ci", profile.ci_pass_reward, TrustReason.CI_PASSED.value, {"passed": True}, "none")

    return TrustDelta(workflow_id, "workflow", "ci", -0.40, TrustReason.CI_FAILED.value, {"passed": False}, "constrain")


def initial_trust_state(component_id: str, component_type: ComponentType = "module") -> TrustState:
    return TrustState(
        component_id=component_id,
        component_type=component_type,
        trust_score=1.0,
        verification_depth="normal",
        permission_scope="passive",
        last_repair_action=None,
        evidence_count=0,
    )


def authority_scale_from_trust(trust_score: float) -> float:
    if trust_score < 0.10:
        return 0.0
    if trust_score < 0.40:
        return 0.25
    if trust_score < 0.75:
        return 0.50
    return 1.0


def scheduler_context_from_trust(state: TrustState) -> dict[str, Any]:
    return {
        "component_id": state.component_id,
        "trust_score": state.trust_score,
        "verification_depth": state.verification_depth,
        "permission_scope": state.permission_scope,
        "authority_scale": authority_scale_from_trust(state.trust_score),
    }
