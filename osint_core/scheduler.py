"""
osint_core.scheduler
====================

Latency-conscious scheduler for the Enterprise Drift-Aware OSINT Control Fabric.

The scheduler allocates time, trust, and authority. It does not execute actions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


RiskLabel = Literal["low", "medium", "high", "critical"]
TrustState = Literal["normal", "degraded", "suspicious", "contested", "unsafe"]
RouteName = Literal["FAST", "DELIBERATIVE", "CONTAINMENT", "FAIL_CLOSED"]


class ScheduleReason(str, Enum):
    FAST_PATH_AVAILABLE = "fast_path_available"
    DELIBERATIVE_PATH_AVAILABLE = "deliberative_path_available"
    DEADLINE_TOO_TIGHT = "deadline_too_tight"
    TRUST_STATE_DEGRADED = "trust_state_degraded"
    SHORTCUT_DEBT_TOO_HIGH = "shortcut_debt_too_high"
    INVARIANT_VIOLATION = "invariant_violation"
    NO_SAFE_ACTION_FITS = "no_safe_action_fits"
    MISSING_ROLLBACK = "missing_rollback"
    LOW_CONFIDENCE = "low_confidence"


@dataclass(frozen=True)
class DecisionPacket:
    intent_id: str
    action: str
    risk_label: RiskLabel
    confidence: float
    reversibility: float
    deadline_ms: int
    verification_cost_ms: int
    execution_cost_ms: int
    rollback_cost_ms: int
    expected_utility_decay: float
    required_checks: tuple[str, ...]
    rollback_plan: str
    uncertainty_notes: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ShortcutDebt:
    reduced_checks: int = 0
    cached_policy_uses: int = 0
    skipped_deep_analysis: int = 0
    emergency_overrides: int = 0

    @property
    def score(self) -> float:
        return min(
            1.0,
            (self.reduced_checks * 0.10)
            + (self.cached_policy_uses * 0.05)
            + (self.skipped_deep_analysis * 0.15)
            + (self.emergency_overrides * 0.40),
        )


@dataclass(frozen=True)
class SystemState:
    trust_state: TrustState = "normal"
    shortcut_debt: ShortcutDebt = field(default_factory=ShortcutDebt)
    shortcut_debt_limit: float = 0.70
    queue_depth: int = 0
    hardware_state: TrustState = "normal"


@dataclass(frozen=True)
class ScheduleDecision:
    route: RouteName
    reason: ScheduleReason
    allowed: bool
    authority_scale: float
    required_checks: tuple[str, ...]
    skipped_checks: tuple[str, ...]
    notes: tuple[str, ...] = field(default_factory=tuple)


INVARIANT_CHECKS: tuple[str, ...] = (
    "hash_salt_present",
    "intent_signature_verified",
    "scope_validated",
    "policy_evaluated",
    "forbidden_modules_blocked",
    "raw_indicators_excluded",
    "conditional_modules_authorized",
)

ADAPTIVE_CHECKS: tuple[str, ...] = (
    "deep_log_correlation",
    "long_horizon_analysis",
    "full_counterfactual_simulation",
    "secondary_model_review",
)


def total_required_time_ms(packet: DecisionPacket) -> int:
    return packet.verification_cost_ms + packet.execution_cost_ms + packet.rollback_cost_ms


def fits_deadline(packet: DecisionPacket) -> bool:
    return total_required_time_ms(packet) <= packet.deadline_ms


def has_required_rollback(packet: DecisionPacket) -> bool:
    if packet.risk_label in {"high", "critical"}:
        return bool(packet.rollback_plan and packet.rollback_cost_ms > 0)
    return True


def invariant_violations(packet: DecisionPacket) -> tuple[str, ...]:
    required = set(packet.required_checks)
    return tuple(check for check in INVARIANT_CHECKS if check not in required)


def risk_weight(risk_label: RiskLabel) -> float:
    return {"low": 0.25, "medium": 0.50, "high": 0.75, "critical": 1.00}[risk_label]


def safe_utility(packet: DecisionPacket) -> float:
    time_ratio = min(1.0, total_required_time_ms(packet) / max(packet.deadline_ms, 1))
    return max(
        0.0,
        (packet.confidence * 0.40)
        + (packet.reversibility * 0.30)
        + ((1.0 - risk_weight(packet.risk_label)) * 0.20)
        + ((1.0 - time_ratio) * 0.10)
        - (packet.expected_utility_decay * 0.10),
    )


def schedule_decision(packet: DecisionPacket, state: SystemState | None = None) -> ScheduleDecision:
    state = state or SystemState()

    missing_invariants = invariant_violations(packet)
    if missing_invariants:
        return ScheduleDecision(
            route="FAIL_CLOSED",
            reason=ScheduleReason.INVARIANT_VIOLATION,
            allowed=False,
            authority_scale=0.0,
            required_checks=tuple(packet.required_checks),
            skipped_checks=missing_invariants,
            notes=("Invariant checks cannot be skipped under deadline pressure.",),
        )

    if not has_required_rollback(packet):
        return ScheduleDecision(
            route="FAIL_CLOSED",
            reason=ScheduleReason.MISSING_ROLLBACK,
            allowed=False,
            authority_scale=0.0,
            required_checks=tuple(packet.required_checks),
            skipped_checks=(),
            notes=("High-impact action requires rollback or containment plan.",),
        )

    if state.shortcut_debt.score >= state.shortcut_debt_limit:
        return containment_decision(packet, ScheduleReason.SHORTCUT_DEBT_TOO_HIGH, "Shortcut debt exceeded configured limit.")

    if state.trust_state in {"contested", "unsafe"} or state.hardware_state in {"contested", "unsafe"}:
        return containment_decision(packet, ScheduleReason.TRUST_STATE_DEGRADED, "Trust or hardware state is contested/unsafe.")

    if packet.confidence < 0.30 and packet.risk_label in {"high", "critical"}:
        return containment_decision(packet, ScheduleReason.LOW_CONFIDENCE, "Confidence too low for high-impact decision.")

    if fits_deadline(packet):
        if packet.risk_label in {"low", "medium"} and packet.reversibility >= 0.50:
            return ScheduleDecision(
                route="FAST",
                reason=ScheduleReason.FAST_PATH_AVAILABLE,
                allowed=True,
                authority_scale=1.0,
                required_checks=tuple(packet.required_checks),
                skipped_checks=(),
                notes=("Low/medium risk action fits available decision window.",),
            )

        return ScheduleDecision(
            route="DELIBERATIVE",
            reason=ScheduleReason.DELIBERATIVE_PATH_AVAILABLE,
            allowed=True,
            authority_scale=0.75,
            required_checks=tuple(packet.required_checks),
            skipped_checks=(),
            notes=("High-impact or lower-reversibility action fits full verification window.",),
        )

    if packet.reversibility >= 0.75:
        return containment_decision(packet, ScheduleReason.DEADLINE_TOO_TIGHT, "Full verification/execution/rollback does not fit deadline.")

    return ScheduleDecision(
        route="FAIL_CLOSED",
        reason=ScheduleReason.NO_SAFE_ACTION_FITS,
        allowed=False,
        authority_scale=0.0,
        required_checks=tuple(packet.required_checks),
        skipped_checks=(),
        notes=("No safe action fits inside the useful decision window.",),
    )


def containment_decision(packet: DecisionPacket, reason: ScheduleReason, note: str) -> ScheduleDecision:
    return ScheduleDecision(
        route="CONTAINMENT",
        reason=reason,
        allowed=True,
        authority_scale=0.25,
        required_checks=tuple(packet.required_checks),
        skipped_checks=tuple(check for check in ADAPTIVE_CHECKS if check in packet.required_checks),
        notes=(note, "Authority reduced; prefer reversible, bounded action."),
    )
