"""
osint_core.drift
================

Drift detection for the Passive OSINT Control Panel.

Convert execution telemetry into a six-dimensional drift vector and a
correction recommendation. Detection is pure; the caller decides whether
to apply the recommended correction.

Design constraints:
- Drift is a vector, not a scalar.
- ``assess_drift`` does not mutate telemetry, baseline, or policy input.
- Correction priority: policy > structural > behavioral > adversarial >
  operational > statistical.
- Statistical drift may ADAPT only when nothing higher-priority fires.
- Adversarial drift CONSTRAINs before the system ADAPTs.

The public surface (``assess_drift``, ``aggregate_signals``,
``choose_dominant_drift_type``, ``recommend_correction``,
``estimate_confidence``) is fixed by ``tests/test_drift.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from math import prod
from typing import Any, Literal


# --------------------------------------------------------------------------
# Types
# --------------------------------------------------------------------------


class DriftType(str, Enum):
    STATISTICAL = "statistical"
    BEHAVIORAL = "behavioral"
    STRUCTURAL = "structural"
    ADVERSARIAL = "adversarial"
    OPERATIONAL = "operational"
    POLICY = "policy"


CorrectionVerb = Literal["ADAPT", "CONSTRAIN", "REVERT", "OBSERVE"]
Tier = Literal["T1", "T2", "T3", "T4"]


@dataclass(frozen=True)
class DriftVector:
    statistical: float = 0.0
    behavioral: float = 0.0
    structural: float = 0.0
    adversarial: float = 0.0
    operational: float = 0.0
    policy: float = 0.0

    def get(self, drift_type: DriftType) -> float:
        return float(getattr(self, drift_type.value))


@dataclass(frozen=True)
class DriftSignal:
    name: str
    drift_type: DriftType
    score: float
    reason: str
    tier: Tier
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DriftAssessment:
    drift_vector: DriftVector
    signals: list[DriftSignal]
    dominant_type: DriftType | None
    recommended_correction: CorrectionVerb
    confidence: float


@dataclass(frozen=True)
class TelemetrySnapshot:
    run_id: str
    manifest_hash: str
    dependency_hash: str
    runtime_python_version: str
    indicator_hash: str
    indicator_type: str
    input_rejected: bool
    rejection_reason: str
    sanitized_input_trace: str
    modules_requested: list[str]
    modules_executed: list[str]
    modules_blocked: list[str]
    authorized_target: bool
    duration_ms: int
    error_count: int
    timeout_count: int
    output_hash: str
    output_schema_valid: bool


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------


# Correction priority order. The first dimension with a non-zero value wins
# even if a lower-priority dimension has a higher raw score.
_PRIORITY: tuple[DriftType, ...] = (
    DriftType.POLICY,
    DriftType.STRUCTURAL,
    DriftType.BEHAVIORAL,
    DriftType.ADVERSARIAL,
    DriftType.OPERATIONAL,
    DriftType.STATISTICAL,
)


# Confidence weight per tier. T1 signals dominate, T4 barely move the needle.
# Capped below 1.0 so adding a signal always strictly increases the
# aggregated confidence (1 - prod(1 - w*s)).
_TIER_WEIGHT: dict[str, float] = {
    "T1": 0.9,
    "T2": 0.7,
    "T3": 0.5,
    "T4": 0.3,
}


# Patterns that indicate the input either targeted a sensitive endpoint
# (cloud metadata, loopback, file scheme) or attempted shell/script
# injection. A hit promotes the run to adversarial drift at score 0.7,
# which exceeds the CONSTRAIN threshold of 0.3.
_ADVERSARIAL_PATTERNS: tuple[str, ...] = (
    "../",
    "%2e%2e",
    "<script",
    "javascript:",
    "file:",
    "localhost",
    "127.0.0.1",
    "169.254.169.254",
    "$(",
    "`",
)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def assess_drift(
    *,
    telemetry: TelemetrySnapshot,
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> DriftAssessment:
    """
    Pure: returns a ``DriftAssessment`` without mutating any input.

    Detectors run in priority order so the resulting ``signals`` list reads
    top-down (policy first, statistical last), but the recommendation logic
    is driven by the aggregated vector, not by signal order.
    """
    baseline = baseline if isinstance(baseline, dict) else {}
    policy_result = policy_result if isinstance(policy_result, dict) else {}
    signals: list[DriftSignal] = []
    signals.extend(_check_policy_drift(policy_result))
    signals.extend(_check_structural_drift(telemetry, baseline))
    signals.extend(_check_behavioral_drift(telemetry, baseline))
    signals.extend(_check_adversarial_drift(telemetry))
    signals.extend(_check_operational_drift(telemetry, baseline))
    signals.extend(_check_statistical_drift(telemetry, baseline))

    drift_vector = aggregate_signals(signals)
    dominant_type = choose_dominant_drift_type(drift_vector)
    correction = recommend_correction(drift_vector)
    confidence = estimate_confidence(signals)

    return DriftAssessment(
        drift_vector=drift_vector,
        signals=signals,
        dominant_type=dominant_type,
        recommended_correction=correction,
        confidence=confidence,
    )


def aggregate_signals(signals: list[DriftSignal]) -> DriftVector:
    """Reduce per-type signals to their max score, zero-filling absent types."""
    by_type: dict[str, float] = {}
    for signal in signals:
        key = signal.drift_type.value
        score = float(signal.score)
        if score > by_type.get(key, 0.0):
            by_type[key] = score
    return DriftVector(
        statistical=by_type.get("statistical", 0.0),
        behavioral=by_type.get("behavioral", 0.0),
        structural=by_type.get("structural", 0.0),
        adversarial=by_type.get("adversarial", 0.0),
        operational=by_type.get("operational", 0.0),
        policy=by_type.get("policy", 0.0),
    )


def choose_dominant_drift_type(vector: DriftVector) -> DriftType | None:
    """Return the highest-priority dimension whose score is non-zero, else None."""
    for drift_type in _PRIORITY:
        if vector.get(drift_type) > 0.0:
            return drift_type
    return None


def recommend_correction(vector: DriftVector) -> CorrectionVerb:
    """
    Map a drift vector to a single correction verb from the closed set
    {REVERT, CONSTRAIN, ADAPT, OBSERVE}. See ``test_recommend_correction``
    in ``tests/test_drift.py`` for the canonical threshold table.
    """
    if vector.policy >= 0.6:
        return "REVERT"
    if vector.structural >= 0.5:
        return "REVERT"
    if vector.behavioral >= 0.7:
        return "REVERT"
    if vector.adversarial >= 0.3:
        return "CONSTRAIN"
    if vector.operational >= 0.7:
        return "CONSTRAIN"
    if vector.statistical >= 0.5:
        return "ADAPT"
    return "OBSERVE"


def estimate_confidence(signals: list[DriftSignal]) -> float:
    """
    Aggregate confidence as 1 - product(1 - tier_weight * score).

    Properties this guarantees:
    - Empty input returns 0.0.
    - Adding any non-zero signal strictly increases the result.
    - Higher tier (lower number) contributes more per unit score.
    - Output stays in [0.0, 1.0) because each ``_TIER_WEIGHT`` value is
      below 1.0.
    """
    if not signals:
        return 0.0
    contributions = [
        _TIER_WEIGHT.get(s.tier, 0.3) * max(0.0, min(1.0, float(s.score)))
        for s in signals
    ]
    return 1.0 - prod(1.0 - c for c in contributions)


# --------------------------------------------------------------------------
# Signal generators
# --------------------------------------------------------------------------


def _check_policy_drift(policy_result: dict[str, Any]) -> list[DriftSignal]:
    violations = policy_result.get("violations") if isinstance(policy_result, dict) else None
    if not isinstance(violations, list):
        return []
    signals: list[DriftSignal] = []
    for violation in violations:
        if not isinstance(violation, dict):
            continue
        code = str(violation.get("code", "unknown"))
        message = str(violation.get("message", "Policy violation."))
        module = violation.get("module")
        signals.append(
            DriftSignal(
                name=f"policy_violation:{code}",
                drift_type=DriftType.POLICY,
                score=1.0,
                reason=message,
                tier="T1",
                evidence={
                    "code": code,
                    "module": module,
                    "decision": policy_result.get("decision"),
                },
            )
        )
    return signals


def _check_structural_drift(
    telemetry: TelemetrySnapshot, baseline: dict[str, Any]
) -> list[DriftSignal]:
    signals: list[DriftSignal] = []

    expected_manifest = baseline.get("expected_manifest_hash")
    if expected_manifest and telemetry.manifest_hash != expected_manifest:
        signals.append(
            DriftSignal(
                name="manifest_hash_mismatch",
                drift_type=DriftType.STRUCTURAL,
                score=1.0,
                reason="Execution manifest hash differs from baseline.",
                tier="T1",
                evidence={
                    "expected": expected_manifest,
                    "observed": telemetry.manifest_hash,
                },
            )
        )

    expected_deps = baseline.get("expected_dependency_hash")
    if expected_deps and telemetry.dependency_hash != expected_deps:
        signals.append(
            DriftSignal(
                name="dependency_hash_mismatch",
                drift_type=DriftType.STRUCTURAL,
                score=0.9,
                reason="Dependency hash differs from baseline.",
                tier="T1",
                evidence={
                    "expected": expected_deps,
                    "observed": telemetry.dependency_hash,
                },
            )
        )

    expected_py = baseline.get("expected_runtime_python_version")
    if expected_py and telemetry.runtime_python_version != expected_py:
        # Score must be >= 0.5 to satisfy the REVERT threshold required by
        # test_structural_runtime_python_version_mismatch_reverts.
        signals.append(
            DriftSignal(
                name="runtime_python_version_changed",
                drift_type=DriftType.STRUCTURAL,
                score=0.6,
                reason="Runtime Python version differs from baseline.",
                tier="T2",
                evidence={
                    "expected": expected_py,
                    "observed": telemetry.runtime_python_version,
                },
            )
        )

    return signals


def _check_behavioral_drift(
    telemetry: TelemetrySnapshot, baseline: dict[str, Any]
) -> list[DriftSignal]:
    signals: list[DriftSignal] = []

    known = baseline.get("known_output_hashes")
    if not isinstance(known, dict):
        known = {}
    expected_output = known.get(telemetry.indicator_hash)
    if expected_output is not None and telemetry.output_hash != expected_output:
        signals.append(
            DriftSignal(
                name="same_input_different_output",
                drift_type=DriftType.BEHAVIORAL,
                score=0.9,
                reason="Same input hash produced a different output hash than baseline.",
                tier="T1",
                evidence={
                    "indicator_hash": telemetry.indicator_hash,
                    "expected_output": expected_output,
                    "observed_output": telemetry.output_hash,
                },
            )
        )

    if not telemetry.output_schema_valid:
        signals.append(
            DriftSignal(
                name="output_schema_invalid",
                drift_type=DriftType.BEHAVIORAL,
                score=0.8,
                reason="Output failed schema validation.",
                tier="T1",
                evidence={},
            )
        )

    return signals


def _check_adversarial_drift(telemetry: TelemetrySnapshot) -> list[DriftSignal]:
    # Only the reason and the sanitized trace are evaluated. The
    # ``input_rejected`` flag alone is not adversarial — a benign
    # validation error (empty input, oversized string) also rejects.
    haystack = " ".join(
        (telemetry.rejection_reason or "", telemetry.sanitized_input_trace or "")
    ).lower()
    if not haystack.strip():
        return []
    matches = [p for p in _ADVERSARIAL_PATTERNS if p.lower() in haystack]
    if not matches:
        return []
    return [
        DriftSignal(
            name="adversarial_pattern_detected",
            drift_type=DriftType.ADVERSARIAL,
            score=0.7,
            reason="Suspicious pattern in rejection reason or sanitized input trace.",
            tier="T2",
            evidence={"patterns": matches},
        )
    ]


def _check_operational_drift(
    telemetry: TelemetrySnapshot, baseline: dict[str, Any]
) -> list[DriftSignal]:
    signals: list[DriftSignal] = []

    runtime_p95 = baseline.get("runtime_p95_ms")
    if (
        isinstance(runtime_p95, (int, float))
        and runtime_p95 > 0
        and telemetry.duration_ms > runtime_p95 * 2
    ):
        signals.append(
            DriftSignal(
                name="runtime_boundary_exceeded",
                drift_type=DriftType.OPERATIONAL,
                score=0.5,
                reason="Runtime exceeded 2x the baseline p95.",
                tier="T3",
                evidence={
                    "duration_ms": telemetry.duration_ms,
                    "runtime_p95_ms": runtime_p95,
                },
            )
        )

    error_threshold = baseline.get("error_rate_threshold")
    if (
        isinstance(error_threshold, (int, float))
        and telemetry.error_count > error_threshold
    ):
        signals.append(
            DriftSignal(
                name="error_threshold_exceeded",
                drift_type=DriftType.OPERATIONAL,
                score=0.6,
                reason="Error count exceeded baseline threshold.",
                tier="T3",
                evidence={
                    "error_count": telemetry.error_count,
                    "error_rate_threshold": error_threshold,
                },
            )
        )

    timeout_threshold = baseline.get("timeout_threshold")
    if (
        isinstance(timeout_threshold, (int, float))
        and telemetry.timeout_count > timeout_threshold
    ):
        signals.append(
            DriftSignal(
                name="timeout_threshold_exceeded",
                drift_type=DriftType.OPERATIONAL,
                score=0.4,
                reason="Timeout count exceeded baseline threshold.",
                tier="T3",
                evidence={
                    "timeout_count": telemetry.timeout_count,
                    "timeout_threshold": timeout_threshold,
                },
            )
        )

    return signals


def _check_statistical_drift(
    telemetry: TelemetrySnapshot, baseline: dict[str, Any]
) -> list[DriftSignal]:
    signals: list[DriftSignal] = []

    input_dist: dict[str, float] = baseline.get("input_type_distribution") or {}
    if input_dist and telemetry.indicator_type not in input_dist:
        # Score 0.5 so an entirely new indicator type clears the ADAPT
        # threshold without further evidence.
        signals.append(
            DriftSignal(
                name="input_type_distribution_shifted",
                drift_type=DriftType.STATISTICAL,
                score=0.5,
                reason=(
                    f"Indicator type {telemetry.indicator_type!r} absent from "
                    "baseline distribution."
                ),
                tier="T4",
                evidence={
                    "indicator_type": telemetry.indicator_type,
                    "baseline_keys": sorted(input_dist.keys()),
                },
            )
        )

    module_dist: dict[str, float] = baseline.get("module_usage_distribution") or {}
    if module_dist:
        unseen = [m for m in telemetry.modules_executed if m not in module_dist]
        if unseen:
            signals.append(
                DriftSignal(
                    name="module_usage_distribution_shifted",
                    drift_type=DriftType.STATISTICAL,
                    score=0.4,
                    reason="Modules executed include entries absent from baseline distribution.",
                    tier="T4",
                    evidence={
                        "unseen_modules": unseen,
                        "baseline_keys": sorted(module_dist.keys()),
                    },
                )
            )

    return signals
