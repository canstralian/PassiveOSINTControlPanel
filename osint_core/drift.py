"""
osint_core.drift
================

Convert execution telemetry into a drift vector.

Principles:
- Drift is a vector, not a scalar.
- Detection does not mutate state: telemetry, baseline, and policy input are
  read-only here.
- Correction is separate from detection and limited to the closed verb set
  (ADAPT, CONSTRAIN, REVERT, OBSERVE).
- Policy drift outranks all other drift.
- Structural and behavioral drift are revert-class.
- Adversarial drift constrains before the system adapts.
- Statistical drift may adapt only when nothing higher-priority fires.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Mapping, Sequence


CorrectionVerb = Literal["ADAPT", "CONSTRAIN", "REVERT", "OBSERVE"]
SignalTier = Literal["T1", "T2", "T3", "T4"]


class DriftType(str, Enum):
    STATISTICAL = "statistical"
    BEHAVIORAL = "behavioral"
    STRUCTURAL = "structural"
    ADVERSARIAL = "adversarial"
    OPERATIONAL = "operational"
    POLICY = "policy"


@dataclass(frozen=True)
class DriftVector:
    statistical: float = 0.0
    behavioral: float = 0.0
    structural: float = 0.0
    adversarial: float = 0.0
    operational: float = 0.0
    policy: float = 0.0

    def value_for(self, drift_type: DriftType) -> float:
        return float(getattr(self, drift_type.value))


@dataclass(frozen=True)
class DriftSignal:
    name: str
    drift_type: DriftType
    score: float
    reason: str
    tier: SignalTier
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TelemetrySnapshot:
    run_id: str
    manifest_hash: str
    dependency_hash: str
    runtime_python_version: str
    indicator_hash: str
    indicator_type: str
    input_rejected: bool = False
    rejection_reason: str = ""
    sanitized_input_trace: str = ""
    modules_requested: list[str] = field(default_factory=list)
    modules_executed: list[str] = field(default_factory=list)
    modules_blocked: list[str] = field(default_factory=list)
    authorized_target: bool = False
    duration_ms: int = 0
    error_count: int = 0
    timeout_count: int = 0
    output_hash: str = ""
    output_schema_valid: bool = True


@dataclass(frozen=True)
class DriftAssessment:
    drift_vector: DriftVector
    signals: list[DriftSignal]
    dominant_type: DriftType | None
    recommended_correction: CorrectionVerb
    confidence: float


# Correction priority: policy > structural > behavioral > adversarial >
# operational > statistical. Do not reorder without out-of-band approval.
DRIFT_PRIORITY: tuple[DriftType, ...] = (
    DriftType.POLICY,
    DriftType.STRUCTURAL,
    DriftType.BEHAVIORAL,
    DriftType.ADVERSARIAL,
    DriftType.OPERATIONAL,
    DriftType.STATISTICAL,
)

SUSPICIOUS_PATTERNS: tuple[str, ...] = (
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
    ";",
    "|",
)

# Weight of a signal's tier when estimating confidence.
TIER_WEIGHTS: dict[str, float] = {"T1": 1.0, "T2": 0.75, "T3": 0.5, "T4": 0.25}

# Policy violation codes mapped to (score, tier).
POLICY_VIOLATION_SEVERITY: dict[str, tuple[float, SignalTier]] = {
    "forbidden_module": (1.0, "T1"),
    "authorization_required": (0.8, "T1"),
}
DEFAULT_POLICY_VIOLATION_SEVERITY: tuple[float, SignalTier] = (0.7, "T2")

# Share below which an indicator type counts as outside the modeled input mix.
MIN_MODELED_INPUT_SHARE = 0.05


def check_policy_drift(policy_result: Mapping[str, Any]) -> list[DriftSignal]:
    signals: list[DriftSignal] = []
    for violation in policy_result.get("violations", []) or []:
        code = str(violation.get("code", "unknown"))
        score, tier = POLICY_VIOLATION_SEVERITY.get(
            code, DEFAULT_POLICY_VIOLATION_SEVERITY
        )
        signals.append(
            DriftSignal(
                name="policy_violation",
                drift_type=DriftType.POLICY,
                score=score,
                reason=str(violation.get("message", "Policy violation recorded")),
                tier=tier,
                evidence={"code": code, "module": violation.get("module")},
            )
        )
    return signals


def check_adversarial_drift(telemetry: TelemetrySnapshot) -> list[DriftSignal]:
    signals: list[DriftSignal] = []
    haystacks = (telemetry.rejection_reason, telemetry.sanitized_input_trace)
    for pattern in SUSPICIOUS_PATTERNS:
        if any(pattern in haystack for haystack in haystacks if haystack):
            signals.append(
                DriftSignal(
                    name="suspicious_input_pattern",
                    drift_type=DriftType.ADVERSARIAL,
                    score=0.7,
                    reason="Suspicious input pattern detected",
                    tier="T2",
                    evidence={"pattern": pattern},
                )
            )
    return signals


def check_operational_drift(
    telemetry: TelemetrySnapshot, baseline: Mapping[str, Any]
) -> list[DriftSignal]:
    signals: list[DriftSignal] = []

    runtime_p95 = float(baseline.get("runtime_p95_ms", 0) or 0)
    if runtime_p95 > 0 and telemetry.duration_ms > runtime_p95 * 2:
        signals.append(
            DriftSignal(
                name="runtime_boundary_exceeded",
                drift_type=DriftType.OPERATIONAL,
                score=0.5,
                reason="Runtime exceeded expected boundary",
                tier="T3",
                evidence={
                    "duration_ms": telemetry.duration_ms,
                    "runtime_p95_ms": runtime_p95,
                },
            )
        )

    error_threshold = int(baseline.get("error_rate_threshold", 0) or 0)
    if telemetry.error_count > error_threshold:
        signals.append(
            DriftSignal(
                name="error_threshold_exceeded",
                drift_type=DriftType.OPERATIONAL,
                score=0.6,
                reason="Error rate exceeded baseline",
                tier="T3",
                evidence={
                    "error_count": telemetry.error_count,
                    "error_rate_threshold": error_threshold,
                },
            )
        )

    timeout_threshold = int(baseline.get("timeout_threshold", 0) or 0)
    if telemetry.timeout_count > timeout_threshold:
        signals.append(
            DriftSignal(
                name="timeout_threshold_exceeded",
                drift_type=DriftType.OPERATIONAL,
                score=0.4,
                reason="Timeout rate elevated",
                tier="T3",
                evidence={
                    "timeout_count": telemetry.timeout_count,
                    "timeout_threshold": timeout_threshold,
                },
            )
        )

    return signals


def check_structural_drift(
    telemetry: TelemetrySnapshot,
    baseline: Mapping[str, Any],
    manifest: Mapping[str, Any] | None = None,
) -> list[DriftSignal]:
    signals: list[DriftSignal] = []

    expected_manifest = (
        manifest.get("hash") if manifest else baseline.get("expected_manifest_hash")
    )
    if expected_manifest and telemetry.manifest_hash != expected_manifest:
        signals.append(
            DriftSignal(
                name="manifest_hash_mismatch",
                drift_type=DriftType.STRUCTURAL,
                score=1.0,
                reason="Execution manifest mismatch",
                tier="T1",
                evidence={
                    "observed": telemetry.manifest_hash,
                    "expected": expected_manifest,
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
                reason="Dependency graph changed",
                tier="T1",
                evidence={
                    "observed": telemetry.dependency_hash,
                    "expected": expected_deps,
                },
            )
        )

    expected_python = baseline.get("expected_runtime_python_version")
    if expected_python and telemetry.runtime_python_version != expected_python:
        signals.append(
            DriftSignal(
                name="runtime_python_version_changed",
                drift_type=DriftType.STRUCTURAL,
                score=0.6,
                reason="Runtime version changed",
                tier="T2",
                evidence={
                    "observed": telemetry.runtime_python_version,
                    "expected": expected_python,
                },
            )
        )

    return signals


def check_behavioral_drift(
    telemetry: TelemetrySnapshot, baseline: Mapping[str, Any]
) -> list[DriftSignal]:
    signals: list[DriftSignal] = []

    known_hashes: Mapping[str, str] = baseline.get("known_output_hashes", {}) or {}
    previous_output = known_hashes.get(telemetry.indicator_hash)
    if previous_output is not None and telemetry.output_hash != previous_output:
        signals.append(
            DriftSignal(
                name="output_hash_changed",
                drift_type=DriftType.BEHAVIORAL,
                score=0.9,
                reason="Same input produced different output",
                tier="T1",
                evidence={
                    "indicator_hash": telemetry.indicator_hash,
                    "observed": telemetry.output_hash,
                    "expected": previous_output,
                },
            )
        )

    if not telemetry.output_schema_valid:
        signals.append(
            DriftSignal(
                name="output_schema_invalid",
                drift_type=DriftType.BEHAVIORAL,
                score=0.8,
                reason="Output schema invalid",
                tier="T1",
                evidence={"run_id": telemetry.run_id},
            )
        )

    return signals


def check_statistical_drift(
    telemetry: TelemetrySnapshot, baseline: Mapping[str, Any]
) -> list[DriftSignal]:
    signals: list[DriftSignal] = []

    input_distribution: Mapping[str, float] = (
        baseline.get("input_type_distribution", {}) or {}
    )
    observed_share = float(input_distribution.get(telemetry.indicator_type, 0.0))
    if input_distribution and observed_share < MIN_MODELED_INPUT_SHARE:
        signals.append(
            DriftSignal(
                name="input_type_distribution_shifted",
                drift_type=DriftType.STATISTICAL,
                score=0.5,
                reason="Input type distribution shifted",
                tier="T4",
                evidence={
                    "indicator_type": telemetry.indicator_type,
                    "modeled_share": observed_share,
                },
            )
        )

    module_distribution: Mapping[str, float] = (
        baseline.get("module_usage_distribution", {}) or {}
    )
    unmodeled_modules = [
        module
        for module in telemetry.modules_executed
        if float(module_distribution.get(module, 0.0)) <= 0.0
    ]
    if module_distribution and unmodeled_modules:
        signals.append(
            DriftSignal(
                name="module_usage_distribution_shifted",
                drift_type=DriftType.STATISTICAL,
                score=0.3,
                reason="Module usage distribution shifted",
                tier="T4",
                evidence={"unmodeled_modules": unmodeled_modules},
            )
        )

    return signals


def aggregate_signals(signals: Sequence[DriftSignal]) -> DriftVector:
    """Aggregate signals into a drift vector using the max score per type."""
    scores: dict[str, float] = {drift_type.value: 0.0 for drift_type in DriftType}
    for signal in signals:
        key = signal.drift_type.value
        scores[key] = max(scores[key], float(signal.score))
    return DriftVector(**scores)


def choose_dominant_drift_type(vector: DriftVector) -> DriftType | None:
    """Return the highest-priority non-zero drift type, or None if clean."""
    for drift_type in DRIFT_PRIORITY:
        if vector.value_for(drift_type) > 0.0:
            return drift_type
    return None


def recommend_correction(
    vector: DriftVector, signals: Sequence[DriftSignal] | None = None
) -> CorrectionVerb:
    """Map a drift vector onto the closed correction-verb set."""
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


def estimate_confidence(signals: Sequence[DriftSignal]) -> float:
    """
    Estimate detection confidence from signal scores and tiers.

    Saturating in [0, 1): every additional signal strictly increases
    confidence, higher tiers (T1 strongest) and scores contribute more,
    and no signals means zero confidence.
    """
    weighted = sum(
        float(signal.score) * TIER_WEIGHTS.get(str(signal.tier), 0.25)
        for signal in signals
    )
    if weighted <= 0.0:
        return 0.0
    return weighted / (weighted + 1.0)


def assess_drift(
    *,
    telemetry: TelemetrySnapshot,
    baseline: Mapping[str, Any],
    policy_result: Mapping[str, Any],
    manifest: Mapping[str, Any] | None = None,
) -> DriftAssessment:
    """
    Assess drift for a single run. Pure: inputs are never mutated.

    Parameters
    ----------
    telemetry:
        Snapshot of the run being assessed.
    baseline:
        Expected values (hashes, thresholds, distributions) for a clean run.
    policy_result:
        Serialized policy evaluation for the run (decision, violations, ...).
    manifest:
        Optional approved manifest; its "hash" overrides the baseline's
        expected manifest hash when provided.
    """
    signals: list[DriftSignal] = []
    signals += check_policy_drift(policy_result)
    signals += check_adversarial_drift(telemetry)
    signals += check_operational_drift(telemetry, baseline)
    signals += check_structural_drift(telemetry, baseline, manifest)
    signals += check_behavioral_drift(telemetry, baseline)
    signals += check_statistical_drift(telemetry, baseline)

    drift_vector = aggregate_signals(signals)

    return DriftAssessment(
        drift_vector=drift_vector,
        signals=signals,
        dominant_type=choose_dominant_drift_type(drift_vector),
        recommended_correction=recommend_correction(drift_vector, signals),
        confidence=estimate_confidence(signals),
    )
