"""
osint_core/drift.py

Purpose:
    Convert execution telemetry into a drift vector.

Principles:
    - Drift is a vector, not a scalar.
    - Detection does not mutate state.
    - Correction is separate.
    - Policy drift outranks statistical drift.
    - Adversarial drift constrains before adapting.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal


class DriftType(str, Enum):
    """Enumeration of drift categories."""
    STATISTICAL = "statistical"
    BEHAVIORAL = "behavioral"
    STRUCTURAL = "structural"
    ADVERSARIAL = "adversarial"
    OPERATIONAL = "operational"
    POLICY = "policy"


@dataclass(frozen=True)
class DriftVector:
    """
    Six-dimensional drift vector representing detection confidence in each category.
    All values range from 0.0 (no drift) to 1.0 (maximum drift).
    """
    statistical: float = 0.0
    behavioral: float = 0.0
    structural: float = 0.0
    adversarial: float = 0.0
    operational: float = 0.0
    policy: float = 0.0


@dataclass(frozen=True)
class DriftSignal:
    """
    Individual drift detection signal with evidence and classification.
    """
    name: str
    drift_type: DriftType
    score: float
    reason: str
    tier: Literal["T1", "T2", "T3", "T4"]
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TelemetrySnapshot:
    """
    Immutable snapshot of a single execution run's telemetry.
    """
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


@dataclass(frozen=True)
class DriftAssessment:
    """
    Complete drift assessment including vector, signals, and recommended action.
    """
    drift_vector: DriftVector
    signals: list[DriftSignal]
    dominant_type: DriftType | None
    recommended_correction: str
    confidence: float


def assess_drift(
    telemetry: TelemetrySnapshot,
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> DriftAssessment:
    """
    Main drift assessment function.

    Analyzes telemetry against baseline and policy to detect drift across all categories.
    Returns a complete assessment with signals, vector, and recommended correction.

    Args:
        telemetry: Immutable snapshot of execution telemetry
        baseline: Baseline data dictionary
        policy_result: Policy evaluation result

    Returns:
        DriftAssessment with complete analysis
    """
    signals: list[DriftSignal] = []

    # Check drift in priority order (though all checks run)
    signals.extend(check_policy_drift(policy_result))
    signals.extend(check_adversarial_drift(telemetry))
    signals.extend(check_operational_drift(telemetry, baseline))
    signals.extend(check_structural_drift(telemetry, baseline))
    signals.extend(check_behavioral_drift(telemetry, baseline))
    signals.extend(check_statistical_drift(telemetry, baseline))

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


def check_policy_drift(policy_result: dict[str, Any]) -> list[DriftSignal]:
    """Check for policy violations."""
    signals: list[DriftSignal] = []

    violations = policy_result.get("violations", [])
    if not violations:
        return signals

    for violation in violations:
        signals.append(
            DriftSignal(
                name="policy_violation",
                drift_type=DriftType.POLICY,
                score=1.0,
                reason=violation.get("message", "Policy violation"),
                tier="T1",
                evidence={"code": violation.get("code"), "module": violation.get("module")},
            )
        )

    return signals


def check_adversarial_drift(telemetry: TelemetrySnapshot) -> list[DriftSignal]:
    """Check for adversarial or suspicious input patterns."""
    signals: list[DriftSignal] = []

    suspicious_patterns = [
        (r"\.\./", "path_traversal"),
        (r"%2e%2e", "encoded_traversal"),
        (r"<script", "xss_attempt"),
        (r"javascript:", "javascript_protocol"),
        (r"file:", "file_protocol"),
        (r"localhost", "localhost_target"),
        (r"127\.0\.0\.1", "loopback_target"),
        (r"169\.254\.169\.254", "metadata_endpoint"),
        (r"\$\(", "command_substitution"),
        (r"`", "backtick_execution"),
        (r";", "command_separator"),
        (r"\|", "pipe_operator"),
    ]

    check_text = (telemetry.rejection_reason + " " + telemetry.sanitized_input_trace).lower()

    for pattern, pattern_name in suspicious_patterns:
        if re.search(pattern, check_text):
            signals.append(
                DriftSignal(
                    name="adversarial_pattern_detected",
                    drift_type=DriftType.ADVERSARIAL,
                    score=0.7,
                    reason=f"Suspicious pattern detected: {pattern_name}",
                    tier="T2",
                    evidence={"pattern": pattern_name, "matched": pattern},
                )
            )
            break  # Only report one adversarial signal to avoid duplication

    return signals


def check_operational_drift(
    telemetry: TelemetrySnapshot,
    baseline: dict[str, Any],
) -> list[DriftSignal]:
    """Check for operational anomalies (runtime, errors, timeouts)."""
    signals: list[DriftSignal] = []

    runtime_p95 = baseline.get("runtime_p95_ms", 500)
    if telemetry.duration_ms > runtime_p95 * 2:
        signals.append(
            DriftSignal(
                name="runtime_boundary_exceeded",
                drift_type=DriftType.OPERATIONAL,
                score=0.5,
                reason="Runtime exceeded expected boundary",
                tier="T3",
                evidence={"duration_ms": telemetry.duration_ms, "p95": runtime_p95},
            )
        )

    error_threshold = baseline.get("error_rate_threshold", 2)
    if telemetry.error_count > error_threshold:
        signals.append(
            DriftSignal(
                name="error_threshold_exceeded",
                drift_type=DriftType.OPERATIONAL,
                score=0.6,
                reason="Error rate exceeded baseline",
                tier="T3",
                evidence={"error_count": telemetry.error_count, "threshold": error_threshold},
            )
        )

    timeout_threshold = baseline.get("timeout_threshold", 1)
    if telemetry.timeout_count > timeout_threshold:
        signals.append(
            DriftSignal(
                name="timeout_threshold_exceeded",
                drift_type=DriftType.OPERATIONAL,
                score=0.4,
                reason="Timeout rate elevated",
                tier="T3",
                evidence={"timeout_count": telemetry.timeout_count, "threshold": timeout_threshold},
            )
        )

    return signals


def check_structural_drift(
    telemetry: TelemetrySnapshot,
    baseline: dict[str, Any],
) -> list[DriftSignal]:
    """Check for structural changes (manifest, dependencies, runtime)."""
    signals: list[DriftSignal] = []

    expected_manifest = baseline.get("expected_manifest_hash", "")
    if expected_manifest and telemetry.manifest_hash != expected_manifest:
        signals.append(
            DriftSignal(
                name="manifest_mismatch",
                drift_type=DriftType.STRUCTURAL,
                score=1.0,
                reason="Execution manifest mismatch",
                tier="T1",
                evidence={
                    "expected": expected_manifest,
                    "actual": telemetry.manifest_hash,
                },
            )
        )

    expected_deps = baseline.get("expected_dependency_hash", "")
    if expected_deps and telemetry.dependency_hash != expected_deps:
        signals.append(
            DriftSignal(
                name="dependency_mismatch",
                drift_type=DriftType.STRUCTURAL,
                score=0.9,
                reason="Dependency graph changed",
                tier="T1",
                evidence={
                    "expected": expected_deps,
                    "actual": telemetry.dependency_hash,
                },
            )
        )

    expected_version = baseline.get("expected_runtime_python_version", "")
    if expected_version and telemetry.runtime_python_version != expected_version:
        signals.append(
            DriftSignal(
                name="runtime_version_changed",
                drift_type=DriftType.STRUCTURAL,
                score=0.6,
                reason="Runtime version changed",
                tier="T2",
                evidence={
                    "expected": expected_version,
                    "actual": telemetry.runtime_python_version,
                },
            )
        )

    return signals


def check_behavioral_drift(
    telemetry: TelemetrySnapshot,
    baseline: dict[str, Any],
) -> list[DriftSignal]:
    """Check for behavioral changes (same input → different output)."""
    signals: list[DriftSignal] = []

    known_hashes = baseline.get("known_output_hashes", {})
    if telemetry.indicator_hash in known_hashes:
        expected_output = known_hashes[telemetry.indicator_hash]
        if telemetry.output_hash != expected_output:
            signals.append(
                DriftSignal(
                    name="output_hash_mismatch",
                    drift_type=DriftType.BEHAVIORAL,
                    score=0.9,
                    reason="Same input produced different output",
                    tier="T1",
                    evidence={
                        "indicator_hash": telemetry.indicator_hash,
                        "expected": expected_output,
                        "actual": telemetry.output_hash,
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
    telemetry: TelemetrySnapshot,
    baseline: dict[str, Any],
) -> list[DriftSignal]:
    """Check for statistical distribution shifts."""
    signals: list[DriftSignal] = []

    # Input type distribution drift
    input_dist = baseline.get("input_type_distribution", {})
    if input_dist and telemetry.indicator_type not in input_dist:
        # New type never seen before
        signals.append(
            DriftSignal(
                name="input_type_distribution_shifted",
                drift_type=DriftType.STATISTICAL,
                score=0.6,
                reason="Input type distribution shifted (new type)",
                tier="T4",
                evidence={
                    "type": telemetry.indicator_type,
                    "baseline": list(input_dist.keys()),
                },
            )
        )
    elif input_dist and telemetry.indicator_type in input_dist:
        # Check if this type is significantly underrepresented
        if input_dist[telemetry.indicator_type] < 0.05:  # Less than 5% in baseline
            signals.append(
                DriftSignal(
                    name="input_type_distribution_shifted",
                    drift_type=DriftType.STATISTICAL,
                    score=0.4,
                    reason="Input type distribution shifted (rare type)",
                    tier="T4",
                    evidence={
                        "type": telemetry.indicator_type,
                        "baseline_frequency": input_dist[telemetry.indicator_type],
                    },
                )
            )

    # Module usage distribution drift (simplified)
    module_dist = baseline.get("module_usage_distribution", {})
    for module in telemetry.modules_executed:
        if module_dist and module not in module_dist:
            signals.append(
                DriftSignal(
                    name="module_usage_distribution_shifted",
                    drift_type=DriftType.STATISTICAL,
                    score=0.3,
                    reason="Module usage distribution shifted (new module)",
                    tier="T4",
                    evidence={
                        "module": module,
                        "baseline": list(module_dist.keys()),
                    },
                )
            )
            break  # Only report once

    return signals


def aggregate_signals(signals: list[DriftSignal]) -> DriftVector:
    """
    Aggregate signals into a drift vector using max score per type.

    Args:
        signals: List of drift signals

    Returns:
        DriftVector with max score for each drift type
    """
    scores = {
        "statistical": 0.0,
        "behavioral": 0.0,
        "structural": 0.0,
        "adversarial": 0.0,
        "operational": 0.0,
        "policy": 0.0,
    }

    for signal in signals:
        drift_type_key = signal.drift_type.value
        scores[drift_type_key] = max(scores[drift_type_key], signal.score)

    return DriftVector(**scores)


def choose_dominant_drift_type(vector: DriftVector) -> DriftType | None:
    """
    Choose dominant drift type based on priority order, not raw score.

    Priority: policy > structural > behavioral > adversarial > operational > statistical

    Args:
        vector: DriftVector to analyze

    Returns:
        Dominant DriftType or None if no drift detected
    """
    priority_order = [
        (DriftType.POLICY, vector.policy),
        (DriftType.STRUCTURAL, vector.structural),
        (DriftType.BEHAVIORAL, vector.behavioral),
        (DriftType.ADVERSARIAL, vector.adversarial),
        (DriftType.OPERATIONAL, vector.operational),
        (DriftType.STATISTICAL, vector.statistical),
    ]

    for drift_type, score in priority_order:
        if score > 0:
            return drift_type

    return None


def recommend_correction(vector: DriftVector) -> str:
    """
    Recommend correction action based on drift vector.

    Correction priority:
    - REVERT: policy, structural, behavioral violations
    - CONSTRAIN: adversarial, severe operational issues
    - ADAPT: statistical drift when safe
    - OBSERVE: no significant drift

    Args:
        vector: DriftVector to analyze

    Returns:
        Correction verb: "REVERT", "CONSTRAIN", "ADAPT", or "OBSERVE"
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
    Estimate confidence in drift detection based on signal quality.

    Higher confidence when:
    - More signals present
    - Signals are higher tier (T1 > T2 > T3 > T4)
    - Scores are higher

    Args:
        signals: List of drift signals

    Returns:
        Confidence score from 0.0 to 1.0
    """
    if not signals:
        return 0.0

    # Tier weights
    tier_weights = {"T1": 1.0, "T2": 0.75, "T3": 0.5, "T4": 0.25}

    # Weighted sum of signals
    weighted_sum = sum(
        signal.score * tier_weights.get(signal.tier, 0.25)
        for signal in signals
    )

    # Normalize by signal count (with diminishing returns)
    signal_count_factor = min(len(signals) / 3.0, 1.0)

    confidence = min(weighted_sum * signal_count_factor, 1.0)

    return confidence
