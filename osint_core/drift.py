"""
osint_core/drift.py
===================

Drift layer: convert execution telemetry into a *drift vector* and recommend a
single, closed-set correction verb.

Design intent
-------------
- **Drift is a vector, not a scalar.** Six independent drift classes are scored
  separately (:class:`DriftVector`); collapsing them to one number loses the
  information needed to choose a correction.
- **Detection is pure.** :func:`assess_drift` never mutates telemetry, baseline,
  or policy input — it only reads them and returns a new
  :class:`DriftAssessment`. See ``test_assess_drift_is_pure_and_does_not_mutate_inputs``.
- **Correction is separate from detection.** Signals aggregate into a vector; a
  single verb is chosen from that vector by :func:`recommend_correction`. The
  correction thresholds live in exactly one place so callers (the orchestrator,
  the UI) do not maintain parallel threshold tables.
- **Priority is fixed:** ``policy > structural > behavioral > adversarial >
  operational > statistical``. Policy drift outranks everything; adversarial
  drift CONSTRAINs before the system ADAPTs; statistical drift may ADAPT only
  when nothing higher-priority fires.

Adversarial pattern matching (see :data:`_ADVERSARIAL_PATTERNS`)
---------------------------------------------------------------
Patterns are matched with word boundaries / structural anchors rather than bare
substring containment, so ``file:`` does not fire inside ``profile:`` and
``localhost`` does not fire inside ``notlocalhost``.

Single-character shell metacharacters (``;`` ``|`` `` ` ``) from the original
pseudocode are **intentionally excluded**. As bare substrings they match a large
fraction of benign OSINT inputs (query strings, base64, normal prose) and would
drive spurious CONSTRAIN corrections. Only high-signal indicators — SSRF/metadata
targets, path traversal, scheme injection, and command/template substitution —
are treated as adversarial. Command substitution is still covered by the
anchored ``$(`` pattern.

Input entropy drift (present in the original pseudocode) is likewise not
evaluated here: :class:`TelemetrySnapshot` carries no per-run entropy figure to
compare against ``baseline["input_entropy_avg"]``. The baseline field is reserved
for a future telemetry extension; until telemetry supplies an entropy value there
is nothing to score, so no statistical entropy signal is emitted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Mapping


# =============================================================================
# Value objects
# =============================================================================

CorrectionVerb = Literal["ADAPT", "CONSTRAIN", "REVERT", "OBSERVE"]
Tier = Literal["T1", "T2", "T3", "T4"]


class DriftType(str, Enum):
    """The six drift classes, ordered by correction priority in code below."""

    STATISTICAL = "statistical"
    BEHAVIORAL = "behavioral"
    STRUCTURAL = "structural"
    ADVERSARIAL = "adversarial"
    OPERATIONAL = "operational"
    POLICY = "policy"


# Fixed priority order: policy outranks all, statistical is the weakest.
_PRIORITY_ORDER: tuple[DriftType, ...] = (
    DriftType.POLICY,
    DriftType.STRUCTURAL,
    DriftType.BEHAVIORAL,
    DriftType.ADVERSARIAL,
    DriftType.OPERATIONAL,
    DriftType.STATISTICAL,
)


@dataclass(frozen=True)
class DriftVector:
    """Per-class drift magnitudes in ``[0.0, 1.0]``. Defaults to all zeros."""

    statistical: float = 0.0
    behavioral: float = 0.0
    structural: float = 0.0
    adversarial: float = 0.0
    operational: float = 0.0
    policy: float = 0.0

    def component(self, drift_type: DriftType) -> float:
        return float(getattr(self, drift_type.value))


@dataclass(frozen=True)
class DriftSignal:
    """A single detector observation contributing to one drift class."""

    name: str
    drift_type: DriftType
    score: float
    reason: str
    tier: Tier
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TelemetrySnapshot:
    """Immutable snapshot of a single enrichment run's telemetry."""

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
    """The full result of assessing one run's drift."""

    drift_vector: DriftVector
    signals: list[DriftSignal]
    dominant_type: DriftType | None
    recommended_correction: CorrectionVerb
    confidence: float


# =============================================================================
# Adversarial pattern table
# =============================================================================

# (name, compiled anchored pattern, score, tier). Matched against the combined
# rejection reason + sanitized input trace. See module docstring for why bare
# shell metacharacters and an entropy detector are excluded.
_ADVERSARIAL_PATTERNS: tuple[tuple[str, re.Pattern[str], float, Tier], ...] = (
    ("path_traversal", re.compile(r"\.\./"), 0.7, "T2"),
    ("path_traversal_encoded", re.compile(r"%2e%2e", re.IGNORECASE), 0.7, "T2"),
    ("ssrf_metadata_ip", re.compile(r"\b169\.254\.169\.254\b"), 0.7, "T2"),
    ("loopback_ip", re.compile(r"\b127\.0\.0\.1\b"), 0.7, "T2"),
    ("loopback_host", re.compile(r"\blocalhost\b", re.IGNORECASE), 0.7, "T2"),
    ("script_injection", re.compile(r"<script", re.IGNORECASE), 0.7, "T2"),
    ("javascript_scheme", re.compile(r"\bjavascript:", re.IGNORECASE), 0.7, "T2"),
    ("file_scheme", re.compile(r"\bfile:", re.IGNORECASE), 0.7, "T2"),
    ("command_substitution", re.compile(r"\$\("), 0.7, "T2"),
)


# =============================================================================
# Per-class detectors (pure functions of their inputs)
# =============================================================================

# Policy violation codes map to a severity score. Anything not listed is still
# a policy signal (unknown violations are treated as revert-class).
_POLICY_VIOLATION_SCORES: Mapping[str, float] = {
    "forbidden_module": 1.0,
    "authorization_required": 0.6,
}
_POLICY_VIOLATION_DEFAULT_SCORE = 0.8


def _check_policy_drift(policy_result: Mapping[str, Any]) -> list[DriftSignal]:
    signals: list[DriftSignal] = []
    for violation in policy_result.get("violations", []) or []:
        is_mapping = isinstance(violation, Mapping)
        # A violation may carry an explicit ``None`` code/message; normalise both
        # so the signal name falls back to "unknown" and reason stays a ``str``.
        code_value = violation.get("code") if is_mapping else None
        code = str(code_value) if code_value is not None else ""
        score = _POLICY_VIOLATION_SCORES.get(code, _POLICY_VIOLATION_DEFAULT_SCORE)
        message = violation.get("message") if is_mapping else None
        reason = str(message) if message is not None else "Policy violation detected"
        signals.append(
            DriftSignal(
                name=f"policy_violation:{code or 'unknown'}",
                drift_type=DriftType.POLICY,
                score=score,
                reason=reason,
                tier="T1",
                evidence={"violation": dict(violation) if is_mapping else violation},
            )
        )
    return signals


def _check_adversarial_drift(telemetry: TelemetrySnapshot) -> list[DriftSignal]:
    rejection_reason = telemetry.rejection_reason or ""
    sanitized_input_trace = telemetry.sanitized_input_trace or ""
    haystack = f"{rejection_reason}\n{sanitized_input_trace}"
    if not haystack.strip():
        return []

    signals: list[DriftSignal] = []
    for name, pattern, score, tier in _ADVERSARIAL_PATTERNS:
        if pattern.search(haystack):
            signals.append(
                DriftSignal(
                    name=f"adversarial_pattern:{name}",
                    drift_type=DriftType.ADVERSARIAL,
                    score=score,
                    reason="Suspicious input pattern detected",
                    tier=tier,
                    evidence={"pattern": name},
                )
            )
    return signals


def _check_operational_drift(
    telemetry: TelemetrySnapshot, baseline: Mapping[str, Any]
) -> list[DriftSignal]:
    signals: list[DriftSignal] = []

    runtime_p95 = baseline.get("runtime_p95_ms")
    if runtime_p95 is not None and telemetry.duration_ms > runtime_p95 * 2:
        signals.append(
            DriftSignal(
                name="runtime_boundary_exceeded",
                drift_type=DriftType.OPERATIONAL,
                score=0.5,
                reason="Runtime exceeded expected boundary",
                tier="T3",
                evidence={"duration_ms": telemetry.duration_ms, "runtime_p95_ms": runtime_p95},
            )
        )

    error_threshold = baseline.get("error_rate_threshold")
    if error_threshold is not None and telemetry.error_count > error_threshold:
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

    timeout_threshold = baseline.get("timeout_threshold")
    if timeout_threshold is not None and telemetry.timeout_count > timeout_threshold:
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


def _check_structural_drift(
    telemetry: TelemetrySnapshot, baseline: Mapping[str, Any]
) -> list[DriftSignal]:
    signals: list[DriftSignal] = []

    expected_manifest = baseline.get("expected_manifest_hash")
    if expected_manifest is not None and telemetry.manifest_hash != expected_manifest:
        signals.append(
            DriftSignal(
                name="manifest_hash_mismatch",
                drift_type=DriftType.STRUCTURAL,
                score=1.0,
                reason="Execution manifest mismatch",
                tier="T1",
                evidence={"expected": expected_manifest, "observed": telemetry.manifest_hash},
            )
        )

    expected_deps = baseline.get("expected_dependency_hash")
    if expected_deps is not None and telemetry.dependency_hash != expected_deps:
        signals.append(
            DriftSignal(
                name="dependency_hash_changed",
                drift_type=DriftType.STRUCTURAL,
                score=0.9,
                reason="Dependency graph changed",
                tier="T1",
                evidence={"expected": expected_deps, "observed": telemetry.dependency_hash},
            )
        )

    expected_py = baseline.get("expected_runtime_python_version")
    if expected_py is not None and telemetry.runtime_python_version != expected_py:
        signals.append(
            DriftSignal(
                name="runtime_python_version_changed",
                drift_type=DriftType.STRUCTURAL,
                score=0.6,
                reason="Runtime version changed",
                tier="T2",
                evidence={"expected": expected_py, "observed": telemetry.runtime_python_version},
            )
        )

    return signals


def _check_behavioral_drift(
    telemetry: TelemetrySnapshot, baseline: Mapping[str, Any]
) -> list[DriftSignal]:
    signals: list[DriftSignal] = []

    known_outputs: Mapping[str, str] = baseline.get("known_output_hashes", {}) or {}
    previous_output = known_outputs.get(telemetry.indicator_hash)
    if previous_output is not None and previous_output != telemetry.output_hash:
        signals.append(
            DriftSignal(
                name="output_hash_changed",
                drift_type=DriftType.BEHAVIORAL,
                score=0.9,
                reason="Same input produced different output",
                tier="T1",
                evidence={"expected": previous_output, "observed": telemetry.output_hash},
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
                evidence={},
            )
        )

    return signals


def _check_statistical_drift(
    telemetry: TelemetrySnapshot, baseline: Mapping[str, Any]
) -> list[DriftSignal]:
    signals: list[DriftSignal] = []

    type_distribution: Mapping[str, float] = baseline.get("input_type_distribution", {}) or {}
    if type_distribution and telemetry.indicator_type not in type_distribution:
        signals.append(
            DriftSignal(
                name="input_type_distribution_shifted",
                drift_type=DriftType.STATISTICAL,
                score=0.5,
                reason="Input type distribution shifted",
                tier="T4",
                evidence={"indicator_type": telemetry.indicator_type},
            )
        )

    module_distribution: Mapping[str, float] = baseline.get("module_usage_distribution", {}) or {}
    if module_distribution:
        novel_modules = [
            module for module in telemetry.modules_executed if module not in module_distribution
        ]
        if novel_modules:
            signals.append(
                DriftSignal(
                    name="module_usage_distribution_shifted",
                    drift_type=DriftType.STATISTICAL,
                    score=0.3,
                    reason="Module usage distribution shifted",
                    tier="T4",
                    evidence={"novel_modules": novel_modules},
                )
            )

    return signals


# =============================================================================
# Aggregation, dominance, correction, confidence
# =============================================================================


def aggregate_signals(signals: list[DriftSignal]) -> DriftVector:
    """Collapse signals into a vector, taking the max score per drift class."""
    scores: dict[str, float] = {drift_type.value: 0.0 for drift_type in DriftType}
    for signal in signals:
        key = signal.drift_type.value
        if signal.score > scores[key]:
            scores[key] = signal.score
    return DriftVector(**scores)


def choose_dominant_drift_type(vector: DriftVector) -> DriftType | None:
    """Return the highest-priority drift class with a non-zero magnitude."""
    for drift_type in _PRIORITY_ORDER:
        if vector.component(drift_type) > 0.0:
            return drift_type
    return None


def _coerce_vector(vector: DriftVector | Mapping[str, float]) -> DriftVector:
    if isinstance(vector, DriftVector):
        return vector
    scores: dict[str, float] = {}
    for drift_type in DriftType:
        value = vector.get(drift_type.value)
        # Tolerate a mapping that omits a class or carries a None / non-numeric
        # value: treat anything not castable to float as zero drift.
        try:
            scores[drift_type.value] = float(value) if value is not None else 0.0
        except (TypeError, ValueError):
            scores[drift_type.value] = 0.0
    return DriftVector(**scores)


def recommend_correction(vector: DriftVector | Mapping[str, float]) -> CorrectionVerb:
    """
    Map a drift vector to a single correction verb.

    This is the single source of truth for correction thresholds; callers must
    not maintain parallel threshold tables. Checks run in priority order.

    Accepts a :class:`DriftVector` or a plain mapping of class name -> magnitude
    so the orchestrator (which carries a ``dict`` drift vector) can delegate here.
    """
    v = _coerce_vector(vector)

    if v.policy >= 0.6:
        return "REVERT"
    if v.structural >= 0.5:
        return "REVERT"
    if v.behavioral >= 0.7:
        return "REVERT"
    if v.adversarial >= 0.3:
        return "CONSTRAIN"
    if v.operational >= 0.7:
        return "CONSTRAIN"
    if v.statistical >= 0.5:
        return "ADAPT"
    return "OBSERVE"


# Tier weights for confidence: T1 observations are the most trustworthy.
_TIER_CONFIDENCE_WEIGHT: Mapping[str, float] = {
    "T1": 0.9,
    "T2": 0.7,
    "T3": 0.5,
    "T4": 0.3,
}


def estimate_confidence(signals: list[DriftSignal]) -> float:
    """
    Confidence that observed drift is real, in ``[0.0, 1.0)``.

    Uses a noisy-OR combination of per-signal weights so that (a) adding any
    signal strictly increases confidence, and (b) stronger signals (higher score
    and higher tier) contribute more. No single signal reaches 1.0, so an extra
    corroborating signal always moves the needle.
    """
    complement = 1.0
    for signal in signals:
        tier_weight = _TIER_CONFIDENCE_WEIGHT.get(signal.tier, 0.3)
        weight = max(0.0, min(0.95, signal.score * tier_weight))
        complement *= 1.0 - weight
    return 1.0 - complement


# =============================================================================
# Top-level entry point
# =============================================================================


def assess_drift(
    telemetry: TelemetrySnapshot,
    baseline: Mapping[str, Any] | None,
    policy_result: Mapping[str, Any] | None,
) -> DriftAssessment:
    """
    Assess drift for a single run. Pure: does not mutate any input.

    Detectors run in priority order for readability, but ordering does not affect
    the result — aggregation takes the max score per class and correction is
    chosen from the aggregated vector.
    """
    if telemetry is None:
        raise ValueError("telemetry cannot be None")
    signals: list[DriftSignal] = []
    signals += _check_policy_drift(policy_result)
    signals += _check_structural_drift(telemetry, baseline)
    signals += _check_behavioral_drift(telemetry, baseline)
    signals += _check_adversarial_drift(telemetry)
    signals += _check_operational_drift(telemetry, baseline)
    signals += _check_statistical_drift(telemetry, baseline)

    drift_vector = aggregate_signals(signals)
    dominant_type = choose_dominant_drift_type(drift_vector)
    recommended_correction = recommend_correction(drift_vector)
    confidence = estimate_confidence(signals)

    return DriftAssessment(
        drift_vector=drift_vector,
        signals=signals,
        dominant_type=dominant_type,
        recommended_correction=recommended_correction,
        confidence=confidence,
    )
