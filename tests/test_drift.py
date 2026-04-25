"""
tests/test_drift.py
===================

Contract tests for osint_core.drift.

These tests define the expected behavior of the drift layer before implementation.

Core invariants:
- Drift is represented as a vector, not a scalar.
- Drift detection is pure: it does not mutate baseline, manifest, telemetry, or policy input.
- Policy drift outranks all other drift.
- Structural and behavioral drift are revert-class.
- Adversarial drift constrains before the system adapts.
- Statistical drift may adapt only when higher-priority drift classes are absent.
"""

from __future__ import annotations

import copy
from dataclasses import asdict
from typing import Any

import pytest

from osint_core.drift import (
    DriftAssessment,
    DriftSignal,
    DriftType,
    DriftVector,
    TelemetrySnapshot,
    aggregate_signals,
    assess_drift,
    choose_dominant_drift_type,
    estimate_confidence,
    recommend_correction,
)


def make_telemetry(**overrides: Any) -> TelemetrySnapshot:
    data: dict[str, Any] = {
        "run_id": "run_test_001",
        "manifest_hash": "manifest_good",
        "dependency_hash": "deps_good",
        "runtime_python_version": "3.13.0",
        "indicator_hash": "hmac_abc123",
        "indicator_type": "domain",
        "input_rejected": False,
        "rejection_reason": "",
        "sanitized_input_trace": "",
        "modules_requested": ["resource_links"],
        "modules_executed": ["resource_links"],
        "modules_blocked": [],
        "authorized_target": False,
        "duration_ms": 100,
        "error_count": 0,
        "timeout_count": 0,
        "output_hash": "output_good",
        "output_schema_valid": True,
    }
    data.update(overrides)
    return TelemetrySnapshot(**data)


def make_baseline(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "runtime_p95_ms": 500,
        "error_rate_threshold": 2,
        "timeout_threshold": 1,
        "expected_manifest_hash": "manifest_good",
        "expected_dependency_hash": "deps_good",
        "expected_runtime_python_version": "3.13.0",
        "known_output_hashes": {
            "hmac_abc123": "output_good",
        },
        "input_type_distribution": {
            "domain": 0.8,
            "username": 0.2,
        },
        "module_usage_distribution": {
            "resource_links": 1.0,
        },
        "input_entropy_avg": 3.2,
    }
    data.update(overrides)
    return data


def make_policy_result(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "decision": "allow",
        "allowed_modules": ["resource_links"],
        "blocked_modules": [],
        "violations": [],
    }
    data.update(overrides)
    return data


@pytest.fixture
def telemetry() -> TelemetrySnapshot:
    return make_telemetry()


@pytest.fixture
def baseline() -> dict[str, Any]:
    return make_baseline()


@pytest.fixture
def policy_result() -> dict[str, Any]:
    return make_policy_result()


def test_drift_vector_defaults_to_zero() -> None:
    vector = DriftVector()

    assert vector.statistical == 0.0
    assert vector.behavioral == 0.0
    assert vector.structural == 0.0
    assert vector.adversarial == 0.0
    assert vector.operational == 0.0
    assert vector.policy == 0.0


def test_aggregate_signals_empty_returns_zero_vector() -> None:
    assert aggregate_signals([]) == DriftVector()


def test_aggregate_signals_uses_max_score_per_type() -> None:
    signals = [
        DriftSignal(
            name="weak_adversarial_signal",
            drift_type=DriftType.ADVERSARIAL,
            score=0.2,
            reason="weak suspicious pattern",
            tier="T2",
            evidence={"pattern": ";"},
        ),
        DriftSignal(
            name="strong_adversarial_signal",
            drift_type=DriftType.ADVERSARIAL,
            score=0.7,
            reason="strong suspicious pattern",
            tier="T2",
            evidence={"pattern": "169.254.169.254"},
        ),
        DriftSignal(
            name="operational_signal",
            drift_type=DriftType.OPERATIONAL,
            score=0.4,
            reason="runtime elevated",
            tier="T3",
            evidence={"duration_ms": 1500},
        ),
    ]

    vector = aggregate_signals(signals)

    assert vector.adversarial == 0.7
    assert vector.operational == 0.4
    assert vector.policy == 0.0


def test_dominant_type_prefers_adversarial_over_statistical() -> None:
    # Adversarial outranks statistical even if statistical has a higher raw score.
    vector = DriftVector(
        statistical=0.9,
        adversarial=0.4,
        policy=0.0,
    )

    assert choose_dominant_drift_type(vector) == DriftType.ADVERSARIAL


def test_dominant_type_prefers_policy_over_all() -> None:
    vector = DriftVector(
        statistical=0.9,
        adversarial=0.4,
        policy=0.6,
    )

    assert choose_dominant_drift_type(vector) == DriftType.POLICY


def test_dominant_type_respects_structural_over_behavioral_over_operational() -> None:
    vector = DriftVector(structural=0.1, behavioral=0.9, operational=1.0)
    assert choose_dominant_drift_type(vector) == DriftType.STRUCTURAL

    vector = DriftVector(behavioral=0.2, adversarial=0.9, operational=1.0)
    assert choose_dominant_drift_type(vector) == DriftType.BEHAVIORAL


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        (DriftVector(policy=0.6, statistical=1.0, adversarial=0.2), "REVERT"),
        (DriftVector(structural=0.5), "REVERT"),
        (DriftVector(behavioral=0.7), "REVERT"),
        (DriftVector(adversarial=0.3, statistical=0.9), "CONSTRAIN"),
        (DriftVector(statistical=0.5), "ADAPT"),
        (DriftVector(statistical=0.1, operational=0.1), "OBSERVE"),
    ],
    ids=[
        "policy_revert",
        "structural_revert",
        "behavioral_revert",
        "adversarial_constrain",
        "statistical_adapt",
        "default_observe",
    ],
)
def test_recommend_correction(vector: DriftVector, expected: str) -> None:
    assert recommend_correction(vector) == expected


def test_policy_violation_creates_policy_signal_and_revert_recommendation(
    telemetry: TelemetrySnapshot,
    baseline: dict[str, Any],
) -> None:
    policy_result = make_policy_result(
        decision="constrain",
        blocked_modules=["port_scan"],
        violations=[
            {
                "code": "forbidden_module",
                "message": "Forbidden module blocked: Port Scan",
                "module": "port_scan",
            }
        ],
    )

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert isinstance(assessment, DriftAssessment)
    assert assessment.drift_vector.policy == 1.0
    assert assessment.dominant_type == DriftType.POLICY
    assert assessment.recommended_correction == "REVERT"
    assert any(signal.drift_type == DriftType.POLICY for signal in assessment.signals)


def test_authorization_gate_trigger_creates_policy_signal(
    baseline: dict[str, Any],
) -> None:
    telemetry = make_telemetry(
        modules_requested=["http_headers"],
        modules_blocked=["http_headers"],
        authorized_target=False,
    )
    policy_result = make_policy_result(
        decision="constrain",
        blocked_modules=["http_headers"],
        violations=[
            {
                "code": "authorization_required",
                "message": "Authorization required for module: HTTP Headers",
                "module": "http_headers",
            }
        ],
    )

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector.policy >= 0.6
    assert assessment.recommended_correction == "REVERT"


def test_adversarial_patterns_create_constrain_recommendation(
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> None:
    telemetry = make_telemetry(
        input_rejected=True,
        rejection_reason="Input contains a blocked pattern.",
        sanitized_input_trace="https://example.com/?next=http://169.254.169.254/latest",
    )

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector.adversarial >= 0.7
    assert assessment.dominant_type == DriftType.ADVERSARIAL
    assert assessment.recommended_correction == "CONSTRAIN"


def test_input_rejected_without_trace_does_not_trigger_adversarial_drift(
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> None:
    telemetry = make_telemetry(
        input_rejected=True,
        rejection_reason="",
        sanitized_input_trace="",
    )

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector.adversarial == 0.0
    assert not any(s.drift_type == DriftType.ADVERSARIAL for s in assessment.signals)


def test_operational_runtime_drift_detected(
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> None:
    telemetry = make_telemetry(duration_ms=1200)

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector.operational >= 0.5
    assert any(signal.name == "runtime_boundary_exceeded" for signal in assessment.signals)


def test_operational_error_drift_detected(
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> None:
    telemetry = make_telemetry(error_count=3)

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector.operational >= 0.6
    assert any(signal.name == "error_threshold_exceeded" for signal in assessment.signals)


def test_operational_timeout_drift_detected(
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> None:
    telemetry = make_telemetry(timeout_count=2)
    baseline = make_baseline(timeout_threshold=1)

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector.operational > 0.0
    assert any(signal.name == "timeout_threshold_exceeded" for signal in assessment.signals)


def test_structural_manifest_mismatch_reverts(
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> None:
    telemetry = make_telemetry(manifest_hash="manifest_changed")

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector.structural == 1.0
    assert assessment.dominant_type == DriftType.STRUCTURAL
    assert assessment.recommended_correction == "REVERT"


def test_structural_dependency_mismatch_reverts(
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> None:
    telemetry = make_telemetry(dependency_hash="deps_changed")

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector.structural >= 0.9
    assert assessment.recommended_correction == "REVERT"


def test_structural_runtime_python_version_mismatch_reverts(
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> None:
    telemetry = make_telemetry(runtime_python_version="3.13.1")

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector.structural > 0.0
    assert assessment.recommended_correction == "REVERT"
    assert any(signal.name == "runtime_python_version_changed" for signal in assessment.signals)


def test_behavioral_same_input_different_output_reverts(
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> None:
    telemetry = make_telemetry(
        indicator_hash="hmac_abc123",
        output_hash="output_changed",
    )
    baseline = make_baseline(
        known_output_hashes={"hmac_abc123": "output_good"},
    )

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector.behavioral >= 0.9
    assert assessment.dominant_type == DriftType.BEHAVIORAL
    assert assessment.recommended_correction == "REVERT"


def test_behavioral_invalid_schema_reverts(
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> None:
    telemetry = make_telemetry(output_schema_valid=False)

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector.behavioral >= 0.8
    assert assessment.recommended_correction == "REVERT"


def test_statistical_shift_can_adapt_when_no_higher_priority_signal(
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> None:
    telemetry = make_telemetry(indicator_type="ip")
    baseline = make_baseline(
        input_type_distribution={"domain": 0.9, "username": 0.1},
    )

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector.statistical >= 0.5
    assert assessment.dominant_type == DriftType.STATISTICAL
    assert assessment.recommended_correction == "ADAPT"


def test_statistical_module_usage_shift_detected(
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> None:
    telemetry = make_telemetry(
        modules_executed=["resource_links", "dns_lookup"],
    )
    baseline = make_baseline(
        module_usage_distribution={"resource_links": 1.0},
    )

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector.statistical > 0.0
    assert any(signal.name == "module_usage_distribution_shifted" for signal in assessment.signals)


def test_policy_drift_overrides_statistical_adaptation(
    baseline: dict[str, Any],
) -> None:
    telemetry = make_telemetry(indicator_type="ip")
    baseline = make_baseline(
        input_type_distribution={"domain": 0.9, "username": 0.1},
    )
    policy_result = make_policy_result(
        decision="constrain",
        blocked_modules=["port_scan"],
        violations=[
            {
                "code": "forbidden_module",
                "message": "Forbidden module blocked",
                "module": "port_scan",
            }
        ],
    )

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector.statistical >= 0.5
    assert assessment.drift_vector.policy == 1.0
    assert assessment.dominant_type == DriftType.POLICY
    assert assessment.recommended_correction == "REVERT"


def test_adversarial_drift_overrides_statistical_adaptation(
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> None:
    telemetry = make_telemetry(
        indicator_type="ip",
        sanitized_input_trace="http://169.254.169.254/latest",
    )
    baseline = make_baseline(
        input_type_distribution={"domain": 0.9, "username": 0.1},
    )

    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector.statistical >= 0.5
    assert assessment.drift_vector.adversarial >= 0.7
    assert assessment.dominant_type == DriftType.ADVERSARIAL
    assert assessment.recommended_correction == "CONSTRAIN"


def test_estimate_confidence_increases_with_signal_count_and_tier() -> None:
    low_signal = DriftSignal(
        name="weak",
        drift_type=DriftType.STATISTICAL,
        score=0.3,
        reason="weak distribution shift",
        tier="T4",
        evidence={},
    )
    high_signal = DriftSignal(
        name="policy",
        drift_type=DriftType.POLICY,
        score=1.0,
        reason="forbidden module",
        tier="T1",
        evidence={},
    )

    assert estimate_confidence([]) == 0.0
    assert estimate_confidence([high_signal]) > estimate_confidence([low_signal])

    # Contract: adding a signal should strictly increase confidence.
    assert estimate_confidence([low_signal, high_signal]) > estimate_confidence([high_signal])


def test_assess_drift_is_pure_and_does_not_mutate_inputs(
    telemetry: TelemetrySnapshot,
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> None:
    telemetry_before = copy.deepcopy(asdict(telemetry))
    baseline_before = copy.deepcopy(baseline)
    policy_before = copy.deepcopy(policy_result)

    assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert asdict(telemetry) == telemetry_before
    assert baseline == baseline_before
    assert policy_result == policy_before


def test_clean_execution_observes_without_significant_drift(
    telemetry: TelemetrySnapshot,
    baseline: dict[str, Any],
    policy_result: dict[str, Any],
) -> None:
    assessment = assess_drift(
        telemetry=telemetry,
        baseline=baseline,
        policy_result=policy_result,
    )

    assert assessment.drift_vector == DriftVector()
    assert assessment.signals == []
    assert assessment.dominant_type is None
    assert assessment.recommended_correction == "OBSERVE"
    assert assessment.confidence == pytest.approx(0.0)
