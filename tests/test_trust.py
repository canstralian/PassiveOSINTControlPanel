from dataclasses import dataclass

from osint_core.trust import (
    TrustDelta,
    TrustState,
    apply_trust_delta,
    apply_trust_deltas,
    authority_scale_from_trust,
    derive_permission_scope,
    derive_verification_depth,
    initial_trust_state,
    scheduler_context_from_trust,
    trust_delta_from_ci,
    trust_delta_from_drift,
    trust_delta_from_reconciliation,
)


@dataclass(frozen=True)
class FakeDriftVector:
    statistical: float = 0.0
    behavioral: float = 0.0
    structural: float = 0.0
    adversarial: float = 0.0
    operational: float = 0.0
    policy: float = 0.0


@dataclass(frozen=True)
class FakeDrift:
    drift_vector: FakeDriftVector


@dataclass(frozen=True)
class FakeReconciliation:
    correction: str


def test_initial_trust_state_is_high_trust():
    state = initial_trust_state("module.resource_links")
    assert state.trust_score == 1.0
    assert state.verification_depth == "normal"
    assert state.permission_scope == "passive"


def test_positive_trust_recovers_slowly():
    state = TrustState(
        component_id="module.test",
        component_type="module",
        trust_score=0.5,
    )
    delta = TrustDelta(
        component_id="module.test",
        component_type="module",
        source="verification",
        score_delta=0.4,
        reason="clean_execution",
    )

    updated = apply_trust_delta(state, delta)

    assert updated.trust_score < 0.9
    assert updated.trust_score == 0.6


def test_negative_trust_decays_quickly():
    state = TrustState(
        component_id="module.test",
        component_type="module",
        trust_score=0.9,
    )
    delta = TrustDelta(
        component_id="module.test",
        component_type="module",
        source="drift",
        score_delta=-0.4,
        reason="structural_drift",
    )

    updated = apply_trust_delta(state, delta)

    assert updated.trust_score == 0.5


def test_structural_drift_creates_large_negative_delta():
    drift = FakeDrift(FakeDriftVector(structural=1.0))
    deltas = trust_delta_from_drift(
        component_id="module.http_headers",
        component_type="module",
        drift_assessment=drift,
    )

    assert len(deltas) == 1
    assert deltas[0].score_delta <= -0.9
    assert deltas[0].repair_action == "rollback"


def test_statistical_drift_creates_small_negative_delta():
    drift = FakeDrift(FakeDriftVector(statistical=1.0))
    deltas = trust_delta_from_drift(
        component_id="module.dns",
        component_type="module",
        drift_assessment=drift,
    )

    assert len(deltas) == 1
    assert -0.11 <= deltas[0].score_delta <= -0.09
    assert deltas[0].repair_action == "adapt"


def test_no_drift_creates_small_positive_delta():
    drift = FakeDrift(FakeDriftVector())
    deltas = trust_delta_from_drift(
        component_id="module.resource_links",
        component_type="module",
        drift_assessment=drift,
    )

    assert len(deltas) == 1
    assert deltas[0].score_delta > 0
    assert deltas[0].reason == "clean_execution"


def test_multiple_deltas_apply_in_order():
    state = initial_trust_state("module.test")
    deltas = (
        TrustDelta("module.test", "module", "drift", -0.4, "bad"),
        TrustDelta("module.test", "module", "verification", 0.4, "good"),
    )

    updated = apply_trust_deltas(state, deltas)

    assert updated.trust_score == 0.7
    assert updated.evidence_count == 2


def test_verification_depth_thresholds():
    assert derive_verification_depth(0.90) == "normal"
    assert derive_verification_depth(0.60) == "elevated"
    assert derive_verification_depth(0.20) == "strict"
    assert derive_verification_depth(0.05) == "quarantined"


def test_permission_scope_thresholds():
    assert derive_permission_scope(0.90) == "passive"
    assert derive_permission_scope(0.60) == "conditional"
    assert derive_permission_scope(0.20) == "restricted"
    assert derive_permission_scope(0.05) == "blocked"


def test_reconciliation_constrain_creates_negative_delta():
    delta = trust_delta_from_reconciliation(
        component_id="module.http_headers",
        component_type="module",
        reconciliation_result=FakeReconciliation("CONSTRAIN"),
    )

    assert delta.score_delta < 0
    assert delta.repair_action == "constrain"


def test_ci_pass_and_fail_deltas():
    passed = trust_delta_from_ci(workflow_id="ci.yml", passed=True)
    failed = trust_delta_from_ci(workflow_id="ci.yml", passed=False)

    assert passed.score_delta > 0
    assert failed.score_delta < 0
    assert failed.repair_action == "constrain"


def test_scheduler_context_from_trust():
    state = TrustState(
        component_id="module.test",
        component_type="module",
        trust_score=0.30,
        verification_depth="strict",
        permission_scope="restricted",
    )

    context = scheduler_context_from_trust(state)

    assert context["trust_score"] == 0.30
    assert context["authority_scale"] == 0.25


def test_authority_scale_from_trust():
    assert authority_scale_from_trust(0.9) == 1.0
    assert authority_scale_from_trust(0.6) == 0.5
    assert authority_scale_from_trust(0.2) == 0.25
    assert authority_scale_from_trust(0.05) == 0.0
