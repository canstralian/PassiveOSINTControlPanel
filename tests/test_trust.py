from __future__ import annotations

from types import SimpleNamespace

import pytest

from osint_core.trust import (
    TrustDelta,
    TrustState,
    apply_trust_delta,
    calculate_trust_delta,
    derive_permission_scope,
    derive_scheduler_route,
    derive_verification_depth,
)


def test_negative_trust_delta_applies_at_full_strength() -> None:
    state = TrustState(
        component_id="module:resource_links",
        component_type="module",
        trust_score=0.8,
    )
    delta = TrustDelta(
        component_id=state.component_id,
        component_type="module",
        source="drift",
        score_delta=-0.5,
        reason="policy drift",
        evidence={},
        repair_action="constrain",
    )

    updated = apply_trust_delta(state, delta)

    assert updated.trust_score == pytest.approx(0.3)
    assert updated.verification_depth == "strict"
    assert updated.permission_scope == "restricted"
    assert updated.last_repair_action == "constrain"


def test_positive_trust_delta_recovers_slowly() -> None:
    state = TrustState(
        component_id="workflow:hf-sync",
        component_type="workflow",
        trust_score=0.5,
    )
    delta = TrustDelta(
        component_id=state.component_id,
        component_type="workflow",
        source="ci",
        score_delta=0.5,
        reason="ci passed",
        evidence={},
        repair_action="observe",
    )

    updated = apply_trust_delta(state, delta)

    assert updated.trust_score == pytest.approx(0.675)
    assert updated.verification_depth == "elevated"


def test_trust_may_not_expand_authority_automatically() -> None:
    state = TrustState(
        component_id="module:resource_links",
        component_type="module",
        trust_score=0.95,
        permission_scope="passive",
    )
    delta = TrustDelta(
        component_id=state.component_id,
        component_type="module",
        source="verification",
        score_delta=0.5,
        reason="clean run",
        evidence={},
        repair_action="observe",
    )

    updated = apply_trust_delta(state, delta)

    assert updated.trust_score == pytest.approx(1.0)
    assert updated.permission_scope == "passive"


def test_trust_can_reduce_authority_automatically() -> None:
    state = TrustState(
        component_id="module:http_headers",
        component_type="module",
        trust_score=0.7,
        permission_scope="conditional",
    )
    delta = TrustDelta(
        component_id=state.component_id,
        component_type="module",
        source="audit",
        score_delta=-0.8,
        reason="audit unsafe",
        evidence={},
        repair_action="quarantine",
    )

    updated = apply_trust_delta(state, delta)

    assert updated.permission_scope == "blocked"
    assert updated.verification_depth == "quarantined"


def test_permission_scope_derivation_never_broadens_current_scope() -> None:
    assert derive_permission_scope(0.95, "restricted") == "restricted"
    assert derive_permission_scope(0.95, "passive") == "passive"
    assert derive_permission_scope(0.95, "conditional") == "conditional"
    assert derive_permission_scope(0.35, "conditional") == "restricted"
    assert derive_permission_scope(0.1, "conditional") == "blocked"


def test_verification_depth_thresholds() -> None:
    assert derive_verification_depth(0.1) == "quarantined"
    assert derive_verification_depth(0.3) == "strict"
    assert derive_verification_depth(0.6) == "elevated"
    assert derive_verification_depth(0.9) == "normal"


def test_calculate_trust_delta_penalizes_revert_drift() -> None:
    assessment = SimpleNamespace(
        recommended_correction="REVERT",
        confidence=0.9,
        dominant_type=SimpleNamespace(value="structural"),
        signals=[object(), object()],
    )

    delta = calculate_trust_delta(
        component_id="module:dns_records",
        component_type="module",
        drift_assessment=assessment,
    )

    assert delta.source == "drift"
    assert delta.score_delta == pytest.approx(-0.9)
    assert delta.repair_action == "rollback"
    assert delta.evidence["dominant_drift_type"] == "structural"


def test_calculate_trust_delta_rewards_clean_drift_only_slightly() -> None:
    assessment = SimpleNamespace(
        recommended_correction="OBSERVE",
        confidence=0.0,
        dominant_type=None,
        signals=[],
    )

    delta = calculate_trust_delta(
        component_id="module:resource_links",
        component_type="module",
        drift_assessment=assessment,
    )

    assert delta.score_delta == pytest.approx(0.12)
    assert delta.repair_action == "observe"


def test_calculate_trust_delta_quarantines_failed_audit() -> None:
    delta = calculate_trust_delta(
        component_id="audit:ledger",
        component_type="service",
        audit_result={"audit_safe": False},
    )

    assert delta.source == "audit"
    assert delta.score_delta == pytest.approx(-0.7)
    assert delta.repair_action == "quarantine"


def test_audit_trust_delta_excludes_raw_indicator_fields() -> None:
    delta = calculate_trust_delta(
        component_id="audit:ledger",
        component_type="service",
        audit_result={
            "audit_safe": False,
            "raw_indicator": "1.2.3.4",
            "raw_indicator_type": "ip",
            "raw_indicator_value": "sensitive",
        },
    )

    assert delta.source == "audit"
    assert delta.score_delta == pytest.approx(-0.7)
    assert delta.repair_action == "quarantine"
    assert "raw_indicator" not in delta.evidence
    assert "raw_indicator_type" not in delta.evidence
    assert "raw_indicator_value" not in delta.evidence
    assert "1.2.3.4" not in str(delta.evidence)
    assert "sensitive" not in str(delta.evidence)


def test_strictest_repair_action_is_preserved() -> None:
    delta = calculate_trust_delta(
        component_id="audit:ledger",
        component_type="service",
        audit_result={"audit_safe": False},
        ci_result={"passed": False},
    )

    assert delta.source == "ci"
    assert delta.score_delta == pytest.approx(-1.0)
    assert delta.repair_action == "quarantine"


def test_scheduler_routes_by_trust_and_risk() -> None:
    high = TrustState(
        component_id="workflow:hf-sync",
        component_type="workflow",
        trust_score=0.9,
        permission_scope="passive",
    )
    medium = TrustState(
        component_id="workflow:hf-sync",
        component_type="workflow",
        trust_score=0.6,
        permission_scope="passive",
    )
    low = TrustState(
        component_id="workflow:hf-sync",
        component_type="workflow",
        trust_score=0.3,
        permission_scope="restricted",
    )
    collapsed = TrustState(
        component_id="workflow:hf-sync",
        component_type="workflow",
        trust_score=0.1,
        permission_scope="blocked",
    )

    assert derive_scheduler_route(risk="low", trust_state=high) == "FAST"
    assert derive_scheduler_route(risk="low", trust_state=medium) == "DELIBERATIVE"
    assert derive_scheduler_route(risk="low", trust_state=low) == "CONTAINMENT"
    assert derive_scheduler_route(risk="low", trust_state=collapsed) == "FAIL_CLOSED"
    assert derive_scheduler_route(risk="high", trust_state=high) == "CONTAINMENT"
