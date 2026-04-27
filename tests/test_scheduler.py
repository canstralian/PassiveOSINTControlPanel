from osint_core.scheduler import (
    INVARIANT_CHECKS,
    DecisionPacket,
    ScheduleReason,
    ShortcutDebt,
    SystemState,
    fits_deadline,
    safe_utility,
    schedule_decision,
    total_required_time_ms,
)


def make_packet(**overrides):
    data = {
        "intent_id": "intent_123",
        "action": "enrich_indicator",
        "risk_label": "low",
        "confidence": 0.90,
        "reversibility": 0.90,
        "deadline_ms": 1000,
        "verification_cost_ms": 100,
        "execution_cost_ms": 100,
        "rollback_cost_ms": 100,
        "expected_utility_decay": 0.10,
        "required_checks": INVARIANT_CHECKS,
        "rollback_plan": "observe_only",
        "uncertainty_notes": (),
    }
    data.update(overrides)
    return DecisionPacket(**data)


def test_total_required_time_and_deadline_fit():
    packet = make_packet()
    assert total_required_time_ms(packet) == 300
    assert fits_deadline(packet) is True


def test_fast_path_for_low_risk_reversible_action():
    decision = schedule_decision(make_packet(risk_label="low"))
    assert decision.route == "FAST"
    assert decision.allowed is True
    assert decision.reason == ScheduleReason.FAST_PATH_AVAILABLE


def test_deliberative_path_for_high_risk_action_that_fits_deadline():
    packet = make_packet(
        risk_label="high",
        confidence=0.90,
        reversibility=0.70,
        rollback_plan="sandbox",
        rollback_cost_ms=200,
        deadline_ms=1000,
    )
    decision = schedule_decision(packet)
    assert decision.route == "DELIBERATIVE"
    assert decision.allowed is True


def test_invariant_checks_cannot_be_skipped():
    packet = make_packet(required_checks=("scope_validated",))
    decision = schedule_decision(packet)
    assert decision.route == "FAIL_CLOSED"
    assert decision.allowed is False
    assert decision.reason == ScheduleReason.INVARIANT_VIOLATION
    assert "hash_salt_present" in decision.skipped_checks


def test_high_risk_without_rollback_fails_closed():
    packet = make_packet(
        risk_label="critical",
        rollback_plan="",
        rollback_cost_ms=0,
    )
    decision = schedule_decision(packet)
    assert decision.route == "FAIL_CLOSED"
    assert decision.reason == ScheduleReason.MISSING_ROLLBACK


def test_deadline_too_tight_routes_to_containment_when_reversible():
    packet = make_packet(
        deadline_ms=100,
        verification_cost_ms=100,
        execution_cost_ms=100,
        rollback_cost_ms=100,
        reversibility=0.90,
    )
    decision = schedule_decision(packet)
    assert decision.route == "CONTAINMENT"
    assert decision.reason == ScheduleReason.DEADLINE_TOO_TIGHT
    assert decision.authority_scale == 0.25


def test_deadline_too_tight_and_not_reversible_fails_closed():
    packet = make_packet(
        deadline_ms=100,
        reversibility=0.20,
    )
    decision = schedule_decision(packet)
    assert decision.route == "FAIL_CLOSED"
    assert decision.reason == ScheduleReason.NO_SAFE_ACTION_FITS


def test_shortcut_debt_forces_containment():
    state = SystemState(shortcut_debt=ShortcutDebt(emergency_overrides=2), shortcut_debt_limit=0.70)
    decision = schedule_decision(make_packet(), state)
    assert decision.route == "CONTAINMENT"
    assert decision.reason == ScheduleReason.SHORTCUT_DEBT_TOO_HIGH


def test_contested_trust_state_forces_containment():
    state = SystemState(trust_state="contested")
    decision = schedule_decision(make_packet(), state)
    assert decision.route == "CONTAINMENT"
    assert decision.reason == ScheduleReason.TRUST_STATE_DEGRADED


def test_low_confidence_high_risk_forces_containment():
    packet = make_packet(risk_label="high", confidence=0.20, rollback_plan="sandbox")
    decision = schedule_decision(packet)
    assert decision.route == "CONTAINMENT"
    assert decision.reason == ScheduleReason.LOW_CONFIDENCE


def test_safe_utility_is_bounded():
    score = safe_utility(make_packet())
    assert 0.0 <= score <= 1.0
