"""
tests/test_scheduler.py
=======================

Contract tests for osint_core.scheduler.

Core invariants asserted here:
- DecisionPacket and SystemState are immutable.
- ShortcutDebt.score is monotonic, weight-correct, and capped at 1.0.
- The scheduler is pure: identical inputs produce identical decisions and
  inputs are not mutated.
- Mandatory invariants override timing budget. Deadline pressure never bypasses
  invariant checks.
- FAIL_CLOSED signals (missing salt, raw indicator leakage, forbidden module,
  manifest signature mismatch) always collapse to FAIL_CLOSED, even when the
  budget would otherwise permit FAST.
- CONTAINMENT signals (suspicious input, policy disagreement, repeated auth
  failure, drift over threshold) collapse to CONTAINMENT, even when the budget
  would otherwise permit FAST.
- Shortcut debt at the limit and degraded trust both force CONTAINMENT.
- When the window is too tight, reversibility >= threshold falls back to
  CONTAINMENT; below the threshold falls back to FAIL_CLOSED.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from osint_core.scheduler import (
    CONTAINMENT_SIGNALS,
    DEFAULT_REVERSIBILITY_CONTAINMENT_THRESHOLD,
    DEFAULT_SHORTCUT_DEBT_LIMIT,
    DELIBERATIVE_ACTIONS,
    DEGRADED_TRUST_STATES,
    FAIL_CLOSED_SIGNALS,
    FAST_ACTIONS,
    MANDATORY_INVARIANTS,
    DecisionPacket,
    RouteMode,
    ScheduleDecision,
    ScheduleReasonCode,
    ShortcutDebt,
    SystemState,
    all_signal_names,
    classify_action,
    containment,
    deliberative_path,
    fail_closed,
    fast_path,
    find_invariant_violations,
    make_system_state,
    schedule_decision,
    violates_invariant,
    with_required_checks,
)


def make_packet(**overrides) -> DecisionPacket:
    data = dict(
        intent_id="intent_test_0001",
        action="source_link_generation",
        risk_label="low",
        confidence=0.9,
        reversibility=0.95,
        deadline_ms=1000,
        verification_cost_ms=100,
        execution_cost_ms=100,
        rollback_cost_ms=100,
        expected_utility_decay=0.1,
        required_checks=(),
        rollback_plan="discard_generated_links_buffer",
        uncertainty_notes=(),
    )
    data.update(overrides)
    return DecisionPacket(**data)


def make_state(**overrides) -> SystemState:
    """Build a SystemState that satisfies every mandatory invariant by default."""
    defaults = dict(
        trust_state="trusted",
        passed_checks=MANDATORY_INVARIANTS,
        failed_checks=(),
    )
    defaults.update(overrides)
    return make_system_state(**defaults)


# -- Constant integrity ----------------------------------------------------


def test_route_mode_set_is_closed():
    assert {member.value for member in RouteMode} == {
        "FAST",
        "DELIBERATIVE",
        "CONTAINMENT",
        "FAIL_CLOSED",
    }


def test_named_signal_sets_are_disjoint_and_named_correctly():
    assert FAIL_CLOSED_SIGNALS.isdisjoint(CONTAINMENT_SIGNALS)
    assert FAST_ACTIONS.isdisjoint(DELIBERATIVE_ACTIONS)
    assert "missing_salt" in FAIL_CLOSED_SIGNALS
    assert "raw_indicator_leakage" in FAIL_CLOSED_SIGNALS
    assert "forbidden_module_requested" in FAIL_CLOSED_SIGNALS
    assert "manifest_signature_mismatch" in FAIL_CLOSED_SIGNALS
    assert "suspicious_input_pattern" in CONTAINMENT_SIGNALS
    assert "policy_disagreement" in CONTAINMENT_SIGNALS
    assert "repeated_authorization_failure" in CONTAINMENT_SIGNALS
    assert "drift_vector_above_threshold" in CONTAINMENT_SIGNALS


def test_mandatory_invariants_cover_documented_set():
    expected = {
        "osint_hash_salt_present",
        "intent_signature_verified",
        "scope_explicit",
        "policy_evaluation_completed",
        "forbidden_modules_blocked",
        "raw_indicators_excluded_from_audit",
        "conditional_modules_require_authorization",
        "rollback_or_containment_path_exists",
    }
    assert set(MANDATORY_INVARIANTS) == expected


def test_degraded_trust_states_are_contested_and_unsafe():
    assert DEGRADED_TRUST_STATES == frozenset({"contested", "unsafe"})


def test_default_thresholds_match_specification():
    assert DEFAULT_REVERSIBILITY_CONTAINMENT_THRESHOLD == 0.75
    assert DEFAULT_SHORTCUT_DEBT_LIMIT == 1.0


def test_all_signal_names_returns_closed_sets():
    names = all_signal_names()
    assert set(names["mandatory_invariants"]) == set(MANDATORY_INVARIANTS)
    assert set(names["fail_closed_signals"]) == set(FAIL_CLOSED_SIGNALS)
    assert set(names["containment_signals"]) == set(CONTAINMENT_SIGNALS)
    assert set(names["fast_actions"]) == set(FAST_ACTIONS)
    assert set(names["deliberative_actions"]) == set(DELIBERATIVE_ACTIONS)


# -- DecisionPacket / SystemState immutability -----------------------------


def test_decision_packet_is_frozen():
    packet = make_packet()
    with pytest.raises(FrozenInstanceError):
        packet.action = "mutated"  # type: ignore[misc]


def test_system_state_is_frozen():
    state = make_state()
    with pytest.raises(FrozenInstanceError):
        state.trust_state = "unsafe"  # type: ignore[misc]


def test_decision_packet_required_time_and_fits_window():
    packet = make_packet(
        verification_cost_ms=100,
        execution_cost_ms=200,
        rollback_cost_ms=300,
        deadline_ms=600,
    )
    assert packet.required_time_ms == 600
    assert packet.fits_window is True

    too_tight = make_packet(
        verification_cost_ms=100,
        execution_cost_ms=200,
        rollback_cost_ms=400,
        deadline_ms=600,
    )
    assert too_tight.required_time_ms == 700
    assert too_tight.fits_window is False


# -- ShortcutDebt ----------------------------------------------------------


def test_shortcut_debt_default_is_zero():
    assert ShortcutDebt().score == 0.0


def test_shortcut_debt_weights():
    assert ShortcutDebt(reduced_checks=1).score == pytest.approx(0.1)
    assert ShortcutDebt(cached_policy_uses=1).score == pytest.approx(0.05)
    assert ShortcutDebt(skipped_deep_analysis=1).score == pytest.approx(0.15)
    assert ShortcutDebt(emergency_overrides=1).score == pytest.approx(0.4)


def test_shortcut_debt_score_is_capped_at_one():
    debt = ShortcutDebt(
        reduced_checks=20,
        cached_policy_uses=20,
        skipped_deep_analysis=20,
        emergency_overrides=20,
    )
    assert debt.score == 1.0


def test_shortcut_debt_is_monotonic_and_additive():
    base = ShortcutDebt(reduced_checks=1).score
    more = ShortcutDebt(reduced_checks=1, cached_policy_uses=2).score
    assert more > base


# -- classify_action -------------------------------------------------------


def test_classify_action_for_known_fast_actions():
    for name in FAST_ACTIONS:
        assert classify_action(name) is RouteMode.FAST


def test_classify_action_for_known_deliberative_actions():
    for name in DELIBERATIVE_ACTIONS:
        assert classify_action(name) is RouteMode.DELIBERATIVE


def test_classify_action_returns_none_for_unknown():
    assert classify_action("rm_minus_rf") is None
    assert classify_action("") is None


# -- with_required_checks --------------------------------------------------


def test_with_required_checks_does_not_mutate_packet():
    original = make_packet(required_checks=("policy_evaluation_completed",))
    extended = with_required_checks(original, "intent_signature_verified")
    assert original.required_checks == ("policy_evaluation_completed",)
    assert extended.required_checks == (
        "policy_evaluation_completed",
        "intent_signature_verified",
    )


def test_with_required_checks_dedupes():
    packet = make_packet(required_checks=("scope_explicit",))
    merged = with_required_checks(packet, "scope_explicit", "scope_explicit")
    assert merged.required_checks == ("scope_explicit",)


# -- find_invariant_violations --------------------------------------------


def test_find_invariant_violations_when_state_is_clean():
    packet = make_packet()
    state = make_state()
    assert find_invariant_violations(packet, state) == ()
    assert violates_invariant(packet, state) is False


def test_find_invariant_violations_for_missing_mandatory_check():
    packet = make_packet()
    state = make_system_state(
        passed_checks=tuple(
            c for c in MANDATORY_INVARIANTS if c != "intent_signature_verified"
        ),
    )
    violations = find_invariant_violations(packet, state)
    assert "intent_signature_verified" in violations
    assert violates_invariant(packet, state) is True


def test_find_invariant_violations_for_missing_rollback_plan():
    packet = make_packet(rollback_plan="   ")
    state = make_state()
    violations = find_invariant_violations(packet, state)
    assert "rollback_or_containment_path_exists" in violations


def test_find_invariant_violations_for_required_check_unmet():
    packet = make_packet(required_checks=("custom_extra_check",))
    state = make_state()
    violations = find_invariant_violations(packet, state)
    assert "custom_extra_check" in violations


def test_find_invariant_violations_includes_fail_closed_signals():
    packet = make_packet()
    state = make_state(failed_checks=("missing_salt",))
    violations = find_invariant_violations(packet, state)
    assert "missing_salt" in violations


# -- schedule_decision: FAST path -----------------------------------------


def test_low_risk_action_that_fits_window_routes_fast():
    packet = make_packet(risk_label="low", deadline_ms=1000)
    decision = schedule_decision(packet, make_state())
    assert decision.route is RouteMode.FAST
    assert decision.reason_code is ScheduleReasonCode.LOW_RISK_FITS_WINDOW
    assert decision.intent_id == packet.intent_id
    assert decision.required_time_ms == packet.required_time_ms
    assert decision.remaining_window_ms == packet.deadline_ms


def test_medium_risk_action_that_fits_window_routes_fast():
    packet = make_packet(risk_label="medium", deadline_ms=1000)
    decision = schedule_decision(packet, make_state())
    assert decision.route is RouteMode.FAST


# -- schedule_decision: DELIBERATIVE path ---------------------------------


def test_high_risk_action_that_fits_window_routes_deliberative():
    packet = make_packet(
        risk_label="high",
        action="conditional_http_header_fetch",
        deadline_ms=2000,
    )
    decision = schedule_decision(packet, make_state())
    assert decision.route is RouteMode.DELIBERATIVE
    assert decision.reason_code is ScheduleReasonCode.HIGH_RISK_FITS_WINDOW


def test_critical_risk_action_that_fits_window_routes_deliberative():
    packet = make_packet(risk_label="critical", deadline_ms=2000)
    decision = schedule_decision(packet, make_state())
    assert decision.route is RouteMode.DELIBERATIVE


# -- schedule_decision: CONTAINMENT routes --------------------------------


def test_shortcut_debt_at_limit_forces_containment():
    state = make_state(
        shortcut_debt=ShortcutDebt(emergency_overrides=3),
    )
    assert state.shortcut_debt.score >= state.shortcut_debt_limit
    decision = schedule_decision(make_packet(), state)
    assert decision.route is RouteMode.CONTAINMENT
    assert decision.reason_code is ScheduleReasonCode.SHORTCUT_DEBT_EXCEEDED


def test_contested_trust_state_forces_containment():
    decision = schedule_decision(
        make_packet(), make_state(trust_state="contested")
    )
    assert decision.route is RouteMode.CONTAINMENT
    assert decision.reason_code is ScheduleReasonCode.TRUST_STATE_DEGRADED


def test_unsafe_trust_state_forces_containment():
    decision = schedule_decision(
        make_packet(), make_state(trust_state="unsafe")
    )
    assert decision.route is RouteMode.CONTAINMENT
    assert decision.reason_code is ScheduleReasonCode.TRUST_STATE_DEGRADED


def test_degraded_but_not_contested_does_not_force_containment_by_trust():
    # "degraded" is a recognised trust state but not in the degraded set
    # that forces CONTAINMENT; the scheduler should still route normally.
    decision = schedule_decision(
        make_packet(), make_state(trust_state="degraded")
    )
    assert decision.route is RouteMode.FAST


@pytest.mark.parametrize("signal", sorted(CONTAINMENT_SIGNALS))
def test_each_containment_signal_routes_containment(signal):
    state = make_state(failed_checks=(signal,))
    decision = schedule_decision(make_packet(), state)
    assert decision.route is RouteMode.CONTAINMENT
    assert decision.reason_code is ScheduleReasonCode.CONTAINMENT_SIGNAL
    assert signal in decision.triggers


def test_deadline_too_tight_but_reversible_routes_containment():
    packet = make_packet(
        verification_cost_ms=400,
        execution_cost_ms=400,
        rollback_cost_ms=400,
        deadline_ms=500,
        reversibility=0.9,
        risk_label="high",
    )
    decision = schedule_decision(packet, make_state())
    assert decision.route is RouteMode.CONTAINMENT
    assert (
        decision.reason_code is ScheduleReasonCode.DEADLINE_TOO_TIGHT_REVERSIBLE
    )


# -- schedule_decision: FAIL_CLOSED routes --------------------------------


@pytest.mark.parametrize("signal", sorted(FAIL_CLOSED_SIGNALS))
def test_each_fail_closed_signal_collapses_to_fail_closed(signal):
    packet = make_packet(risk_label="low", deadline_ms=10_000)
    state = make_state(failed_checks=(signal,))
    decision = schedule_decision(packet, state)
    assert decision.route is RouteMode.FAIL_CLOSED
    assert decision.reason_code is ScheduleReasonCode.FAIL_CLOSED_SIGNAL
    assert signal in decision.invariant_violations


def test_missing_mandatory_invariant_fails_closed():
    packet = make_packet()
    state = make_system_state(
        passed_checks=tuple(
            c for c in MANDATORY_INVARIANTS if c != "scope_explicit"
        ),
    )
    decision = schedule_decision(packet, state)
    assert decision.route is RouteMode.FAIL_CLOSED
    assert decision.reason_code is ScheduleReasonCode.INVARIANT_VIOLATION
    assert "scope_explicit" in decision.invariant_violations


def test_missing_rollback_plan_fails_closed_even_with_clean_state():
    packet = make_packet(rollback_plan="")
    decision = schedule_decision(packet, make_state())
    assert decision.route is RouteMode.FAIL_CLOSED
    assert decision.reason_code is ScheduleReasonCode.INVARIANT_VIOLATION
    assert "rollback_or_containment_path_exists" in decision.invariant_violations


def test_required_check_missing_fails_closed():
    packet = make_packet(required_checks=("custom_required_check",))
    decision = schedule_decision(packet, make_state())
    assert decision.route is RouteMode.FAIL_CLOSED
    assert "custom_required_check" in decision.invariant_violations


def test_no_safe_action_fits_when_irreversible_and_window_too_tight():
    packet = make_packet(
        verification_cost_ms=400,
        execution_cost_ms=400,
        rollback_cost_ms=400,
        deadline_ms=500,
        reversibility=0.2,
        risk_label="high",
    )
    decision = schedule_decision(packet, make_state())
    assert decision.route is RouteMode.FAIL_CLOSED
    assert decision.reason_code is ScheduleReasonCode.NO_SAFE_ACTION_FITS


# -- Priority ordering ----------------------------------------------------


def test_invariant_violation_takes_precedence_over_containment_signal():
    # Both a FAIL_CLOSED signal and a CONTAINMENT signal are present.
    state = make_state(
        failed_checks=("missing_salt", "policy_disagreement"),
    )
    decision = schedule_decision(make_packet(), state)
    assert decision.route is RouteMode.FAIL_CLOSED
    assert decision.reason_code is ScheduleReasonCode.FAIL_CLOSED_SIGNAL


def test_invariant_violation_overrides_fitting_fast_window():
    # Even when budget would permit FAST, a missing invariant fails closed.
    packet = make_packet(risk_label="low", deadline_ms=10_000)
    state = make_system_state(
        passed_checks=tuple(
            c for c in MANDATORY_INVARIANTS if c != "policy_evaluation_completed"
        ),
    )
    decision = schedule_decision(packet, state)
    assert decision.route is RouteMode.FAIL_CLOSED


def test_shortcut_debt_takes_precedence_over_fast_window():
    state = make_state(shortcut_debt=ShortcutDebt(emergency_overrides=3))
    decision = schedule_decision(make_packet(), state)
    assert decision.route is RouteMode.CONTAINMENT
    assert decision.reason_code is ScheduleReasonCode.SHORTCUT_DEBT_EXCEEDED


def test_trust_degradation_takes_precedence_over_containment_signal_path():
    # When both degraded trust and a containment signal are present, the
    # scheduler still routes CONTAINMENT but reports the trust reason first.
    state = make_state(
        trust_state="unsafe",
        failed_checks=("policy_disagreement",),
    )
    decision = schedule_decision(make_packet(), state)
    assert decision.route is RouteMode.CONTAINMENT
    assert decision.reason_code is ScheduleReasonCode.TRUST_STATE_DEGRADED


# -- Purity ---------------------------------------------------------------


def test_schedule_decision_is_pure_and_does_not_mutate_inputs():
    packet = make_packet(risk_label="high", deadline_ms=2000)
    state = make_state(
        shortcut_debt=ShortcutDebt(reduced_checks=2),
        passed_checks=MANDATORY_INVARIANTS,
        failed_checks=("policy_disagreement",),
    )

    packet_before = replace(packet)
    state_before = replace(state)

    first = schedule_decision(packet, state)
    second = schedule_decision(packet, state)

    assert first == second
    assert packet == packet_before
    assert state == state_before


def test_schedule_decision_returns_frozen_decision():
    decision = schedule_decision(make_packet(), make_state())
    assert isinstance(decision, ScheduleDecision)
    with pytest.raises(FrozenInstanceError):
        decision.route = RouteMode.FAIL_CLOSED  # type: ignore[misc]


# -- Helper factory functions ---------------------------------------------


def test_fast_path_helper_emits_fast_decision():
    decision = fast_path(make_packet(), make_state())
    assert decision.route is RouteMode.FAST


def test_deliberative_path_helper_emits_deliberative_decision():
    decision = deliberative_path(
        make_packet(risk_label="high"), make_state()
    )
    assert decision.route is RouteMode.DELIBERATIVE


def test_containment_helper_records_triggers_and_state():
    state = make_state(
        shortcut_debt=ShortcutDebt(reduced_checks=1),
        trust_state="contested",
    )
    decision = containment(
        make_packet(),
        state,
        reason="forced",
        reason_code=ScheduleReasonCode.TRUST_STATE_DEGRADED,
        triggers=("policy_disagreement",),
    )
    assert decision.route is RouteMode.CONTAINMENT
    assert decision.triggers == ("policy_disagreement",)
    assert decision.trust_state == "contested"
    assert decision.shortcut_debt_score == pytest.approx(0.1)


def test_fail_closed_helper_records_invariant_violations():
    decision = fail_closed(
        make_packet(),
        make_state(),
        reason="forced",
        invariant_violations=("scope_explicit",),
    )
    assert decision.route is RouteMode.FAIL_CLOSED
    assert decision.invariant_violations == ("scope_explicit",)


def test_make_system_state_dedupes_check_tuples():
    state = make_system_state(
        passed_checks=("a", "a", " b ", "c"),
        failed_checks=("x", "x"),
    )
    assert state.passed_checks == ("a", "b", "c")
    assert state.failed_checks == ("x",)


# -- Mapping coverage: documented OSINT actions ---------------------------


def test_documented_fast_osint_actions_fit_fast_route_under_clean_state():
    for action in FAST_ACTIONS:
        packet = make_packet(action=action, risk_label="low")
        decision = schedule_decision(packet, make_state())
        assert decision.route is RouteMode.FAST, action


def test_documented_deliberative_osint_actions_route_deliberative_when_high_risk():
    for action in DELIBERATIVE_ACTIONS:
        packet = make_packet(
            action=action,
            risk_label="high",
            deadline_ms=2000,
        )
        decision = schedule_decision(packet, make_state())
        assert decision.route is RouteMode.DELIBERATIVE, action
