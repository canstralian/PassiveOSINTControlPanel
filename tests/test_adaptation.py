"""
Tests for osint_core.adaptation.

Covers recommend_from_event and recommend_adaptations: disposition-to-rationale
mapping, recommendation_id format, and de-duplication logic.
"""

from __future__ import annotations

import pytest

from osint_core.adaptation import recommend_adaptations, recommend_from_event
from osint_core.types import AdaptationRecommendation, ConstraintEvent


# ---------------------------------------------------------------------------
# Helpers: build ConstraintEvent with controlled score dimensions
# ---------------------------------------------------------------------------


def make_event(
    *,
    constraint_id: str,
    risk_reduction: float,
    generative_yield: float,
    friction_cost: float,
    learning_value: float,
    decision: str = "block",
    action_id: str = "test_action",
    run_id: str = "run_test",
) -> ConstraintEvent:
    return ConstraintEvent(
        run_id=run_id,
        action_id=action_id,
        constraint_id=constraint_id,
        constraint_class="hard",
        decision=decision,  # type: ignore[arg-type]
        original_action=action_id,
        replacement_action=None,
        rationale="test rationale",
        risk_reduction=risk_reduction,
        generative_yield=generative_yield,
        friction_cost=friction_cost,
        learning_value=learning_value,
    )


# ---------------------------------------------------------------------------
# recommend_from_event — disposition "preserve"
# ---------------------------------------------------------------------------


def test_recommend_from_event_preserve_disposition():
    # risk_reduction >= 0.8 and generative_yield >= 0.6  → preserve
    event = make_event(
        constraint_id="forbidden_capability",
        risk_reduction=1.0,
        generative_yield=0.6,
        friction_cost=0.5,
        learning_value=0.8,
    )
    rec = recommend_from_event(event)

    assert isinstance(rec, AdaptationRecommendation)
    assert rec.constraint_id == "forbidden_capability"
    assert rec.action == "preserve"
    assert "Preserve" in rec.rationale
    assert "forbidden_capability" in rec.rationale
    assert rec.recommendation_id == "rec_forbidden_capability_preserve"


# ---------------------------------------------------------------------------
# recommend_from_event — disposition "refine"
# ---------------------------------------------------------------------------


def test_recommend_from_event_refine_disposition():
    # risk_reduction >= 0.8 and friction_cost >= 0.7 (generative_yield < 0.6) → refine
    event = make_event(
        constraint_id="authorized_target_required",
        risk_reduction=0.9,
        generative_yield=0.4,
        friction_cost=0.8,
        learning_value=0.6,
    )
    rec = recommend_from_event(event)

    assert rec.action == "refine"
    assert "Refine" in rec.rationale
    assert "authorized_target_required" in rec.rationale
    assert rec.recommendation_id == "rec_authorized_target_required_refine"


# ---------------------------------------------------------------------------
# recommend_from_event — disposition "simulate"
# ---------------------------------------------------------------------------


def test_recommend_from_event_simulate_disposition():
    # learning_value >= 0.7 and risk_reduction < 0.5 → simulate
    event = make_event(
        constraint_id="source_conflict",
        risk_reduction=0.2,
        generative_yield=0.4,
        friction_cost=0.2,
        learning_value=0.8,
    )
    rec = recommend_from_event(event)

    assert rec.action == "simulate"
    assert "simulation" in rec.rationale
    assert "source_conflict" in rec.rationale
    assert rec.recommendation_id == "rec_source_conflict_simulate"


# ---------------------------------------------------------------------------
# recommend_from_event — disposition "relax_candidate"
# ---------------------------------------------------------------------------


def test_recommend_from_event_relax_candidate_disposition():
    # risk_reduction < 0.3 and friction_cost >= 0.7 → relax_candidate
    event = make_event(
        constraint_id="deadening_limit",
        risk_reduction=0.1,
        generative_yield=0.1,
        friction_cost=0.9,
        learning_value=0.2,
    )
    rec = recommend_from_event(event)

    assert rec.action == "relax_candidate"
    assert "relaxation candidate" in rec.rationale
    assert "deadening_limit" in rec.rationale
    assert rec.recommendation_id == "rec_deadening_limit_relax_candidate"


# ---------------------------------------------------------------------------
# recommend_from_event — disposition "observe" (fallback)
# ---------------------------------------------------------------------------


def test_recommend_from_event_observe_disposition():
    # Moderate values that do not trigger any threshold → observe
    event = make_event(
        constraint_id="mild_limit",
        risk_reduction=0.4,
        generative_yield=0.4,
        friction_cost=0.4,
        learning_value=0.4,
    )
    rec = recommend_from_event(event)

    assert rec.action == "observe"
    assert "Observe" in rec.rationale or "observe" in rec.rationale.lower()
    assert "mild_limit" in rec.rationale
    assert rec.recommendation_id == "rec_mild_limit_observe"


# ---------------------------------------------------------------------------
# recommend_from_event — recommendation_id format
# ---------------------------------------------------------------------------


def test_recommend_from_event_recommendation_id_format():
    event = make_event(
        constraint_id="my_constraint",
        risk_reduction=1.0,
        generative_yield=0.9,
        friction_cost=0.1,
        learning_value=0.5,
    )
    rec = recommend_from_event(event)

    assert rec.recommendation_id.startswith("rec_my_constraint_")
    assert rec.recommendation_id == f"rec_my_constraint_{rec.action}"


# ---------------------------------------------------------------------------
# recommend_adaptations — basic list processing
# ---------------------------------------------------------------------------


def test_recommend_adaptations_empty_list():
    result = recommend_adaptations([])
    assert result == []


def test_recommend_adaptations_single_event():
    event = make_event(
        constraint_id="forbidden_capability",
        risk_reduction=1.0,
        generative_yield=0.6,
        friction_cost=0.5,
        learning_value=0.8,
    )
    result = recommend_adaptations([event])

    assert len(result) == 1
    assert result[0].constraint_id == "forbidden_capability"


# ---------------------------------------------------------------------------
# recommend_adaptations — de-duplication by constraint_id
# ---------------------------------------------------------------------------


def test_recommend_adaptations_deduplicates_by_constraint_id():
    """Only the first event per constraint_id produces a recommendation."""
    event_a = make_event(
        constraint_id="forbidden_capability",
        risk_reduction=1.0,
        generative_yield=0.6,
        friction_cost=0.5,
        learning_value=0.8,
        action_id="action_a",
    )
    event_b = make_event(
        constraint_id="forbidden_capability",  # same constraint_id
        risk_reduction=1.0,
        generative_yield=0.6,
        friction_cost=0.5,
        learning_value=0.8,
        action_id="action_b",
    )
    result = recommend_adaptations([event_a, event_b])

    assert len(result) == 1
    assert result[0].constraint_id == "forbidden_capability"


def test_recommend_adaptations_preserves_distinct_constraints():
    event_a = make_event(
        constraint_id="forbidden_capability",
        risk_reduction=1.0,
        generative_yield=0.6,
        friction_cost=0.5,
        learning_value=0.8,
    )
    event_b = make_event(
        constraint_id="authorized_target_required",
        risk_reduction=0.9,
        generative_yield=0.5,
        friction_cost=0.4,
        learning_value=0.7,
    )
    result = recommend_adaptations([event_a, event_b])

    assert len(result) == 2
    constraint_ids = {r.constraint_id for r in result}
    assert constraint_ids == {"forbidden_capability", "authorized_target_required"}


def test_recommend_adaptations_preserves_input_order():
    events = [
        make_event(
            constraint_id=f"constraint_{i}",
            risk_reduction=0.4,
            generative_yield=0.4,
            friction_cost=0.4,
            learning_value=0.4,
        )
        for i in range(4)
    ]
    result = recommend_adaptations(events)

    assert [r.constraint_id for r in result] == [f"constraint_{i}" for i in range(4)]


# ---------------------------------------------------------------------------
# recommend_adaptations — returns AdaptationRecommendation instances
# ---------------------------------------------------------------------------


def test_recommend_adaptations_returns_adaptation_recommendations():
    event = make_event(
        constraint_id="some_constraint",
        risk_reduction=0.5,
        generative_yield=0.5,
        friction_cost=0.5,
        learning_value=0.5,
    )
    result = recommend_adaptations([event])

    assert all(isinstance(r, AdaptationRecommendation) for r in result)


# ---------------------------------------------------------------------------
# Integration: forbidden_capability event from real evaluate_constraints
# ---------------------------------------------------------------------------


def test_recommend_from_event_with_real_forbidden_event():
    """Forbidden capability events should produce 'preserve' recommendations."""
    from osint_core.constraints import evaluate_constraints

    evaluation = evaluate_constraints(
        run_id="run_test",
        requested_modules=["nmap"],
        authorized_target=True,
        passive_only=False,
    )

    forbidden_events = [e for e in evaluation.events if e.constraint_id == "forbidden_capability"]
    assert forbidden_events, "Expected at least one forbidden_capability event"

    rec = recommend_from_event(forbidden_events[0])
    assert rec.action == "preserve"
    assert rec.constraint_id == "forbidden_capability"


def test_recommend_adaptations_with_real_mixed_evaluation():
    """recommend_adaptations de-duplicates across a real evaluation."""
    from osint_core.constraints import evaluate_constraints

    evaluation = evaluate_constraints(
        run_id="run_test",
        requested_modules=["Resource Links", "nmap", "nmap"],
        authorized_target=False,
        passive_only=True,
    )

    recommendations = recommend_adaptations(evaluation.events)
    constraint_ids = [r.constraint_id for r in recommendations]
    # Each constraint_id appears at most once
    assert len(constraint_ids) == len(set(constraint_ids))