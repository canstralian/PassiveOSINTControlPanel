from osint_core.scorecard import (
    classify_constraint,
    clamp01,
    score_with_disposition,
)
from osint_core.types import ConstraintScore


def test_clamp01_bounds_scores():
    assert clamp01(-1) == 0.0
    assert clamp01(0.5) == 0.5
    assert clamp01(2) == 1.0


def test_preserve_high_safety_high_yield_constraint():
    score = ConstraintScore(
        constraint_id="forbidden_capability",
        risk_reduction=1.0,
        generative_yield=0.7,
        friction_cost=0.5,
        learning_value=0.8,
    )

    assert classify_constraint(score) == "preserve"


def test_refine_high_safety_high_friction_constraint():
    score = ConstraintScore(
        constraint_id="authorized_target_required",
        risk_reduction=0.9,
        generative_yield=0.4,
        friction_cost=0.8,
        learning_value=0.6,
    )

    assert classify_constraint(score) == "refine"


def test_simulate_low_risk_high_learning_constraint():
    score = ConstraintScore(
        constraint_id="source_conflict",
        risk_reduction=0.2,
        generative_yield=0.4,
        friction_cost=0.2,
        learning_value=0.8,
    )

    assert classify_constraint(score) == "simulate"


def test_relax_candidate_requires_low_risk_reduction_and_high_friction():
    score = ConstraintScore(
        constraint_id="deadening_limit",
        risk_reduction=0.1,
        generative_yield=0.1,
        friction_cost=0.9,
        learning_value=0.2,
    )

    assert classify_constraint(score) == "relax_candidate"


def test_score_with_disposition_normalizes_and_classifies():
    score = score_with_disposition(
        ConstraintScore(
            constraint_id="overflow",
            risk_reduction=2.0,
            generative_yield=2.0,
            friction_cost=-1.0,
            learning_value=0.5,
        )
    )

    assert score.risk_reduction == 1.0
    assert score.generative_yield == 1.0
    assert score.friction_cost == 0.0
    assert score.disposition == "preserve"
