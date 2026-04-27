"""
osint_core.scorecard
====================

Constraint scoring for the Passive OSINT Control Panel.

The scorecard turns policy pressure into an explicit operating signal. It does
not broaden authority or relax hard boundaries; it classifies whether a
constraint should be preserved, refined, simulated, reviewed as a relaxation
candidate, or simply observed.
"""

from __future__ import annotations

from typing import Protocol

from .types import ConstraintDisposition, ConstraintScore, clamp_score


class ScorableConstraintEvent(Protocol):
    """Structural protocol for event-like objects with score dimensions."""

    constraint_id: str
    risk_reduction: float
    generative_yield: float
    friction_cost: float
    learning_value: float


def clamp01(value: float) -> float:
    """Clamp a numeric value to the closed interval [0.0, 1.0]."""
    return clamp_score(value)


def classify_constraint(score: ConstraintScore) -> ConstraintDisposition:
    """
    Classify a constraint without mutating policy.

    The order is deliberate: high safety plus useful design pressure is
    preserved; high safety plus high friction is refined, not relaxed; low-risk
    learning constraints are kept in simulation; only low-safety, high-friction
    constraints become relaxation candidates.
    """
    normalized = score.normalized()

    if normalized.risk_reduction >= 0.8 and normalized.generative_yield >= 0.6:
        return "preserve"

    if normalized.risk_reduction >= 0.8 and normalized.friction_cost >= 0.7:
        return "refine"

    if normalized.learning_value >= 0.7 and normalized.risk_reduction < 0.5:
        return "simulate"

    if normalized.risk_reduction < 0.3 and normalized.friction_cost >= 0.7:
        return "relax_candidate"

    return "observe"


def score_with_disposition(score: ConstraintScore) -> ConstraintScore:
    """Return a normalized score with its deterministic disposition applied."""
    normalized = score.normalized()
    return ConstraintScore(
        constraint_id=normalized.constraint_id,
        risk_reduction=normalized.risk_reduction,
        generative_yield=normalized.generative_yield,
        friction_cost=normalized.friction_cost,
        learning_value=normalized.learning_value,
        disposition=classify_constraint(normalized),
    )


def score_constraint_event(event: ScorableConstraintEvent) -> ConstraintScore:
    """Score any constraint event-like object without coupling modules together."""
    return score_with_disposition(
        ConstraintScore(
            constraint_id=event.constraint_id,
            risk_reduction=event.risk_reduction,
            generative_yield=event.generative_yield,
            friction_cost=event.friction_cost,
            learning_value=event.learning_value,
        )
    )
