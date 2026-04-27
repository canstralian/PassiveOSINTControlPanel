"""
osint_core.adaptation
=====================

Adaptation layer for the constraint-aware invention engine.

Adaptation converts repeated or high-signal constraint pressure into bounded
recommendations. It never changes policy by itself.
"""

from __future__ import annotations

from .scorecard import score_constraint_event
from .types import AdaptationRecommendation, ConstraintEvent


def recommend_from_event(event: ConstraintEvent) -> AdaptationRecommendation:
    """Recommend a bounded future adjustment from one event."""
    score = score_constraint_event(event)

    if score.disposition == "preserve":
        rationale = f"Preserve `{event.constraint_id}` because it reduces risk while retaining useful design pressure."
    elif score.disposition == "refine":
        rationale = f"Refine `{event.constraint_id}` because it reduces risk but imposes high friction."
    elif score.disposition == "simulate":
        rationale = f"Keep `{event.constraint_id}` in simulation because it has learning value without being a hard runtime boundary."
    elif score.disposition == "relax_candidate":
        rationale = f"Review `{event.constraint_id}` as a relaxation candidate only if it does not protect a hard boundary."
    else:
        rationale = f"Observe `{event.constraint_id}` until more evidence accumulates."

    return AdaptationRecommendation(
        recommendation_id=f"rec_{event.constraint_id}_{score.disposition}",
        constraint_id=event.constraint_id,
        action=score.disposition,
        rationale=rationale,
    )


def recommend_adaptations(events: list[ConstraintEvent]) -> list[AdaptationRecommendation]:
    """Return deterministic recommendations, de-duplicated by constraint ID."""
    recommendations: list[AdaptationRecommendation] = []
    seen: set[str] = set()

    for event in events:
        if event.constraint_id in seen:
            continue
        recommendations.append(recommend_from_event(event))
        seen.add(event.constraint_id)

    return recommendations
