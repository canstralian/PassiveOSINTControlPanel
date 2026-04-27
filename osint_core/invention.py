"""
osint_core.invention
====================

Four-loop constraint-aware invention engine.

The engine composes generation, constraint evaluation, reflection, and
adaptation without executing OSINT modules directly. It is a planning/control
layer, not an autonomy expansion layer.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from .adaptation import recommend_adaptations
from .constraints import ConstraintEvaluation, evaluate_constraints
from .reflection import reflect_on_events
from .types import AuthorityMode, InventionRequest, InventionResponse


def make_run_id(prefix: str = "invent") -> str:
    """Create a run identifier without embedding raw indicators."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{stamp}_{uuid.uuid4().hex[:8]}"


def passive_only_for_mode(authority_mode: AuthorityMode, requested_passive_only: bool) -> bool:
    """Resolve passive-only enforcement from the requested authority mode."""
    if authority_mode == "operator_authorized":
        return requested_passive_only
    return True


def run_invention_loop(request: InventionRequest, *, run_id: str | None = None) -> InventionResponse:
    """
    Execute the four-loop planning circuit.

    1. Generative loop: requested modules become proposed actions.
    2. Constraint loop: policy evaluates the proposed actions.
    3. Reflection loop: events become operator-readable lessons.
    4. Adaptation loop: events become bounded future recommendations.
    """
    resolved_run_id = run_id or make_run_id()
    passive_only = passive_only_for_mode(request.authority_mode, request.passive_only)

    evaluation: ConstraintEvaluation = evaluate_constraints(
        run_id=resolved_run_id,
        requested_modules=request.requested_modules,
        authorized_target=request.authorized_target,
        passive_only=passive_only,
    )
    reflections = reflect_on_events(evaluation.events)
    recommendations = recommend_adaptations(evaluation.events)

    return InventionResponse(
        run_id=resolved_run_id,
        request=request,
        evaluation=evaluation,
        reflections=reflections,
        recommendations=recommendations,
    )


def summarize_invention_response(response: InventionResponse) -> str:
    """Render a compact Markdown summary for a UI panel or issue comment."""
    lines = [
        "## Constraint-Aware Invention Engine",
        "",
        f"- Run ID: `{response.run_id}`",
        f"- Objective: {response.request.objective}",
        f"- Authority Mode: `{response.request.authority_mode}`",
        f"- Allowed Actions: `{len(response.evaluation.allowed_actions)}`",
        f"- Blocked Actions: `{len(response.evaluation.blocked_actions)}`",
        "",
        "### Constraint Events",
    ]

    if not response.evaluation.events:
        lines.append("- None")
    else:
        for event in response.evaluation.events:
            lines.append(
                f"- `{event.action_id}` → `{event.decision}` via `{event.constraint_id}`"
            )

    lines.append("")
    lines.append("### Recommendations")
    if not response.recommendations:
        lines.append("- None")
    else:
        for recommendation in response.recommendations:
            lines.append(f"- `{recommendation.action}`: {recommendation.rationale}")

    return "\n".join(lines)
