"""
osint_core.reflection
=====================

Reflection layer for constraint-aware OSINT workflows.

Reflection explains how a proposal changed under pressure. It does not execute
modules or mutate policy; it converts constraint events into operator-readable
lessons and reusable design patterns.
"""

from __future__ import annotations

from .types import ConstraintEvent, ReflectionFinding


def reflect_on_event(event: ConstraintEvent) -> ReflectionFinding:
    """Convert one constraint event into a lesson."""
    reusable_pattern: str | None = None

    if event.constraint_id == "authorized_target_required":
        reusable_pattern = "Gate target-touching modules behind explicit authorization."
    elif event.constraint_id == "forbidden_capability":
        reusable_pattern = "Replace active or intrusive capability with passive source correlation."
    elif event.constraint_id == "unknown_module":
        reusable_pattern = "Reject unregistered modules until they are declared in policy."
    elif event.constraint_id == "module_allowed":
        reusable_pattern = "Preserve low-risk passive path as a stable default."

    lesson = (
        f"{event.original_action} met `{event.constraint_id}` and resolved as "
        f"`{event.decision}`. {event.rationale}"
    )

    if event.replacement_action:
        lesson += f" Safer substitute: {event.replacement_action}."

    return ReflectionFinding(
        action_id=event.action_id,
        constraint_id=event.constraint_id,
        decision=event.decision,
        lesson=lesson,
        reusable_pattern=reusable_pattern,
    )


def reflect_on_events(events: list[ConstraintEvent]) -> list[ReflectionFinding]:
    """Reflect on a list of constraint events while preserving event order."""
    return [reflect_on_event(event) for event in events]


def render_reflections_markdown(reflections: list[ReflectionFinding]) -> str:
    """Render reflections for reports or a Gradio panel."""
    if not reflections:
        return "_No reflection findings recorded._"

    lines = ["## Reflection", ""]
    for finding in reflections:
        lines.append(f"- **{finding.action_id}**: {finding.lesson}")
        if finding.reusable_pattern:
            lines.append(f"  - Pattern: {finding.reusable_pattern}")
    return "\n".join(lines)
