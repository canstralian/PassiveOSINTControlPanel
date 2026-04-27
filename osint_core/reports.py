"""
osint_core.reports
==================

Report helpers for constraint-aware OSINT workflows.

These functions render planning, reflection, and adaptation output. They do not
execute modules or write audit payloads.
"""

from __future__ import annotations

from .invention import summarize_invention_response
from .ledger import summarize_constraint_events
from .reflection import render_reflections_markdown
from .types import InventionResponse


def render_constraint_report(response: InventionResponse) -> str:
    """Render a Markdown report for the invention engine response."""
    return "\n\n".join(
        [
            summarize_invention_response(response),
            summarize_constraint_events(response.evaluation.events),
            render_reflections_markdown(response.reflections),
        ]
    )
