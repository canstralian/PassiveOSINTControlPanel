"""
osint_core.enrichment
=====================

Passive enrichment facade.

This module is intentionally thin in the constraint-engine slice. Runtime
execution still lives in the current app/orchestrator path; this facade provides
a stable import target for future extraction without adding active capability.
"""

from __future__ import annotations

from .constraints import propose_actions
from .types import ProposedAction


def plan_passive_enrichment(requested_modules: list[str]) -> list[ProposedAction]:
    """Plan enrichment actions without executing network operations."""
    return propose_actions(requested_modules)
