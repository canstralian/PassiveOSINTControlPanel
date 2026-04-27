"""
osint_core.audit
================

Audit helpers for constraint-aware OSINT workflows.

This module preserves the no-raw-indicator invariant by delegating payload
validation to the policy layer before persistence.
"""

from __future__ import annotations

from pathlib import Path

from .ledger import write_constraint_ledger
from .policy import enforce_audit_payload
from .types import ConstraintEvaluation


def assert_audit_safe(payload: dict) -> None:
    """Validate that an audit payload does not contain raw indicator fields."""
    enforce_audit_payload(payload)


def write_constraint_audit(
    evaluation: ConstraintEvaluation,
    *,
    directory: Path | str = Path("runs") / "constraints",
) -> Path:
    """Persist a constraint evaluation as an audit-safe ledger document."""
    return write_constraint_ledger(evaluation, directory=directory)
