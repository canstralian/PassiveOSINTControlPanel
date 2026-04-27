"""
osint_core package
==================

Core logic for the Passive OSINT Control Panel.

This package is intentionally structured to separate:
- validation (input trust boundary)
- policy enforcement (allowed behavior)
- enrichment planning (passive intelligence gathering)
- constraint evaluation (bounded authority)
- reflection and adaptation (learning from pressure)
- audit and ledger output (traceability)

Design principles:
- No module should perform implicit state mutation.
- Validation is the first gate; nothing downstream should re-validate.
- Public API is explicitly exported via __all__.
- Internal modules remain decoupled and testable.
"""

from .validators import (
    validate_indicator,
    assert_valid_or_raise,
    ValidationResult,
    ValidationErrorCode,
)
from .types import (
    InventionRequest,
    InventionResponse,
    ProposedAction,
    ConstraintEvent,
    ConstraintEvaluation,
    ReflectionFinding,
    AdaptationRecommendation,
)
from .constraints import evaluate_constraints, propose_actions, passive_module_actions
from .invention import run_invention_loop, summarize_invention_response
from .ledger import write_constraint_ledger, summarize_constraint_events
from .reports import render_constraint_report

__all__ = [
    # validation
    "validate_indicator",
    "assert_valid_or_raise",
    "ValidationResult",
    "ValidationErrorCode",
    # constraint-aware invention engine
    "InventionRequest",
    "InventionResponse",
    "ProposedAction",
    "ConstraintEvent",
    "ConstraintEvaluation",
    "ReflectionFinding",
    "AdaptationRecommendation",
    "evaluate_constraints",
    "propose_actions",
    "passive_module_actions",
    "run_invention_loop",
    "summarize_invention_response",
    "write_constraint_ledger",
    "summarize_constraint_events",
    "render_constraint_report",
]

__version__ = "0.1.0"
