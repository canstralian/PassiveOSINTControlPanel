"""
osint_core package
==================

Core logic for the Passive OSINT Control Panel.

This package is intentionally structured to separate:
- validation (input trust boundary)
- policy enforcement (allowed behavior)
- enrichment (passive intelligence gathering)
- drift detection (state vs expectation)
- correction (controlled mutation decisions)
- audit (traceability)

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

# Future modules (to be added as you build them)
# from .policy import enforce_policy
# from .enrichment import run_passive_enrichment
# from .drift import detect_drift
# from .correction import choose_correction
# from .audit import write_audit_event

__all__ = [
    # validation
    "validate_indicator",
    "assert_valid_or_raise",
    "ValidationResult",
    "ValidationErrorCode",
]

__version__ = "0.1.0"