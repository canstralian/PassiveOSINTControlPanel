"""
osint_core.constraints
======================

Constraint engine for the Passive OSINT Control Panel.

Where ``osint_core.policy`` answers "is this module allowed?", the constraint
engine answers "given the full request shape, which invariants must hold, and
which ones are violated?". It composes multiple named constraints, each
producing structured evidence, and emits a single ``ConstraintReport`` plus a
redacted, audit-safe ledger entry.

Design constraints (the meta-constraints on this module):

- Pure evaluation. No I/O except in ``write_constraint_ledger``.
- Single source of truth for policy. Constraints consult
  ``policy.evaluate_modules`` rather than re-implementing risk rules.
- Decisions are derived, not invented. The decision mirrors
  ``PolicyDecision`` (ALLOW or CONSTRAIN) so callers can branch on one enum.
- Closed correction-verb vocabulary. The engine derives a recommended verb
  via priority ordering and validates it through
  ``policy.enforce_correction_verb``.
- Raw indicators never appear in the ledger. ``write_constraint_ledger``
  refuses any payload that ``policy.enforce_audit_payload`` would reject.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable

from .policy import (
    ALLOWED_CORRECTION_VERBS,
    CorrectionVerb,
    PolicyDecision,
    PolicyErrorCode,
    PolicyEvaluation,
    PolicyViolationException,
    enforce_audit_payload,
    enforce_correction_verb,
    evaluate_modules,
)


LEDGER_SCHEMA_VERSION = "1.0.0"


class ConstraintStatus(str, Enum):
    SATISFIED = "satisfied"
    VIOLATED = "violated"
    NOT_APPLICABLE = "not_applicable"


class ConstraintSeverity(str, Enum):
    ENFORCE = "enforce"
    WARN = "warn"


class ConstraintCode(str, Enum):
    AUTHORIZATION = "authorization"
    PASSIVITY = "passivity"
    FORBIDDEN_CAPABILITY = "forbidden_capability"
    UNKNOWN_MODULE = "unknown_module"
    AUDIT_PAYLOAD = "audit_payload"
    CORRECTION_VERB = "correction_verb"


@dataclass(frozen=True)
class ConstraintContext:
    """
    Per-request inputs the engine evaluates against.

    The engine never reads raw indicator material; only the indicator hash and
    type travel through, so the ledger entry is safe to persist as-is.
    """
    requested_modules: tuple[str, ...]
    authorized_target: bool
    passive_only: bool
    indicator_hash: str | None = None
    indicator_type: str | None = None
    audit_payload: dict | None = None
    correction_verb: str | None = None


@dataclass(frozen=True)
class ConstraintResult:
    name: str
    code: ConstraintCode
    status: ConstraintStatus
    severity: ConstraintSeverity
    message: str
    evidence: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ConstraintReport:
    decision: PolicyDecision
    results: tuple[ConstraintResult, ...]
    policy_evaluation: PolicyEvaluation
    enforced_correction_verb: CorrectionVerb
    timestamp: str

    @property
    def violated(self) -> tuple[ConstraintResult, ...]:
        return tuple(r for r in self.results if r.status == ConstraintStatus.VIOLATED)

    @property
    def enforced_violations(self) -> tuple[ConstraintResult, ...]:
        return tuple(
            r
            for r in self.results
            if r.status == ConstraintStatus.VIOLATED
            and r.severity == ConstraintSeverity.ENFORCE
        )


# Map PolicyErrorCode → ConstraintCode for evidence translation.
_POLICY_TO_CONSTRAINT_CODE: dict[PolicyErrorCode, ConstraintCode] = {
    PolicyErrorCode.AUTHORIZATION_REQUIRED: ConstraintCode.AUTHORIZATION,
    PolicyErrorCode.FORBIDDEN_MODULE: ConstraintCode.FORBIDDEN_CAPABILITY,
    PolicyErrorCode.UNKNOWN_MODULE: ConstraintCode.UNKNOWN_MODULE,
    PolicyErrorCode.RAW_LOGGING_BLOCKED: ConstraintCode.AUDIT_PAYLOAD,
    PolicyErrorCode.INVALID_CORRECTION_VERB: ConstraintCode.CORRECTION_VERB,
}


# Correction-verb priority for derived recommendations.
# Higher index in this tuple wins when multiple constraints fire.
# Order: forbidden/raw-logging escalate to REVERT; authorization-class
# violations CONSTRAIN; everything else OBSERVE.
_CONSTRAIN_VERBS: dict[ConstraintCode, CorrectionVerb] = {
    ConstraintCode.FORBIDDEN_CAPABILITY: "REVERT",
    ConstraintCode.AUDIT_PAYLOAD: "REVERT",
    ConstraintCode.CORRECTION_VERB: "REVERT",
    ConstraintCode.AUTHORIZATION: "CONSTRAIN",
    ConstraintCode.PASSIVITY: "CONSTRAIN",
    ConstraintCode.UNKNOWN_MODULE: "CONSTRAIN",
}

_VERB_PRIORITY: tuple[CorrectionVerb, ...] = ("OBSERVE", "ADAPT", "CONSTRAIN", "REVERT")


# A constraint evaluator is a pure function: (context, policy_evaluation) -> result.
ConstraintEvaluator = Callable[[ConstraintContext, PolicyEvaluation], ConstraintResult]


@dataclass(frozen=True)
class Constraint:
    name: str
    code: ConstraintCode
    severity: ConstraintSeverity
    evaluator: ConstraintEvaluator


# -----------------------------------------------------------------------------
# Built-in constraints
# -----------------------------------------------------------------------------

def _authorization_constraint(
    context: ConstraintContext, policy_eval: PolicyEvaluation
) -> ConstraintResult:
    auth_violations = [
        v for v in policy_eval.violations
        if v.code == PolicyErrorCode.AUTHORIZATION_REQUIRED
    ]
    if not auth_violations:
        return ConstraintResult(
            name="authorization",
            code=ConstraintCode.AUTHORIZATION,
            status=ConstraintStatus.SATISFIED,
            severity=ConstraintSeverity.ENFORCE,
            message="No authorized-only modules requested without authorization.",
        )
    return ConstraintResult(
        name="authorization",
        code=ConstraintCode.AUTHORIZATION,
        status=ConstraintStatus.VIOLATED,
        severity=ConstraintSeverity.ENFORCE,
        message="Authorized-only module requested without explicit authorization.",
        evidence={
            "blocked_modules": [v.module for v in auth_violations if v.module],
            "authorized_target": context.authorized_target,
            "passive_only": context.passive_only,
        },
    )


def _forbidden_capability_constraint(
    context: ConstraintContext, policy_eval: PolicyEvaluation
) -> ConstraintResult:
    forbidden = [
        v for v in policy_eval.violations
        if v.code == PolicyErrorCode.FORBIDDEN_MODULE
    ]
    if not forbidden:
        return ConstraintResult(
            name="forbidden_capability",
            code=ConstraintCode.FORBIDDEN_CAPABILITY,
            status=ConstraintStatus.SATISFIED,
            severity=ConstraintSeverity.ENFORCE,
            message="No forbidden capabilities requested.",
        )
    return ConstraintResult(
        name="forbidden_capability",
        code=ConstraintCode.FORBIDDEN_CAPABILITY,
        status=ConstraintStatus.VIOLATED,
        severity=ConstraintSeverity.ENFORCE,
        message="Forbidden capability requested.",
        evidence={"blocked_modules": [v.module for v in forbidden if v.module]},
    )


def _unknown_module_constraint(
    context: ConstraintContext, policy_eval: PolicyEvaluation
) -> ConstraintResult:
    unknown = [
        v for v in policy_eval.violations
        if v.code == PolicyErrorCode.UNKNOWN_MODULE
    ]
    if not unknown:
        return ConstraintResult(
            name="unknown_module",
            code=ConstraintCode.UNKNOWN_MODULE,
            status=ConstraintStatus.SATISFIED,
            severity=ConstraintSeverity.ENFORCE,
            message="All requested modules are registered.",
        )
    return ConstraintResult(
        name="unknown_module",
        code=ConstraintCode.UNKNOWN_MODULE,
        status=ConstraintStatus.VIOLATED,
        severity=ConstraintSeverity.ENFORCE,
        message="Unknown module requested.",
        evidence={"blocked_modules": [v.module for v in unknown if v.module]},
    )


def _audit_payload_constraint(
    context: ConstraintContext, policy_eval: PolicyEvaluation
) -> ConstraintResult:
    if context.audit_payload is None:
        return ConstraintResult(
            name="audit_payload",
            code=ConstraintCode.AUDIT_PAYLOAD,
            status=ConstraintStatus.NOT_APPLICABLE,
            severity=ConstraintSeverity.ENFORCE,
            message="No audit payload supplied; constraint not evaluated.",
        )
    try:
        enforce_audit_payload(context.audit_payload)
    except PolicyViolationException as exc:
        return ConstraintResult(
            name="audit_payload",
            code=ConstraintCode.AUDIT_PAYLOAD,
            status=ConstraintStatus.VIOLATED,
            severity=ConstraintSeverity.ENFORCE,
            message=str(exc),
            evidence={"violation_code": exc.violation.code.value},
        )
    return ConstraintResult(
        name="audit_payload",
        code=ConstraintCode.AUDIT_PAYLOAD,
        status=ConstraintStatus.SATISFIED,
        severity=ConstraintSeverity.ENFORCE,
        message="Audit payload contains no raw indicator fields.",
    )


def _correction_verb_constraint(
    context: ConstraintContext, policy_eval: PolicyEvaluation
) -> ConstraintResult:
    if context.correction_verb is None:
        return ConstraintResult(
            name="correction_verb",
            code=ConstraintCode.CORRECTION_VERB,
            status=ConstraintStatus.NOT_APPLICABLE,
            severity=ConstraintSeverity.ENFORCE,
            message="No correction verb supplied; constraint not evaluated.",
        )
    try:
        normalized = enforce_correction_verb(context.correction_verb)
    except PolicyViolationException as exc:
        return ConstraintResult(
            name="correction_verb",
            code=ConstraintCode.CORRECTION_VERB,
            status=ConstraintStatus.VIOLATED,
            severity=ConstraintSeverity.ENFORCE,
            message=str(exc),
            evidence={"supplied": context.correction_verb},
        )
    return ConstraintResult(
        name="correction_verb",
        code=ConstraintCode.CORRECTION_VERB,
        status=ConstraintStatus.SATISFIED,
        severity=ConstraintSeverity.ENFORCE,
        message="Correction verb is in the closed allowlist.",
        evidence={"verb": normalized},
    )


DEFAULT_CONSTRAINTS: tuple[Constraint, ...] = (
    Constraint(
        name="authorization",
        code=ConstraintCode.AUTHORIZATION,
        severity=ConstraintSeverity.ENFORCE,
        evaluator=_authorization_constraint,
    ),
    Constraint(
        name="forbidden_capability",
        code=ConstraintCode.FORBIDDEN_CAPABILITY,
        severity=ConstraintSeverity.ENFORCE,
        evaluator=_forbidden_capability_constraint,
    ),
    Constraint(
        name="unknown_module",
        code=ConstraintCode.UNKNOWN_MODULE,
        severity=ConstraintSeverity.ENFORCE,
        evaluator=_unknown_module_constraint,
    ),
    Constraint(
        name="audit_payload",
        code=ConstraintCode.AUDIT_PAYLOAD,
        severity=ConstraintSeverity.ENFORCE,
        evaluator=_audit_payload_constraint,
    ),
    Constraint(
        name="correction_verb",
        code=ConstraintCode.CORRECTION_VERB,
        severity=ConstraintSeverity.ENFORCE,
        evaluator=_correction_verb_constraint,
    ),
)


# -----------------------------------------------------------------------------
# Engine
# -----------------------------------------------------------------------------

def evaluate_constraints(
    context: ConstraintContext,
    *,
    constraints: Iterable[Constraint] = DEFAULT_CONSTRAINTS,
    allow_unknown_modules: bool = False,
) -> ConstraintReport:
    """
    Evaluate every registered constraint and return a ``ConstraintReport``.

    The function is pure: it does not mutate ``context`` or any shared state.
    """
    policy_eval = evaluate_modules(
        list(context.requested_modules),
        authorized_target=context.authorized_target,
        passive_only=context.passive_only,
        allow_unknown_modules=allow_unknown_modules,
    )

    results = tuple(c.evaluator(context, policy_eval) for c in constraints)

    enforced_violations = [
        r for r in results
        if r.status == ConstraintStatus.VIOLATED
        and r.severity == ConstraintSeverity.ENFORCE
    ]

    if enforced_violations:
        decision = PolicyDecision.CONSTRAIN
    else:
        decision = PolicyDecision.ALLOW

    enforced_verb = _derive_correction_verb(enforced_violations)

    return ConstraintReport(
        decision=decision,
        results=results,
        policy_evaluation=policy_eval,
        enforced_correction_verb=enforced_verb,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def _derive_correction_verb(
    enforced_violations: list[ConstraintResult],
) -> CorrectionVerb:
    """
    Pick the highest-priority recommended verb across fired constraints.
    """
    if not enforced_violations:
        return enforce_correction_verb("OBSERVE")

    candidates: list[CorrectionVerb] = [
        _CONSTRAIN_VERBS.get(r.code, "CONSTRAIN") for r in enforced_violations
    ]
    chosen = max(candidates, key=_VERB_PRIORITY.index)
    # Validate through the closed allowlist as a defense-in-depth check.
    return enforce_correction_verb(chosen)


# -----------------------------------------------------------------------------
# Ledger
# -----------------------------------------------------------------------------

LEDGER_DIRNAME = "constraints"


def build_ledger_entry(
    report: ConstraintReport,
    *,
    run_id: str,
    indicator_hash: str,
    indicator_type: str,
) -> dict:
    """
    Produce a JSON-serializable, audit-safe ledger entry from a report.

    Raises ``PolicyViolationException`` if the resulting entry would contain
    any of the forbidden raw-indicator fields.
    """
    entry = {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "run_id": run_id,
        "timestamp": report.timestamp,
        "indicator_hash": indicator_hash,
        "indicator_type": indicator_type,
        "decision": report.decision.value,
        "enforced_correction_verb": report.enforced_correction_verb,
        "constraint_results": [
            {
                "name": r.name,
                "code": r.code.value,
                "status": r.status.value,
                "severity": r.severity.value,
                "message": r.message,
                "evidence": dict(r.evidence),
            }
            for r in report.results
        ],
        "policy": {
            "decision": report.policy_evaluation.decision.value,
            "allowed_modules": list(report.policy_evaluation.allowed_modules),
            "blocked_modules": list(report.policy_evaluation.blocked_modules),
            "violation_codes": [v.code.value for v in report.policy_evaluation.violations],
        },
    }
    enforce_audit_payload(entry)
    return entry


def write_constraint_ledger(
    report: ConstraintReport,
    *,
    run_id: str,
    indicator_hash: str,
    indicator_type: str,
    base_dir: Path,
) -> Path:
    """
    Persist the ledger entry as JSON under ``base_dir/constraints/{run_id}.json``.

    ``base_dir`` is typically the app's ``runs/`` directory. The directory is
    created if it does not exist.
    """
    entry = build_ledger_entry(
        report,
        run_id=run_id,
        indicator_hash=indicator_hash,
        indicator_type=indicator_type,
    )
    ledger_dir = Path(base_dir) / LEDGER_DIRNAME
    ledger_dir.mkdir(parents=True, exist_ok=True)
    path = ledger_dir / f"{run_id}.json"
    path.write_text(json.dumps(entry, indent=2, sort_keys=True), encoding="utf-8")
    return path


__all__ = [
    "ConstraintCode",
    "ConstraintContext",
    "ConstraintResult",
    "ConstraintReport",
    "ConstraintSeverity",
    "ConstraintStatus",
    "Constraint",
    "DEFAULT_CONSTRAINTS",
    "LEDGER_SCHEMA_VERSION",
    "evaluate_constraints",
    "build_ledger_entry",
    "write_constraint_ledger",
]
