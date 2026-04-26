"""
osint_core.observer
===================

Independent observer circuit for the Enterprise Drift-Aware OSINT Control Fabric.
The observer does not execute. It reconstructs expected behavior from intent,
policy, and executor trace, then emits dissent when reality does not match
declared constraints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class ObserverSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ObserverCheck:
    name: str
    ok: bool
    severity: ObserverSeverity
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExecutionTrace:
    intent_id: str
    modules_requested: tuple[str, ...]
    modules_executed: tuple[str, ...]
    modules_blocked: tuple[str, ...]
    observed_effects: tuple[str, ...]
    output_schema_valid: bool
    audit_payload: Mapping[str, Any]
    errors: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ObserverAssessment:
    intent_id: str
    checks: tuple[ObserverCheck, ...]

    @property
    def dissent(self) -> bool:
        return any(not check.ok for check in self.checks)

    @property
    def has_critical_violation(self) -> bool:
        return any((not check.ok) and check.severity == ObserverSeverity.CRITICAL for check in self.checks)


RAW_AUDIT_KEYS = {
    "raw_indicator",
    "raw_input",
    "indicator",
    "email",
    "domain",
    "username",
    "url",
    "ip",
}


def observe_execution(intent: Any, trace: ExecutionTrace, policy_result: Any) -> ObserverAssessment:
    checks = (
        check_intent_trace_match(intent, trace),
        check_modules_match_policy(trace, policy_result),
        check_output_schema(trace),
        check_no_raw_indicator_leak(trace),
        check_expected_side_effects(intent, trace),
    )
    return ObserverAssessment(intent_id=trace.intent_id, checks=checks)


def check_intent_trace_match(intent: Any, trace: ExecutionTrace) -> ObserverCheck:
    expected_intent_id = getattr(intent, "intent_id", None)
    ok = expected_intent_id == trace.intent_id
    return ObserverCheck(
        name="intent_trace_match",
        ok=ok,
        severity=ObserverSeverity.CRITICAL,
        reason="Execution trace must correspond to the intent packet.",
        evidence={"expected": expected_intent_id, "actual": trace.intent_id},
    )


def check_modules_match_policy(trace: ExecutionTrace, policy_result: Any) -> ObserverCheck:
    if isinstance(policy_result, dict):
        allowed = set(policy_result.get("allowed_modules", []))
    else:
        allowed = set(getattr(policy_result, "allowed_modules", []))

    executed = set(trace.modules_executed)
    unexpected = sorted(executed - allowed)
    return ObserverCheck(
        name="modules_match_policy",
        ok=not unexpected,
        severity=ObserverSeverity.CRITICAL,
        reason="Executed modules must be allowed by policy.",
        evidence={"unexpected_modules": unexpected},
    )


def check_output_schema(trace: ExecutionTrace) -> ObserverCheck:
    return ObserverCheck(
        name="output_schema_valid",
        ok=trace.output_schema_valid,
        severity=ObserverSeverity.WARNING,
        reason="Executor output should conform to expected schema.",
        evidence={},
    )


def check_no_raw_indicator_leak(trace: ExecutionTrace) -> ObserverCheck:
    present = sorted(set(trace.audit_payload.keys()).intersection(RAW_AUDIT_KEYS))
    return ObserverCheck(
        name="no_raw_indicator_leak",
        ok=not present,
        severity=ObserverSeverity.CRITICAL,
        reason="Audit payload must not contain raw indicator fields.",
        evidence={"raw_fields": present},
    )


def check_expected_side_effects(intent: Any, trace: ExecutionTrace) -> ObserverCheck:
    expected = set(getattr(intent, "expected_side_effects", ()))
    observed = set(trace.observed_effects)
    missing = sorted(expected - observed)
    return ObserverCheck(
        name="expected_side_effects_present",
        ok=not missing,
        severity=ObserverSeverity.WARNING,
        reason="Declared expected side effects should be observed or explained.",
        evidence={"missing_effects": missing},
    )
