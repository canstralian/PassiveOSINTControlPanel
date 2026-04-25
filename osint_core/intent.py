"""
osint_core.intent
=================

Intent packet modeling for the Enterprise Drift-Aware OSINT Control Fabric.

This module turns a validated user request into an explicit, bounded, signed
intent packet. It does not execute actions, perform network calls, mutate
policy, update memory, or write audit records.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Literal, Mapping


IntentAction = Literal[
    "enrich_indicator",
    "generate_report",
    "update_sources",
    "run_module",
    "export_audit",
]

RiskLabel = Literal["low", "medium", "high", "critical"]
RollbackStrategy = Literal["none", "observe_only", "disable_module", "sandbox", "revert"]
IndicatorType = Literal["domain", "username", "email", "ip", "url", "unknown"]


class IntentErrorCode(str, Enum):
    MISSING_FIELD = "missing_field"
    INVALID_ACTION = "invalid_action"
    INVALID_RISK = "invalid_risk"
    INVALID_SCOPE = "invalid_scope"
    INVALID_ROLLBACK = "invalid_rollback"
    FORBIDDEN_OPERATION_REQUESTED = "forbidden_operation_requested"
    RAW_INDICATOR_LEAK = "raw_indicator_leak"
    UNSIGNED_PACKET = "unsigned_packet"
    SIGNATURE_MISMATCH = "signature_mismatch"
    SECRET_MISSING = "secret_missing"


class IntentValidationError(ValueError):
    def __init__(self, message: str, code: IntentErrorCode):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class IntentScope:
    """Explicit scope boundary for an intent.

    target_hash must be a hash/HMAC of the target. Raw indicators do not belong
    in scope objects or intent packets.
    """

    target_hash: str
    indicator_type: IndicatorType
    allowed_operations: tuple[str, ...]
    forbidden_operations: tuple[str, ...] = field(default_factory=tuple)
    time_horizon_seconds: int = 300
    success_criteria: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IntentPacket:
    """Signed, immutable description of a requested action."""

    intent_id: str
    action: IntentAction
    purpose: str
    scope: IntentScope
    requested_modules: tuple[str, ...]
    expected_side_effects: tuple[str, ...]
    rollback_strategy: RollbackStrategy
    risk_label: RiskLabel
    manifest_hash: str
    created_at: str
    schema_version: str = "1.0.0"
    signature: str | None = None

    def unsigned_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("signature", None)
        return payload

    def to_dict(self, include_signature: bool = True) -> dict[str, Any]:
        payload = asdict(self)
        if not include_signature:
            payload.pop("signature", None)
        return payload

    def to_json(self, include_signature: bool = True) -> str:
        return canonical_json(self.to_dict(include_signature=include_signature))


@dataclass(frozen=True)
class IntentValidationResult:
    ok: bool
    errors: tuple[str, ...] = field(default_factory=tuple)
    error_codes: tuple[IntentErrorCode, ...] = field(default_factory=tuple)


VALID_ACTIONS: set[str] = {
    "enrich_indicator",
    "generate_report",
    "update_sources",
    "run_module",
    "export_audit",
}

VALID_RISKS: set[str] = {"low", "medium", "high", "critical"}
VALID_ROLLBACK_STRATEGIES: set[str] = {
    "none",
    "observe_only",
    "disable_module",
    "sandbox",
    "revert",
}

DEFAULT_FORBIDDEN_OPERATIONS: tuple[str, ...] = (
    "port_scan",
    "mass_scan",
    "brute_force",
    "credential_testing",
    "exploitation",
    "directory_fuzzing",
    "web_vulnerability_scan",
    "password_spray",
    "login_attempt",
)

RAW_FIELD_NAMES: set[str] = {
    "raw_indicator",
    "raw_input",
    "indicator",
    "target",
    "domain",
    "email",
    "username",
    "url",
    "ip",
}

HASH_RE = re.compile(r"^[a-fA-F0-9]{32,128}$")


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(value: Mapping[str, Any]) -> str:
    """Return deterministic JSON for signing and hashing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def get_intent_signing_secret() -> str:
    """Return signing secret.

    Production should use INTENT_SIGNING_SECRET. Smaller deployments may fall
    back to OSINT_HASH_SALT, but separating both is preferred.
    """
    secret = os.getenv("INTENT_SIGNING_SECRET") or os.getenv("OSINT_HASH_SALT")
    if not secret:
        raise IntentValidationError(
            "Missing INTENT_SIGNING_SECRET or OSINT_HASH_SALT.",
            IntentErrorCode.SECRET_MISSING,
        )
    return secret


def hash_manifest_payload(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def sign_payload(payload: Mapping[str, Any], secret: str | None = None) -> str:
    secret = secret or get_intent_signing_secret()
    return hmac.new(
        secret.encode("utf-8"),
        canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def sign_intent(packet: IntentPacket, secret: str | None = None) -> IntentPacket:
    signature = sign_payload(packet.unsigned_payload(), secret=secret)
    return replace(packet, signature=signature)


def verify_intent_signature(packet: IntentPacket, secret: str | None = None) -> bool:
    if not packet.signature:
        raise IntentValidationError("Intent packet is unsigned.", IntentErrorCode.UNSIGNED_PACKET)

    expected = sign_payload(packet.unsigned_payload(), secret=secret)
    if not hmac.compare_digest(expected, packet.signature):
        raise IntentValidationError(
            "Intent signature mismatch.",
            IntentErrorCode.SIGNATURE_MISMATCH,
        )
    return True


def make_scope(
    *,
    target_hash: str,
    indicator_type: IndicatorType,
    allowed_operations: Iterable[str],
    forbidden_operations: Iterable[str] | None = None,
    time_horizon_seconds: int = 300,
    success_criteria: Iterable[str] | None = None,
) -> IntentScope:
    merged_forbidden = tuple(
        dedupe_preserve_order(
            [
                *(forbidden_operations or ()),
                *DEFAULT_FORBIDDEN_OPERATIONS,
            ]
        )
    )

    scope = IntentScope(
        target_hash=target_hash,
        indicator_type=indicator_type,
        allowed_operations=tuple(dedupe_preserve_order(allowed_operations)),
        forbidden_operations=merged_forbidden,
        time_horizon_seconds=time_horizon_seconds,
        success_criteria=tuple(success_criteria or ()),
    )
    validate_scope_or_raise(scope)
    return scope


def create_intent_packet(
    *,
    action: IntentAction,
    purpose: str,
    scope: IntentScope,
    requested_modules: Iterable[str],
    expected_side_effects: Iterable[str] | None = None,
    rollback_strategy: RollbackStrategy = "observe_only",
    risk_label: RiskLabel = "low",
    manifest_hash: str,
    intent_id: str | None = None,
    created_at: str | None = None,
    sign: bool = True,
    signing_secret: str | None = None,
) -> IntentPacket:
    packet = IntentPacket(
        intent_id=intent_id or f"intent_{uuid.uuid4().hex}",
        action=action,
        purpose=purpose.strip(),
        scope=scope,
        requested_modules=tuple(dedupe_preserve_order(requested_modules)),
        expected_side_effects=tuple(expected_side_effects or ()),
        rollback_strategy=rollback_strategy,
        risk_label=risk_label,
        manifest_hash=manifest_hash,
        created_at=created_at or now_utc(),
    )

    validate_intent_or_raise(packet)

    if sign:
        packet = sign_intent(packet, secret=signing_secret)
        verify_intent_signature(packet, secret=signing_secret)

    return packet


def validate_scope(scope: IntentScope) -> IntentValidationResult:
    errors: list[str] = []
    codes: list[IntentErrorCode] = []

    if not scope.target_hash:
        errors.append("scope.target_hash is required.")
        codes.append(IntentErrorCode.MISSING_FIELD)
    elif not HASH_RE.fullmatch(scope.target_hash):
        errors.append("scope.target_hash must look like a cryptographic hash.")
        codes.append(IntentErrorCode.INVALID_SCOPE)

    if scope.indicator_type not in {"domain", "username", "email", "ip", "url", "unknown"}:
        errors.append("scope.indicator_type is invalid.")
        codes.append(IntentErrorCode.INVALID_SCOPE)

    if not scope.allowed_operations:
        errors.append("scope.allowed_operations must not be empty.")
        codes.append(IntentErrorCode.MISSING_FIELD)

    if scope.time_horizon_seconds <= 0 or scope.time_horizon_seconds > 86_400:
        errors.append("scope.time_horizon_seconds must be between 1 and 86400.")
        codes.append(IntentErrorCode.INVALID_SCOPE)

    overlap = set(scope.allowed_operations).intersection(scope.forbidden_operations)
    if overlap:
        errors.append(f"Allowed operations include forbidden operation(s): {sorted(overlap)}")
        codes.append(IntentErrorCode.FORBIDDEN_OPERATION_REQUESTED)

    return IntentValidationResult(ok=not errors, errors=tuple(errors), error_codes=tuple(codes))


def validate_scope_or_raise(scope: IntentScope) -> None:
    result = validate_scope(scope)
    if not result.ok:
        raise IntentValidationError(result.errors[0], result.error_codes[0])


def validate_intent(packet: IntentPacket) -> IntentValidationResult:
    errors: list[str] = []
    codes: list[IntentErrorCode] = []

    if packet.action not in VALID_ACTIONS:
        errors.append(f"Invalid action: {packet.action}")
        codes.append(IntentErrorCode.INVALID_ACTION)

    if not packet.purpose:
        errors.append("purpose is required.")
        codes.append(IntentErrorCode.MISSING_FIELD)

    if packet.risk_label not in VALID_RISKS:
        errors.append(f"Invalid risk label: {packet.risk_label}")
        codes.append(IntentErrorCode.INVALID_RISK)

    if packet.rollback_strategy not in VALID_ROLLBACK_STRATEGIES:
        errors.append(f"Invalid rollback strategy: {packet.rollback_strategy}")
        codes.append(IntentErrorCode.INVALID_ROLLBACK)

    if not packet.manifest_hash or not HASH_RE.fullmatch(packet.manifest_hash):
        errors.append("manifest_hash must look like a cryptographic hash.")
        codes.append(IntentErrorCode.MISSING_FIELD)

    scope_result = validate_scope(packet.scope)
    errors.extend(scope_result.errors)
    codes.extend(scope_result.error_codes)

    raw_leak_paths = find_raw_indicator_fields(packet.to_dict())
    if raw_leak_paths:
        errors.append(f"Raw indicator-like field(s) are not allowed in intent packet: {raw_leak_paths}")
        codes.append(IntentErrorCode.RAW_INDICATOR_LEAK)

    return IntentValidationResult(ok=not errors, errors=tuple(errors), error_codes=tuple(codes))


def validate_intent_or_raise(packet: IntentPacket) -> None:
    result = validate_intent(packet)
    if not result.ok:
        raise IntentValidationError(result.errors[0], result.error_codes[0])


def find_raw_indicator_fields(value: Any, path: str = "") -> list[str]:
    findings: list[str] = []

    if isinstance(value, Mapping):
        for key, child in value.items():
            key_str = str(key)
            child_path = f"{path}.{key_str}" if path else key_str
            if key_str.lower() in RAW_FIELD_NAMES:
                findings.append(child_path)
            findings.extend(find_raw_indicator_fields(child, child_path))

    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            findings.extend(find_raw_indicator_fields(child, f"{path}[{index}]"))

    return findings


def intent_fingerprint(packet: IntentPacket) -> str:
    return hashlib.sha256(packet.to_json(include_signature=True).encode("utf-8")).hexdigest()


def unsigned_intent_fingerprint(packet: IntentPacket) -> str:
    return hashlib.sha256(packet.to_json(include_signature=False).encode("utf-8")).hexdigest()


def risk_score(risk_label: RiskLabel) -> float:
    return {
        "low": 0.25,
        "medium": 0.5,
        "high": 0.75,
        "critical": 1.0,
    }[risk_label]


def default_rollback_for_risk(risk_label: RiskLabel) -> RollbackStrategy:
    if risk_label == "low":
        return "observe_only"
    if risk_label == "medium":
        return "disable_module"
    if risk_label == "high":
        return "sandbox"
    return "revert"


def derive_risk_label(
    *,
    requested_modules: Iterable[str],
    authorized_target: bool,
    contains_conditional_operation: bool = False,
) -> RiskLabel:
    modules = {str(module).strip().lower().replace(" ", "_") for module in requested_modules}

    forbidden = {
        "port_scan",
        "nmap",
        "masscan",
        "brute_force",
        "credential_testing",
        "exploitation",
    }
    conditional = {
        "http_headers",
        "robots_txt",
        "screenshot",
        "ssl_labs_ssl_test",
    }

    if modules.intersection(forbidden):
        return "critical"

    if contains_conditional_operation or modules.intersection(conditional):
        return "medium" if authorized_target else "high"

    return "low"


def dedupe_preserve_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        normalized = str(value).strip()
        if not normalized:
            continue
        if normalized not in seen:
            output.append(normalized)
            seen.add(normalized)
    return output
