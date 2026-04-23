"""
osint_core.policy
=================

Policy enforcement for the Passive OSINT Control Panel.

This module is the authorization boundary between validated input and execution.

Design constraints:
- Passive by default.
- No module execution decision should be made outside this layer.
- Authorized-only modules must be blocked unless explicit authorization is present.
- Forbidden capabilities are always denied.
- Correction verbs are closed over a fixed allowlist.
- Policy evaluation is side-effect free: it returns a decision, it does not execute.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Literal


CorrectionVerb = Literal["ADAPT", "CONSTRAIN", "REVERT", "OBSERVE"]
RiskLevel = Literal["low", "conditional", "forbidden"]
PolicyTier = Literal["T1", "T2", "T3", "T4"]


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    CONSTRAIN = "constrain"


class PolicyErrorCode(str, Enum):
    UNKNOWN_MODULE = "unknown_module"
    AUTHORIZATION_REQUIRED = "authorization_required"
    FORBIDDEN_MODULE = "forbidden_module"
    INVALID_CORRECTION_VERB = "invalid_correction_verb"
    POLICY_MUTATION_BLOCKED = "policy_mutation_blocked"
    RAW_LOGGING_BLOCKED = "raw_logging_blocked"


@dataclass(frozen=True)
class ModulePolicy:
    name: str
    canonical_name: str
    risk: RiskLevel
    tier: PolicyTier
    description: str
    requires_authorization: bool = False


@dataclass(frozen=True)
class PolicyViolation:
    code: PolicyErrorCode
    message: str
    module: str | None = None


@dataclass(frozen=True)
class PolicyEvaluation:
    decision: PolicyDecision
    allowed_modules: list[str] = field(default_factory=list)
    blocked_modules: list[str] = field(default_factory=list)
    violations: list[PolicyViolation] = field(default_factory=list)
    correction_verbs_allowed: list[CorrectionVerb] = field(default_factory=list)


ALLOWED_CORRECTION_VERBS: tuple[CorrectionVerb, ...] = (
    "ADAPT",
    "CONSTRAIN",
    "REVERT",
    "OBSERVE",
)

# Canonical module registry.
# Keep this small and explicit. New capabilities should be added deliberately.
MODULE_POLICIES: dict[str, ModulePolicy] = {
    "resource_links": ModulePolicy(
        name="Resource Links",
        canonical_name="resource_links",
        risk="low",
        tier="T4",
        description="Generate links to external OSINT resources without contacting the target.",
    ),
    "dns_records": ModulePolicy(
        name="DNS Records",
        canonical_name="dns_records",
        risk="low",
        tier="T3",
        description="Resolve DNS records using a resolver. Low-impact, but still a network lookup.",
    ),
    "local_url_parse": ModulePolicy(
        name="Local URL Parse",
        canonical_name="local_url_parse",
        risk="low",
        tier="T4",
        description="Parse a URL locally without contacting the target.",
    ),
    "http_headers": ModulePolicy(
        name="HTTP Headers",
        canonical_name="http_headers",
        risk="conditional",
        tier="T2",
        description="Fetch HTTP headers from an explicitly authorized target.",
        requires_authorization=True,
    ),
    "robots_txt": ModulePolicy(
        name="Robots.txt",
        canonical_name="robots_txt",
        risk="conditional",
        tier="T2",
        description="Fetch robots.txt from an explicitly authorized target.",
        requires_authorization=True,
    ),
    "screenshot": ModulePolicy(
        name="Screenshot",
        canonical_name="screenshot",
        risk="conditional",
        tier="T2",
        description="Render a screenshot of an explicitly authorized URL.",
        requires_authorization=True,
    ),
    "port_scan": ModulePolicy(
        name="Port Scan",
        canonical_name="port_scan",
        risk="forbidden",
        tier="T1",
        description="Port scanning is outside the passive OSINT boundary.",
    ),
    "brute_force": ModulePolicy(
        name="Brute Force",
        canonical_name="brute_force",
        risk="forbidden",
        tier="T1",
        description="Credential or username brute forcing is forbidden.",
    ),
    "credential_testing": ModulePolicy(
        name="Credential Testing",
        canonical_name="credential_testing",
        risk="forbidden",
        tier="T1",
        description="Credential testing is forbidden.",
    ),
    "exploitation": ModulePolicy(
        name="Exploitation",
        canonical_name="exploitation",
        risk="forbidden",
        tier="T1",
        description="Exploit execution is forbidden.",
    ),
}


ALIASES: dict[str, str] = {
    "resource links": "resource_links",
    "links": "resource_links",
    "source links": "resource_links",
    "dns": "dns_records",
    "dns records": "dns_records",
    "local url parse": "local_url_parse",
    "url parse": "local_url_parse",
    "http headers": "http_headers",
    "headers": "http_headers",
    "robots.txt": "robots_txt",
    "robots": "robots_txt",
    "screenshot": "screenshot",
    "port scan": "port_scan",
    "nmap": "port_scan",
    "masscan": "port_scan",
    "brute force": "brute_force",
    "bruteforce": "brute_force",
    "credential testing": "credential_testing",
    "creds": "credential_testing",
    "exploitation": "exploitation",
    "exploit": "exploitation",
}


def canonicalize_module_name(module_name: str) -> str:
    """
    Convert a UI label or alias to canonical module name.
    """
    key = str(module_name or "").strip().lower().replace("-", " ").replace("_", " ")
    return ALIASES.get(key, key.replace(" ", "_"))


def get_module_policy(module_name: str) -> ModulePolicy | None:
    return MODULE_POLICIES.get(canonicalize_module_name(module_name))


def evaluate_modules(
    requested_modules: Iterable[str],
    *,
    authorized_target: bool = False,
    passive_only: bool = True,
    allow_unknown_modules: bool = False,
) -> PolicyEvaluation:
    """
    Evaluate requested modules against the policy.

    Parameters
    ----------
    requested_modules:
        Module names from UI/API.
    authorized_target:
        Explicit confirmation that the target is authorized for conditional interaction.
    passive_only:
        When True, conditional modules are blocked even if authorization is present.
        Use False only for an authorized execution mode.
    allow_unknown_modules:
        Should remain False in production.

    Returns
    -------
    PolicyEvaluation
        Side-effect-free decision describing what may execute.
    """
    allowed: list[str] = []
    blocked: list[str] = []
    violations: list[PolicyViolation] = []

    for raw_name in requested_modules:
        canonical = canonicalize_module_name(raw_name)
        policy = MODULE_POLICIES.get(canonical)

        if policy is None:
            if allow_unknown_modules:
                allowed.append(canonical)
            else:
                blocked.append(canonical)
                violations.append(
                    PolicyViolation(
                        code=PolicyErrorCode.UNKNOWN_MODULE,
                        message=f"Unknown module blocked: {raw_name}",
                        module=canonical,
                    )
                )
            continue

        if policy.risk == "forbidden":
            blocked.append(policy.canonical_name)
            violations.append(
                PolicyViolation(
                    code=PolicyErrorCode.FORBIDDEN_MODULE,
                    message=f"Forbidden module blocked: {policy.name}",
                    module=policy.canonical_name,
                )
            )
            continue

        if policy.requires_authorization:
            if passive_only:
                blocked.append(policy.canonical_name)
                violations.append(
                    PolicyViolation(
                        code=PolicyErrorCode.AUTHORIZATION_REQUIRED,
                        message=f"Conditional module blocked in passive-only mode: {policy.name}",
                        module=policy.canonical_name,
                    )
                )
                continue

            if not authorized_target:
                blocked.append(policy.canonical_name)
                violations.append(
                    PolicyViolation(
                        code=PolicyErrorCode.AUTHORIZATION_REQUIRED,
                        message=f"Authorization required for module: {policy.name}",
                        module=policy.canonical_name,
                    )
                )
                continue

        allowed.append(policy.canonical_name)

    if violations:
        # Any T1 forbidden issue or policy/auth issue should constrain execution.
        decision = PolicyDecision.CONSTRAIN
    else:
        decision = PolicyDecision.ALLOW

    return PolicyEvaluation(
        decision=decision,
        allowed_modules=dedupe_preserve_order(allowed),
        blocked_modules=dedupe_preserve_order(blocked),
        violations=violations,
        correction_verbs_allowed=list(ALLOWED_CORRECTION_VERBS),
    )


def enforce_correction_verb(verb: str) -> CorrectionVerb:
    """
    Validate that a correction verb is part of the closed mutation vocabulary.
    """
    normalized = str(verb or "").strip().upper()
    if normalized not in ALLOWED_CORRECTION_VERBS:
        raise PolicyViolationException(
            PolicyViolation(
                code=PolicyErrorCode.INVALID_CORRECTION_VERB,
                message=f"Invalid correction verb: {verb}",
            )
        )
    return normalized  # type: ignore[return-value]


def may_mutate_policy(*, out_of_band_approval: bool = False) -> bool:
    """
    Policy cannot rewrite itself. Mutation requires an out-of-band gate.
    """
    return bool(out_of_band_approval)


def enforce_policy_mutation_gate(*, out_of_band_approval: bool = False) -> None:
    if not may_mutate_policy(out_of_band_approval=out_of_band_approval):
        raise PolicyViolationException(
            PolicyViolation(
                code=PolicyErrorCode.POLICY_MUTATION_BLOCKED,
                message="Policy mutation requires out-of-band approval.",
            )
        )


def enforce_audit_payload(payload: dict) -> None:
    """
    Prevent raw sensitive indicators from appearing in audit payloads.

    This is a defensive check. The audit module should already avoid raw values.
    """
    forbidden_keys = {
        "raw_indicator",
        "raw_input",
        "indicator",
        "email",
        "domain",
        "username",
        "url",
        "ip",
    }

    present = forbidden_keys.intersection(payload.keys())
    if present:
        raise PolicyViolationException(
            PolicyViolation(
                code=PolicyErrorCode.RAW_LOGGING_BLOCKED,
                message=f"Audit payload contains forbidden raw field(s): {sorted(present)}",
            )
        )


def module_catalog() -> list[dict[str, str | bool]]:
    """
    Return a serializable catalog suitable for UI display.
    """
    return [
        {
            "name": policy.name,
            "canonical_name": policy.canonical_name,
            "risk": policy.risk,
            "tier": policy.tier,
            "requires_authorization": policy.requires_authorization,
            "description": policy.description,
        }
        for policy in MODULE_POLICIES.values()
    ]


def allowed_ui_modules(*, include_conditional: bool = True) -> list[str]:
    """
    Return user-facing modules, excluding forbidden capabilities.
    """
    names: list[str] = []
    for policy in MODULE_POLICIES.values():
        if policy.risk == "forbidden":
            continue
        if policy.risk == "conditional" and not include_conditional:
            continue
        names.append(policy.name)
    return names


def dedupe_preserve_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value not in seen:
            output.append(value)
            seen.add(value)
    return output


class PolicyViolationException(PermissionError):
    def __init__(self, violation: PolicyViolation):
        super().__init__(violation.message)
        self.violation = violation
