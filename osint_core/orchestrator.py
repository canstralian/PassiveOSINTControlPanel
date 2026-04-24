"""
osint_core.orchestrator
=======================

Orchestrator agent for coordinating passive OSINT enrichment workflows.

Design principles:
- Coordinates validation → policy → enrichment → drift → audit pipeline
- Manages skills (capabilities) and tools (external actions)
- Maintains execution context and telemetry
- Enforces security boundaries at each stage
- Pure orchestration — does not implement enrichment logic directly

The orchestrator pattern:
1. Accept user request (indicator + modules + authorization)
2. Validate input (osint_core.validators)
3. Evaluate policy (osint_core.policy)
4. Execute allowed modules via skills
5. Detect drift (osint_core.drift when implemented)
6. Choose correction verb
7. Generate audit trail
8. Return structured result
"""

from __future__ import annotations

import subprocess
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Literal

from .policy import (
    PolicyEvaluation,
    evaluate_modules,
    enforce_correction_verb,
)
from .validators import (
    IndicatorType,
    ValidationResult,
    validate_indicator,
)


# =============================================================================
# Agent data structures
# =============================================================================

AgentRole = Literal["orchestrator", "validator", "enricher", "analyst"]
SkillCategory = Literal["validation", "passive_lookup", "conditional_fetch", "analysis"]
ToolType = Literal["subprocess", "network", "file", "computation"]


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class Tool:
    """
    A tool is an atomic capability that performs external actions.

    Examples: DNS query, whois lookup, HTTP request, file parsing
    """
    name: str
    tool_type: ToolType
    description: str
    requires_authorization: bool = False
    timeout_seconds: float = 5.0


@dataclass(frozen=True)
class Skill:
    """
    A skill is a higher-level capability composed of tools.

    Examples: "Resolve DNS", "Fetch WHOIS", "Parse URL"
    """
    name: str
    category: SkillCategory
    description: str
    canonical_name: str
    required_indicator_types: list[IndicatorType]
    tools: list[Tool]
    requires_authorization: bool = False


@dataclass
class ExecutionContext:
    """
    Execution context tracks the state of an enrichment workflow.
    """
    run_id: str
    started_at: str
    indicator_type: IndicatorType
    normalized_indicator: str
    indicator_hash: str
    requested_modules: list[str]
    authorized_target: bool
    passive_only: bool
    policy_evaluation: PolicyEvaluation | None = None
    telemetry: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


@dataclass
class SkillResult:
    """
    Result from executing a skill.
    """
    skill_name: str
    status: ExecutionStatus
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_ms: int = 0


@dataclass
class EnrichmentWorkflow:
    """
    Complete enrichment workflow result.
    """
    context: ExecutionContext
    validation_result: ValidationResult
    policy_evaluation: PolicyEvaluation
    skill_results: list[SkillResult]
    drift_vector: dict[str, float]
    correction_verb: str
    duration_ms: int


# =============================================================================
# Tool implementations
# =============================================================================

# DNS resolution tool
DNS_QUERY_TOOL = Tool(
    name="dns_query",
    tool_type="network",
    description="Query DNS records using system resolver",
    requires_authorization=False,
    timeout_seconds=4.0,
)

# WHOIS lookup tool
WHOIS_TOOL = Tool(
    name="whois",
    tool_type="subprocess",
    description="Perform WHOIS lookup via system command",
    requires_authorization=False,
    timeout_seconds=5.0,
)

# URL parser tool (local, no network)
URL_PARSE_TOOL = Tool(
    name="url_parse",
    tool_type="computation",
    description="Parse URL components locally",
    requires_authorization=False,
    timeout_seconds=1.0,
)

# HTTP header fetcher (conditional, requires auth)
HTTP_HEADERS_TOOL = Tool(
    name="http_headers",
    tool_type="network",
    description="Fetch HTTP headers from target",
    requires_authorization=True,
    timeout_seconds=5.0,
)

# Robots.txt fetcher (conditional, requires auth)
ROBOTS_TXT_TOOL = Tool(
    name="robots_txt",
    tool_type="network",
    description="Fetch robots.txt from target",
    requires_authorization=True,
    timeout_seconds=5.0,
)


# =============================================================================
# Skill definitions
# =============================================================================

SKILLS_REGISTRY: dict[str, Skill] = {
    "resource_links": Skill(
        name="Resource Links",
        canonical_name="resource_links",
        category="passive_lookup",
        description="Generate links to external OSINT resources",
        required_indicator_types=["domain", "username", "email", "ip", "url"],
        tools=[],  # No external tools needed
        requires_authorization=False,
    ),
    "dns_records": Skill(
        name="DNS Records",
        canonical_name="dns_records",
        category="passive_lookup",
        description="Resolve DNS A, AAAA, MX, NS records",
        required_indicator_types=["domain"],
        tools=[DNS_QUERY_TOOL],
        requires_authorization=False,
    ),
    "local_url_parse": Skill(
        name="Local URL Parse",
        canonical_name="local_url_parse",
        category="analysis",
        description="Parse URL components without contacting target",
        required_indicator_types=["url"],
        tools=[URL_PARSE_TOOL],
        requires_authorization=False,
    ),
    "http_headers": Skill(
        name="HTTP Headers",
        canonical_name="http_headers",
        category="conditional_fetch",
        description="Fetch HTTP headers from authorized target",
        required_indicator_types=["url", "domain"],
        tools=[HTTP_HEADERS_TOOL],
        requires_authorization=True,
    ),
    "robots_txt": Skill(
        name="Robots.txt",
        canonical_name="robots_txt",
        category="conditional_fetch",
        description="Fetch robots.txt from authorized target",
        required_indicator_types=["url", "domain"],
        tools=[ROBOTS_TXT_TOOL],
        requires_authorization=True,
    ),
}


# =============================================================================
# Orchestrator agent
# =============================================================================

class OrchestratorAgent:
    """
    Orchestrator agent coordinates the full enrichment workflow.

    Responsibilities:
    - Create execution context
    - Route requests through validation → policy → enrichment
    - Execute skills based on policy decisions
    - Aggregate results
    - Generate telemetry
    """

    def __init__(self, role: AgentRole = "orchestrator"):
        self.role = role
        self.skills = SKILLS_REGISTRY

    def create_context(
        self,
        raw_indicator: str,
        indicator_type_hint: str,
        requested_modules: list[str],
        authorized_target: bool,
        passive_only: bool = True,
    ) -> ExecutionContext:
        """
        Create execution context for a new enrichment request.
        """
        run_id = f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        started_at = datetime.now(timezone.utc).isoformat()

        # Validate indicator first
        validation_result = validate_indicator(
            raw_indicator,
            forced_type=indicator_type_hint,
        )

        if not validation_result.ok:
            # Create a minimal context for failed validation
            return ExecutionContext(
                run_id=run_id,
                started_at=started_at,
                indicator_type="unknown",
                normalized_indicator="",
                indicator_hash="",
                requested_modules=requested_modules,
                authorized_target=authorized_target,
                passive_only=passive_only,
                errors=[validation_result.error or "Validation failed"],
            )

        # For successful validation, hash the indicator
        import hashlib
        import hmac
        import os

        salt = os.getenv("OSINT_HASH_SALT", "dev-only-change-me")
        indicator_hash = hmac.new(
            salt.encode("utf-8"),
            validation_result.normalized.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return ExecutionContext(
            run_id=run_id,
            started_at=started_at,
            indicator_type=validation_result.indicator_type,
            normalized_indicator=validation_result.normalized,
            indicator_hash=indicator_hash,
            requested_modules=requested_modules,
            authorized_target=authorized_target,
            passive_only=passive_only,
        )

    def execute_workflow(
        self,
        raw_indicator: str,
        indicator_type_hint: str = "Auto",
        requested_modules: list[str] | None = None,
        authorized_target: bool = False,
        passive_only: bool = True,
    ) -> EnrichmentWorkflow:
        """
        Execute complete enrichment workflow.

        Returns a structured workflow result containing:
        - Execution context
        - Validation result
        - Policy evaluation
        - Skill results
        - Drift assessment
        - Correction decision
        """
        started = time.perf_counter()

        requested_modules = requested_modules or ["resource_links"]

        # Step 1: Validate input
        validation_result = validate_indicator(
            raw_indicator,
            forced_type=indicator_type_hint,
        )

        if not validation_result.ok:
            # Early exit for validation failure
            context = self.create_context(
                raw_indicator,
                indicator_type_hint,
                requested_modules,
                authorized_target,
                passive_only,
            )
            return EnrichmentWorkflow(
                context=context,
                validation_result=validation_result,
                policy_evaluation=PolicyEvaluation(
                    decision="BLOCK",  # type: ignore
                    blocked_modules=requested_modules,
                    violations=[],
                ),
                skill_results=[],
                drift_vector={},
                correction_verb="REVERT",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        # Step 2: Create execution context
        context = self.create_context(
            raw_indicator,
            indicator_type_hint,
            requested_modules,
            authorized_target,
            passive_only,
        )

        # Step 3: Evaluate policy
        policy_eval = evaluate_modules(
            requested_modules,
            authorized_target=authorized_target,
            passive_only=passive_only,
            allow_unknown_modules=False,
        )
        context.policy_evaluation = policy_eval

        # Step 4: Execute allowed skills
        skill_results = self._execute_skills(
            context,
            policy_eval.allowed_modules,
        )

        # Step 5: Detect drift
        drift_vector = self._detect_drift(
            context,
            skill_results,
            policy_eval,
        )

        # Step 6: Choose correction verb
        correction_verb = self._choose_correction(drift_vector, policy_eval)

        duration_ms = int((time.perf_counter() - started) * 1000)
        # Ensure we always return at least 1ms to indicate actual work was done
        if duration_ms == 0:
            duration_ms = 1

        return EnrichmentWorkflow(
            context=context,
            validation_result=validation_result,
            policy_evaluation=policy_eval,
            skill_results=skill_results,
            drift_vector=drift_vector,
            correction_verb=correction_verb,
            duration_ms=duration_ms,
        )

    def _execute_skills(
        self,
        context: ExecutionContext,
        allowed_modules: list[str],
    ) -> list[SkillResult]:
        """
        Execute allowed skills based on policy evaluation.
        """
        results: list[SkillResult] = []

        for module_name in allowed_modules:
            skill = self.skills.get(module_name)
            if not skill:
                results.append(SkillResult(
                    skill_name=module_name,
                    status=ExecutionStatus.FAILED,
                    error=f"Skill not found: {module_name}",
                ))
                continue

            # Check if indicator type is supported by this skill
            if skill.required_indicator_types and context.indicator_type not in skill.required_indicator_types:
                results.append(SkillResult(
                    skill_name=skill.name,
                    status=ExecutionStatus.BLOCKED,
                    error=f"Skill {skill.name} requires indicator type in {skill.required_indicator_types}, got {context.indicator_type}",
                ))
                continue

            # Execute skill
            result = self._execute_skill(skill, context)
            results.append(result)

        return results

    def _execute_skill(
        self,
        skill: Skill,
        context: ExecutionContext,
    ) -> SkillResult:
        """
        Execute a single skill.

        For now, this is a stub that returns placeholder data.
        In production, this would invoke the skill's tools.
        """
        started = time.perf_counter()

        try:
            # Placeholder: skill execution logic would go here
            # Each skill would use its tools to perform enrichment

            if skill.canonical_name == "resource_links":
                data = {"type": "links", "generated": True}
            elif skill.canonical_name == "dns_records":
                data = {"A": [], "AAAA": [], "MX": [], "NS": []}
            elif skill.canonical_name == "local_url_parse":
                data = {"scheme": "", "hostname": "", "path": ""}
            else:
                data = {"status": "not_implemented"}

            duration_ms = int((time.perf_counter() - started) * 1000)

            return SkillResult(
                skill_name=skill.name,
                status=ExecutionStatus.COMPLETED,
                data=data,
                duration_ms=duration_ms,
            )

        except Exception as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            return SkillResult(
                skill_name=skill.name,
                status=ExecutionStatus.FAILED,
                error=str(exc),
                duration_ms=duration_ms,
            )

    def _detect_drift(
        self,
        context: ExecutionContext,
        skill_results: list[SkillResult],
        policy_eval: PolicyEvaluation,
    ) -> dict[str, float]:
        """
        Detect drift from execution telemetry.

        This is a simplified version. Full drift detection
        would use osint_core.drift when implemented.
        """
        drift = {
            "statistical": 0.0,
            "behavioral": 0.0,
            "structural": 0.0,
            "adversarial": 0.0,
            "operational": 0.0,
            "policy": 0.0,
        }

        # Policy drift: blocked modules indicate policy boundary hit
        if policy_eval.blocked_modules:
            drift["policy"] = 0.4

        # Operational drift: failed skills
        failed_count = sum(1 for r in skill_results if r.status == ExecutionStatus.FAILED)
        if failed_count > 0:
            drift["operational"] = min(0.2 * failed_count, 1.0)

        # Adversarial drift: check for suspicious patterns (stub)
        # Full implementation would analyze normalized_indicator

        return drift

    def _choose_correction(
        self,
        drift_vector: dict[str, float],
        policy_eval: PolicyEvaluation,
    ) -> str:
        """
        Choose correction verb based on drift vector.

        Priority: policy > structural > behavioral > adversarial > operational > statistical
        """
        if drift_vector.get("policy", 0.0) >= 0.4:
            return "CONSTRAIN"

        if drift_vector.get("structural", 0.0) >= 0.5:
            return "REVERT"

        if drift_vector.get("behavioral", 0.0) >= 0.5:
            return "REVERT"

        if drift_vector.get("adversarial", 0.0) >= 0.3:
            return "CONSTRAIN"

        if drift_vector.get("operational", 0.0) >= 0.4:
            return "CONSTRAIN"

        if drift_vector.get("statistical", 0.0) >= 0.5 and drift_vector.get("adversarial", 0.0) == 0:
            return "ADAPT"

        return "OBSERVE"


# =============================================================================
# Public API
# =============================================================================

def create_orchestrator() -> OrchestratorAgent:
    """
    Factory function to create an orchestrator agent.
    """
    return OrchestratorAgent(role="orchestrator")


def list_skills() -> dict[str, Skill]:
    """
    Return the skills registry.
    """
    return SKILLS_REGISTRY.copy()


def get_skill(skill_name: str) -> Skill | None:
    """
    Get a skill by canonical name.
    """
    return SKILLS_REGISTRY.get(skill_name)
