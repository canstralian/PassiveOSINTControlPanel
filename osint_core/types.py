"""
osint_core.types
================

Shared value objects for the Passive OSINT Control Panel.

This module keeps the constraint-aware invention engine's vocabulary explicit
and closed. It does not execute modules, mutate policy, or persist telemetry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


CorrectionVerb = Literal["ADAPT", "CONSTRAIN", "REVERT", "OBSERVE"]
RiskTier = Literal["T1", "T2", "T3", "T4"]
IndicatorType = Literal["domain", "username", "email", "ip", "url", "unknown"]
AuthorityMode = Literal[
    "observation",
    "correlation",
    "analysis",
    "proposal",
    "operator_authorized",
]
ConstraintClass = Literal["hard", "elastic", "informative", "adversarial"]
ConstraintDecision = Literal["allow", "modify", "require_approval", "block"]
ConstraintDisposition = Literal[
    "preserve",
    "refine",
    "simulate",
    "relax_candidate",
    "observe",
]


def clamp_score(value: float) -> float:
    """Clamp a score dimension to the closed interval [0.0, 1.0]."""
    return max(0.0, min(1.0, float(value)))


@dataclass(frozen=True)
class InventionRequest:
    """Request envelope for the constraint-aware invention loop."""

    objective: str
    requested_modules: list[str]
    authority_mode: AuthorityMode = "observation"
    authorized_target: bool = False
    passive_only: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProposedAction:
    """A candidate action before constraint evaluation."""

    action_id: str
    module: str
    touches_target: bool
    requires_authorization: bool
    expected_signal: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ConstraintEvent:
    """A structured record of an action meeting a constraint."""

    run_id: str
    action_id: str
    constraint_id: str
    constraint_class: ConstraintClass
    decision: ConstraintDecision
    original_action: str
    replacement_action: str | None
    rationale: str
    risk_reduction: float
    generative_yield: float
    friction_cost: float
    learning_value: float


@dataclass(frozen=True)
class ConstraintScore:
    """Numerical assessment of a constraint's design effect."""

    constraint_id: str
    risk_reduction: float
    generative_yield: float
    friction_cost: float
    learning_value: float
    disposition: ConstraintDisposition = "observe"

    def normalized(self) -> "ConstraintScore":
        """Return a copy with all score dimensions clamped to [0.0, 1.0]."""
        return ConstraintScore(
            constraint_id=self.constraint_id,
            risk_reduction=clamp_score(self.risk_reduction),
            generative_yield=clamp_score(self.generative_yield),
            friction_cost=clamp_score(self.friction_cost),
            learning_value=clamp_score(self.learning_value),
            disposition=self.disposition,
        )


@dataclass(frozen=True)
class ConstraintEvaluation:
    """Complete constraint-loop output for a proposed workflow."""

    run_id: str
    proposed_actions: list[ProposedAction]
    allowed_actions: list[ProposedAction]
    blocked_actions: list[ProposedAction]
    events: list[ConstraintEvent]
    requires_approval_actions: list[ProposedAction] = field(default_factory=list)


@dataclass(frozen=True)
class ReflectionFinding:
    """Operator-readable analysis of a constraint event."""

    action_id: str
    constraint_id: str
    decision: ConstraintDecision
    lesson: str
    reusable_pattern: str | None = None


@dataclass(frozen=True)
class AdaptationRecommendation:
    """A bounded future adjustment suggested by repeated constraint pressure."""

    recommendation_id: str
    constraint_id: str
    action: ConstraintDisposition
    rationale: str


@dataclass(frozen=True)
class InventionResponse:
    """Full output from the four-loop invention engine."""

    run_id: str
    request: InventionRequest
    evaluation: ConstraintEvaluation
    reflections: list[ReflectionFinding]
    recommendations: list[AdaptationRecommendation]
