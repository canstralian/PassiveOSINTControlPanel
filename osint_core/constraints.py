"""
osint_core.constraints
======================

Constraint evaluation for the Passive OSINT Control Panel.

This layer translates policy pressure into structured constraint events. It is
side-effect free: it does not execute modules, mutate policy, or expand scope.
"""

from __future__ import annotations

from .policy import (
    MODULE_POLICIES,
    PolicyErrorCode,
    PolicyViolation,
    canonicalize_module_name,
    evaluate_modules,
    get_module_policy,
    module_touches_target,
)
from .types import ConstraintEvaluation, ConstraintEvent, ProposedAction


def propose_actions(requested_modules: list[str]) -> list[ProposedAction]:
    """Convert requested module labels into proposed actions."""
    actions: list[ProposedAction] = []

    for raw_name in requested_modules:
        canonical = canonicalize_module_name(raw_name)
        policy = get_module_policy(canonical)
        module_label = policy.name if policy else str(raw_name)
        requires_authorization = bool(policy.requires_authorization) if policy else False
        touches_target = module_touches_target(canonical)
        expected_signal = policy.description if policy else "Unknown or unregistered module."

        actions.append(
            ProposedAction(
                action_id=canonical,
                module=module_label,
                touches_target=touches_target,
                requires_authorization=requires_authorization,
                expected_signal=expected_signal,
                metadata={"canonical_name": canonical},
            )
        )

    return actions


def evaluate_constraints(
    *,
    run_id: str,
    requested_modules: list[str],
    authorized_target: bool,
    passive_only: bool = True,
) -> ConstraintEvaluation:
    """
    Evaluate proposed module actions against the current policy boundary.

    This function wraps `policy.evaluate_modules` and enriches the result with
    constraint events suitable for UI display, reporting, and ledger writes.
    """
    proposed = propose_actions(requested_modules)
    proposal_by_id = {action.action_id: action for action in proposed}

    policy_eval = evaluate_modules(
        requested_modules,
        authorized_target=authorized_target,
        passive_only=passive_only,
        allow_unknown_modules=False,
    )

    events: list[ConstraintEvent] = []

    for action in proposed:
        if action.action_id in policy_eval.allowed_modules:
            events.append(
                ConstraintEvent(
                    run_id=run_id,
                    action_id=action.action_id,
                    constraint_id="module_allowed",
                    constraint_class="informative",
                    decision="allow",
                    original_action=action.module,
                    replacement_action=None,
                    rationale=f"{action.module} is allowed under the current passive OSINT policy.",
                    risk_reduction=0.2,
                    generative_yield=0.7,
                    friction_cost=0.0,
                    learning_value=0.3,
                )
            )

    for violation in policy_eval.violations:
        if not violation.module:
            continue
        action = proposal_by_id.get(violation.module)
        if action is None:
            action = ProposedAction(
                action_id=violation.module,
                module=violation.module,
                touches_target=module_touches_target(violation.module),
                requires_authorization=False,
                expected_signal="Unregistered module blocked by policy.",
            )
        events.append(_event_from_violation(run_id, action, violation))

    allowed_modules = set(policy_eval.allowed_modules)
    blocked_modules = set(policy_eval.blocked_modules)
    approval_modules = {
        event.action_id
        for event in events
        if event.constraint_id == "authorized_target_required"
    }

    allowed_actions = [
        action for action in proposed if action.action_id in allowed_modules
    ]
    blocked_actions = [
        action for action in proposed if action.action_id in blocked_modules
    ]
    requires_approval_actions = [
        action for action in proposed if action.action_id in approval_modules
    ]

    return ConstraintEvaluation(
        run_id=run_id,
        proposed_actions=proposed,
        allowed_actions=allowed_actions,
        blocked_actions=blocked_actions,
        events=events,
        requires_approval_actions=requires_approval_actions,
    )


def _event_from_violation(
    run_id: str,
    action: ProposedAction,
    violation: PolicyViolation,
) -> ConstraintEvent:
    if violation.code == PolicyErrorCode.FORBIDDEN_MODULE:
        return ConstraintEvent(
            run_id=run_id,
            action_id=action.action_id,
            constraint_id="forbidden_capability",
            constraint_class="hard",
            decision="block",
            original_action=action.module,
            replacement_action="Resource Links",
            rationale=violation.message,
            risk_reduction=1.0,
            generative_yield=0.6,
            friction_cost=0.5,
            learning_value=0.8,
        )

    if violation.code == PolicyErrorCode.AUTHORIZATION_REQUIRED:
        return ConstraintEvent(
            run_id=run_id,
            action_id=action.action_id,
            constraint_id="authorized_target_required",
            constraint_class="hard",
            decision="block",
            original_action=action.module,
            replacement_action="Resource Links",
            rationale=f"{violation.message} Action remains blocked until the required approval and execution mode are present.",
            risk_reduction=0.9,
            generative_yield=0.5,
            friction_cost=0.4,
            learning_value=0.7,
        )

    if violation.code == PolicyErrorCode.UNKNOWN_MODULE:
        return ConstraintEvent(
            run_id=run_id,
            action_id=action.action_id,
            constraint_id="unknown_module",
            constraint_class="hard",
            decision="block",
            original_action=action.module,
            replacement_action=None,
            rationale=violation.message,
            risk_reduction=0.8,
            generative_yield=0.2,
            friction_cost=0.6,
            learning_value=0.6,
        )

    return ConstraintEvent(
        run_id=run_id,
        action_id=action.action_id,
        constraint_id="policy_violation",
        constraint_class="hard",
        decision="block",
        original_action=action.module,
        replacement_action=None,
        rationale=violation.message,
        risk_reduction=0.8,
        generative_yield=0.2,
        friction_cost=0.6,
        learning_value=0.5,
    )


def passive_module_actions() -> list[ProposedAction]:
    """Return registered module actions that are allowed in passive-only mode."""
    return propose_actions([
        policy.name
        for policy in MODULE_POLICIES.values()
        if policy.risk != "forbidden"
        and not policy.requires_authorization
        and not policy.touches_target
    ])
