"""
osint_core.scheduler
====================

Latency-conscious decision scheduler for the Drift-Aware OSINT Control Fabric.

The scheduler sits between policy evaluation and execution. It does not validate
input, mutate policy, perform I/O, or write audit records. Its only job is to
allocate time, trust, and authority to a `DecisionPacket` produced upstream and
return a `ScheduleDecision` describing one of four routes:

    FAST          - low-risk, reversible, prevalidated action
    DELIBERATIVE  - high-impact or ambiguous action requiring stronger checks
    CONTAINMENT   - signals conflict, time is short, trust is degraded, or
                    shortcut debt is high
    FAIL_CLOSED   - no safe action can be verified, executed, and recovered
                    from inside the available window

Governing rule
--------------
Take the strongest action whose verification, execution, and rollback fit
inside the remaining useful window. If no strong action fits, choose reversible
containment. If no safe action fits, preserve evidence and fail closed.

Hard invariant
--------------
Deadline pressure may reduce adaptive checks. Deadline pressure may never
remove invariant checks. The mandatory invariants below are enforced regardless
of timing budget; failing any of them collapses the route to FAIL_CLOSED.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Iterable, Literal


RouteName = Literal["FAST", "DELIBERATIVE", "CONTAINMENT", "FAIL_CLOSED"]
TrustState = Literal["trusted", "degraded", "contested", "unsafe"]
RiskLabel = Literal["low", "medium", "high", "critical"]


class RouteMode(str, Enum):
    FAST = "FAST"
    DELIBERATIVE = "DELIBERATIVE"
    CONTAINMENT = "CONTAINMENT"
    FAIL_CLOSED = "FAIL_CLOSED"


class ScheduleReasonCode(str, Enum):
    INVARIANT_VIOLATION = "invariant_violation"
    FAIL_CLOSED_SIGNAL = "fail_closed_signal"
    SHORTCUT_DEBT_EXCEEDED = "shortcut_debt_exceeded"
    TRUST_STATE_DEGRADED = "trust_state_degraded"
    CONTAINMENT_SIGNAL = "containment_signal"
    LOW_RISK_FITS_WINDOW = "low_risk_fits_window"
    HIGH_RISK_FITS_WINDOW = "high_risk_fits_window"
    DEADLINE_TOO_TIGHT_REVERSIBLE = "deadline_too_tight_reversible"
    NO_SAFE_ACTION_FITS = "no_safe_action_fits"


# OSINT-specific action classification. These sets are informational and feed
# the `classify_action` helper. Routing inside `schedule_decision` is driven
# primarily by `risk_label` and the timing budget, per the governing rule.
FAST_ACTIONS: frozenset[str] = frozenset(
    {
        "source_link_generation",
        "local_url_parsing",
        "audit_export",
        "cached_passive_lookup",
    }
)

DELIBERATIVE_ACTIONS: frozenset[str] = frozenset(
    {
        "dependency_update",
        "source_registry_update",
        "conditional_http_header_fetch",
        "docker_module_activation",
    }
)

# Signals that, when present in `SystemState.failed_checks`, force a route.
# CONTAINMENT_SIGNALS reflect contested execution conditions; the system can
# still emit a reversible response. FAIL_CLOSED_SIGNALS reflect breaches of
# the control fabric's safety boundary; nothing further executes.
CONTAINMENT_SIGNALS: frozenset[str] = frozenset(
    {
        "suspicious_input_pattern",
        "policy_disagreement",
        "repeated_authorization_failure",
        "drift_vector_above_threshold",
    }
)

FAIL_CLOSED_SIGNALS: frozenset[str] = frozenset(
    {
        "missing_salt",
        "raw_indicator_leakage",
        "forbidden_module_requested",
        "manifest_signature_mismatch",
    }
)

# Mandatory invariants the scheduler refuses to bypass under any deadline.
# Each name must appear in `SystemState.passed_checks` for the packet to
# advance past invariant validation.
MANDATORY_INVARIANTS: tuple[str, ...] = (
    "osint_hash_salt_present",
    "intent_signature_verified",
    "scope_explicit",
    "policy_evaluation_completed",
    "forbidden_modules_blocked",
    "raw_indicators_excluded_from_audit",
    "conditional_modules_require_authorization",
    "rollback_or_containment_path_exists",
)

DEGRADED_TRUST_STATES: frozenset[str] = frozenset({"contested", "unsafe"})

DEFAULT_REVERSIBILITY_CONTAINMENT_THRESHOLD: float = 0.75
DEFAULT_SHORTCUT_DEBT_LIMIT: float = 1.0


@dataclass(frozen=True)
class DecisionPacket:
    """Immutable input to the scheduler.

    All time fields are in milliseconds. `deadline_ms` represents the remaining
    useful window for this decision (budget from now to the latest moment the
    action is still useful). `verification_cost_ms`, `execution_cost_ms`, and
    `rollback_cost_ms` are the conservative upper-bound costs the executor and
    observer have estimated for this packet.

    `reversibility` is a [0.0, 1.0] estimate: 0.0 means irreversible,
    1.0 means trivially reversible. `expected_utility_decay` is informational
    and may be used by future memory-tuned schedulers to prefer FAST routes
    when utility decays sharply.

    `required_checks` is the set of mandatory invariant names the scheduler
    must observe in `SystemState.passed_checks` before any route other than
    FAIL_CLOSED is permitted.
    """

    intent_id: str
    action: str
    risk_label: RiskLabel
    confidence: float
    reversibility: float
    deadline_ms: int
    verification_cost_ms: int
    execution_cost_ms: int
    rollback_cost_ms: int
    expected_utility_decay: float
    required_checks: tuple[str, ...]
    rollback_plan: str
    uncertainty_notes: tuple[str, ...] = ()

    @property
    def required_time_ms(self) -> int:
        return (
            self.verification_cost_ms
            + self.execution_cost_ms
            + self.rollback_cost_ms
        )

    @property
    def fits_window(self) -> bool:
        return self.required_time_ms <= self.deadline_ms


@dataclass(frozen=True)
class ShortcutDebt:
    """Accumulated cost of taking shortcuts during prior decisions.

    The score is a soft signal in [0.0, 1.0]. When it reaches the configured
    limit, the scheduler stops permitting fast paths and routes to CONTAINMENT
    until the debt is paid down upstream (e.g. by full re-verification).
    """

    reduced_checks: int = 0
    cached_policy_uses: int = 0
    skipped_deep_analysis: int = 0
    emergency_overrides: int = 0

    @property
    def score(self) -> float:
        return min(
            1.0,
            (self.reduced_checks * 0.1)
            + (self.cached_policy_uses * 0.05)
            + (self.skipped_deep_analysis * 0.15)
            + (self.emergency_overrides * 0.4),
        )


@dataclass(frozen=True)
class SystemState:
    """Operating-environment context the scheduler reads but never mutates.

    `passed_checks` and `failed_checks` carry named signals upstream layers
    (intent verification, policy evaluation, observer telemetry) have set on
    this run. The scheduler reads them and does not write them back.
    """

    trust_state: TrustState = "trusted"
    shortcut_debt: ShortcutDebt = field(default_factory=ShortcutDebt)
    shortcut_debt_limit: float = DEFAULT_SHORTCUT_DEBT_LIMIT
    passed_checks: tuple[str, ...] = ()
    failed_checks: tuple[str, ...] = ()
    reversibility_containment_threshold: float = (
        DEFAULT_REVERSIBILITY_CONTAINMENT_THRESHOLD
    )


@dataclass(frozen=True)
class ScheduleDecision:
    """Scheduler output. Pure description; no side effects performed."""

    route: RouteMode
    intent_id: str
    action: str
    reason: str
    reason_code: ScheduleReasonCode
    required_time_ms: int
    remaining_window_ms: int
    risk_label: RiskLabel
    invariant_violations: tuple[str, ...] = ()
    triggers: tuple[str, ...] = ()
    shortcut_debt_score: float = 0.0
    trust_state: TrustState = "trusted"


def classify_action(action: str) -> RouteMode | None:
    """Return the route preferred for this action by name, if known.

    Used to surface inconsistencies between an action's nominal category and
    its declared `risk_label`. The scheduler does not branch on this; the
    governing rule branches on risk and timing. Callers can use this to log
    or refuse mismatches upstream.
    """
    normalized = (action or "").strip().lower()
    if normalized in FAST_ACTIONS:
        return RouteMode.FAST
    if normalized in DELIBERATIVE_ACTIONS:
        return RouteMode.DELIBERATIVE
    return None


def find_invariant_violations(
    packet: DecisionPacket, system_state: SystemState
) -> tuple[str, ...]:
    """Return names of mandatory invariants this packet/state pair fails.

    A missing `rollback_plan` always counts: the scheduler requires either a
    rollback path or an explicit containment path to be declared on the
    packet itself. Otherwise the invariant set is the union of
    `MANDATORY_INVARIANTS`, `packet.required_checks`, and any FAIL_CLOSED
    signal observed in `SystemState.failed_checks`.
    """
    violations: list[str] = []
    passed = set(system_state.passed_checks)
    failed = set(system_state.failed_checks)

    if not packet.rollback_plan or not packet.rollback_plan.strip():
        violations.append("rollback_or_containment_path_exists")

    for invariant in MANDATORY_INVARIANTS:
        if invariant in violations:
            continue
        if invariant not in passed:
            violations.append(invariant)

    for required in packet.required_checks:
        if required in violations:
            continue
        if required not in passed:
            violations.append(required)

    fail_closed_present = sorted(failed.intersection(FAIL_CLOSED_SIGNALS))
    for signal in fail_closed_present:
        if signal not in violations:
            violations.append(signal)

    return tuple(violations)


def violates_invariant(
    packet: DecisionPacket, system_state: SystemState
) -> bool:
    return bool(find_invariant_violations(packet, system_state))


def _containment_triggers(system_state: SystemState) -> tuple[str, ...]:
    failed = set(system_state.failed_checks)
    return tuple(sorted(failed.intersection(CONTAINMENT_SIGNALS)))


def _decision(
    *,
    route: RouteMode,
    packet: DecisionPacket,
    system_state: SystemState,
    reason: str,
    reason_code: ScheduleReasonCode,
    invariant_violations: tuple[str, ...] = (),
    triggers: tuple[str, ...] = (),
) -> ScheduleDecision:
    return ScheduleDecision(
        route=route,
        intent_id=packet.intent_id,
        action=packet.action,
        reason=reason,
        reason_code=reason_code,
        required_time_ms=packet.required_time_ms,
        remaining_window_ms=packet.deadline_ms,
        risk_label=packet.risk_label,
        invariant_violations=invariant_violations,
        triggers=triggers,
        shortcut_debt_score=system_state.shortcut_debt.score,
        trust_state=system_state.trust_state,
    )


def fail_closed(
    packet: DecisionPacket,
    system_state: SystemState,
    *,
    reason: str,
    reason_code: ScheduleReasonCode = ScheduleReasonCode.NO_SAFE_ACTION_FITS,
    invariant_violations: tuple[str, ...] = (),
) -> ScheduleDecision:
    return _decision(
        route=RouteMode.FAIL_CLOSED,
        packet=packet,
        system_state=system_state,
        reason=reason,
        reason_code=reason_code,
        invariant_violations=invariant_violations,
    )


def containment(
    packet: DecisionPacket,
    system_state: SystemState,
    *,
    reason: str,
    reason_code: ScheduleReasonCode,
    triggers: tuple[str, ...] = (),
) -> ScheduleDecision:
    return _decision(
        route=RouteMode.CONTAINMENT,
        packet=packet,
        system_state=system_state,
        reason=reason,
        reason_code=reason_code,
        triggers=triggers,
    )


def fast_path(
    packet: DecisionPacket, system_state: SystemState
) -> ScheduleDecision:
    return _decision(
        route=RouteMode.FAST,
        packet=packet,
        system_state=system_state,
        reason=(
            f"Risk {packet.risk_label} fits the available window "
            f"({packet.required_time_ms}ms <= {packet.deadline_ms}ms)."
        ),
        reason_code=ScheduleReasonCode.LOW_RISK_FITS_WINDOW,
    )


def deliberative_path(
    packet: DecisionPacket, system_state: SystemState
) -> ScheduleDecision:
    return _decision(
        route=RouteMode.DELIBERATIVE,
        packet=packet,
        system_state=system_state,
        reason=(
            f"Risk {packet.risk_label} requires deeper verification; "
            f"window permits ({packet.required_time_ms}ms <= "
            f"{packet.deadline_ms}ms)."
        ),
        reason_code=ScheduleReasonCode.HIGH_RISK_FITS_WINDOW,
    )


def schedule_decision(
    packet: DecisionPacket, system_state: SystemState
) -> ScheduleDecision:
    """Allocate a route for this decision packet.

    Order of evaluation (each step short-circuits):

    1. Invariant check — any mandatory invariant unmet, any required check
       missing, any FAIL_CLOSED signal observed: route FAIL_CLOSED.
    2. Shortcut debt at or above the configured limit: route CONTAINMENT.
    3. Trust state in the degraded set ({"contested", "unsafe"}): route
       CONTAINMENT.
    4. Containment signals observed (suspicious input, policy disagreement,
       repeated auth failure, drift over threshold): route CONTAINMENT.
    5. Required time fits the remaining window:
         - low/medium risk -> FAST
         - high/critical risk -> DELIBERATIVE
    6. Required time exceeds the window but reversibility is at or above the
       configured threshold: route CONTAINMENT.
    7. Otherwise: FAIL_CLOSED.
    """
    invariant_violations = find_invariant_violations(packet, system_state)
    if invariant_violations:
        fail_closed_signal = next(
            (v for v in invariant_violations if v in FAIL_CLOSED_SIGNALS), None
        )
        if fail_closed_signal is not None:
            return fail_closed(
                packet,
                system_state,
                reason=f"FAIL_CLOSED signal observed: {fail_closed_signal}.",
                reason_code=ScheduleReasonCode.FAIL_CLOSED_SIGNAL,
                invariant_violations=invariant_violations,
            )
        return fail_closed(
            packet,
            system_state,
            reason=(
                "Mandatory invariant unmet: "
                f"{invariant_violations[0]}."
            ),
            reason_code=ScheduleReasonCode.INVARIANT_VIOLATION,
            invariant_violations=invariant_violations,
        )

    debt_score = system_state.shortcut_debt.score
    if debt_score >= system_state.shortcut_debt_limit:
        return containment(
            packet,
            system_state,
            reason=(
                f"Shortcut debt {debt_score:.2f} at or above limit "
                f"{system_state.shortcut_debt_limit:.2f}."
            ),
            reason_code=ScheduleReasonCode.SHORTCUT_DEBT_EXCEEDED,
        )

    if system_state.trust_state in DEGRADED_TRUST_STATES:
        return containment(
            packet,
            system_state,
            reason=f"Trust state degraded: {system_state.trust_state}.",
            reason_code=ScheduleReasonCode.TRUST_STATE_DEGRADED,
        )

    triggers = _containment_triggers(system_state)
    if triggers:
        return containment(
            packet,
            system_state,
            reason=f"Containment signal(s) observed: {', '.join(triggers)}.",
            reason_code=ScheduleReasonCode.CONTAINMENT_SIGNAL,
            triggers=triggers,
        )

    if packet.fits_window:
        if packet.risk_label in {"low", "medium"}:
            return fast_path(packet, system_state)
        return deliberative_path(packet, system_state)

    if packet.reversibility >= system_state.reversibility_containment_threshold:
        return containment(
            packet,
            system_state,
            reason=(
                f"Deadline too tight for full verification "
                f"({packet.required_time_ms}ms > {packet.deadline_ms}ms); "
                f"reversibility {packet.reversibility:.2f} permits "
                "reversible containment."
            ),
            reason_code=ScheduleReasonCode.DEADLINE_TOO_TIGHT_REVERSIBLE,
        )

    return fail_closed(
        packet,
        system_state,
        reason=(
            f"No safe action fits the available window "
            f"({packet.required_time_ms}ms > {packet.deadline_ms}ms) "
            f"and reversibility {packet.reversibility:.2f} is below the "
            "containment threshold."
        ),
        reason_code=ScheduleReasonCode.NO_SAFE_ACTION_FITS,
    )


def with_required_checks(
    packet: DecisionPacket, *checks: str
) -> DecisionPacket:
    """Return a copy of `packet` with additional required invariant names.

    Convenience for callers building a packet incrementally; the original is
    not mutated (DecisionPacket is frozen).
    """
    merged: list[str] = list(packet.required_checks)
    for check in checks:
        if check and check not in merged:
            merged.append(check)
    return replace(packet, required_checks=tuple(merged))


def all_signal_names() -> dict[str, tuple[str, ...]]:
    """Return the closed sets of named signals the scheduler recognises.

    Useful for upstream layers that emit `passed_checks` / `failed_checks`
    so they can validate they are not inventing new signal names.
    """
    return {
        "mandatory_invariants": MANDATORY_INVARIANTS,
        "fail_closed_signals": tuple(sorted(FAIL_CLOSED_SIGNALS)),
        "containment_signals": tuple(sorted(CONTAINMENT_SIGNALS)),
        "fast_actions": tuple(sorted(FAST_ACTIONS)),
        "deliberative_actions": tuple(sorted(DELIBERATIVE_ACTIONS)),
    }


def _coerce_check_tuple(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        normalized = str(value).strip()
        if not normalized or normalized in seen:
            continue
        output.append(normalized)
        seen.add(normalized)
    return tuple(output)


def make_system_state(
    *,
    trust_state: TrustState = "trusted",
    shortcut_debt: ShortcutDebt | None = None,
    shortcut_debt_limit: float = DEFAULT_SHORTCUT_DEBT_LIMIT,
    passed_checks: Iterable[str] = (),
    failed_checks: Iterable[str] = (),
    reversibility_containment_threshold: float = (
        DEFAULT_REVERSIBILITY_CONTAINMENT_THRESHOLD
    ),
) -> SystemState:
    """Construct a `SystemState` with deduplicated, normalised check tuples."""
    return SystemState(
        trust_state=trust_state,
        shortcut_debt=shortcut_debt or ShortcutDebt(),
        shortcut_debt_limit=shortcut_debt_limit,
        passed_checks=_coerce_check_tuple(passed_checks),
        failed_checks=_coerce_check_tuple(failed_checks),
        reversibility_containment_threshold=(
            reversibility_containment_threshold
        ),
    )
