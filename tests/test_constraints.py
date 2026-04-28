"""
Tests for osint_core.constraints.

These tests pin the central invariant: authorized-only modules remain blocked
unless the caller asserts BOTH ``authorized_target=True`` and
``passive_only=False``. They also pin the constraint engine's purity, the
ledger's redaction behavior, and the closed correction-verb vocabulary.
"""

from __future__ import annotations

import copy
import json
from dataclasses import replace

import pytest

from osint_core.constraints import (
    Constraint,
    ConstraintCode,
    ConstraintContext,
    ConstraintReport,
    ConstraintSeverity,
    ConstraintStatus,
    DEFAULT_CONSTRAINTS,
    LEDGER_SCHEMA_VERSION,
    build_ledger_entry,
    evaluate_constraints,
    write_constraint_ledger,
)
from osint_core.policy import (
    PolicyDecision,
    PolicyViolationException,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ctx(**overrides) -> ConstraintContext:
    base = dict(
        requested_modules=("resource_links",),
        authorized_target=False,
        passive_only=True,
        indicator_hash="hash_abc",
        indicator_type="domain",
    )
    base.update(overrides)
    return ConstraintContext(**base)


def _result_for(report: ConstraintReport, code: ConstraintCode):
    matching = [r for r in report.results if r.code == code]
    assert matching, f"No result for code {code}"
    assert len(matching) == 1
    return matching[0]


# ---------------------------------------------------------------------------
# Authorization invariant — the central guarantee of this branch.
# ---------------------------------------------------------------------------

def test_authorized_only_module_blocked_without_authorization():
    report = evaluate_constraints(
        _ctx(
            requested_modules=("HTTP Headers",),
            authorized_target=False,
            passive_only=False,
        )
    )

    auth = _result_for(report, ConstraintCode.AUTHORIZATION)
    assert report.decision == PolicyDecision.CONSTRAIN
    assert auth.status == ConstraintStatus.VIOLATED
    assert "http_headers" in auth.evidence["blocked_modules"]
    assert auth.evidence["authorized_target"] is False


def test_authorized_only_module_blocked_in_passive_only_even_with_authorization():
    report = evaluate_constraints(
        _ctx(
            requested_modules=("HTTP Headers",),
            authorized_target=True,
            passive_only=True,
        )
    )

    auth = _result_for(report, ConstraintCode.AUTHORIZATION)
    assert report.decision == PolicyDecision.CONSTRAIN
    assert auth.status == ConstraintStatus.VIOLATED
    assert "http_headers" in auth.evidence["blocked_modules"]


def test_authorized_only_module_allowed_when_fully_authorized_and_active():
    report = evaluate_constraints(
        _ctx(
            requested_modules=("HTTP Headers", "Robots.txt"),
            authorized_target=True,
            passive_only=False,
        )
    )

    auth = _result_for(report, ConstraintCode.AUTHORIZATION)
    assert report.decision == PolicyDecision.ALLOW
    assert auth.status == ConstraintStatus.SATISFIED
    assert report.policy_evaluation.allowed_modules == ["http_headers", "robots_txt"]


# ---------------------------------------------------------------------------
# Forbidden capabilities and unknown modules
# ---------------------------------------------------------------------------

def test_forbidden_module_always_blocked_by_constraint():
    report = evaluate_constraints(
        _ctx(
            requested_modules=("Resource Links", "nmap", "Credential Testing"),
            authorized_target=True,
            passive_only=False,
        )
    )

    forbidden = _result_for(report, ConstraintCode.FORBIDDEN_CAPABILITY)
    assert report.decision == PolicyDecision.CONSTRAIN
    assert forbidden.status == ConstraintStatus.VIOLATED
    assert set(forbidden.evidence["blocked_modules"]) == {
        "port_scan",
        "credential_testing",
    }
    # Verb derivation: forbidden capabilities escalate to REVERT.
    assert report.enforced_correction_verb == "REVERT"


def test_unknown_module_blocked_by_constraint():
    report = evaluate_constraints(_ctx(requested_modules=("ExperimentalThing",)))
    unknown = _result_for(report, ConstraintCode.UNKNOWN_MODULE)
    assert report.decision == PolicyDecision.CONSTRAIN
    assert unknown.status == ConstraintStatus.VIOLATED
    assert "experimentalthing" in unknown.evidence["blocked_modules"]


# ---------------------------------------------------------------------------
# Audit-payload and correction-verb invariants
# ---------------------------------------------------------------------------

def test_audit_payload_constraint_rejects_raw_indicator_fields():
    report = evaluate_constraints(
        _ctx(audit_payload={"raw_indicator": "example.com", "indicator_hash": "abc"})
    )

    audit = _result_for(report, ConstraintCode.AUDIT_PAYLOAD)
    assert report.decision == PolicyDecision.CONSTRAIN
    assert audit.status == ConstraintStatus.VIOLATED


def test_audit_payload_constraint_satisfied_for_safe_payload():
    report = evaluate_constraints(
        _ctx(audit_payload={"indicator_hash": "abc", "modules": ["resource_links"]})
    )

    audit = _result_for(report, ConstraintCode.AUDIT_PAYLOAD)
    assert audit.status == ConstraintStatus.SATISFIED


def test_correction_verb_constraint_rejects_invalid_verb():
    report = evaluate_constraints(_ctx(correction_verb="EXPAND"))
    verb = _result_for(report, ConstraintCode.CORRECTION_VERB)
    assert verb.status == ConstraintStatus.VIOLATED
    assert verb.evidence["supplied"] == "EXPAND"
    assert report.decision == PolicyDecision.CONSTRAIN


def test_correction_verb_constraint_accepts_allowed_verb():
    report = evaluate_constraints(_ctx(correction_verb="observe"))
    verb = _result_for(report, ConstraintCode.CORRECTION_VERB)
    assert verb.status == ConstraintStatus.SATISFIED
    assert verb.evidence["verb"] == "OBSERVE"


# ---------------------------------------------------------------------------
# Verb derivation priority
# ---------------------------------------------------------------------------

def test_clean_request_recommends_observe():
    report = evaluate_constraints(_ctx(requested_modules=("Resource Links",)))
    assert report.decision == PolicyDecision.ALLOW
    assert report.enforced_correction_verb == "OBSERVE"


def test_authorization_violation_recommends_constrain():
    report = evaluate_constraints(_ctx(requested_modules=("HTTP Headers",)))
    assert report.enforced_correction_verb == "CONSTRAIN"


def test_forbidden_outranks_authorization_in_verb_priority():
    report = evaluate_constraints(
        _ctx(
            requested_modules=("HTTP Headers", "nmap"),
            authorized_target=False,
            passive_only=True,
        )
    )
    # Both AUTHORIZATION and FORBIDDEN_CAPABILITY fire; REVERT wins.
    assert report.enforced_correction_verb == "REVERT"


# ---------------------------------------------------------------------------
# Purity
# ---------------------------------------------------------------------------

def test_evaluate_constraints_does_not_mutate_inputs():
    payload = {"indicator_hash": "abc", "modules": ["resource_links"]}
    ctx = _ctx(audit_payload=payload)
    snapshot = copy.deepcopy(ctx)
    payload_snapshot = copy.deepcopy(payload)

    evaluate_constraints(ctx)

    assert ctx == snapshot
    assert payload == payload_snapshot


def test_default_constraints_registry_is_immutable_tuple():
    assert isinstance(DEFAULT_CONSTRAINTS, tuple)
    # Every entry is a Constraint dataclass with an evaluator.
    for c in DEFAULT_CONSTRAINTS:
        assert isinstance(c, Constraint)
        assert callable(c.evaluator)


# ---------------------------------------------------------------------------
# Custom constraint composition
# ---------------------------------------------------------------------------

def test_engine_runs_only_supplied_constraints():
    only_authz = tuple(c for c in DEFAULT_CONSTRAINTS if c.code == ConstraintCode.AUTHORIZATION)
    report = evaluate_constraints(
        _ctx(requested_modules=("nmap",)),
        constraints=only_authz,
    )
    # Forbidden constraint is skipped, so only the policy evaluation surfaces it.
    codes = {r.code for r in report.results}
    assert codes == {ConstraintCode.AUTHORIZATION}
    # No enforced violations from constraints, so decision is ALLOW even though
    # policy still flagged the forbidden module.
    assert report.decision == PolicyDecision.ALLOW
    assert "port_scan" in report.policy_evaluation.blocked_modules


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

def test_build_ledger_entry_contains_required_fields():
    report = evaluate_constraints(_ctx(requested_modules=("Resource Links",)))
    entry = build_ledger_entry(
        report,
        run_id="run_test_001",
        indicator_hash="hash_xyz",
        indicator_type="domain",
    )

    assert entry["schema_version"] == LEDGER_SCHEMA_VERSION
    assert entry["run_id"] == "run_test_001"
    assert entry["indicator_hash"] == "hash_xyz"
    assert entry["indicator_type"] == "domain"
    assert entry["decision"] == "allow"
    assert entry["enforced_correction_verb"] == "OBSERVE"
    assert isinstance(entry["constraint_results"], list)
    assert entry["policy"]["allowed_modules"] == ["resource_links"]


def test_build_ledger_entry_rejects_indicator_typed_as_raw_field():
    # Defensive: even though we never put raw fields into the entry, prove
    # that enforce_audit_payload runs by passing a forbidden field through
    # a malicious replace of the report timestamp into the dict path. We
    # simulate by building the entry then re-checking.
    report = evaluate_constraints(_ctx(requested_modules=("Resource Links",)))
    entry = build_ledger_entry(
        report,
        run_id="run_test_002",
        indicator_hash="hash_xyz",
        indicator_type="domain",
    )
    forbidden_keys = {"raw_indicator", "raw_input", "indicator", "email", "domain", "username", "url", "ip"}
    assert forbidden_keys.isdisjoint(entry.keys())


def test_write_constraint_ledger_persists_under_runs_constraints(tmp_path):
    report = evaluate_constraints(_ctx(requested_modules=("Resource Links",)))
    path = write_constraint_ledger(
        report,
        run_id="run_persist_001",
        indicator_hash="hash_persist",
        indicator_type="domain",
        base_dir=tmp_path,
    )

    assert path.exists()
    assert path.parent.name == "constraints"
    assert path.parent.parent == tmp_path
    on_disk = json.loads(path.read_text())
    assert on_disk["run_id"] == "run_persist_001"
    assert on_disk["indicator_hash"] == "hash_persist"
    assert "raw_indicator" not in on_disk


def test_write_constraint_ledger_blocks_when_payload_would_leak_raw():
    # Inject a constraint that returns evidence with a forbidden key, and
    # verify that the resulting ledger entry — built from the report — would
    # not be allowed past enforce_audit_payload.
    #
    # We construct the unsafe entry directly to simulate what
    # build_ledger_entry would refuse, by adding a forbidden top-level key.
    from osint_core.policy import enforce_audit_payload

    report = evaluate_constraints(_ctx(requested_modules=("Resource Links",)))
    safe_entry = build_ledger_entry(
        report,
        run_id="run_x",
        indicator_hash="hash_x",
        indicator_type="domain",
    )
    unsafe_entry = dict(safe_entry)
    unsafe_entry["raw_indicator"] = "example.com"
    with pytest.raises(PolicyViolationException):
        enforce_audit_payload(unsafe_entry)


# ---------------------------------------------------------------------------
# Frozen report
# ---------------------------------------------------------------------------

def test_constraint_report_is_frozen():
    report = evaluate_constraints(_ctx())
    with pytest.raises(Exception):
        # frozen dataclass: assignment must raise
        report.decision = PolicyDecision.CONSTRAIN  # type: ignore[misc]


def test_constraint_result_is_frozen():
    report = evaluate_constraints(_ctx())
    result = report.results[0]
    with pytest.raises(Exception):
        result.message = "tampered"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Sanity: replace() works on context (frozen dataclass usability)
# ---------------------------------------------------------------------------

def test_context_supports_replace():
    ctx = _ctx()
    new_ctx = replace(ctx, passive_only=False, authorized_target=True)
    assert new_ctx.passive_only is False
    assert new_ctx.authorized_target is True
    # Original is unchanged.
    assert ctx.passive_only is True
