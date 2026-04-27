"""
Tests for osint_core.audit.

Covers assert_audit_safe and write_constraint_audit: raw-indicator rejection,
safe payload acceptance, and filesystem persistence delegation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from osint_core.audit import assert_audit_safe, write_constraint_audit
from osint_core.constraints import evaluate_constraints
from osint_core.policy import PolicyViolationException


# ---------------------------------------------------------------------------
# assert_audit_safe — safe payloads pass without exception
# ---------------------------------------------------------------------------


def test_assert_audit_safe_accepts_safe_payload():
    payload = {
        "run_id": "run_abc123",
        "indicator_hash": "deadbeef" * 8,
        "modules": ["resource_links"],
    }
    # Should not raise
    assert_audit_safe(payload)


def test_assert_audit_safe_accepts_empty_payload():
    # Empty dict has no forbidden keys
    assert_audit_safe({})


def test_assert_audit_safe_accepts_nested_safe_payload():
    payload = {
        "run_id": "run_test",
        "results": {"resource_links": {"status": "ok"}},
        "hash": "abc123def456",
    }
    assert_audit_safe(payload)


# ---------------------------------------------------------------------------
# assert_audit_safe — raw indicator fields are rejected
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("forbidden_key", [
    "raw_indicator",
    "indicator",
    "email",
    "domain",
    "username",
    "url",
    "ip",
])
def test_assert_audit_safe_rejects_raw_indicator_fields(forbidden_key: str):
    payload = {
        "run_id": "run_test",
        forbidden_key: "example.com",
    }
    with pytest.raises(PolicyViolationException):
        assert_audit_safe(payload)


def test_assert_audit_safe_rejects_multiple_raw_fields():
    payload = {
        "run_id": "run_test",
        "domain": "example.com",
        "ip": "192.168.1.1",
    }
    with pytest.raises(PolicyViolationException):
        assert_audit_safe(payload)


# ---------------------------------------------------------------------------
# write_constraint_audit — delegates to write_constraint_ledger
# ---------------------------------------------------------------------------


def test_write_constraint_audit_returns_path(tmp_path: Path):
    evaluation = evaluate_constraints(
        run_id="audit_run_test",
        requested_modules=["Resource Links"],
        authorized_target=False,
        passive_only=True,
    )

    result = write_constraint_audit(evaluation, directory=tmp_path)

    assert isinstance(result, Path)
    assert result.exists()
    assert result.name == "audit_run_test.json"


def test_write_constraint_audit_writes_valid_json(tmp_path: Path):
    evaluation = evaluate_constraints(
        run_id="audit_json_test",
        requested_modules=["HTTP Headers"],
        authorized_target=False,
        passive_only=True,
    )

    path = write_constraint_audit(evaluation, directory=tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))

    assert data["run_id"] == "audit_json_test"
    assert "events" in data
    assert isinstance(data["events"], list)


def test_write_constraint_audit_creates_directory(tmp_path: Path):
    nested_dir = tmp_path / "nested" / "sub"
    evaluation = evaluate_constraints(
        run_id="audit_nested",
        requested_modules=["Resource Links"],
        authorized_target=False,
        passive_only=True,
    )

    path = write_constraint_audit(evaluation, directory=nested_dir)

    assert nested_dir.is_dir()
    assert path.exists()


def test_write_constraint_audit_no_raw_indicators_in_output(tmp_path: Path):
    """Written file must not contain raw indicator fields."""
    evaluation = evaluate_constraints(
        run_id="audit_clean",
        requested_modules=["Resource Links", "nmap"],
        authorized_target=False,
        passive_only=True,
    )

    path = write_constraint_audit(evaluation, directory=tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))

    forbidden_keys = {"raw_indicator", "raw_input", "indicator", "domain", "username", "email", "url", "ip"}
    assert forbidden_keys.isdisjoint(data.keys())


def test_write_constraint_audit_records_blocked_actions(tmp_path: Path):
    evaluation = evaluate_constraints(
        run_id="audit_blocked",
        requested_modules=["nmap"],
        authorized_target=True,
        passive_only=False,
    )

    path = write_constraint_audit(evaluation, directory=tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))

    assert "port_scan" in data["blocked_actions"]
    assert data["allowed_actions"] == []


def test_write_constraint_audit_accepts_path_string(tmp_path: Path):
    """directory parameter accepts str as well as Path."""
    evaluation = evaluate_constraints(
        run_id="audit_str_path",
        requested_modules=["Resource Links"],
        authorized_target=False,
        passive_only=True,
    )

    path = write_constraint_audit(evaluation, directory=str(tmp_path))
    assert path.exists()


# ---------------------------------------------------------------------------
# Regression: write_constraint_audit on mixed allowed+blocked evaluation
# ---------------------------------------------------------------------------


def test_write_constraint_audit_mixed_evaluation(tmp_path: Path):
    evaluation = evaluate_constraints(
        run_id="audit_mixed",
        requested_modules=["Resource Links", "HTTP Headers"],
        authorized_target=False,
        passive_only=True,
    )

    path = write_constraint_audit(evaluation, directory=tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))

    assert "resource_links" in data["allowed_actions"]
    assert "http_headers" in data["blocked_actions"]