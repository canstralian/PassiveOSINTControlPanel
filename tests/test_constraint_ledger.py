import json

import pytest

from osint_core.constraints import evaluate_constraints
from osint_core.ledger import (
    evaluation_to_dict,
    summarize_constraint_events,
    validate_run_id,
    write_constraint_ledger,
)


FORBIDDEN_KEYS = {
    "raw_indicator",
    "raw_input",
    "indicator",
    "domain",
    "username",
    "email",
    "url",
    "ip",
}


def collect_keys(value):
    if isinstance(value, dict):
        keys = set(value.keys())
        for nested in value.values():
            keys.update(collect_keys(nested))
        return keys

    if isinstance(value, list):
        keys = set()
        for item in value:
            keys.update(collect_keys(item))
        return keys

    return set()


def test_evaluation_to_dict_contains_no_raw_indicator_fields():
    evaluation = evaluate_constraints(
        run_id="run_test",
        requested_modules=["HTTP Headers"],
        authorized_target=False,
        passive_only=True,
    )

    payload = evaluation_to_dict(evaluation)

    assert payload["run_id"] == "run_test"
    assert "events" in payload
    assert FORBIDDEN_KEYS.isdisjoint(collect_keys(payload))


def test_write_constraint_ledger_writes_json(tmp_path):
    evaluation = evaluate_constraints(
        run_id="run_test",
        requested_modules=["Resource Links", "nmap"],
        authorized_target=False,
        passive_only=True,
    )

    path = write_constraint_ledger(evaluation, directory=tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))

    assert path.name == "run_test.json"
    assert data["run_id"] == "run_test"
    assert data["allowed_actions"] == ["resource_links"]
    assert data["blocked_actions"] == ["port_scan"]
    assert any(event["constraint_id"] == "forbidden_capability" for event in data["events"])


def test_write_constraint_ledger_rejects_path_traversal_run_id(tmp_path):
    evaluation = evaluate_constraints(
        run_id="../escape",
        requested_modules=["Resource Links"],
        authorized_target=False,
        passive_only=True,
    )

    with pytest.raises(ValueError):
        write_constraint_ledger(evaluation, directory=tmp_path)


def test_validate_run_id_accepts_filename_safe_tokens():
    assert validate_run_id("run_20260427.abc-123") == "run_20260427.abc-123"


@pytest.mark.parametrize("run_id", ["", "../escape", "bad/name", "bad\\name"])
def test_validate_run_id_rejects_unsafe_tokens(run_id):
    with pytest.raises(ValueError):
        validate_run_id(run_id)


def test_summarize_constraint_events_returns_markdown():
    evaluation = evaluate_constraints(
        run_id="run_test",
        requested_modules=["HTTP Headers"],
        authorized_target=False,
        passive_only=True,
    )

    markdown = summarize_constraint_events(evaluation.events)

    assert "Constraint Decisions" in markdown
    assert "authorized_target_required" in markdown
