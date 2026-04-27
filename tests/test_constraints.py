from osint_core.constraints import evaluate_constraints, passive_module_actions, propose_actions
from osint_core.types import ProposedAction


def test_propose_actions_uses_canonical_module_names():
    actions = propose_actions(["Resource Links", "HTTP Headers"])

    assert [action.action_id for action in actions] == ["resource_links", "http_headers"]
    assert actions[0].touches_target is False
    assert actions[1].touches_target is True


def test_low_risk_module_allowed():
    result = evaluate_constraints(
        run_id="run_test",
        requested_modules=["Resource Links"],
        authorized_target=False,
        passive_only=True,
    )

    assert [action.action_id for action in result.allowed_actions] == ["resource_links"]
    assert result.blocked_actions == []
    assert result.events[0].decision == "allow"
    assert result.events[0].constraint_id == "module_allowed"


def test_conditional_module_requires_authorization_in_passive_mode():
    result = evaluate_constraints(
        run_id="run_test",
        requested_modules=["HTTP Headers"],
        authorized_target=True,
        passive_only=True,
    )

    assert [action.action_id for action in result.blocked_actions] == ["http_headers"]
    assert [action.action_id for action in result.requires_approval_actions] == [
        "http_headers"
    ]
    assert result.events[0].decision == "block"
    assert result.events[0].constraint_id == "authorized_target_required"


def test_forbidden_module_is_blocked_with_passive_substitution():
    result = evaluate_constraints(
        run_id="run_test",
        requested_modules=["nmap"],
        authorized_target=True,
        passive_only=False,
    )

    assert [action.action_id for action in result.blocked_actions] == ["port_scan"]
    assert result.events[0].decision == "block"
    assert result.events[0].constraint_id == "forbidden_capability"
    assert result.events[0].replacement_action == "Resource Links"


def test_unknown_module_is_blocked():
    result = evaluate_constraints(
        run_id="run_test",
        requested_modules=["Unregistered Module"],
        authorized_target=False,
        passive_only=True,
    )

    assert [action.action_id for action in result.blocked_actions] == ["unregistered_module"]
    assert result.events[0].constraint_id == "unknown_module"


# ---------------------------------------------------------------------------
# passive_module_actions — new function added in this PR
# ---------------------------------------------------------------------------


def test_passive_module_actions_returns_list_of_proposed_actions():
    actions = passive_module_actions()

    assert isinstance(actions, list)
    assert all(isinstance(a, ProposedAction) for a in actions)


def test_passive_module_actions_excludes_forbidden_modules():
    """Forbidden modules (port_scan, brute_force, etc.) must not appear."""
    actions = passive_module_actions()
    action_ids = {a.action_id for a in actions}

    assert "port_scan" not in action_ids
    assert "brute_force" not in action_ids
    assert "credential_testing" not in action_ids
    assert "exploitation" not in action_ids


def test_passive_module_actions_includes_low_risk_modules():
    actions = passive_module_actions()
    action_ids = {a.action_id for a in actions}

    assert "resource_links" in action_ids
    assert "dns_records" in action_ids
    assert "local_url_parse" in action_ids


def test_passive_module_actions_excludes_conditional_modules():
    """Conditional target-touching modules are not passive-only actions."""
    actions = passive_module_actions()
    action_ids = {a.action_id for a in actions}

    assert "http_headers" not in action_ids
    assert "robots_txt" not in action_ids
    assert "screenshot" not in action_ids


def test_passive_module_actions_is_non_empty():
    actions = passive_module_actions()
    assert len(actions) > 0


def test_passive_module_actions_each_has_valid_action_id():
    actions = passive_module_actions()
    for action in actions:
        assert action.action_id, "action_id must be a non-empty string"
        assert isinstance(action.action_id, str)
