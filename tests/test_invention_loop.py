from osint_core.invention import run_invention_loop, summarize_invention_response
from osint_core.types import InventionRequest


def test_invention_loop_runs_all_four_loops():
    request = InventionRequest(
        objective="Build a passive domain profile",
        requested_modules=["Resource Links", "HTTP Headers"],
        authority_mode="observation",
        authorized_target=True,
        passive_only=True,
    )

    response = run_invention_loop(request, run_id="invent_test")

    assert response.run_id == "invent_test"
    assert [action.action_id for action in response.evaluation.allowed_actions] == ["resource_links"]
    assert [action.action_id for action in response.evaluation.blocked_actions] == ["http_headers"]
    assert [
        action.action_id for action in response.evaluation.requires_approval_actions
    ] == ["http_headers"]
    assert response.reflections
    assert response.recommendations


def test_operator_authorized_mode_can_allow_conditional_when_not_passive_only():
    request = InventionRequest(
        objective="Inspect authorized target headers",
        requested_modules=["HTTP Headers"],
        authority_mode="operator_authorized",
        authorized_target=True,
        passive_only=False,
    )

    response = run_invention_loop(request, run_id="invent_test")

    assert [action.action_id for action in response.evaluation.allowed_actions] == ["http_headers"]
    assert response.evaluation.blocked_actions == []
    assert response.evaluation.requires_approval_actions == []


def test_non_authorized_modes_force_passive_only():
    request = InventionRequest(
        objective="Analyze without touching target",
        requested_modules=["HTTP Headers"],
        authority_mode="analysis",
        authorized_target=True,
        passive_only=False,
    )

    response = run_invention_loop(request, run_id="invent_test")

    assert [action.action_id for action in response.evaluation.blocked_actions] == ["http_headers"]
    assert [
        action.action_id for action in response.evaluation.requires_approval_actions
    ] == ["http_headers"]


def test_summary_mentions_constraint_events():
    request = InventionRequest(
        objective="Build a passive domain profile",
        requested_modules=["nmap"],
    )

    response = run_invention_loop(request, run_id="invent_test")
    summary = summarize_invention_response(response)

    assert "Constraint-Aware Invention Engine" in summary
    assert "forbidden_capability" in summary
