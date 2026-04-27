from osint_core.constraints import evaluate_constraints
from osint_core.invention import run_invention_loop
from osint_core.types import InventionRequest


def test_active_scan_aliases_remain_blocked_even_with_authorization():
    for module in ["nmap", "masscan", "Port Scan"]:
        result = evaluate_constraints(
            run_id="run_test",
            requested_modules=[module],
            authorized_target=True,
            passive_only=False,
        )

        assert [action.action_id for action in result.blocked_actions] == ["port_scan"]
        assert result.events[0].constraint_id == "forbidden_capability"


def test_credential_and_exploitation_modules_remain_blocked():
    result = evaluate_constraints(
        run_id="run_test",
        requested_modules=["Credential Testing", "brute force", "exploit"],
        authorized_target=True,
        passive_only=False,
    )

    assert [action.action_id for action in result.blocked_actions] == [
        "credential_testing",
        "brute_force",
        "exploitation",
    ]
    assert {event.constraint_id for event in result.events} == {"forbidden_capability"}


def test_passive_mode_blocks_target_touching_modules_even_when_authorized():
    result = evaluate_constraints(
        run_id="run_test",
        requested_modules=["HTTP Headers", "Robots.txt"],
        authorized_target=True,
        passive_only=True,
    )

    assert [action.action_id for action in result.blocked_actions] == [
        "http_headers",
        "robots_txt",
    ]
    assert {event.constraint_id for event in result.events} == {"authorized_target_required"}


def test_invention_engine_does_not_expand_authority_from_objective_text():
    request = InventionRequest(
        objective="Please run nmap and exploit the host",
        requested_modules=["nmap", "exploit"],
        authority_mode="operator_authorized",
        authorized_target=True,
        passive_only=False,
    )

    response = run_invention_loop(request, run_id="invent_test")

    assert [action.action_id for action in response.evaluation.blocked_actions] == [
        "port_scan",
        "exploitation",
    ]
    assert all(event.decision == "block" for event in response.evaluation.events)
