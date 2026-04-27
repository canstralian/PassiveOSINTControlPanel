"""
Tests for osint_core.enrichment.

Covers plan_passive_enrichment: it is a thin facade over propose_actions so
tests verify the delegation contract, ProposedAction shape, and that no network
operations are triggered.
"""

from __future__ import annotations

import pytest

from osint_core.enrichment import plan_passive_enrichment
from osint_core.types import ProposedAction


# ---------------------------------------------------------------------------
# Return type and shape
# ---------------------------------------------------------------------------


def test_plan_passive_enrichment_returns_list_of_proposed_actions():
    result = plan_passive_enrichment(["Resource Links"])

    assert isinstance(result, list)
    assert all(isinstance(a, ProposedAction) for a in result)


def test_plan_passive_enrichment_empty_list():
    result = plan_passive_enrichment([])
    assert result == []


# ---------------------------------------------------------------------------
# Canonical name resolution (delegates to propose_actions)
# ---------------------------------------------------------------------------


def test_plan_passive_enrichment_canonicalizes_module_names():
    result = plan_passive_enrichment(["Resource Links"])

    assert len(result) == 1
    assert result[0].action_id == "resource_links"


def test_plan_passive_enrichment_resolves_alias():
    """robots.txt alias should resolve to robots_txt canonical name."""
    result = plan_passive_enrichment(["robots.txt"])

    assert len(result) == 1
    assert result[0].action_id == "robots_txt"


def test_plan_passive_enrichment_nmap_alias_resolves_to_port_scan():
    """nmap alias resolves to port_scan even in enrichment planning."""
    result = plan_passive_enrichment(["nmap"])

    assert len(result) == 1
    assert result[0].action_id == "port_scan"


# ---------------------------------------------------------------------------
# touches_target flag for target-touching modules
# ---------------------------------------------------------------------------


def test_plan_passive_enrichment_target_touching_modules_flagged():
    result = plan_passive_enrichment(["HTTP Headers", "Robots.txt"])

    touches = {a.action_id: a.touches_target for a in result}
    assert touches["http_headers"] is True
    assert touches["robots_txt"] is True


def test_plan_passive_enrichment_non_target_touching_modules_not_flagged():
    result = plan_passive_enrichment(["Resource Links", "DNS Records"])

    for action in result:
        assert action.touches_target is False, (
            f"{action.action_id} should not touch target"
        )


# ---------------------------------------------------------------------------
# Preserves order
# ---------------------------------------------------------------------------


def test_plan_passive_enrichment_preserves_order():
    modules = ["Resource Links", "DNS Records", "HTTP Headers"]
    result = plan_passive_enrichment(modules)

    assert [a.action_id for a in result] == [
        "resource_links",
        "dns_records",
        "http_headers",
    ]


# ---------------------------------------------------------------------------
# Unknown module gets a fallback description (no network call)
# ---------------------------------------------------------------------------


def test_plan_passive_enrichment_unknown_module_does_not_raise():
    """Unregistered modules return a ProposedAction with a fallback description."""
    result = plan_passive_enrichment(["completely_unknown_module"])

    assert len(result) == 1
    action = result[0]
    assert action.action_id == "completely_unknown_module"
    assert "Unknown" in action.expected_signal or action.expected_signal


def test_plan_passive_enrichment_requires_authorization_flag():
    """HTTP Headers (conditional) should require authorization."""
    result = plan_passive_enrichment(["HTTP Headers"])

    assert len(result) == 1
    assert result[0].requires_authorization is True


def test_plan_passive_enrichment_passive_module_does_not_require_authorization():
    result = plan_passive_enrichment(["Resource Links"])

    assert len(result) == 1
    assert result[0].requires_authorization is False


# ---------------------------------------------------------------------------
# Multiple modules — correct count and mapping
# ---------------------------------------------------------------------------


def test_plan_passive_enrichment_multiple_modules():
    result = plan_passive_enrichment(["Resource Links", "DNS Records", "HTTP Headers"])

    assert len(result) == 3
    ids = [a.action_id for a in result]
    assert "resource_links" in ids
    assert "dns_records" in ids
    assert "http_headers" in ids


# ---------------------------------------------------------------------------
# Regression: repeated module produces repeated action (no de-dup at this layer)
# ---------------------------------------------------------------------------


def test_plan_passive_enrichment_repeated_module_produces_repeated_action():
    """The planning facade does not de-duplicate; caller is responsible."""
    result = plan_passive_enrichment(["Resource Links", "Resource Links"])

    assert len(result) == 2
    assert all(a.action_id == "resource_links" for a in result)
