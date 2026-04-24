import pytest

from osint_core.policy import (
    ALLOWED_CORRECTION_VERBS,
    PolicyDecision,
    PolicyErrorCode,
    PolicyViolationException,
    allowed_ui_modules,
    canonicalize_module_name,
    enforce_audit_payload,
    enforce_correction_verb,
    enforce_policy_mutation_gate,
    evaluate_modules,
    get_module_policy,
    may_mutate_policy,
    module_catalog,
)


def test_canonicalize_module_aliases():
    assert canonicalize_module_name("Resource Links") == "resource_links"
    assert canonicalize_module_name("robots.txt") == "robots_txt"
    assert canonicalize_module_name("nmap") == "port_scan"


def test_low_risk_modules_allowed_in_passive_mode():
    result = evaluate_modules(
        ["Resource Links", "DNS Records", "Local URL Parse"],
        authorized_target=False,
        passive_only=True,
    )

    assert result.decision == PolicyDecision.ALLOW
    assert result.allowed_modules == [
        "resource_links",
        "dns_records",
        "local_url_parse",
    ]
    assert result.blocked_modules == []
    assert result.violations == []


def test_conditional_module_blocked_without_authorization():
    result = evaluate_modules(
        ["HTTP Headers"],
        authorized_target=False,
        passive_only=False,
    )

    assert result.decision == PolicyDecision.CONSTRAIN
    assert result.allowed_modules == []
    assert result.blocked_modules == ["http_headers"]
    assert result.violations[0].code == PolicyErrorCode.AUTHORIZATION_REQUIRED


def test_conditional_module_blocked_in_passive_only_even_with_authorization():
    result = evaluate_modules(
        ["HTTP Headers"],
        authorized_target=True,
        passive_only=True,
    )

    assert result.decision == PolicyDecision.CONSTRAIN
    assert result.allowed_modules == []
    assert result.blocked_modules == ["http_headers"]
    assert result.violations[0].code == PolicyErrorCode.AUTHORIZATION_REQUIRED


def test_conditional_module_allowed_when_authorized_and_not_passive_only():
    result = evaluate_modules(
        ["HTTP Headers", "Robots.txt"],
        authorized_target=True,
        passive_only=False,
    )

    assert result.decision == PolicyDecision.ALLOW
    assert result.allowed_modules == ["http_headers", "robots_txt"]
    assert result.blocked_modules == []


def test_forbidden_module_is_always_blocked():
    result = evaluate_modules(
        ["Resource Links", "nmap", "Credential Testing"],
        authorized_target=True,
        passive_only=False,
    )

    assert result.decision == PolicyDecision.CONSTRAIN
    assert "resource_links" in result.allowed_modules
    assert "port_scan" in result.blocked_modules
    assert "credential_testing" in result.blocked_modules
    assert {v.code for v in result.violations} == {PolicyErrorCode.FORBIDDEN_MODULE}


def test_unknown_module_blocked_by_default():
    result = evaluate_modules(["Unknown Thing"])

    assert result.decision == PolicyDecision.CONSTRAIN
    assert result.allowed_modules == []
    assert result.blocked_modules == ["unknown_thing"]
    assert result.violations[0].code == PolicyErrorCode.UNKNOWN_MODULE


def test_unknown_module_can_be_allowed_only_when_explicitly_enabled():
    result = evaluate_modules(["Experimental"], allow_unknown_modules=True)

    assert result.decision == PolicyDecision.ALLOW
    assert result.allowed_modules == ["experimental"]
    assert result.blocked_modules == []


def test_correction_verbs_are_closed():
    assert set(ALLOWED_CORRECTION_VERBS) == {"ADAPT", "CONSTRAIN", "REVERT", "OBSERVE"}
    assert enforce_correction_verb("adapt") == "ADAPT"
    assert enforce_correction_verb(" OBSERVE ") == "OBSERVE"

    with pytest.raises(PolicyViolationException) as exc:
        enforce_correction_verb("EXPAND")

    assert exc.value.violation.code == PolicyErrorCode.INVALID_CORRECTION_VERB


def test_policy_cannot_mutate_without_out_of_band_approval():
    assert may_mutate_policy(out_of_band_approval=False) is False
    assert may_mutate_policy(out_of_band_approval=True) is True

    with pytest.raises(PolicyViolationException) as exc:
        enforce_policy_mutation_gate(out_of_band_approval=False)

    assert exc.value.violation.code == PolicyErrorCode.POLICY_MUTATION_BLOCKED

    enforce_policy_mutation_gate(out_of_band_approval=True)


def test_audit_payload_blocks_raw_indicator_fields():
    safe_payload = {
        "run_id": "run_123",
        "indicator_hash": "abc123",
        "modules": ["resource_links"],
    }
    enforce_audit_payload(safe_payload)

    with pytest.raises(PolicyViolationException) as exc:
        enforce_audit_payload({"raw_indicator": "example.com", "indicator_hash": "abc"})

    assert exc.value.violation.code == PolicyErrorCode.RAW_LOGGING_BLOCKED


def test_catalog_and_ui_modules_exclude_forbidden_by_default():
    catalog = module_catalog()
    names = {item["canonical_name"] for item in catalog}
    assert "resource_links" in names
    assert "port_scan" in names

    ui_modules = allowed_ui_modules()
    assert "Resource Links" in ui_modules
    assert "HTTP Headers" in ui_modules
    assert "Port Scan" not in ui_modules
    assert "Credential Testing" not in ui_modules

    passive_ui_modules = allowed_ui_modules(include_conditional=False)
    assert "Resource Links" in passive_ui_modules
    assert "HTTP Headers" not in passive_ui_modules


def test_get_module_policy_returns_registered_policy():
    policy = get_module_policy("Resource Links")
    assert policy is not None
    assert policy.canonical_name == "resource_links"
    assert policy.risk == "low"
