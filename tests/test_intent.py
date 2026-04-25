"""
tests/test_intent.py
====================

Contract tests for osint_core.intent.

Core invariants:
- Intent packets are immutable.
- Intent packets do not store raw indicators.
- Scope boundaries are explicit and validated.
- Forbidden operations cannot appear in allowed operations.
- Packets can be signed and verified.
- Signature tampering is detected.
- Risk and rollback helpers are deterministic.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from osint_core.intent import (
    DEFAULT_FORBIDDEN_OPERATIONS,
    IntentErrorCode,
    IntentPacket,
    IntentValidationError,
    canonical_json,
    create_intent_packet,
    default_rollback_for_risk,
    derive_risk_label,
    find_raw_indicator_fields,
    hash_manifest_payload,
    intent_fingerprint,
    make_scope,
    risk_score,
    sign_payload,
    unsigned_intent_fingerprint,
    validate_intent,
    validate_scope,
    verify_intent_signature,
)


TEST_SECRET = "test-intent-signing-secret"
TARGET_HASH = "a" * 64
MANIFEST_HASH = "b" * 64


def make_valid_scope(**overrides):
    data = {
        "target_hash": TARGET_HASH,
        "indicator_type": "domain",
        "allowed_operations": ["resource_links"],
        "success_criteria": ["links_generated"],
    }
    data.update(overrides)
    return make_scope(**data)


def make_valid_packet(**overrides):
    scope = overrides.pop("scope", make_valid_scope())
    data = {
        "action": "enrich_indicator",
        "purpose": "Generate passive OSINT source links for a validated indicator.",
        "scope": scope,
        "requested_modules": ["resource_links"],
        "expected_side_effects": ["report_created", "audit_event_created"],
        "rollback_strategy": "observe_only",
        "risk_label": "low",
        "manifest_hash": MANIFEST_HASH,
        "signing_secret": TEST_SECRET,
    }
    data.update(overrides)
    return create_intent_packet(**data)


def test_make_scope_adds_default_forbidden_operations():
    scope = make_valid_scope()
    for operation in DEFAULT_FORBIDDEN_OPERATIONS:
        assert operation in scope.forbidden_operations
    assert scope.target_hash == TARGET_HASH
    assert scope.indicator_type == "domain"
    assert scope.allowed_operations == ("resource_links",)


def test_scope_rejects_missing_target_hash():
    result = validate_scope(make_valid_scope(target_hash="c" * 64))
    assert result.ok is True
    with pytest.raises(IntentValidationError) as exc:
        make_valid_scope(target_hash="")
    assert exc.value.code == IntentErrorCode.MISSING_FIELD


def test_scope_rejects_non_hash_target_identity():
    with pytest.raises(IntentValidationError) as exc:
        make_valid_scope(target_hash="example.com")
    assert exc.value.code == IntentErrorCode.INVALID_SCOPE


def test_scope_rejects_empty_allowed_operations():
    with pytest.raises(IntentValidationError) as exc:
        make_valid_scope(allowed_operations=[])
    assert exc.value.code == IntentErrorCode.MISSING_FIELD


def test_scope_rejects_forbidden_operation_overlap():
    with pytest.raises(IntentValidationError) as exc:
        make_valid_scope(allowed_operations=["resource_links", "port_scan"])
    assert exc.value.code == IntentErrorCode.FORBIDDEN_OPERATION_REQUESTED


def test_scope_rejects_invalid_time_horizon():
    with pytest.raises(IntentValidationError) as exc:
        make_valid_scope(time_horizon_seconds=0)
    assert exc.value.code == IntentErrorCode.INVALID_SCOPE

    with pytest.raises(IntentValidationError) as exc:
        make_valid_scope(time_horizon_seconds=90_000)
    assert exc.value.code == IntentErrorCode.INVALID_SCOPE


def test_create_intent_packet_signs_and_verifies():
    packet = make_valid_packet()
    assert isinstance(packet, IntentPacket)
    assert packet.signature is not None
    assert verify_intent_signature(packet, secret=TEST_SECRET) is True


def test_intent_packet_is_immutable():
    packet = make_valid_packet()
    with pytest.raises(FrozenInstanceError):
        packet.purpose = "mutated"  # type: ignore[misc]


def test_unsigned_payload_excludes_signature():
    packet = make_valid_packet()
    payload = packet.unsigned_payload()
    assert "signature" not in payload
    assert packet.signature is not None


def test_signature_tampering_is_detected():
    packet = make_valid_packet()
    tampered = replace(packet, purpose="Changed purpose after signing.")
    with pytest.raises(IntentValidationError) as exc:
        verify_intent_signature(tampered, secret=TEST_SECRET)
    assert exc.value.code == IntentErrorCode.SIGNATURE_MISMATCH


def test_unsigned_packet_fails_verification():
    packet = create_intent_packet(
        action="enrich_indicator",
        purpose="Generate passive links.",
        scope=make_valid_scope(),
        requested_modules=["resource_links"],
        expected_side_effects=["report_created"],
        rollback_strategy="observe_only",
        risk_label="low",
        manifest_hash=MANIFEST_HASH,
        sign=False,
    )
    assert packet.signature is None
    with pytest.raises(IntentValidationError) as exc:
        verify_intent_signature(packet, secret=TEST_SECRET)
    assert exc.value.code == IntentErrorCode.UNSIGNED_PACKET


def test_packet_rejects_invalid_action():
    with pytest.raises(IntentValidationError) as exc:
        make_valid_packet(action="delete_everything")  # type: ignore[arg-type]
    assert exc.value.code == IntentErrorCode.INVALID_ACTION


def test_packet_rejects_invalid_risk_label():
    with pytest.raises(IntentValidationError) as exc:
        make_valid_packet(risk_label="extreme")  # type: ignore[arg-type]
    assert exc.value.code == IntentErrorCode.INVALID_RISK


def test_packet_rejects_invalid_rollback_strategy():
    with pytest.raises(IntentValidationError) as exc:
        make_valid_packet(rollback_strategy="YOLO")  # type: ignore[arg-type]
    assert exc.value.code == IntentErrorCode.INVALID_ROLLBACK


def test_packet_rejects_invalid_manifest_hash():
    with pytest.raises(IntentValidationError) as exc:
        make_valid_packet(manifest_hash="not-a-hash")
    assert exc.value.code == IntentErrorCode.MISSING_FIELD


def test_packet_rejects_empty_purpose():
    with pytest.raises(IntentValidationError) as exc:
        make_valid_packet(purpose="   ")
    assert exc.value.code == IntentErrorCode.MISSING_FIELD


def test_raw_indicator_field_detection():
    payload = {
        "safe": {"target_hash": TARGET_HASH},
        "unsafe": {
            "raw_indicator": "example.com",
            "nested": {"email": "user@example.com"},
        },
    }
    findings = find_raw_indicator_fields(payload)
    assert "unsafe.raw_indicator" in findings
    assert "unsafe.nested.email" in findings


def test_validate_intent_rejects_raw_indicator_like_fields():
    packet = make_valid_packet()
    unsafe_dict = packet.to_dict()
    unsafe_dict["raw_indicator"] = "example.com"
    findings = find_raw_indicator_fields(unsafe_dict)
    assert "raw_indicator" in findings


def test_canonical_json_is_deterministic():
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})


def test_sign_payload_is_deterministic_for_same_payload_and_secret():
    payload = {"a": 1, "b": 2}
    assert sign_payload(payload, TEST_SECRET) == sign_payload(payload, TEST_SECRET)
    assert sign_payload(payload, TEST_SECRET) != sign_payload(payload, "different-secret")


def test_hash_manifest_payload_is_stable():
    payload = {"artifact": "test", "version": "1.0.0"}
    assert hash_manifest_payload(payload) == hash_manifest_payload(payload)
    assert len(hash_manifest_payload(payload)) == 64


def test_intent_fingerprints_are_stable_and_distinct():
    packet = make_valid_packet()
    signed_fp = intent_fingerprint(packet)
    unsigned_fp = unsigned_intent_fingerprint(packet)
    assert len(signed_fp) == 64
    assert len(unsigned_fp) == 64
    assert signed_fp != unsigned_fp


def test_validate_intent_accepts_valid_packet():
    result = validate_intent(make_valid_packet())
    assert result.ok is True
    assert result.errors == ()
    assert result.error_codes == ()


def test_risk_score_mapping():
    assert risk_score("low") == 0.25
    assert risk_score("medium") == 0.5
    assert risk_score("high") == 0.75
    assert risk_score("critical") == 1.0


def test_default_rollback_for_risk():
    assert default_rollback_for_risk("low") == "observe_only"
    assert default_rollback_for_risk("medium") == "disable_module"
    assert default_rollback_for_risk("high") == "sandbox"
    assert default_rollback_for_risk("critical") == "revert"


def test_derive_risk_label_for_low_risk_passive_modules():
    assert derive_risk_label(
        requested_modules=["resource_links"],
        authorized_target=False,
    ) == "low"


def test_derive_risk_label_for_conditional_authorized_modules():
    assert derive_risk_label(
        requested_modules=["http_headers"],
        authorized_target=True,
    ) == "medium"


def test_derive_risk_label_for_conditional_unauthorized_modules():
    assert derive_risk_label(
        requested_modules=["http_headers"],
        authorized_target=False,
    ) == "high"


def test_derive_risk_label_for_forbidden_modules():
    assert derive_risk_label(
        requested_modules=["nmap"],
        authorized_target=True,
    ) == "critical"
