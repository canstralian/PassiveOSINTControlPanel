"""
osint_core.validators
=====================

Input validation and normalization for the Passive OSINT Control Panel.

Design goals:
- Treat all input as hostile.
- Normalize before hashing, enrichment, audit, or reporting.
- Return structured results so downstream modules do not guess intent.
- Reject ambiguous or dangerous inputs early.
- Avoid network calls. This module is pure validation/normalization.

Supported indicator types:
- domain
- username
- email
- ip
- url
"""

from __future__ import annotations

import html
import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Literal
from urllib.parse import urlparse, urlunparse


IndicatorType = Literal["domain", "username", "email", "ip", "url", "unknown"]


class ValidationErrorCode(str, Enum):
    EMPTY_INPUT = "empty_input"
    TOO_LONG = "too_long"
    CONTROL_CHARACTERS = "control_characters"
    INVALID_TYPE = "invalid_type"
    INVALID_DOMAIN = "invalid_domain"
    INVALID_USERNAME = "invalid_username"
    INVALID_EMAIL = "invalid_email"
    INVALID_IP = "invalid_ip"
    INVALID_URL = "invalid_url"
    UNSUPPORTED_INDICATOR = "unsupported_indicator"
    BLOCKED_LOCAL_TARGET = "blocked_local_target"
    BLOCKED_DANGEROUS_PATTERN = "blocked_dangerous_pattern"


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    indicator_type: IndicatorType
    normalized: str
    original_length: int
    warnings: list[str]
    error: str | None = None
    error_code: ValidationErrorCode | None = None


MAX_INPUT_LENGTH = 256
MAX_USERNAME_LENGTH = 64
MAX_EMAIL_LOCAL_LENGTH = 64
MAX_EMAIL_LENGTH = 320
MAX_DOMAIN_LENGTH = 253
MAX_URL_LENGTH = 2048

CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{2,64}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,63}$")

DANGEROUS_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\.\./",
        r"%2e%2e",
        r"<\s*script",
        r"javascript:",
        r"data:",
        r"file:",
        r";",
        r"\|",
        r"&&",
        r"\$\(",
        r"`",
        r"\{.*\}",
    ]
]

LOCAL_HOSTNAMES = {"localhost", "ip6-localhost", "ip6-loopback"}
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def validate_indicator(raw_value: str, forced_type: str = "Auto", allow_private_targets: bool = False) -> ValidationResult:
    """
    Validate and normalize a user-supplied OSINT indicator.

    Parameters
    ----------
    raw_value:
        User input.
    forced_type:
        One of: Auto, Domain, Username, Email, IP, URL.
    allow_private_targets:
        Whether private/local network targets should be accepted.
        This should remain False for public Spaces.

    Returns
    -------
    ValidationResult
        Structured validation result.
    """
    original_length = len(raw_value) if raw_value is not None else 0
    warnings: list[str] = []

    try:
        cleaned = sanitize_raw_input(raw_value)
        check_dangerous_patterns(cleaned)
        forced = normalize_forced_type(forced_type)

        if forced != "auto":
            indicator_type, normalized = validate_as_type(cleaned, forced, allow_private_targets)
        else:
            indicator_type, normalized = classify_auto(cleaned, allow_private_targets)

        if normalized != cleaned:
            warnings.append("Input was normalized before processing.")

        return ValidationResult(
            ok=True,
            indicator_type=indicator_type,
            normalized=normalized,
            original_length=original_length,
            warnings=warnings,
        )

    except ValidationException as exc:
        return ValidationResult(
            ok=False,
            indicator_type="unknown",
            normalized="",
            original_length=original_length,
            warnings=warnings,
            error=str(exc),
            error_code=exc.code,
        )


class ValidationException(ValueError):
    def __init__(self, message: str, code: ValidationErrorCode):
        super().__init__(message)
        self.code = code


def sanitize_raw_input(raw_value: str) -> str:
    if raw_value is None:
        raise ValidationException("Input is required.", ValidationErrorCode.EMPTY_INPUT)

    value = str(raw_value).strip()

    if not value:
        raise ValidationException("Input is empty.", ValidationErrorCode.EMPTY_INPUT)

    if CONTROL_CHARS_RE.search(value):
        raise ValidationException(
            "Input contains control characters.",
            ValidationErrorCode.CONTROL_CHARACTERS,
        )

    if len(value) > MAX_INPUT_LENGTH:
        raise ValidationException(
            f"Input exceeds {MAX_INPUT_LENGTH} characters.",
            ValidationErrorCode.TOO_LONG,
        )

    # Escape then unescape to normalize obvious HTML entity tricks without
    # returning an escaped value to downstream validators.
    escaped = html.escape(value, quote=True)
    return html.unescape(escaped).strip()


def check_dangerous_patterns(value: str) -> None:
    for pattern in DANGEROUS_PATTERNS:
        if pattern.search(value):
            raise ValidationException(
                "Input contains a blocked pattern.",
                ValidationErrorCode.BLOCKED_DANGEROUS_PATTERN,
            )


def normalize_forced_type(forced_type: str) -> str:
    value = (forced_type or "Auto").strip().lower()

    aliases = {
        "auto": "auto",
        "domain": "domain",
        "username": "username",
        "user": "username",
        "email": "email",
        "mail": "email",
        "ip": "ip",
        "ip address": "ip",
        "url": "url",
        "uri": "url",
    }

    if value not in aliases:
        raise ValidationException(
            f"Unsupported forced type: {forced_type}",
            ValidationErrorCode.INVALID_TYPE,
        )

    return aliases[value]


def classify_auto(value: str, allow_private_targets: bool) -> tuple[IndicatorType, str]:
    # URL first, because URLs can contain domains/IPs.
    if looks_like_url(value):
        return validate_url(value, allow_private_targets)

    # IP before domain.
    try:
        return validate_ip(value, allow_private_targets)
    except ValidationException:
        pass

    if "@" in value:
        return validate_email(value, allow_private_targets)

    if "." in value:
        return validate_domain(value, allow_private_targets)

    if USERNAME_RE.fullmatch(value):
        return validate_username(value, allow_private_targets)

    raise ValidationException(
        "Unsupported or malformed indicator.",
        ValidationErrorCode.UNSUPPORTED_INDICATOR,
    )


def validate_as_type(value: str, forced: str, allow_private_targets: bool) -> tuple[IndicatorType, str]:
    if forced == "domain":
        return validate_domain(value, allow_private_targets)
    if forced == "username":
        return validate_username(value, allow_private_targets)
    if forced == "email":
        return validate_email(value, allow_private_targets)
    if forced == "ip":
        return validate_ip(value, allow_private_targets)
    if forced == "url":
        return validate_url(value, allow_private_targets)

    raise ValidationException("Unsupported indicator type.", ValidationErrorCode.INVALID_TYPE)


def validate_domain(value: str, allow_private_targets: bool = False) -> tuple[IndicatorType, str]:
    domain = value.strip().lower().rstrip(".")

    if len(domain) > MAX_DOMAIN_LENGTH or not DOMAIN_RE.fullmatch(domain):
        raise ValidationException("Invalid domain.", ValidationErrorCode.INVALID_DOMAIN)

    labels = domain.split(".")
    for label in labels:
        if label.startswith("-") or label.endswith("-"):
            raise ValidationException("Invalid domain label.", ValidationErrorCode.INVALID_DOMAIN)

    if domain in LOCAL_HOSTNAMES and not allow_private_targets:
        raise ValidationException(
            "Local/private targets are blocked by policy.",
            ValidationErrorCode.BLOCKED_LOCAL_TARGET,
        )

    return "domain", domain


def validate_username(value: str, allow_private_targets: bool = False) -> tuple[IndicatorType, str]:
    del allow_private_targets

    username = value.strip()

    if len(username) > MAX_USERNAME_LENGTH or not USERNAME_RE.fullmatch(username):
        raise ValidationException("Invalid username.", ValidationErrorCode.INVALID_USERNAME)

    if username in {".", ".."}:
        raise ValidationException("Invalid username.", ValidationErrorCode.INVALID_USERNAME)

    return "username", username


def validate_email(value: str, allow_private_targets: bool = False) -> tuple[IndicatorType, str]:
    email = value.strip().lower()

    if len(email) > MAX_EMAIL_LENGTH or not EMAIL_RE.fullmatch(email):
        raise ValidationException("Invalid email address.", ValidationErrorCode.INVALID_EMAIL)

    local, domain = email.rsplit("@", 1)

    if len(local) > MAX_EMAIL_LOCAL_LENGTH:
        raise ValidationException("Invalid email local part.", ValidationErrorCode.INVALID_EMAIL)

    _, normalized_domain = validate_domain(domain, allow_private_targets)
    return "email", f"{local}@{normalized_domain}"


def validate_ip(value: str, allow_private_targets: bool = False) -> tuple[IndicatorType, str]:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValidationException("Invalid IP address.", ValidationErrorCode.INVALID_IP) from exc

    if not allow_private_targets and is_private_or_local_ip(ip):
        raise ValidationException(
            "Local/private targets are blocked by policy.",
            ValidationErrorCode.BLOCKED_LOCAL_TARGET,
        )

    return "ip", str(ip)


def validate_url(value: str, allow_private_targets: bool = False) -> tuple[IndicatorType, str]:
    if len(value) > MAX_URL_LENGTH:
        raise ValidationException("URL is too long.", ValidationErrorCode.TOO_LONG)

    parsed = urlparse(value.strip())

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValidationException(
            "Invalid URL. Only http:// and https:// URLs are supported.",
            ValidationErrorCode.INVALID_URL,
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValidationException("Invalid URL hostname.", ValidationErrorCode.INVALID_URL)

    hostname = hostname.lower().rstrip(".")

    if hostname in LOCAL_HOSTNAMES and not allow_private_targets:
        raise ValidationException(
            "Local/private targets are blocked by policy.",
            ValidationErrorCode.BLOCKED_LOCAL_TARGET,
        )

    # Validate hostname as IP or domain.
    try:
        _, normalized_host = validate_ip(hostname, allow_private_targets)
    except ValidationException:
        _, normalized_host = validate_domain(hostname, allow_private_targets)

    # Strip fragments. Fragments are client-side and not useful for passive OSINT hashing.
    normalized = urlunparse(
        (
            parsed.scheme.lower(),
            normalized_host if parsed.port is None else f"{normalized_host}:{parsed.port}",
            parsed.path or "",
            "",
            parsed.query or "",
            "",
        )
    )

    return "url", normalized


def looks_like_url(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith("http://") or lowered.startswith("https://")


def is_private_or_local_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or any(ip in net for net in PRIVATE_NETS)
    )


def assert_valid_or_raise(raw_value: str, forced_type: str = "Auto", allow_private_targets: bool = False) -> tuple[IndicatorType, str]:
    """
    Convenience helper for callers that prefer exceptions.
    """
    result = validate_indicator(raw_value, forced_type, allow_private_targets)
    if not result.ok:
        raise ValidationException(result.error or "Validation failed.", result.error_code or ValidationErrorCode.UNSUPPORTED_INDICATOR)
    return result.indicator_type, result.normalized
