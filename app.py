"""
Passive OSINT Control Panel
Drift-aware, passive-first OSINT enrichment interface for Hugging Face Spaces.

Design constraints:
- Passive by default.
- No scanning, brute forcing, exploitation, or credential testing.
- All inputs are validated, sanitised, normalised, and hashed before audit logging.
- Modules that touch a user-provided target require explicit authorization.
- Correction verbs are limited to: ADAPT, CONSTRAIN, REVERT.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import socket
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote_plus, urlparse

import gradio as gr

# Import new drift and baseline modules
from osint_core.baseline import load_baseline, update_baseline
from osint_core.drift import (
    DriftAssessment,
    DriftVector,
    TelemetrySnapshot,
    assess_drift,
)


# =============================================================================
# Runtime configuration
# =============================================================================

APP_NAME = "Passive OSINT Control Panel"
APP_VERSION = "0.1.0"

BASE_DIR = Path(__file__).resolve().parent
RUNS_DIR = BASE_DIR / "runs"
REPORTS_DIR = RUNS_DIR / "reports"
AUDIT_DIR = RUNS_DIR / "audit"

for directory in (RUNS_DIR, REPORTS_DIR, AUDIT_DIR):
    directory.mkdir(parents=True, exist_ok=True)

MAX_INPUT_LENGTH = 256
NETWORK_TIMEOUT_SECONDS = 4.0

CorrectionVerb = Literal["ADAPT", "CONSTRAIN", "REVERT", "OBSERVE"]
RiskTier = Literal["T1", "T2", "T3", "T4"]
IndicatorType = Literal["domain", "username", "email", "ip", "url", "unknown"]


# =============================================================================
# Source registry
# =============================================================================

OSINT_LINKS: dict[str, list[dict[str, str]]] = {
    "domain": [
        {
            "name": "crt.sh",
            "url": "https://crt.sh/?q={query}",
            "description": "Certificate Transparency search",
        },
        {
            "name": "SecurityTrails",
            "url": "https://securitytrails.com/domain/{query}/dns",
            "description": "DNS and historical domain intelligence",
        },
        {
            "name": "URLScan",
            "url": "https://urlscan.io/search/#{query}",
            "description": "Public URL scan search",
        },
        {
            "name": "VirusTotal",
            "url": "https://www.virustotal.com/gui/domain/{query}",
            "description": "Public domain reputation lookup",
        },
        {
            "name": "Wayback Machine",
            "url": "https://web.archive.org/web/*/{query}",
            "description": "Archived pages",
        },
    ],
    "username": [
        {
            "name": "WhatsMyName",
            "url": "https://whatsmyname.app/?q={query}",
            "description": "Username presence search",
        },
        {
            "name": "Namechk",
            "url": "https://namechk.com/{query}",
            "description": "Username availability and footprinting",
        },
        {
            "name": "GitHub",
            "url": "https://github.com/{query}",
            "description": "GitHub profile lookup",
        },
        {
            "name": "Reddit",
            "url": "https://www.reddit.com/user/{query}",
            "description": "Reddit profile lookup",
        },
    ],
    "email": [
        {
            "name": "Have I Been Pwned",
            "url": "https://haveibeenpwned.com/",
            "description": "Manual breach exposure check",
        },
        {
            "name": "EmailRep",
            "url": "https://emailrep.io/query/{query}",
            "description": "Email reputation lookup",
        },
    ],
    "ip": [
        {
            "name": "AbuseIPDB",
            "url": "https://www.abuseipdb.com/check/{query}",
            "description": "IP abuse reputation",
        },
        {
            "name": "VirusTotal",
            "url": "https://www.virustotal.com/gui/ip-address/{query}",
            "description": "Public IP reputation lookup",
        },
        {
            "name": "Shodan",
            "url": "https://www.shodan.io/host/{query}",
            "description": "Public internet exposure data",
        },
    ],
    "url": [
        {
            "name": "URLScan",
            "url": "https://urlscan.io/search/#{query}",
            "description": "Public URL scan search",
        },
        {
            "name": "VirusTotal",
            "url": "https://www.virustotal.com/gui/search/{query}",
            "description": "Public URL reputation lookup",
        },
        {
            "name": "Wayback Machine",
            "url": "https://web.archive.org/web/*/{query}",
            "description": "Archived page history",
        },
    ],
}


# =============================================================================
# Data models
# =============================================================================

@dataclass
class Manifest:
    artifact_id: str
    version: str
    assumptions: list[str]
    invariants: list[str]
    tier: RiskTier
    manifest_hash: str


@dataclass
class TelemetryEvent:
    run_id: str
    timestamp: str
    artifact_id: str
    manifest_hash: str
    indicator_type: IndicatorType
    indicator_hash: str
    authorized_target: bool
    modules_requested: list[str]
    modules_executed: list[str]
    modules_blocked: list[str]
    drift_vector: dict[str, float]
    correction_verb: CorrectionVerb
    duration_ms: int
    errors: list[str]


@dataclass
class EnrichmentResult:
    run_id: str
    indicator_type: IndicatorType
    normalized_indicator: str
    indicator_hash: str
    links_markdown: str
    passive_results: dict[str, Any]
    drift_vector: dict[str, float]
    correction_verb: CorrectionVerb
    report_path: str
    audit_path: str
    errors: list[str]
    drift_assessment: DriftAssessment | None = None  # New field for full drift details


# =============================================================================
# Manifest and hashing
# =============================================================================

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_hash_salt() -> str:
    """
    Use OSINT_HASH_SALT in production.
    In local/dev mode, allow a deterministic fallback only when explicitly enabled.
    """
    salt = os.getenv("OSINT_HASH_SALT")
    if salt:
        return salt

    if os.getenv("ALLOW_DEV_SALT", "").lower() == "true":
        return "dev-only-change-me"

    raise RuntimeError(
        "Missing OSINT_HASH_SALT. Add it as a Hugging Face Space Secret. "
        "For local testing only, set ALLOW_DEV_SALT=true."
    )


def hmac_sha256(value: str) -> str:
    salt = get_hash_salt()
    return hmac.new(
        salt.encode("utf-8"),
        value.strip().lower().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def make_manifest() -> Manifest:
    assumptions = [
        "OSINT activity is passive unless authorization is explicitly provided.",
        "Raw indicators are not written to audit logs.",
        "External target interaction requires authorized_target=True.",
        "All mutation decisions route through Correction verbs.",
    ]
    invariants = [
        "Reject unsupported or malformed inputs.",
        "Escape HTML and remove control characters.",
        "Hash indicators before audit persistence.",
        "Block authorized-only modules without explicit confirmation.",
    ]
    body = {
        "artifact_id": "passive_osint_control_panel",
        "version": APP_VERSION,
        "assumptions": assumptions,
        "invariants": invariants,
        "tier": "T2",
    }
    manifest_hash = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    return Manifest(
        artifact_id=body["artifact_id"],
        version=body["version"],
        assumptions=assumptions,
        invariants=invariants,
        tier="T2",
        manifest_hash=manifest_hash,
    )


MANIFEST = make_manifest()
BASELINE = load_baseline()  # Load baseline for drift detection


# =============================================================================
# Validation and sanitisation
# =============================================================================

CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{2,64}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,63}$")


def sanitize_text(value: str) -> str:
    if value is None:
        raise ValueError("Input is required.")

    value = str(value).strip()
    value = CONTROL_CHARS.sub("", value)
    value = html.escape(value, quote=True)

    if not value:
        raise ValueError("Input is empty.")

    if len(value) > MAX_INPUT_LENGTH:
        raise ValueError(f"Input exceeds {MAX_INPUT_LENGTH} characters.")

    return value


def classify_and_normalize(raw_value: str, forced_type: str = "Auto") -> tuple[IndicatorType, str]:
    safe = sanitize_text(raw_value)
    candidate = html.unescape(safe).strip()

    if forced_type != "Auto":
        wanted = forced_type.lower()
        return validate_as_type(candidate, wanted)

    # URL
    parsed = urlparse(candidate)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        host = parsed.netloc.lower()
        return "url", f"{parsed.scheme.lower()}://{host}{parsed.path or ''}"

    # IP
    try:
        return "ip", str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    # Email
    lowered = candidate.lower()
    if EMAIL_RE.fullmatch(lowered):
        return "email", lowered

    # Domain
    domain = lowered.rstrip(".")
    if DOMAIN_RE.fullmatch(domain):
        return "domain", domain

    # Username
    if USERNAME_RE.fullmatch(candidate):
        return "username", candidate

    raise ValueError(
        "Unsupported or malformed indicator. Supported types: domain, username, email, IP, URL."
    )


def validate_as_type(candidate: str, wanted: str) -> tuple[IndicatorType, str]:
    if wanted == "domain":
        domain = candidate.lower().rstrip(".")
        if DOMAIN_RE.fullmatch(domain):
            return "domain", domain
        raise ValueError("Invalid domain.")

    if wanted == "username":
        if USERNAME_RE.fullmatch(candidate):
            return "username", candidate
        raise ValueError("Invalid username.")

    if wanted == "email":
        lowered = candidate.lower()
        if EMAIL_RE.fullmatch(lowered):
            return "email", lowered
        raise ValueError("Invalid email.")

    if wanted == "ip":
        try:
            return "ip", str(ipaddress.ip_address(candidate))
        except ValueError as exc:
            raise ValueError("Invalid IP address.") from exc

    if wanted == "url":
        parsed = urlparse(candidate)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return "url", f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path or ''}"
        raise ValueError("Invalid URL. Only http:// and https:// are supported.")

    raise ValueError("Unknown indicator type.")


# =============================================================================
# Passive modules
# =============================================================================

AUTHORIZED_ONLY_MODULES = {
    "HTTP Headers",
    "Robots.txt",
}

PASSIVE_MODULES = {
    "Resource Links",
    "DNS Records",
    "Local URL Parse",
    "HTTP Headers",
    "Robots.txt",
}


def build_links(indicator_type: IndicatorType, normalized: str) -> str:
    links = OSINT_LINKS.get(indicator_type, [])
    if not links:
        return "_No source links registered for this indicator type._"

    query = quote_plus(normalized)
    rows = []
    for source in links:
        url = source["url"].replace("{query}", query)
        rows.append(f"- [{source['name']}]({url}) — {source['description']}")
    return "\n".join(rows)


def resolve_dns(domain: str) -> dict[str, Any]:
    """
    Uses local resolver. This is passive/low-impact but still a network lookup.
    """
    result: dict[str, Any] = {"A": [], "AAAA": [], "MX": [], "NS": []}

    try:
        socket.setdefaulttimeout(NETWORK_TIMEOUT_SECONDS)
        for family, key in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
            try:
                records = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
                result[key] = sorted({record[4][0] for record in records})
            except socket.gaierror:
                result[key] = []
    except Exception as exc:
        result["error"] = str(exc)

    return result


def parse_url_locally(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    return {
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "path": parsed.path,
        "query_present": bool(parsed.query),
        "fragment_present": bool(parsed.fragment),
    }


def fetch_http_headers(url_or_domain: str) -> dict[str, Any]:
    """
    Conditional module. Requires explicit authorization.
    Uses Python stdlib sockets? To avoid extra dependency, only emit a safe placeholder.
    Add httpx to requirements.txt and implement a bounded HEAD request if desired.
    """
    return {
        "status": "not_implemented",
        "reason": "HTTP header fetching is gated and intentionally stubbed in the base app. "
        "Implement with httpx only after authorization/rate-limit review.",
    }


def fetch_robots(url_or_domain: str) -> dict[str, Any]:
    return {
        "status": "not_implemented",
        "reason": "robots.txt retrieval is gated and intentionally stubbed in the base app.",
    }


# =============================================================================
# Reporting and audit
# =============================================================================

def write_audit(event: TelemetryEvent) -> Path:
    path = AUDIT_DIR / f"{event.run_id}.json"
    path.write_text(json.dumps(asdict(event), indent=2, sort_keys=True), encoding="utf-8")
    return path


def write_report(result: EnrichmentResult, manifest: Manifest) -> Path:
    path = REPORTS_DIR / f"{result.run_id}.md"

    passive_json = json.dumps(result.passive_results, indent=2, sort_keys=True)
    drift_json = json.dumps(result.drift_vector, indent=2, sort_keys=True)

    body = f"""# Passive OSINT Report

## Run

- Run ID: `{result.run_id}`
- Timestamp: `{now_utc()}`
- Indicator Type: `{result.indicator_type}`
- Indicator Hash: `{result.indicator_hash}`
- Correction Verb: `{result.correction_verb}`

## Manifest

- Artifact: `{manifest.artifact_id}`
- Version: `{manifest.version}`
- Manifest Hash: `{manifest.manifest_hash}`
- Tier: `{manifest.tier}`

## Source Links

{result.links_markdown}

## Passive Results

```json
{passive_json}
```

## Drift Vector

```json
{drift_json}
```

## Errors

{chr(10).join(f"- {error}" for error in result.errors) if result.errors else "- None"}
"""

    path.write_text(body, encoding="utf-8")
    return path


def format_result_markdown(result: EnrichmentResult) -> str:
    passive_json = json.dumps(result.passive_results, indent=2, sort_keys=True)
    drift_json = json.dumps(result.drift_vector, indent=2, sort_keys=True)

    # Format drift signals if available
    drift_details = ""
    if result.drift_assessment:
        assessment = result.drift_assessment

        # Dominant type and confidence
        dominant_str = assessment.dominant_type.value if assessment.dominant_type else "None"
        drift_details = f"""
### Drift Analysis

**Dominant Drift Type:** {dominant_str}
**Confidence:** {assessment.confidence:.2f}
**Recommended Correction:** {assessment.recommended_correction}

"""

        # Drift signals
        if assessment.signals:
            drift_details += "**Drift Signals Detected:**\n\n"
            for signal in assessment.signals:
                drift_details += f"- **{signal.name}** [{signal.tier}]\n"
                drift_details += f"  - Type: {signal.drift_type.value}\n"
                drift_details += f"  - Score: {signal.score:.2f}\n"
                drift_details += f"  - Reason: {signal.reason}\n"
                if signal.evidence:
                    drift_details += f"  - Evidence: {json.dumps(signal.evidence, sort_keys=True)}\n"
                drift_details += "\n"
        else:
            drift_details += "**Drift Signals:** None (clean execution)\n\n"

    return f"""
## Result

**Run ID:** `{result.run_id}`
**Type:** `{result.indicator_type}`
**Indicator Hash:** `{result.indicator_hash}`
**Correction:** `{result.correction_verb}`

### Source Links

{result.links_markdown}

### Passive Results

```json
{passive_json}
```

### Drift Vector

```json
{drift_json}
```

{drift_details}### Logs

- Audit: `{result.audit_path}`
- Report: `{result.report_path}`

### Errors

{chr(10).join(f"- {error}" for error in result.errors) if result.errors else "- None"}
"""


# =============================================================================
# Main orchestration
# =============================================================================

def run_enrichment(
    raw_indicator: str,
    forced_type: str,
    selected_modules: list[str],
    authorized_target: bool,
) -> tuple[str, str | None, str | None]:
    started = time.perf_counter()
    run_id = f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

    errors: list[str] = []
    modules_executed: list[str] = []
    modules_blocked: list[str] = []
    passive_results: dict[str, Any] = {}

    try:
        indicator_type, normalized = classify_and_normalize(raw_indicator, forced_type)
        indicator_hash = hmac_sha256(normalized)
    except Exception as exc:
        return f"## Input rejected\n\n{str(exc)}", None, None

    selected_modules = selected_modules or ["Resource Links"]

    # Authorization gate
    for module in selected_modules:
        if module in AUTHORIZED_ONLY_MODULES and not authorized_target:
            modules_blocked.append(module)

    executable_modules = [m for m in selected_modules if m not in modules_blocked]

    links_markdown = ""
    if "Resource Links" in executable_modules:
        links_markdown = build_links(indicator_type, normalized)
        modules_executed.append("Resource Links")
    else:
        links_markdown = "_Resource link generation not selected._"

    if "DNS Records" in executable_modules:
        if indicator_type == "domain":
            passive_results["dns"] = resolve_dns(normalized)
            modules_executed.append("DNS Records")
        else:
            errors.append("DNS Records module requires a domain indicator.")

    if "Local URL Parse" in executable_modules:
        if indicator_type == "url":
            passive_results["url_parse"] = parse_url_locally(normalized)
            modules_executed.append("Local URL Parse")
        else:
            errors.append("Local URL Parse module requires a URL indicator.")

    if "HTTP Headers" in executable_modules:
        passive_results["http_headers"] = fetch_http_headers(normalized)
        modules_executed.append("HTTP Headers")

    if "Robots.txt" in executable_modules:
        passive_results["robots"] = fetch_robots(normalized)
        modules_executed.append("Robots.txt")

    if modules_blocked:
        errors.append(
            "Blocked authorized-only module(s): "
            + ", ".join(modules_blocked)
            + ". Confirm target authorization to enable them."
        )

    duration_ms = int((time.perf_counter() - started) * 1000)

    # Compute output hash for behavioral drift detection
    output_data = json.dumps({
        "links": links_markdown,
        "passive_results": passive_results,
        "modules_executed": sorted(modules_executed),
    }, sort_keys=True)
    output_hash = hashlib.sha256(output_data.encode()).hexdigest()

    # Create telemetry snapshot for drift assessment
    telemetry = TelemetrySnapshot(
        run_id=run_id,
        manifest_hash=MANIFEST.manifest_hash,
        dependency_hash=MANIFEST.dependency_hash,
        runtime_python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        indicator_hash=indicator_hash,
        indicator_type=indicator_type,
        input_rejected=False,
        rejection_reason="",
        sanitized_input_trace=normalized,
        modules_requested=selected_modules,
        modules_executed=modules_executed,
        modules_blocked=modules_blocked,
        authorized_target=authorized_target,
        duration_ms=duration_ms,
        error_count=len(errors),
        timeout_count=0,
        output_hash=output_hash,
        output_schema_valid=True,
    )

    # Policy result for drift assessment
    policy_result = {
        "decision": "constrain" if modules_blocked else "allow",
        "allowed_modules": modules_executed,
        "blocked_modules": modules_blocked,
        "violations": [
            {"code": "authorization_required", "message": f"Authorization required for module: {m}", "module": m}
            for m in modules_blocked
        ] if modules_blocked else [],
    }

    # Assess drift using new drift detection system
    global BASELINE
    drift_assessment = assess_drift(telemetry, BASELINE, policy_result)

    # Update baseline only for adaptive outcomes so revert/constrain-class drift
    # cannot be learned into the baseline.
    if drift_assessment.recommended_correction == "ADAPT":
        BASELINE = update_baseline(BASELINE, telemetry, drift_assessment)

    # Extract drift vector as dict for backward compatibility with existing TelemetryEvent
    drift = {
        "statistical": drift_assessment.drift_vector.statistical,
        "behavioral": drift_assessment.drift_vector.behavioral,
        "structural": drift_assessment.drift_vector.structural,
        "adversarial": drift_assessment.drift_vector.adversarial,
        "operational": drift_assessment.drift_vector.operational,
        "policy": drift_assessment.drift_vector.policy,
    }
    correction = drift_assessment.recommended_correction

    event = TelemetryEvent(
        run_id=run_id,
        timestamp=now_utc(),
        artifact_id=MANIFEST.artifact_id,
        manifest_hash=MANIFEST.manifest_hash,
        indicator_type=indicator_type,
        indicator_hash=indicator_hash,
        authorized_target=authorized_target,
        modules_requested=selected_modules,
        modules_executed=modules_executed,
        modules_blocked=modules_blocked,
        drift_vector=drift,
        correction_verb=correction,
        duration_ms=duration_ms,
        errors=errors,
    )
    audit_path = write_audit(event)

    result = EnrichmentResult(
        run_id=run_id,
        indicator_type=indicator_type,
        normalized_indicator="[redacted]",
        indicator_hash=indicator_hash,
        links_markdown=links_markdown,
        passive_results=passive_results,
        drift_vector=drift,
        correction_verb=correction,
        report_path="",
        audit_path=str(audit_path),
        errors=errors,
        drift_assessment=drift_assessment,  # Pass full drift assessment
    )
    report_path = write_report(result, MANIFEST)
    result.report_path = str(report_path)

    return format_result_markdown(result), str(report_path), str(audit_path)


def export_audit_index() -> str | None:
    audit_files = sorted(AUDIT_DIR.glob("*.json"))
    if not audit_files:
        return None

    csv_path = RUNS_DIR / "audit_index.csv"

    rows = []
    for path in audit_files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            rows.append(
                {
                    "timestamp": data.get("timestamp"),
                    "run_id": data.get("run_id"),
                    "artifact_id": data.get("artifact_id"),
                    "indicator_type": data.get("indicator_type"),
                    "indicator_hash": data.get("indicator_hash"),
                    "authorized_target": data.get("authorized_target"),
                    "correction_verb": data.get("correction_verb"),
                    "duration_ms": data.get("duration_ms"),
                }
            )
        except Exception:
            continue

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    return str(csv_path)


def show_manifest() -> str:
    return f"""```json
{json.dumps(asdict(MANIFEST), indent=2, sort_keys=True)}
```"""


# =============================================================================
# Gradio UI
# =============================================================================

DESCRIPTION = """
This Space is a passive, drift-aware OSINT control panel.

It validates, sanitises, normalises, and hashes indicators before audit persistence.
Authorized-only modules are blocked unless explicitly confirmed.
Correction decisions are limited to ADAPT, CONSTRAIN, REVERT, or OBSERVE.
"""

with gr.Blocks(title=APP_NAME) as demo:
    gr.Markdown(f"# {APP_NAME}")
    gr.Markdown(DESCRIPTION)

    with gr.Tab("Control Panel"):
        with gr.Row():
            raw_indicator = gr.Textbox(
                label="Indicator",
                placeholder="example.com, username, user@example.com, 8.8.8.8, https://example.com/path",
                max_lines=1,
            )
            forced_type = gr.Dropdown(
                ["Auto", "Domain", "Username", "Email", "IP", "URL"],
                value="Auto",
                label="Indicator Type",
            )

        selected_modules = gr.CheckboxGroup(
            choices=sorted(PASSIVE_MODULES),
            value=["Resource Links"],
            label="Modules",
        )

        authorized_target = gr.Checkbox(
            label="I confirm this target is authorized for conditional interaction",
            value=False,
        )

        run_button = gr.Button("Run Passive Enrichment", variant="primary")

        output = gr.Markdown(label="Output")
        report_file = gr.File(label="Markdown Report")
        audit_file = gr.File(label="Audit JSON")

        run_button.click(
            fn=run_enrichment,
            inputs=[raw_indicator, forced_type, selected_modules, authorized_target],
            outputs=[output, report_file, audit_file],
        )

    with gr.Tab("Manifest"):
        gr.Markdown(
            "The manifest declares the assumptions and invariants this artifact was built under."
        )
        manifest_output = gr.Markdown(value=show_manifest())

    with gr.Tab("Audit Export"):
        gr.Markdown("Export a CSV index of audit records. Raw indicators are not included.")
        export_button = gr.Button("Export Audit Index")
        audit_index_file = gr.File(label="Audit Index CSV")
        export_button.click(fn=export_audit_index, inputs=[], outputs=[audit_index_file])

    with gr.Tab("Policy"):
        gr.Markdown(
            """
## Operating Policy

- Passive by default.
- No scanning, brute forcing, exploitation, credential testing, or directory fuzzing.
- No raw indicators in audit logs.
- Authorized-only modules require explicit confirmation.
- Correction is the only state mutation authority.
- Correction cannot rewrite its own policy.

## Correction Verbs

- **ADAPT**: assumptions may be safely updated.
- **CONSTRAIN**: reduce capability under uncertainty or adversarial pressure.
- **REVERT**: restore prior known-good state.
- **OBSERVE**: log only; no mutation.
"""
        )


if __name__ == "__main__":
    demo.launch()
