---
title: Passive OSINT Control Panel
emoji: 🛰️
colorFrom: gray
colorTo: indigo
sdk: gradio
sdk_version: 6.13.0
app_file: app.py
pinned: false
license: apache-2.0
short_description: Drift-aware, passive OSINT control system.
---

<p align="center">
  <img src="https://img.shields.io/badge/Hugging%20Face-Space-yellow?logo=huggingface" alt="Hugging Face Space">
  <img src="https://img.shields.io/badge/SDK-Gradio%206.13.0-orange?logo=gradio" alt="Gradio SDK">
  <img src="https://img.shields.io/badge/Python-3.13-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/License-Apache--2.0-green" alt="Apache 2.0 License">
  <img src="https://img.shields.io/badge/Security-Policy-blue" alt="Security Policy">
  <img src="https://img.shields.io/badge/OSINT-Passive%20by%20Default-indigo" alt="Passive OSINT">
  <img src="https://img.shields.io/badge/Drift--Aware-Control%20Loop-purple" alt="Drift-Aware Control Loop">
</p>

![CI](https://github.com/YOUR_USERNAME/YOUR_REPO/actions/workflows/ci.yml/badge.svg)
![Sync](https://github.com/YOUR_USERNAME/YOUR_REPO/actions/workflows/sync-huggingface.yml/badge.svg)

# Passive OSINT Control Panel (Hugging Face Space)

## Overview
The Passive OSINT Control Panel is a controlled, security-first environment for conducting open-source intelligence (OSINT) enrichment. It is designed to operate as a passive system by default, generating intelligence from publicly available data sources without interacting directly with third-party infrastructure unless explicitly authorized.

The system is structured as a layered pipeline:

text Input → Validation → Sanitisation → Normalisation → Hashing → Passive Enrichment → Caching → Reporting → Audit Logging 

This architecture ensures that all inputs are treated as untrusted, all outputs are controlled, and all actions are traceable.

---

## Design Principles

1. Passive by Default  
No active probing, scanning, or intrusive techniques are executed unless explicitly enabled and authorized.

2. Input is Hostile  
All user input is validated, sanitised, normalized, and constrained before processing.

3. Privacy-Preserving  
Indicators are hashed using salted HMAC before logging or persistence. Raw sensitive values are minimized.

4. Explicit Authorization Gates  
Any module that may interact with external targets requires an explicit “authorized target” confirmation.

5. Deterministic & Auditable  
Every run is logged with reproducible inputs (hashed), module selections, and outputs.

6. Least Privilege Execution  
Modules are isolated and constrained by scope, rate limits, and timeouts.

---

## Features

### Passive OSINT Modules
- WHOIS lookup
- DNS resolution (A, MX, TXT, NS)
- Certificate Transparency (e.g., crt.sh links)
- Username footprint link generation
- Metadata extraction (user-uploaded files only)
- Robots.txt retrieval (authorized targets only)
- HTTP header inspection (authorized targets only)

### Core Capabilities
- Indicator normalization (domains, usernames, emails)
- Sanitisation and injection protection
- Salted HMAC hashing for all stored indicators
- Structured audit logging
- Markdown/JSON report generation
- Cached enrichment results
- Rate-limited execution

---

## System Architecture

text                 ┌────────────────────┐                 │       UI Layer     │                 │ (Gradio / Streamlit)                 └─────────┬──────────┘                           │                 ┌─────────▼──────────┐                 │ Input Validation    │                 │ & Sanitisation      │                 └─────────┬──────────┘                           │                 ┌─────────▼──────────┐                 │ Normalisation       │                 │ (domain/user/email) │                 └─────────┬──────────┘                           │                 ┌─────────▼──────────┐                 │ Hashing Layer       │                 │ (HMAC + Salt)       │                 └─────────┬──────────┘                           │                 ┌─────────▼──────────┐                 │ Enrichment Engine   │                 │ (Passive Modules)   │                 └─────────┬──────────┘                           │                 ┌─────────▼──────────┐                 │ Reporting Engine    │                 └─────────┬──────────┘                           │                 ┌─────────▼──────────┐                 │ Audit Log + Cache   │                 └────────────────────┘ 

---

## Security Controls

### Input Handling
- Length constraints
- Character whitelisting
- HTML escaping
- Control character removal
- Strict format validation (domains, usernames)

### Hashing Strategy
- HMAC-SHA256 with environment-provided salt
- Case-normalized inputs prior to hashing
- No storage of raw indicators unless required

### Secrets Management
- All secrets stored via Hugging Face Space Secrets
- No credentials committed to repository

### Execution Guardrails
- Rate limiting per request
- Per-module timeout enforcement
- Module allowlisting
- Authorization gating for external interaction

---

## Authorization Model

Modules are categorized by risk level:

text LOW RISK (Passive Only) - DNS - WHOIS - Certificate transparency - Link generation  CONDITIONAL (Requires Authorization) - HTTP headers - robots.txt retrieval - webpage screenshotting 

Authorization flow:

text User Input → Validation → Authorization Checkbox → Risk Disclosure → Module Execution (if approved) → Logged Outcome 

---

## Repository Structure

text . ├── app.py ├── requirements.txt ├── README.md ├── Dockerfile ├── data/ │   └── sources.yaml ├── osint_core/ │   ├── validators.py │   ├── sanitize.py │   ├── hashing.py │   ├── enrichment.py │   ├── reports.py │   ├── audit.py │   └── policy.py ├── tests/ │   ├── test_validators.py │   ├── test_sanitize.py │   ├── test_hashing.py │   └── test_enrichment.py 

---

## Installation & Deployment

### Local Development

bash git clone <repo> cd osint-control-panel pip install -r requirements.txt export OSINT_HASH_SALT="your-secure-random-salt" python app.py 

### Hugging Face Space Deployment

1. Create a new Space (Gradio SDK recommended)
2. Push repository
3. Configure Secrets:
   - OSINT_HASH_SALT
   - Any API tokens (optional)
4. Select hardware tier (CPU sufficient for passive mode)

---

## Testing & Assurance

### Test Stack

bash pytest bandit -r osint_core/ ruff check . pip-audit 

### Coverage Areas
- Input validation rejection cases
- Sanitisation correctness
- Hash consistency and salt variation
- Module output structure
- Authorization enforcement

---

## Logging & Audit

Each run produces a structured record:

json {   "timestamp": "ISO8601",   "run_id": "unique_case_id",   "input_type": "domain|username|email",   "indicator_hash": "HMAC_SHA256",   "modules": ["dns", "whois"],   "mode": "passive|authorized",   "authorized_target": false,   "duration_ms": 320 } 

Logs are designed for:
- Reproducibility
- Forensic traceability
- Compliance review

---

## Reporting

Outputs can be exported as:
- Markdown reports
- JSON structured data
- CSV summaries

Report sections:
- Input summary (hashed)
- Enrichment findings
- Source links
- Timeline (if applicable)
- Notes

---

## Phase 2: Docker Module Expansion

Docker-based modules enable controlled extension of capabilities under strict authorization.

### Additional Controls
- Container isolation
- Network egress restriction
- Execution sandboxing
- Resource quotas (CPU/memory)
- Explicit module activation

### Allowed Extensions
- Metadata extraction pipelines
- Screenshot rendering
- Technology fingerprinting (authorized targets only)
- Graph analysis

### Explicitly Excluded
- Port scanning (e.g., nmap)
- Mass scanning (e.g., masscan)
- Brute force tools
- Exploitation frameworks

---

## Compliance & Usage Policy

This system is intended strictly for:
- Lawful OSINT research
- Defensive security analysis
- Educational purposes

Users are responsible for:
- Ensuring authorization before interacting with targets
- Complying with applicable laws and policies
- Avoiding misuse of generated intelligence

---

## Roadmap

text v1.0 - Passive control panel - Core enrichment modules - Hashing + audit system  v1.1 - Graph visualization - Case persistence  v2.0 - Docker modules - Authorization workflow - Advanced reporting  v2.1 - API interface - MCP integration 

---

## License
Specify appropriate license (e.g., MIT, Apache 2.0)

---

## Final Notes
This system is intentionally constrained. Its purpose is not to maximize data extraction, but to maximize signal integrity, safety, and reproducibility.

Treat it as an intelligence circuit:
inputs are normalized, processed through bounded modules, and emitted as structured insight—without uncontrolled side effects.