# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this repository, do **not** open a public issue.

Use one of the following channels instead:

1. GitHub Security Advisories  
   Go to **Security → Report a vulnerability** in this repository.

2. Direct contact  
   Email: `security@example.com`

Replace the email above with the correct security contact before production use.

## Project Scope

This repository implements a passive, drift-aware OSINT control panel.

The system is designed around the following control path:

```text
Validation → Policy → Execution → Drift → Audit
```

The default operating mode is passive. Active interaction with user-provided targets must be gated by explicit authorization.

## In-Scope Vulnerabilities

High-priority reports include:

- Input validation or sanitisation bypass
- Raw indicator leakage before hashing
- `OSINT_HASH_SALT` or other secret exposure
- Authorization gate bypass
- Execution of conditional modules without approval
- Audit log tampering or deletion
- Policy mutation without out-of-band approval
- Drift detection manipulation that hides unsafe behavior
- Dependency behavior that creates structural drift or unsafe execution

Medium-priority reports include:

- Incorrect module risk classification
- Unsafe report generation
- Overly permissive source registry behavior
- Inconsistent correction-verb enforcement
- Unhandled exceptions that expose sensitive runtime details

Low-priority reports include:

- UI-only issues without security impact
- Non-sensitive error message quality
- Documentation inconsistencies

## Out of Scope

The following are not considered vulnerabilities in this repository:

- Issues in third-party OSINT services linked by the application
- Social engineering attacks
- Denial-of-service attempts
- Vulnerabilities requiring unauthorized access to third-party systems
- Reports involving active scanning or exploitation of targets not owned by the reporter
- Misuse of the tool by end users outside the intended authorization model

## Report Requirements

Please include:

- Summary of the issue
- Affected component, if known
- Steps to reproduce
- Expected behavior
- Actual behavior
- Security impact
- Safe proof of concept, if applicable
- Suggested mitigation, if known

Do not include real user data, secrets, unauthorized target data, destructive payloads, or exploit chains against third-party systems.

## Response Process

Expected response timeline:

- Acknowledgement: within 48 hours
- Initial triage: within 5 business days
- Fix plan: after validation and severity assessment
- Coordinated disclosure: if applicable

## Safe Harbor

Security research is welcome when performed in good faith.

You are expected to avoid privacy violations, avoid service degradation, avoid persistence or exfiltration, use only systems and data you are authorized to test, and stop testing if sensitive data is encountered.

## Automated Security Scanning

This repository uses **GitHub CodeQL** for continuous security analysis.

### What CodeQL Does

- Scans all Python code on push, pull request, and weekly schedule
- Detects security vulnerabilities including:
  - Command injection (CWE-078)
  - SQL injection (CWE-089)
  - XSS vulnerabilities (CWE-079)
  - Path traversal (CWE-022)
  - Input validation issues (CWE-020)
  - Cryptographic weaknesses (CWE-326, CWE-327)
  - Deserialization vulnerabilities (CWE-502)
- Provides alerts in the Security tab and PR checks

### Configuration

- **Workflow**: `.github/workflows/codeql.yml`
- **Config**: `.github/codeql/codeql-config.yml`
- **Documentation**: `.github/CODEQL.md`

### For Contributors

All code changes are automatically scanned. CodeQL findings must be:
- Reviewed before merge
- Fixed or dismissed with justification
- Never ignored without team approval

See `.github/CODEQL.md` for detailed guidance on responding to alerts.

## Security Architecture

This project treats security as a feedback circuit.

Core invariants:

```text
No raw indicators in audit logs.
No conditional modules without authorization.
No forbidden modules.
No policy mutation without out-of-band approval.
No correction outside the approved verbs: ADAPT, CONSTRAIN, REVERT, OBSERVE.
```

Reports that improve validation, policy enforcement, drift attribution, or audit integrity are especially valuable.
