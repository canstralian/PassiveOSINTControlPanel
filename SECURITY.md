# Security Policy

## Reporting a Vulnerability

If you believe you have discovered a security vulnerability in this repository, please do **not** open a public issue, discussion, or pull request describing the vulnerability.

Use a private reporting channel instead:

1. **GitHub Private Vulnerability Reporting**  
   Go to **Security → Report a vulnerability** in this repository, if available.

2. **Direct security contact**  
   Email: `security@yourdomain.com`

Replace the email address above with the correct production security contact before publishing this repository.

## Project Scope

This repository implements a passive, drift-aware OSINT control panel.

The system is designed around the following control path:

```text
Validation → Policy → Execution → Drift → Audit
````

The default operating mode is passive. Any active interaction with a user-provided target must be explicitly authorized before execution.

Security reports are most valuable when they help strengthen validation, authorization, policy enforcement, drift detection, audit integrity, or safe handling of indicators.

## Security Model

The project is built around the following invariants:

```text
No raw indicators in audit logs.
No conditional modules without explicit authorization.
No forbidden modules.
No policy mutation without out-of-band approval.
No correction outside the approved verbs: ADAPT, CONSTRAIN, REVERT, OBSERVE.
```

The intended trust boundary is:

```text
User Input → Validation → Policy Decision → Approved Execution → Drift Check → Audit Record
```

Any bypass, mutation, or unsafe shortcut in this chain may be security-relevant.

## In-Scope Vulnerabilities

High-priority reports include:

* Input validation or sanitization bypass
* Raw indicator leakage before hashing or redaction
* Exposure of `OSINT_HASH_SALT` or other secrets
* Authorization gate bypass
* Execution of conditional modules without approval
* Audit log tampering, deletion, or suppression
* Policy mutation without out-of-band approval
* Drift detection manipulation that hides unsafe behavior
* Introduction of forbidden modules or active tooling
* Dependency behavior that causes unsafe execution or structural drift

Medium-priority reports include:

* Incorrect module risk classification
* Unsafe report generation
* Overly permissive source registry behavior
* Inconsistent correction-verb enforcement
* Unhandled exceptions that expose sensitive runtime details
* Incomplete audit records for security-relevant actions
* Configuration behavior that weakens passive-first guarantees

Low-priority reports include:

* UI-only issues without security impact
* Non-sensitive error message quality
* Documentation inconsistencies
* Minor logging or formatting issues that do not affect audit integrity

## Out of Scope

The following are not considered vulnerabilities in this repository:

* Issues in third-party OSINT services linked by the application
* Social engineering attacks
* Denial-of-service attempts
* Physical attacks
* Spam or phishing reports unrelated to this codebase
* Vulnerabilities requiring unauthorized access to third-party systems
* Reports involving active scanning or exploitation of targets not owned or explicitly controlled by the reporter
* Misuse of the tool by end users outside the intended authorization model
* Findings based only on hypothetical impact without a realistic path to exploitation

## Testing Rules

Security testing must be safe, authorized, and non-destructive.

Do not:

* Use real user data
* Submit secrets, credentials, or unauthorized target data
* Perform active scanning against third-party systems
* Attempt persistence, privilege escalation, or data exfiltration
* Degrade service availability
* Run destructive payloads
* Chain exploits against systems outside your authorization scope

If sensitive data is encountered during testing, stop immediately and report the exposure through a private channel.

## Report Requirements

Please include as much of the following as possible:

* Summary of the issue
* Affected component, file, or control path
* Steps to reproduce
* Expected behavior
* Actual behavior
* Security impact
* Safe proof of concept, if applicable
* Suggested mitigation, if known
* Whether the issue affects validation, policy, execution, drift detection, or audit integrity

Please avoid including real user data, live secrets, unauthorized target data, destructive payloads, or exploit chains against third-party systems.

## Response Process

Expected response timeline:

* **Acknowledgement:** within 48 hours
* **Initial triage:** within 5 business days
* **Severity assessment:** after reproduction and impact review
* **Fix plan:** after validation of the issue
* **Coordinated disclosure:** when applicable

Timelines may vary depending on complexity, severity, and maintainer availability.

## Coordinated Disclosure

Please give the maintainers reasonable time to investigate and remediate confirmed vulnerabilities before public disclosure.

If a vulnerability affects users, deployment safety, secrets, or audit integrity, coordinated disclosure may include:

* Patch development
* Regression tests
* Security advisory publication
* Versioned release notes
* Mitigation guidance

## Safe Harbor

Good-faith security research is welcome when it follows this policy.

The project will not pursue action against researchers who:

* Act in good faith
* Stay within authorized scope
* Avoid privacy violations
* Avoid service degradation
* Avoid persistence or exfiltration
* Report vulnerabilities promptly and privately
* Stop testing if sensitive data is encountered

Safe harbor does not apply to activity that targets third-party systems without authorization, uses destructive techniques, or attempts to access, retain, or disclose data that does not belong to the researcher.

## Preferred Areas of Review

Reports are especially useful when they improve:

* Indicator validation
* Hashing and redaction behavior
* Authorization gating
* Passive-first enforcement
* Conditional module controls
* Source registry constraints
* Drift attribution
* Audit log integrity
* Policy mutation safeguards
* Dependency and supply-chain safety

## Security Contact

Primary security contact:

```text
distortedprojection@gmail.com
```

```
```
