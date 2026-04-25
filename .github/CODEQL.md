# CodeQL Security Analysis

This repository is configured with GitHub CodeQL for automated security vulnerability scanning.

## Overview

CodeQL is GitHub's semantic code analysis engine that treats code as data, allowing it to find security vulnerabilities, bugs, and code quality issues. For this security-focused OSINT project, CodeQL provides continuous security analysis of the Python codebase.

## Configuration

### Workflow: `.github/workflows/codeql.yml`

The CodeQL workflow runs automatically on:
- **Push to main branch**: Scans all code changes merged to main
- **Pull requests**: Scans changes in PRs before they're merged
- **Weekly schedule**: Runs every Monday at 3:00 AM UTC for periodic security review
- **Manual trigger**: Can be run manually via workflow_dispatch

### Configuration File: `.github/codeql/codeql-config.yml`

The custom configuration focuses on:
- **Security-extended queries**: Comprehensive security analysis
- **Security-and-quality queries**: Additional quality and security checks
- **Targeted paths**: Analyzes `osint_core/`, `agent/`, and `app.py`
- **Path exclusions**: Skips tests, documentation, and data files
- **CWE-focused filtering**: Prioritizes critical security issues including:
  - CWE-079: Cross-site Scripting (XSS)
  - CWE-089: SQL Injection
  - CWE-078: OS Command Injection
  - CWE-022: Path Traversal
  - CWE-020: Improper Input Validation
  - CWE-327: Use of Broken Cryptography
  - CWE-502: Deserialization Vulnerabilities
  - CWE-326: Inadequate Encryption Strength

## Why These Checks Matter for This Project

This Passive OSINT Control Panel handles:
- **Untrusted user input**: Domain names, usernames, emails
- **External system interaction**: DNS queries, WHOIS lookups, HTTP requests
- **Sensitive operations**: HMAC hashing, audit logging, file handling
- **Security boundaries**: Authorization gates, passive-only enforcement

CodeQL helps ensure:
1. **Input validation is robust**: Prevents injection attacks
2. **Cryptographic operations are secure**: Validates HMAC and hashing implementations
3. **Command execution is safe**: Detects potential command injection
4. **File operations are bounded**: Prevents path traversal
5. **Authentication gates work correctly**: Ensures authorization checks aren't bypassed

## Viewing Results

### In Pull Requests
CodeQL findings appear as:
- Check runs in the PR status
- Code scanning alerts with inline annotations
- Security tab alerts (if enabled)

### In the Security Tab
Navigate to: **Repository → Security → Code scanning alerts**

Filter by:
- **Severity**: Critical, High, Medium, Low
- **Status**: Open, Fixed, Dismissed
- **Tool**: CodeQL
- **Branch**: main, PR branches

## Responding to Alerts

When CodeQL finds an issue:

1. **Review the alert**: Understand the data flow and potential impact
2. **Assess severity**: Is this a true positive or false positive?
3. **Fix or dismiss**:
   - **Fix**: Submit a PR with the remediation
   - **Dismiss**: If it's a false positive, dismiss with justification
4. **Test**: Ensure the fix doesn't break existing functionality

### Example Alert Types You Might See

- **Uncontrolled command execution**: Subprocess calls with unsanitized input
- **Clear-text storage of sensitive information**: Logging raw indicators instead of hashes
- **Incomplete sanitization**: Validation bypasses in input handling
- **Hardcoded credentials**: API keys or secrets in code
- **Use of weak cryptography**: Non-standard hashing approaches

## Local CodeQL Analysis (Optional)

To run CodeQL locally:

```bash
# Install CodeQL CLI
# Download from: https://github.com/github/codeql-cli-binaries/releases

# Create CodeQL database
codeql database create python-db --language=python

# Run queries
codeql database analyze python-db \
  --format=sarif-latest \
  --output=results.sarif \
  codeql/python-queries:codeql-suites/python-security-extended.qls

# View results
codeql bqrs decode python-db/results/*.bqrs
```

## Integration with Development Workflow

1. **Before opening a PR**: Ensure your changes pass CodeQL locally if possible
2. **During PR review**: Check CodeQL status in PR checks
3. **After merge**: Monitor the Security tab for new alerts
4. **Weekly**: Review scheduled scan results for drift or new patterns

## Best Practices

### For Contributors
- **Never disable CodeQL checks** without team discussion
- **Investigate all alerts** before dismissing
- **Document dismissals** with clear justification
- **Prioritize security fixes** over feature work

### For Maintainers
- **Review CodeQL config quarterly** to ensure it matches project risk profile
- **Update query packs** when GitHub releases new security queries
- **Monitor false positive rate** and tune configuration if needed
- **Track metrics**: Alert volume, time to remediation, recurrence

## Custom Queries (Future)

To add project-specific queries:

1. Create `.github/codeql/queries/` directory
2. Write custom QL queries for project-specific patterns
3. Reference in `codeql-config.yml`:
   ```yaml
   queries:
     - uses: ./.github/codeql/queries
   ```

Example use cases:
- Detecting missing authorization checks before external requests
- Validating HMAC salt is never logged or committed
- Ensuring all user input flows through validators

## Troubleshooting

### Workflow fails with "Out of memory"
Increase `timeout-minutes` or reduce scope in config file.

### Too many false positives
Refine `query-filters` in `codeql-config.yml` to exclude specific patterns.

### Missing findings
- Ensure paths in config include all code directories
- Consider adding `security-and-quality` query suite
- Check if paths-ignore is excluding too much

### Workflow doesn't trigger
- Verify branch protection rules allow workflow runs
- Check Actions permissions in repository settings
- Ensure workflow YAML syntax is valid

## References

- [GitHub CodeQL Documentation](https://docs.github.com/en/code-security/code-scanning)
- [CodeQL for Python](https://codeql.github.com/docs/codeql-language-guides/codeql-for-python/)
- [CodeQL Query Reference](https://codeql.github.com/codeql-query-help/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

## Support

For issues with CodeQL setup or configuration:
1. Check workflow run logs in Actions tab
2. Review alert details in Security tab
3. Consult GitHub CodeQL documentation
4. Open an issue in this repository with `codeql` label
