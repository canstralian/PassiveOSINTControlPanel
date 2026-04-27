#!/usr/bin/env python3
"""
CI drift guard.

Purpose:
- Enforce repository-level safety invariants.
- Fail closed when critical files disappear.
- Detect forbidden tooling references in source.
- Detect unsafe outbound request patterns in osint_core/.
- Detect raw indicator leakage in osint_core/.
- Validate structured config files.

Each invariant is a named rule with an explicit allowlist. Allowlists live
next to the rule that consumes them so that drift in one rule cannot silently
relax another.

Usage:
    python scripts/ci_guard.py
    python scripts/ci_guard.py --rule passive_first --rule forbidden_tools
    python scripts/ci_guard.py --list
    python scripts/ci_guard.py --json
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Finding:
    rule: str
    path: Path
    line: int | None
    message: str
    severity: str = "error"


@dataclass(frozen=True)
class Rule:
    name: str
    description: str
    check: Callable[[Path], list[Finding]]


# ---------------------------------------------------------------------------
# Repository traversal
# ---------------------------------------------------------------------------

EXCLUDED_PATH_PREFIXES: tuple[str, ...] = (
    ".git/",
    ".github/workflows/",
    "docs/",
    "README.md",
    ".venv/",
    "venv/",
    "runs/",
)

# Directory names whose contents are excluded wherever they appear in the tree.
EXCLUDED_DIR_COMPONENTS: frozenset[str] = frozenset(
    {"__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}
)

BINARY_SUFFIXES: frozenset[str] = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".ico", ".whl"}
)


def repo_files(root: Path) -> Iterable[Path]:
    """
    Yield repository-tracked files, relative to ``root``.

    Prefers ``git ls-files`` so the guard sees the same set of files CI does.
    Falls back to a pruned ``os.walk`` when git is unavailable (for example
    when running against an exported snapshot). The walk fallback prunes
    excluded directories in place so large trees like ``.git/`` and
    ``.venv/`` are never descended into.
    """
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
        candidates: Iterable[Path] = (
            Path(line) for line in result.stdout.splitlines() if line
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        candidates = _walk_with_pruning(root)

    for relative in candidates:
        if should_skip(relative):
            continue
        absolute = root / relative
        if not absolute.is_file():
            continue
        if absolute.suffix.lower() in BINARY_SUFFIXES:
            continue
        yield relative


def _walk_with_pruning(root: Path) -> Iterable[Path]:
    """
    Yield relative file paths under ``root``, pruning excluded directories
    so we never descend into ``.git/``, ``.venv/``, ``__pycache__/`` etc.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        # Prune in place: os.walk consults the mutated list to decide
        # which subdirectories to descend into next.
        dirnames[:] = [
            d for d in dirnames if not should_skip_dir(_join_rel(rel_dir, d))
        ]
        for filename in filenames:
            yield _join_rel(rel_dir, filename)


def _join_rel(rel_dir: Path, name: str) -> Path:
    if rel_dir == Path("."):
        return Path(name)
    return rel_dir / name


def should_skip(path: Path) -> bool:
    text = path.as_posix()
    for excluded in EXCLUDED_PATH_PREFIXES:
        bare = excluded.rstrip("/")
        if text == bare or text.startswith(excluded):
            return True
    if EXCLUDED_DIR_COMPONENTS.intersection(path.parts):
        return True
    return False


def should_skip_dir(rel_dir: Path) -> bool:
    """
    Directory-level variant of ``should_skip`` for use when pruning a walk.

    Treats ``rel_dir`` as a directory: matches ``EXCLUDED_PATH_PREFIXES``
    against the directory's path with a trailing slash so ``.git/`` matches
    ``.git`` exactly, and excludes any directory whose name is in
    ``EXCLUDED_DIR_COMPONENTS``.
    """
    text = rel_dir.as_posix() + "/"
    for excluded in EXCLUDED_PATH_PREFIXES:
        if not excluded.endswith("/"):
            # File-shaped prefixes (e.g. "README.md") do not prune dirs.
            continue
        if text == excluded or text.startswith(excluded):
            return True
    if EXCLUDED_DIR_COMPONENTS.intersection(rel_dir.parts):
        return True
    return False


def read_text(root: Path, path: Path) -> str:
    return (root / path).read_text(encoding="utf-8", errors="replace")


def iter_lines(root: Path, path: Path) -> Iterable[tuple[int, str]]:
    for line_number, line in enumerate(read_text(root, path).splitlines(), start=1):
        yield line_number, line


def path_in(path: Path, prefixes: Iterable[str]) -> bool:
    text = path.as_posix()
    for prefix in prefixes:
        if prefix.endswith("/"):
            if text.startswith(prefix):
                return True
        elif text == prefix:
            return True
    return False


# ---------------------------------------------------------------------------
# Rule: required_files
# ---------------------------------------------------------------------------

REQUIRED_FILES: tuple[str, ...] = (
    "osint_core/intent.py",
    "osint_core/policy.py",
    "osint_core/validators.py",
    "data/sources.yaml",
)


def check_required_files(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for file_name in REQUIRED_FILES:
        if not (root / file_name).is_file():
            findings.append(
                Finding(
                    rule="required_files",
                    path=Path(file_name),
                    line=None,
                    message=f"Missing required file: {file_name}",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Rule: yaml_integrity
# ---------------------------------------------------------------------------

YAML_INTEGRITY_TARGETS: tuple[str, ...] = ("data/sources.yaml",)


def check_yaml_integrity(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for file_name in YAML_INTEGRITY_TARGETS:
        path = root / file_name
        if not path.is_file():
            # required_files reports the missing-file case.
            continue
        try:
            with path.open(encoding="utf-8") as f:
                parsed = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            findings.append(
                Finding(
                    rule="yaml_integrity",
                    path=Path(file_name),
                    line=None,
                    message=f"Invalid YAML: {exc}",
                )
            )
            continue
        if parsed is None:
            findings.append(
                Finding(
                    rule="yaml_integrity",
                    path=Path(file_name),
                    line=None,
                    message="YAML file is empty.",
                )
            )
        elif not isinstance(parsed, (dict, list)):
            findings.append(
                Finding(
                    rule="yaml_integrity",
                    path=Path(file_name),
                    line=None,
                    message=(
                        f"YAML must parse to a mapping or list, "
                        f"got {type(parsed).__name__}."
                    ),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Rule: forbidden_tools
# ---------------------------------------------------------------------------

FORBIDDEN_TOOLS: tuple[str, ...] = ("nmap", "masscan", "sqlmap", "metasploit")

FORBIDDEN_TOOL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(?:" + "|".join(re.escape(t) for t in FORBIDDEN_TOOLS) + r")"
    r"(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)

# Files that mention forbidden tool names for legitimate policy reasons:
# alias tables that map "nmap" -> "port_scan", forbidden-set membership
# tests, and the guard implementation itself. Each entry must justify why
# the literal appears in a passive-first repo.
FORBIDDEN_TOOLS_PATH_ALLOWLIST: tuple[str, ...] = (
    "osint_core/policy.py",      # ALIASES maps offensive tool names to canonical modules.
    "osint_core/intent.py",      # forbidden-set classification references the same names.
    "tests/test_policy.py",      # asserts ALIASES["nmap"] -> "port_scan".
    "tests/test_intent.py",      # asserts requesting "nmap" yields critical risk.
    "tests/test_ci_guard.py",    # exercises this rule with synthetic samples.
    "scripts/ci_guard.py",       # this file declares the forbidden list.
)


def check_forbidden_tools(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in repo_files(root):
        if path_in(path, FORBIDDEN_TOOLS_PATH_ALLOWLIST):
            continue
        for line_number, line in iter_lines(root, path):
            if FORBIDDEN_TOOL_PATTERN.search(line):
                findings.append(
                    Finding(
                        rule="forbidden_tools",
                        path=path,
                        line=line_number,
                        message=(
                            "Forbidden offensive tooling reference detected: "
                            f"{line.strip()[:120]}"
                        ),
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Rule: raw_indicator_leakage
# ---------------------------------------------------------------------------

RAW_INDICATOR_PATTERN = re.compile(
    r"(example\.com|[A-Za-z0-9._%+-]+@gmail\.com|192\.168\.\d{1,3}\.\d{1,3})"
)

RAW_INDICATOR_SCOPE: tuple[str, ...] = ("osint_core/",)

# osint_core/validators.py declares ipaddress.ip_network("192.168.0.0/16") as
# part of the RFC1918 deny list. That is policy code, not indicator leakage.
RAW_INDICATOR_FILE_ALLOWLIST: tuple[str, ...] = (
    "osint_core/validators.py",
)


def check_raw_indicator_leakage(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in repo_files(root):
        if not path_in(path, RAW_INDICATOR_SCOPE):
            continue
        if path.as_posix() in RAW_INDICATOR_FILE_ALLOWLIST:
            continue
        for line_number, line in iter_lines(root, path):
            if RAW_INDICATOR_PATTERN.search(line):
                findings.append(
                    Finding(
                        rule="raw_indicator_leakage",
                        path=path,
                        line=line_number,
                        message=(
                            "Possible raw indicator leakage: "
                            f"{line.strip()[:120]}"
                        ),
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Rule: passive_first
# ---------------------------------------------------------------------------

HTTP_VERBS: frozenset[str] = frozenset(
    {"get", "post", "put", "patch", "delete", "request"}
)

AUTHORIZED_HINTS: frozenset[str] = frozenset(
    {"authorized", "allow_active", "explicit_scope", "validated_target"}
)

PASSIVE_FIRST_SCOPE: tuple[str, ...] = ("osint_core/",)

# Files in PASSIVE_FIRST_SCOPE that intentionally fail Python parsing.
# osint_core/drift.py is documented pseudocode (see CLAUDE.md). Adding an
# entry here means "this file is exempt from the syntax-error sub-check";
# it does NOT exempt the file from the unauthorized-call sub-check.
PASSIVE_FIRST_PSEUDOCODE_ALLOWLIST: tuple[str, ...] = (
    "osint_core/drift.py",
)


def is_requests_call(node: ast.Call) -> bool:
    """
    Match ``requests.<verb>(...)`` calls.

    This does not catch aliased imports. A stricter implementation can build
    an import map first; until then, the rule covers the canonical pattern
    that the existing shell tripwire targeted.
    """
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr not in HTTP_VERBS:
        return False
    if not isinstance(node.func.value, ast.Name):
        return False
    return node.func.value.id == "requests"


def has_authorization_context(lines: list[str], line_number: int) -> bool:
    """
    Look for explicit safety markers in a small window around the call.

    A real authorization gate would route through ``policy.authorize_target``
    or an ``AuthorizedSession`` wrapper. This window-based heuristic mirrors
    the original shell ``grep -v -E 'authorized|allow_active|explicit_scope'``
    so callers that meant to opt in still pass.
    """
    start = max(0, line_number - 6)
    end = min(len(lines), line_number + 3)
    nearby = "\n".join(lines[start:end]).lower()
    return any(marker in nearby for marker in AUTHORIZED_HINTS)


def check_passive_first(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in repo_files(root):
        if not path_in(path, PASSIVE_FIRST_SCOPE):
            continue
        if path.suffix != ".py":
            continue
        source = read_text(root, path)
        try:
            tree = ast.parse(source, filename=path.as_posix())
        except SyntaxError as exc:
            if path.as_posix() in PASSIVE_FIRST_PSEUDOCODE_ALLOWLIST:
                continue
            findings.append(
                Finding(
                    rule="passive_first",
                    path=path,
                    line=exc.lineno,
                    message=(
                        f"Python syntax error blocks passive_first analysis: "
                        f"{exc.msg}"
                    ),
                )
            )
            continue
        lines = source.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not is_requests_call(node):
                continue
            if has_authorization_context(lines, node.lineno):
                continue
            findings.append(
                Finding(
                    rule="passive_first",
                    path=path,
                    line=node.lineno,
                    message=(
                        "Direct outbound request without visible authorization "
                        "context. Route through a policy-gated client."
                    ),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Rule registry + CLI
# ---------------------------------------------------------------------------

RULES: dict[str, Rule] = {
    "required_files": Rule(
        name="required_files",
        description="Verify critical files exist.",
        check=check_required_files,
    ),
    "yaml_integrity": Rule(
        name="yaml_integrity",
        description="Validate structured YAML configs parse to a mapping or list.",
        check=check_yaml_integrity,
    ),
    "forbidden_tools": Rule(
        name="forbidden_tools",
        description="Reject offensive tooling references outside the policy allowlist.",
        check=check_forbidden_tools,
    ),
    "raw_indicator_leakage": Rule(
        name="raw_indicator_leakage",
        description="Reject raw indicator literals in osint_core/ source.",
        check=check_raw_indicator_leakage,
    ),
    "passive_first": Rule(
        name="passive_first",
        description=(
            "Forbid unauthorized outbound HTTP calls in osint_core/ via AST scan."
        ),
        check=check_passive_first,
    ),
}


def run_rules(root: Path, rule_names: Iterable[str]) -> list[Finding]:
    findings: list[Finding] = []
    for name in rule_names:
        rule = RULES[name]
        try:
            findings.extend(rule.check(root))
        except Exception as exc:  # noqa: BLE001 - rule errors must surface
            findings.append(
                Finding(
                    rule=rule.name,
                    path=Path("."),
                    line=None,
                    message=f"Rule raised {type(exc).__name__}: {exc}",
                )
            )
    return findings


def print_findings_human(findings: list[Finding]) -> None:
    if not findings:
        print("CI guard passed.")
        return
    print("CI guard failed.")
    print()
    for finding in findings:
        location = finding.path.as_posix()
        if finding.line is not None:
            location += f":{finding.line}"
        print(f"[{finding.severity}] {finding.rule}: {location}")
        print(f"  {finding.message}")
        print()


def print_findings_json(findings: list[Finding]) -> None:
    print(
        json.dumps(
            {
                "passed": not findings,
                "findings": [
                    {
                        "rule": f.rule,
                        "path": f.path.as_posix(),
                        "line": f.line,
                        "severity": f.severity,
                        "message": f.message,
                    }
                    for f in findings
                ],
            },
            indent=2,
        )
    )


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CI drift guard for the Passive OSINT Control Panel.",
    )
    parser.add_argument(
        "--root",
        default=str(REPO_ROOT),
        help="Repository root to scan (defaults to the script's parent).",
    )
    parser.add_argument(
        "--rule",
        action="append",
        choices=sorted(RULES),
        help="Run only the named rule. Repeatable. Default: all rules.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available rules and exit.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit findings as JSON instead of human-readable text.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.list:
        for name, rule in RULES.items():
            print(f"{name}\t{rule.description}")
        return 0

    root = Path(args.root).resolve()
    selected = args.rule or list(RULES)
    findings = run_rules(root, selected)

    if args.json:
        print_findings_json(findings)
    else:
        print_findings_human(findings)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
