"""Tests for requirements.txt.

Validates that the file is well-formed, that the gradio dependency added in
this PR is present with the correct version constraints, and that all packages
carry explicit version bounds.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REQUIREMENTS_PATH = Path(__file__).resolve().parents[1] / "requirements.txt"

# Regex for a PEP-508 specifier token: name followed by optional extras and
# one or more version constraints separated by commas.
_LINE_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9._-]*)"  # package name
    r"(\[.*?\])?"                       # optional extras
    r"(?P<spec>[^#\n]+)"               # version specifiers (required)
)

_CONSTRAINT_RE = re.compile(r"[><=!~]{1,2}\s*[\d.*]+")


def _parse_requirements() -> list[str]:
    """Return non-empty, non-comment lines from requirements.txt."""
    lines = []
    for line in REQUIREMENTS_PATH.read_text().splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


# ---------------------------------------------------------------------------
# File-level checks
# ---------------------------------------------------------------------------


def test_requirements_file_exists() -> None:
    assert REQUIREMENTS_PATH.exists()


def test_requirements_file_is_not_empty() -> None:
    assert REQUIREMENTS_PATH.stat().st_size > 0


def test_all_lines_are_parseable() -> None:
    """Every non-blank, non-comment line must look like a valid requirement."""
    for line in _parse_requirements():
        assert _LINE_RE.match(line), f"Unparseable requirement line: {line!r}"


# ---------------------------------------------------------------------------
# Gradio dependency (new in this PR)
# ---------------------------------------------------------------------------


def test_gradio_is_present() -> None:
    lines = _parse_requirements()
    gradio_lines = [l for l in lines if re.match(r"gradio\b", l, re.IGNORECASE)]
    assert gradio_lines, "gradio must be listed in requirements.txt"


def test_gradio_lower_bound_is_6_13_0() -> None:
    lines = _parse_requirements()
    gradio_line = next(
        (l for l in lines if re.match(r"gradio\b", l, re.IGNORECASE)), None
    )
    assert gradio_line is not None
    assert ">=6.13.0" in gradio_line, (
        f"gradio must have >=6.13.0 lower bound, got: {gradio_line!r}"
    )


def test_gradio_upper_bound_excludes_v7() -> None:
    lines = _parse_requirements()
    gradio_line = next(
        (l for l in lines if re.match(r"gradio\b", l, re.IGNORECASE)), None
    )
    assert gradio_line is not None
    assert "<7" in gradio_line, (
        f"gradio must have <7 upper bound to stay on v6, got: {gradio_line!r}"
    )


def test_gradio_is_first_dependency() -> None:
    """The PR placed gradio as the first line; verify ordering is preserved."""
    lines = _parse_requirements()
    assert lines, "requirements.txt must not be empty"
    assert re.match(r"gradio\b", lines[0], re.IGNORECASE), (
        f"gradio must be the first dependency, found: {lines[0]!r}"
    )


# ---------------------------------------------------------------------------
# All packages carry version constraints
# ---------------------------------------------------------------------------


def test_all_packages_have_version_specifiers() -> None:
    """No bare package name without a version constraint is allowed."""
    for line in _parse_requirements():
        constraints = _CONSTRAINT_RE.findall(line)
        assert constraints, (
            f"Package has no version specifier: {line!r}. "
            "All dependencies must be version-pinned."
        )


# ---------------------------------------------------------------------------
# Existing packages still present (regression guard)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pkg",
    [
        "pyyaml",
        "httpx",
        "tldextract",
        "dnspython",
        "python-whois",
        "markdown-it-py",
        "email-validator",
        "cachetools",
        "pydantic",
        "anthropic",
    ],
)
def test_existing_package_still_present(pkg: str) -> None:
    lines = _parse_requirements()
    matching = [l for l in lines if re.match(rf"{re.escape(pkg)}\b", l, re.IGNORECASE)]
    assert matching, f"Expected package {pkg!r} to still be in requirements.txt"


# ---------------------------------------------------------------------------
# Upper bound sanity – no package should allow arbitrarily large versions
# ---------------------------------------------------------------------------


def test_all_packages_have_upper_bound() -> None:
    """Each package should carry at least one upper-bound constraint (<X or <=X)."""
    for line in _parse_requirements():
        upper = re.search(r"[<]=?\s*[\d.]+", line)
        assert upper, (
            f"Package has no upper version bound: {line!r}. "
            "Upper bounds prevent unexpected breaking upgrades."
        )


# ---------------------------------------------------------------------------
# No duplicate package entries
# ---------------------------------------------------------------------------


def test_no_duplicate_packages() -> None:
    names = []
    for line in _parse_requirements():
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if m:
            names.append(m.group(1).lower())
    assert len(names) == len(set(names)), (
        f"Duplicate packages detected in requirements.txt: {names}"
    )