"""Tests for the LICENSE file added in this PR.

Verifies that the Apache License 2.0 text is present, complete, and
correctly structured.
"""
from __future__ import annotations

from pathlib import Path

import pytest

LICENSE_PATH = Path(__file__).resolve().parents[1] / "LICENSE"


@pytest.fixture(scope="module")
def license_text() -> str:
    return LICENSE_PATH.read_text()


# ---------------------------------------------------------------------------
# File existence and basic content
# ---------------------------------------------------------------------------


def test_license_file_exists() -> None:
    assert LICENSE_PATH.exists(), "LICENSE file must exist"


def test_license_file_is_not_empty(license_text: str) -> None:
    assert len(license_text.strip()) > 0, "LICENSE file must not be empty"


def test_license_has_apache_header(license_text: str) -> None:
    assert "Apache License" in license_text


def test_license_specifies_version_2_0(license_text: str) -> None:
    assert "Version 2.0" in license_text


def test_license_references_january_2004(license_text: str) -> None:
    assert "January 2004" in license_text


def test_license_references_apache_url(license_text: str) -> None:
    assert "http://www.apache.org/licenses/" in license_text


# ---------------------------------------------------------------------------
# Required Apache 2.0 sections
# ---------------------------------------------------------------------------


def test_license_contains_terms_and_conditions(license_text: str) -> None:
    assert "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION" in license_text


def test_license_contains_definitions_section(license_text: str) -> None:
    assert "1. Definitions." in license_text


def test_license_contains_copyright_grant(license_text: str) -> None:
    assert "Grant of Copyright License" in license_text


def test_license_contains_patent_grant(license_text: str) -> None:
    assert "Grant of Patent License" in license_text


def test_license_contains_redistribution_section(license_text: str) -> None:
    assert "4. Redistribution." in license_text


def test_license_contains_disclaimer_of_warranty(license_text: str) -> None:
    assert "Disclaimer of Warranty" in license_text
    assert "AS IS" in license_text


def test_license_contains_limitation_of_liability(license_text: str) -> None:
    assert "Limitation of Liability" in license_text


def test_license_contains_end_of_terms(license_text: str) -> None:
    assert "END OF TERMS AND CONDITIONS" in license_text


def test_license_contains_appendix(license_text: str) -> None:
    assert "APPENDIX" in license_text


# ---------------------------------------------------------------------------
# Boilerplate notice in appendix
# ---------------------------------------------------------------------------


def test_license_appendix_references_apache_2_0_url(license_text: str) -> None:
    assert "http://www.apache.org/licenses/LICENSE-2.0" in license_text


def test_license_appendix_contains_boilerplate_placeholder(license_text: str) -> None:
    """The standard boilerplate brackets must be present in the appendix."""
    assert "[yyyy]" in license_text
    assert "[name of copyright owner]" in license_text


# ---------------------------------------------------------------------------
# Structural line-count sanity (Apache 2.0 is typically ~200 lines)
# ---------------------------------------------------------------------------


def test_license_has_substantial_content(license_text: str) -> None:
    line_count = len(license_text.splitlines())
    assert line_count >= 150, (
        f"LICENSE has only {line_count} lines; expected at least 150 for Apache 2.0"
    )


def test_license_ends_with_newline() -> None:
    raw = LICENSE_PATH.read_bytes()
    assert raw.endswith(b"\n"), "LICENSE file must end with a newline"