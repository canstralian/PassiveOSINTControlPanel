"""
Contract tests for ``osint_core.sources``.

These tests cover the verification checklist for the source-registry loader:

- The on-disk registry loads cleanly.
- For ``input: example.com`` -> domain tools render correctly.
- No duplicate source names within an indicator type.
- No missing risk fields (and only allowlisted risk values).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from osint_core.sources import (
    ALLOWED_SOURCE_RISKS,
    SUPPORTED_INDICATOR_TYPES,
    Source,
    SourceErrorCode,
    SourceRegistryError,
    build_links,
    get_default_registry,
    load_sources,
    reload_default_registry,
)


# ---------------------------------------------------------------------------
# On-disk registry (data/sources.yaml) — verify checklist
# ---------------------------------------------------------------------------


def test_default_registry_loads_without_error():
    registry = reload_default_registry()
    assert isinstance(registry, dict)
    # Every indicator type present must be in the supported set; the starter
    # registry is allowed to be a subset.
    extra = set(registry.keys()) - set(SUPPORTED_INDICATOR_TYPES)
    assert extra == set(), f"unsupported indicator types in registry: {extra}"


def test_default_registry_has_no_duplicate_source_names_per_type():
    registry = reload_default_registry()
    for indicator_type, sources in registry.items():
        names = [source.name.lower() for source in sources]
        assert len(names) == len(set(names)), (
            f"Duplicate sources detected for {indicator_type}: {names}"
        )


def test_default_registry_every_source_has_required_fields():
    registry = reload_default_registry()
    for indicator_type, sources in registry.items():
        for source in sources:
            assert source.name, f"missing name in {indicator_type}"
            assert source.url, f"missing url in {indicator_type}"
            assert source.risk in ALLOWED_SOURCE_RISKS, (
                f"missing/invalid risk in {indicator_type}: {source.risk!r}"
            )


# ---------------------------------------------------------------------------
# Rendering: "input: example.com -> domain tools render correctly"
# ---------------------------------------------------------------------------


def test_build_links_renders_domain_tools_for_example_dot_com():
    rendered = build_links("domain", "example.com")

    # Starter registry currently has at least one domain source.
    lines = rendered.splitlines()
    assert lines, "expected at least one rendered link"
    assert all(line.startswith("- [") for line in lines), rendered

    # The query is URL-encoded and substituted everywhere {query} appeared.
    assert "{query}" not in rendered
    assert "example.com" in rendered


def test_build_links_url_encodes_special_characters():
    registry = {
        "url": [
            Source(
                name="ScanSearch",
                url="https://example.test/search?q={query}",
                risk="low",
                description="search",
            )
        ]
    }
    rendered = build_links("url", "https://example.com/path?x=1", registry=registry)
    # quote_plus encodes `:` -> %3A and `/` -> %2F.
    assert "%3A" in rendered and "%2F" in rendered
    assert "{query}" not in rendered


def test_build_links_returns_placeholder_for_unregistered_indicator_type():
    registry = {"domain": [Source(name="X", url="https://x.test", risk="low")]}
    rendered = build_links("ip", "1.2.3.4", registry=registry)
    assert "No source links registered" in rendered


def test_build_links_accepts_explicit_registry():
    registry = {
        "domain": [
            Source(
                name="LocalTest",
                url="https://example.test/{query}",
                risk="low",
                description="local",
            )
        ]
    }
    rendered = build_links("domain", "example.com", registry=registry)
    assert rendered == "- [LocalTest](https://example.test/example.com) — local"


# ---------------------------------------------------------------------------
# Loader validation: missing risk + duplicates are rejected
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "sources.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_loader_rejects_missing_risk_field(tmp_path: Path):
    path = _write(
        tmp_path,
        """
domain:
  - name: NoRisk
    url: "https://example.test/{query}"
""",
    )
    with pytest.raises(SourceRegistryError) as exc:
        load_sources(path)
    assert exc.value.code == SourceErrorCode.MISSING_FIELD


def test_loader_rejects_invalid_risk_value(tmp_path: Path):
    path = _write(
        tmp_path,
        """
domain:
  - name: BadRisk
    url: "https://example.test/{query}"
    risk: forbidden
""",
    )
    with pytest.raises(SourceRegistryError) as exc:
        load_sources(path)
    assert exc.value.code == SourceErrorCode.INVALID_RISK


def test_loader_rejects_duplicate_source_within_type(tmp_path: Path):
    path = _write(
        tmp_path,
        """
domain:
  - name: Same
    url: "https://example.test/a/{query}"
    risk: low
  - name: same
    url: "https://example.test/b/{query}"
    risk: low
""",
    )
    with pytest.raises(SourceRegistryError) as exc:
        load_sources(path)
    assert exc.value.code == SourceErrorCode.DUPLICATE_SOURCE


def test_loader_rejects_unknown_indicator_type(tmp_path: Path):
    path = _write(
        tmp_path,
        """
phone:
  - name: Whatever
    url: "https://example.test/{query}"
    risk: low
""",
    )
    with pytest.raises(SourceRegistryError) as exc:
        load_sources(path)
    assert exc.value.code == SourceErrorCode.UNKNOWN_INDICATOR_TYPE


def test_loader_rejects_missing_file(tmp_path: Path):
    with pytest.raises(SourceRegistryError) as exc:
        load_sources(tmp_path / "does_not_exist.yaml")
    assert exc.value.code == SourceErrorCode.FILE_NOT_FOUND


def test_loader_rejects_invalid_url_scheme(tmp_path: Path):
    path = _write(
        tmp_path,
        """
domain:
  - name: BadScheme
    url: "ftp://example.test/{query}"
    risk: low
""",
    )
    with pytest.raises(SourceRegistryError) as exc:
        load_sources(path)
    assert exc.value.code == SourceErrorCode.INVALID_URL_TEMPLATE


def test_loader_allows_duplicate_name_across_different_indicator_types(tmp_path: Path):
    # VirusTotal legitimately appears under both ``domain`` and ``ip``.
    path = _write(
        tmp_path,
        """
domain:
  - name: VirusTotal
    url: "https://example.test/d/{query}"
    risk: low
ip:
  - name: VirusTotal
    url: "https://example.test/i/{query}"
    risk: low
""",
    )
    registry = load_sources(path)
    assert len(registry["domain"]) == 1
    assert len(registry["ip"]) == 1


# ---------------------------------------------------------------------------
# Cache hygiene
# ---------------------------------------------------------------------------


def test_get_default_registry_is_cached():
    reload_default_registry()
    a = get_default_registry()
    b = get_default_registry()
    assert a is b


def test_reload_default_registry_returns_equivalent_object():
    a = get_default_registry()
    b = reload_default_registry()
    # Cache was cleared, but content matches.
    assert a == b
