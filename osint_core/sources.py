"""
osint_core.sources
==================

Loader for the OSINT source registry (``data/sources.yaml``).

Design constraints:
- The registry is the single source of truth for resource-link rendering.
- Loading is pure I/O + validation: no network calls, no policy decisions.
- Validation is strict at load time so misconfiguration fails fast on import,
  not at click time inside the UI.
- Each source must declare a ``risk`` field. Risk values are constrained to
  a closed allowlist (aligned with ``osint_core.policy``: passive sources are
  ``low`` or ``conditional`` — ``forbidden`` is rejected at load).
- Duplicates within an indicator type are rejected. A duplicate is defined as
  the same ``name`` (case-insensitive) appearing twice.
- The renderer (``build_links``) is the only public string formatter; it
  URL-encodes the query and never trusts the indicator value as markup.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Literal
from urllib.parse import quote_plus

import yaml


IndicatorType = Literal["domain", "username", "email", "ip", "url"]
SourceRisk = Literal["low", "conditional"]

SUPPORTED_INDICATOR_TYPES: tuple[IndicatorType, ...] = (
    "domain",
    "username",
    "email",
    "ip",
    "url",
)

ALLOWED_SOURCE_RISKS: tuple[SourceRisk, ...] = ("low", "conditional")

DEFAULT_SOURCES_PATH = Path(__file__).resolve().parent.parent / "data" / "sources.yaml"


class SourceErrorCode(str, Enum):
    FILE_NOT_FOUND = "file_not_found"
    INVALID_YAML = "invalid_yaml"
    INVALID_ROOT = "invalid_root"
    UNKNOWN_INDICATOR_TYPE = "unknown_indicator_type"
    INVALID_ENTRY = "invalid_entry"
    MISSING_FIELD = "missing_field"
    INVALID_RISK = "invalid_risk"
    INVALID_URL_TEMPLATE = "invalid_url_template"
    DUPLICATE_SOURCE = "duplicate_source"


class SourceRegistryError(ValueError):
    """Raised when ``data/sources.yaml`` is missing required fields or malformed."""

    def __init__(self, code: SourceErrorCode, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    risk: SourceRisk
    description: str = ""

    def render(self, normalized_indicator: str) -> str:
        query = quote_plus(normalized_indicator)
        href = self.url.replace("{query}", query)
        suffix = f" — {self.description}" if self.description else ""
        return f"- [{self.name}]({href}){suffix}"


SourceRegistry = dict[IndicatorType, list[Source]]


def load_sources(path: str | Path | None = None) -> SourceRegistry:
    """
    Load and validate the source registry.

    Parameters
    ----------
    path:
        Optional override. Defaults to ``<repo>/data/sources.yaml``.

    Returns
    -------
    SourceRegistry
        Mapping of indicator type to validated, deduplicated ``Source`` lists.

    Raises
    ------
    SourceRegistryError
        On any structural, schema, or duplication failure.
    """
    target = Path(path) if path is not None else DEFAULT_SOURCES_PATH

    if not target.is_file():
        raise SourceRegistryError(
            SourceErrorCode.FILE_NOT_FOUND,
            f"Source registry not found at {target}.",
        )

    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SourceRegistryError(
            SourceErrorCode.INVALID_YAML,
            f"Failed to parse YAML at {target}: {exc}",
        ) from exc

    if raw is None:
        return {}

    if not isinstance(raw, dict):
        raise SourceRegistryError(
            SourceErrorCode.INVALID_ROOT,
            "Top-level structure of sources.yaml must be a mapping of "
            "indicator_type -> list of sources.",
        )

    registry: SourceRegistry = {}

    for indicator_type, entries in raw.items():
        if indicator_type not in SUPPORTED_INDICATOR_TYPES:
            raise SourceRegistryError(
                SourceErrorCode.UNKNOWN_INDICATOR_TYPE,
                f"Unsupported indicator type in sources.yaml: {indicator_type!r}. "
                f"Allowed: {list(SUPPORTED_INDICATOR_TYPES)}.",
            )

        if entries is None:
            registry[indicator_type] = []
            continue

        if not isinstance(entries, list):
            raise SourceRegistryError(
                SourceErrorCode.INVALID_ENTRY,
                f"Entries for {indicator_type!r} must be a list, got {type(entries).__name__}.",
            )

        registry[indicator_type] = _parse_entries(indicator_type, entries)

    return registry


def _parse_entries(
    indicator_type: IndicatorType,
    entries: Iterable[object],
) -> list[Source]:
    parsed: list[Source] = []
    seen_names: set[str] = set()

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise SourceRegistryError(
                SourceErrorCode.INVALID_ENTRY,
                f"{indicator_type}[{index}] must be a mapping, got {type(entry).__name__}.",
            )

        name = entry.get("name")
        url = entry.get("url")
        risk = entry.get("risk")
        description = entry.get("description", "")

        for field_name, value in (("name", name), ("url", url), ("risk", risk)):
            if not isinstance(value, str) or not value.strip():
                raise SourceRegistryError(
                    SourceErrorCode.MISSING_FIELD,
                    f"{indicator_type}[{index}] is missing required field {field_name!r}.",
                )

        if risk not in ALLOWED_SOURCE_RISKS:
            raise SourceRegistryError(
                SourceErrorCode.INVALID_RISK,
                f"{indicator_type}[{index}] has invalid risk {risk!r}. "
                f"Allowed: {list(ALLOWED_SOURCE_RISKS)}.",
            )

        if not url.startswith(("http://", "https://")):
            raise SourceRegistryError(
                SourceErrorCode.INVALID_URL_TEMPLATE,
                f"{indicator_type}[{index}] url must be http(s).",
            )

        normalized_name_key = name.strip().lower()
        if normalized_name_key in seen_names:
            raise SourceRegistryError(
                SourceErrorCode.DUPLICATE_SOURCE,
                f"Duplicate source name {name!r} under indicator type {indicator_type!r}.",
            )
        seen_names.add(normalized_name_key)

        parsed.append(
            Source(
                name=name.strip(),
                url=url.strip(),
                risk=risk,
                description=str(description).strip(),
            )
        )

    return parsed


@lru_cache(maxsize=1)
def get_default_registry() -> SourceRegistry:
    """
    Cached view of the on-disk registry. Use this from request paths so the
    YAML is not re-read and re-validated on every UI interaction.
    """
    return load_sources()


def reload_default_registry() -> SourceRegistry:
    """Drop the cache and reload. Intended for tests and operator hot-reload."""
    get_default_registry.cache_clear()
    return get_default_registry()


def build_links(
    indicator_type: str,
    normalized_indicator: str,
    *,
    registry: SourceRegistry | None = None,
) -> str:
    """
    Render the markdown bullet list of resource links for an indicator.

    Returns a friendly placeholder when no sources are registered for the type
    so the UI does not blow up on indicator types without entries.
    """
    sources_by_type = registry if registry is not None else get_default_registry()
    sources = sources_by_type.get(indicator_type, [])

    if not sources:
        return "_No source links registered for this indicator type._"

    return "\n".join(source.render(normalized_indicator) for source in sources)


__all__ = [
    "ALLOWED_SOURCE_RISKS",
    "DEFAULT_SOURCES_PATH",
    "IndicatorType",
    "Source",
    "SourceErrorCode",
    "SourceRegistry",
    "SourceRegistryError",
    "SourceRisk",
    "SUPPORTED_INDICATOR_TYPES",
    "build_links",
    "get_default_registry",
    "load_sources",
    "reload_default_registry",
]
