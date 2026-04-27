"""
osint_core.baseline
===================

Persistent baseline management for drift detection.

The baseline stores cross-run reference data without raw indicators. Updates are
conservative, validated on load, and written atomically to reduce corruption risk
under concurrent app requests.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

DEFAULT_BASELINE: dict[str, Any] = {
    "runtime_p95_ms": 500.0,
    "error_rate_threshold": 2,
    "timeout_threshold": 1,
    "expected_manifest_hash": "",
    "expected_dependency_hash": "",
    "expected_runtime_python_version": "",
    "known_output_hashes": {},
    "input_type_distribution": {},
    "module_usage_distribution": {},
    "input_entropy_avg": 3.0,
}

BASELINE_PATH = Path(__file__).resolve().parent.parent / "data" / "baseline.json"
EMA_ALPHA = 0.1


def _coerce_str_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items() if item is not None}


def _coerce_float_distribution(value: Any) -> dict[str, float]:
    if not isinstance(value, dict):
        return {}

    output: dict[str, float] = {}
    for key, item in value.items():
        try:
            numeric = float(item)
        except (TypeError, ValueError):
            continue
        if numeric >= 0:
            output[str(key)] = numeric

    total = sum(output.values())
    if total > 0:
        output = {key: val / total for key, val in output.items()}
    return output


def _coerce_float(value: Any, default: float) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return default
    return numeric if numeric >= 0 else default


def _coerce_int(value: Any, default: int) -> int:
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        return default
    return numeric if numeric >= 0 else default


def normalize_baseline(raw: dict[str, Any] | None) -> dict[str, Any]:
    """Return a type-safe baseline, discarding malformed fields."""
    raw = raw if isinstance(raw, dict) else {}
    baseline = DEFAULT_BASELINE.copy()

    baseline["runtime_p95_ms"] = _coerce_float(
        raw.get("runtime_p95_ms"),
        float(DEFAULT_BASELINE["runtime_p95_ms"]),
    )
    baseline["error_rate_threshold"] = _coerce_int(
        raw.get("error_rate_threshold"),
        int(DEFAULT_BASELINE["error_rate_threshold"]),
    )
    baseline["timeout_threshold"] = _coerce_int(
        raw.get("timeout_threshold"),
        int(DEFAULT_BASELINE["timeout_threshold"]),
    )
    baseline["expected_manifest_hash"] = str(raw.get("expected_manifest_hash") or "")
    baseline["expected_dependency_hash"] = str(raw.get("expected_dependency_hash") or "")
    baseline["expected_runtime_python_version"] = str(
        raw.get("expected_runtime_python_version") or ""
    )
    baseline["known_output_hashes"] = _coerce_str_dict(raw.get("known_output_hashes"))
    baseline["input_type_distribution"] = _coerce_float_distribution(
        raw.get("input_type_distribution")
    )
    baseline["module_usage_distribution"] = _coerce_float_distribution(
        raw.get("module_usage_distribution")
    )
    baseline["input_entropy_avg"] = _coerce_float(
        raw.get("input_entropy_avg"),
        float(DEFAULT_BASELINE["input_entropy_avg"]),
    )
    return baseline


def load_baseline(path: Path | str = BASELINE_PATH) -> dict[str, Any]:
    """Load and validate baseline data from disk."""
    baseline_path = Path(path)
    if not baseline_path.exists():
        return DEFAULT_BASELINE.copy()

    try:
        with baseline_path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        return normalize_baseline(raw)
    except (OSError, json.JSONDecodeError) as error:
        print(f"Warning: Failed to load baseline from {baseline_path}: {error}")
        return DEFAULT_BASELINE.copy()


def save_baseline(baseline: dict[str, Any], path: Path | str = BASELINE_PATH) -> None:
    """Persist baseline using an atomic same-directory replace."""
    baseline_path = Path(path)
    safe_baseline = normalize_baseline(baseline)

    try:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{baseline_path.name}.",
            suffix=".tmp",
            dir=str(baseline_path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(safe_baseline, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            Path(temp_name).replace(baseline_path)
        finally:
            temp_path = Path(temp_name)
            if temp_path.exists():
                temp_path.unlink(missing_ok=True)
    except OSError as error:
        print(f"Warning: Failed to save baseline to {baseline_path}: {error}")


def _ema(previous: float, current: float, alpha: float = EMA_ALPHA) -> float:
    return previous * (1 - alpha) + current * alpha


def _update_distribution(
    distribution: dict[str, float],
    observed: list[str],
) -> dict[str, float]:
    updated = dict(distribution)
    for key in list(updated):
        updated[key] = updated[key] * (1 - EMA_ALPHA)

    for key in observed:
        updated[key] = updated.get(key, 0.0) + EMA_ALPHA

    total = sum(updated.values())
    if total > 0:
        updated = {key: value / total for key, value in updated.items()}
    return updated


def update_baseline(
    baseline: dict[str, Any],
    telemetry: Any,
    assessment: Any | None = None,
    *,
    persist: bool = True,
) -> dict[str, Any]:
    """Return an updated baseline using conservative EMA adaptation."""
    new_baseline = normalize_baseline(baseline)

    if hasattr(telemetry, "duration_ms"):
        current = float(new_baseline.get("runtime_p95_ms", 500.0))
        new_baseline["runtime_p95_ms"] = _ema(current, float(telemetry.duration_ms))

    if hasattr(telemetry, "indicator_hash") and hasattr(telemetry, "output_hash"):
        known_hashes = dict(new_baseline.get("known_output_hashes", {}))
        known_hashes[str(telemetry.indicator_hash)] = str(telemetry.output_hash)
        new_baseline["known_output_hashes"] = known_hashes

    if hasattr(telemetry, "indicator_type"):
        new_baseline["input_type_distribution"] = _update_distribution(
            new_baseline.get("input_type_distribution", {}),
            [str(telemetry.indicator_type)],
        )

    if hasattr(telemetry, "modules_executed"):
        new_baseline["module_usage_distribution"] = _update_distribution(
            new_baseline.get("module_usage_distribution", {}),
            [str(module) for module in telemetry.modules_executed],
        )

    if not new_baseline.get("expected_manifest_hash") and hasattr(telemetry, "manifest_hash"):
        new_baseline["expected_manifest_hash"] = str(telemetry.manifest_hash)

    if not new_baseline.get("expected_dependency_hash") and hasattr(telemetry, "dependency_hash"):
        new_baseline["expected_dependency_hash"] = str(telemetry.dependency_hash)

    if not new_baseline.get("expected_runtime_python_version") and hasattr(
        telemetry,
        "runtime_python_version",
    ):
        new_baseline["expected_runtime_python_version"] = str(
            telemetry.runtime_python_version
        )

    if persist:
        save_baseline(new_baseline)

    return new_baseline
