"""
osint_core/baseline.py

Purpose:
    Persist and manage baseline data for drift detection across runs.

Principles:
    - Baselines are stored in data/baseline.json
    - Baseline updates are incremental and use exponential moving averages
    - Baseline file is created with safe defaults on first run
    - Never mutate baseline during drift detection (separation of concerns)

Design:
    - BaselineData is a dict-like structure for flexibility
    - update_baseline uses conservative update logic (slow adaptation)
    - All I/O is wrapped in error handling to prevent crashes
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Default baseline used when no baseline.json exists
DEFAULT_BASELINE = {
    "runtime_p95_ms": 500,
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

# Path to baseline file
BASELINE_PATH = Path(__file__).resolve().parent.parent / "data" / "baseline.json"

# Exponential moving average weight (0.1 = slow adaptation, 0.9 = fast adaptation)
EMA_ALPHA = 0.1


def load_baseline() -> dict[str, Any]:
    """
    Load baseline from disk, or return default baseline if file doesn't exist.

    Returns:
        dict containing baseline data
    """
    if not BASELINE_PATH.exists():
        return DEFAULT_BASELINE.copy()

    try:
        with open(BASELINE_PATH, "r", encoding="utf-8") as f:
            baseline = json.load(f)

        # Merge with defaults to ensure all required keys exist
        result = DEFAULT_BASELINE.copy()
        result.update(baseline)
        return result
    except (OSError, json.JSONDecodeError) as e:
        # On error, return default baseline but don't crash
        print(f"Warning: Failed to load baseline from {BASELINE_PATH}: {e}")
        return DEFAULT_BASELINE.copy()


def save_baseline(baseline: dict[str, Any]) -> None:
    """
    Save baseline to disk.

    Args:
        baseline: baseline data to persist
    """
    try:
        BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(BASELINE_PATH, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2, sort_keys=True)
    except OSError as e:
        # Log but don't crash if we can't persist
        print(f"Warning: Failed to save baseline to {BASELINE_PATH}: {e}")


def update_baseline(
    baseline: dict[str, Any],
    telemetry: Any,
    assessment: Any | None = None,
) -> dict[str, Any]:
    """
    Update baseline with new telemetry data using exponential moving average.

    This function creates a new baseline dict (does not mutate the input).

    Args:
        baseline: current baseline
        telemetry: TelemetrySnapshot or similar object with run data
        assessment: optional DriftAssessment (for future use)

    Returns:
        updated baseline dict
    """
    new_baseline = baseline.copy()

    # Update runtime p95 (use simple moving max for now, proper p95 requires history)
    if hasattr(telemetry, "duration_ms"):
        current_p95 = new_baseline.get("runtime_p95_ms", 500)
        new_runtime = telemetry.duration_ms
        # Conservative: only increase p95 if we see a higher value
        new_baseline["runtime_p95_ms"] = max(current_p95, new_runtime)

    # Update known output hashes (behavioral drift detection)
    if hasattr(telemetry, "indicator_hash") and hasattr(telemetry, "output_hash"):
        known_hashes = new_baseline.get("known_output_hashes", {})
        known_hashes = known_hashes.copy()  # don't mutate original
        known_hashes[telemetry.indicator_hash] = telemetry.output_hash
        new_baseline["known_output_hashes"] = known_hashes

    # Update input type distribution
    if hasattr(telemetry, "indicator_type"):
        dist = new_baseline.get("input_type_distribution", {})
        dist = dist.copy()
        current_count = dist.get(telemetry.indicator_type, 0.0)
        # Exponential moving average
        dist[telemetry.indicator_type] = current_count * (1 - EMA_ALPHA) + EMA_ALPHA
        # Normalize all values
        total = sum(dist.values())
        if total > 0:
            dist = {k: v / total for k, v in dist.items()}
        new_baseline["input_type_distribution"] = dist

    # Update module usage distribution
    if hasattr(telemetry, "modules_executed"):
        dist = new_baseline.get("module_usage_distribution", {})
        dist = dist.copy()
        for module in telemetry.modules_executed:
            current_count = dist.get(module, 0.0)
            dist[module] = current_count * (1 - EMA_ALPHA) + EMA_ALPHA
        # Normalize
        total = sum(dist.values())
        if total > 0:
            dist = {k: v / total for k, v in dist.items()}
        new_baseline["module_usage_distribution"] = dist

    # Update structural expectations on first run or when explicitly changed
    if not new_baseline.get("expected_manifest_hash") and hasattr(telemetry, "manifest_hash"):
        new_baseline["expected_manifest_hash"] = telemetry.manifest_hash

    if not new_baseline.get("expected_dependency_hash") and hasattr(telemetry, "dependency_hash"):
        new_baseline["expected_dependency_hash"] = telemetry.dependency_hash

    if not new_baseline.get("expected_runtime_python_version") and hasattr(telemetry, "runtime_python_version"):
        new_baseline["expected_runtime_python_version"] = telemetry.runtime_python_version

    # Persist updated baseline to disk
    save_baseline(new_baseline)

    return new_baseline
