---
name: implement-drift
description: Implement the drift detection layer to satisfy tests/test_drift.py
disable-model-invocation: true
---

Implement `osint_core/drift.py` to satisfy `tests/test_drift.py`.

1. **Read first:**
   - Read `osint_core/drift.py` — it is pseudocode (raises `SyntaxError` on import), treat it as a design spec only
   - Read `tests/test_drift.py` in full — these are the contract tests to satisfy
   - Required exports: `DriftAssessment`, `DriftSignal`, `DriftType`, `DriftVector`, `TelemetrySnapshot`, `aggregate_signals`, `assess_drift`, `choose_dominant_drift_type`, `estimate_confidence`, `recommend_correction`

2. **Implement from scratch** (do not edit the pseudocode in-place):
   - Use `from __future__ import annotations`
   - Use `@dataclass(frozen=True)` for all value objects
   - Use `Literal[...]` or `enum.Enum` for `DriftType` and correction verbs
   - `assess_drift` must be **pure** — no mutations to inputs (see `test_assess_drift_is_pure_and_does_not_mutate_inputs`)
   - Correction priority: `policy > structural > behavioral > adversarial > operational > statistical`
   - Adversarial signals must CONSTRAIN before the system ADAPTs; statistical drift may ADAPT only when nothing higher-priority fires

3. **Iterate test-by-test:**
   ```bash
   pytest tests/test_drift.py -v -x   # stop at first failure
   ```

4. **When all pass:**
   ```bash
   pytest -v
   ruff check osint_core/drift.py
   bandit -r osint_core/drift.py
   ```
