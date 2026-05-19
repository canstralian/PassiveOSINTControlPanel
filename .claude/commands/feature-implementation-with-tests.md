---
name: feature-implementation-with-tests
description: Workflow command scaffold for feature-implementation-with-tests in PassiveOSINTControlPanel.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /feature-implementation-with-tests

Use this workflow when working on **feature-implementation-with-tests** in `PassiveOSINTControlPanel`.

## Goal

Implements a new core feature or module, accompanied by corresponding tests to validate new behaviors.

## Common Files

- `osint_core/constraints.py`
- `osint_core/__init__.py`
- `tests/test_constraints.py`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Implement new logic or module in osint_core (e.g., constraints.py).
- Update or create __init__.py to expose new functionality if needed.
- Write or update tests in tests/ (e.g., test_constraints.py) to cover new behaviors and pin invariants.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.