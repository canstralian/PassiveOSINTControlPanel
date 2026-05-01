---
name: refactor-or-tighten-core-module-and-tests
description: Workflow command scaffold for refactor-or-tighten-core-module-and-tests in PassiveOSINTControlPanel.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /refactor-or-tighten-core-module-and-tests

Use this workflow when working on **refactor-or-tighten-core-module-and-tests** in `PassiveOSINTControlPanel`.

## Goal

Refactors or tightens the API and internal logic of a core module, synchronizing changes with corresponding tests.

## Common Files

- `osint_core/constraints.py`
- `tests/test_constraints.py`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Refactor or update logic in the core module (e.g., constraints.py).
- Update or add tests in tests/ (e.g., test_constraints.py) to pin new behaviors or invariants.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.