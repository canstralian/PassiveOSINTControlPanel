# Skill: Constraint-Aware Invention Engine

## Purpose

Use this skill when adding, reviewing, or wiring the constraint-aware invention engine in `osint_core/`.

The engine is a planning and control layer. It must not expand runtime authority, execute active reconnaissance, or mutate policy by itself.

## Relevant files

- `osint_core/types.py`
- `osint_core/constraints.py`
- `osint_core/invention.py`
- `osint_core/reflection.py`
- `osint_core/adaptation.py`
- `osint_core/scorecard.py`
- `osint_core/ledger.py`
- `osint_core/audit.py`
- `osint_core/reports.py`
- `policy/passive_scope_rules.yaml`
- `policy/authority_matrix.yaml`
- `policy/constraint_profiles.yaml`
- `tests/test_constraints.py`
- `tests/test_invention_loop.py`
- `tests/test_constraint_ledger.py`
- `tests/test_scorecard.py`
- `tests/test_passive_boundaries.py`

## Operating model

The engine has four loops:

1. Generative loop
   - Convert requested modules into proposed actions.
   - Do not execute modules.

2. Constraint loop
   - Evaluate proposed actions against `osint_core.policy`.
   - Preserve passive-first behavior.
   - Keep forbidden capabilities blocked.

3. Reflection loop
   - Convert constraint events into operator-readable lessons.
   - Do not introduce new correction verbs.

4. Adaptation loop
   - Produce bounded recommendations.
   - Never mutate policy automatically.

## Hard invariants

- No scanning, brute forcing, credential testing, exploitation, or unscoped target interaction.
- `AUTHORIZATION_REQUIRED` actions are not executable until the correct approval and execution mode exist.
- Approval-gated actions must appear in `requires_approval_actions` and remain blocked while not executable.
- `allowed_actions` means executable now.
- `blocked_actions` means not executable now.
- `requires_approval_actions` means blocked now, but gated rather than forbidden.
- Raw indicators must never appear in audit or ledger payloads.
- Constraint ledger paths must validate `run_id` and prevent traversal.
- Ordering of proposed, allowed, blocked, and approval-gated actions must be deterministic.

## Preferred checks

Run targeted tests after changes:

```bash
PYTHONPATH=. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -q \
  tests/test_constraints.py \
  tests/test_invention_loop.py \
  tests/test_constraint_ledger.py \
  tests/test_scorecard.py \
  tests/test_passive_boundaries.py
```

Run lint and format checks:

```bash
ruff check --fix osint_core tests
ruff format --check osint_core tests
```

## Common changes

When adding a new module capability:

1. Add or update the policy entry in `osint_core/policy.py`.
2. Decide explicitly whether it touches the target.
3. Decide explicitly whether it requires authorization.
4. Add tests that prove passive mode blocks unsafe behavior.
5. Do not add execution logic in this skill unless specifically requested.

When changing constraint decisions:

1. Update `osint_core/constraints.py`.
2. Update the relevant dataclass in `osint_core/types.py` only if the contract changes.
3. Update ledger serialization if new fields should be persisted.
4. Update tests before marking the change complete.
