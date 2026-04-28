# inference-controller

A decision-theoretic metareasoning controller over a typed probabilistic
evidence graph, implemented in a blackboard-style orchestration architecture
with non-monotonic belief maintenance.

## Status

MVP scaffolding. Mock tool gateway only. No real external adapters.

## Layout

```
src/
  domain/      Zod schemas, lifecycle state machine, IDs
  safety/      ScopePolicy, RiskClassifier, ApprovalGate
  audit/       Append-only AuditLogger, EventLogger
  tools/       Mock ToolGateway, ResultValidator
  graph/       BeliefGraph store, contradictions, merge
  controller/  Score decomposition, budgets, modes, stop rules
  chains/      Wired control chains (external action, state mutation)
  storage/     In-memory + JSONL persistence
tests/         Vitest suite covering required test categories
```

## Run

```
npm install
npm run typecheck
npm test
```

## Design invariants

Enforced by code and tests:

- Hypotheses, evidence, provenance, beliefs, contradictions, actions, audit
  events, lifecycle states, and validation results are separate types — never
  collapsed into a single `confidence`/`score`/`status` field.
- External actions are gated by
  `ScopePolicy -> RiskClassifier -> ApprovalGate -> AuditLogger -> ToolGateway -> ResultValidator -> EventLogger -> BeliefGraphUpdater`.
- State mutations are gated by
  `InputValidator -> ScopePolicy -> AuditLogger -> DomainService -> ResultValidator -> EventLogger`.
- Audit log failure causes fail-closed.
- Lifecycle transitions are validated against an explicit state machine.
- Evidence without provenance is excluded from formal posterior updates.
- Merges in MVP are reversible unless explicitly finalized by approval.
- Every controller cycle considers `stop_and_report`.
- Every selected action persists its score decomposition.
