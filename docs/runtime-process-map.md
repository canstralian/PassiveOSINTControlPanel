# Runtime Process Map

## Purpose

This process map shows how the Passive OSINT Control Panel evaluates runtime behavior across validation, drift detection, constraint reconciliation, audit logging, and trust scoring.

The first implementation of the self-healing trust fabric is intentionally bounded:

```text
observe → score → persist → report
```

It does not autonomously expand authority.

```text
Trust may reduce authority automatically.
Trust may not increase authority automatically.
```

## High-Level Runtime Loop

```mermaid
flowchart TD
    A[User Input] --> B[Validate and Sanitize]
    B --> C[Normalize Indicator]
    C --> D[Hash Indicator]
    D --> E[Intent + Policy + Constraint Evaluation]
    E --> F[Scheduler Decision]
    F --> G{Route}

    G -->|FAST| H[Passive Execution]
    G -->|DELIBERATIVE| I[Extra Verification]
    G -->|CONTAINMENT| J[Reduced Scope Execution]
    G -->|FAIL_CLOSED| K[Block and Report]

    H --> L[Observer / Telemetry Snapshot]
    I --> L
    J --> L
    K --> L

    L --> M[Drift Assessment]
    M --> N[Reconciliation Result]
    N --> O[Audit Result]
    O --> P[Trust Delta]
    P --> Q[Trust State Update]
    Q --> R[Report and Persist]
    R --> S[Next Scheduler Decision]
    S --> F
```

## Drift Position

Drift is computed after observation and before reconciliation.

```text
Intent → Policy → Scheduler → Execution → Observer → Drift → Reconciliation
```

Drift is the measurable failure of alignment between intent, policy, and reality:

```text
Drift = Observed Behavior - Expected Behavior under intent + policy + constraints
```

The drift model is documented in [`docs/drift-model.md`](drift-model.md).

## Three Trust Circuits

```mermaid
flowchart LR
    subgraph Verification Circuit
        V1[Declared Intent]
        V2[Policy Rules]
        V3[Validation Gates]
        V4[CI / Runtime Checks]
        V1 --> V2 --> V3 --> V4
    end

    subgraph Divergence Circuit
        D1[Telemetry]
        D2[Baseline]
        D3[Expected Behavior]
        D4[Observed Behavior]
        D5[Drift Assessment]
        D6[Constraint Events]
        D1 --> D4
        D2 --> D3
        D3 --> D5
        D4 --> D5
        D6 --> D5
    end

    subgraph Repair Circuit
        R1[Reconciliation Result]
        R2[Trust Delta]
        R3[Trust State]
        R4[Verification Depth]
        R5[Permission Scope]
        R6[Scheduler Route]
        R1 --> R2 --> R3 --> R4 --> R6
        R3 --> R5 --> R6
    end

    V4 --> D1
    D5 --> R1
    R6 --> V3
```

## Trust Delta Lifecycle

```mermaid
sequenceDiagram
    participant Runtime
    participant Observer
    participant Drift
    participant Reconciliation
    participant Audit
    participant Trust
    participant Scheduler

    Runtime->>Observer: emit execution trace and telemetry
    Observer->>Drift: compare observed behavior to expected behavior
    Drift-->>Reconciliation: drift assessment
    Reconciliation-->>Trust: reconciliation result
    Audit-->>Trust: audit result
    Trust->>Trust: calculate_trust_delta()
    Trust->>Trust: apply_trust_delta()
    Trust-->>Scheduler: TrustState
    Scheduler->>Scheduler: derive route
    Scheduler-->>Runtime: FAST / DELIBERATIVE / CONTAINMENT / FAIL_CLOSED
```

## Scheduler Routing

```mermaid
flowchart TD
    A[Decision Packet + System State + Trust State] --> B{Trust Score / Scope}

    B -->|High trust + low risk| C[FAST]
    B -->|Medium trust| D[DELIBERATIVE]
    B -->|Low trust| E[CONTAINMENT]
    B -->|Collapsed trust| F[FAIL_CLOSED]

    C --> C1[Normal passive execution]
    D --> D1[Extra checks before execution]
    E --> E1[Reduced scope and isolated outputs]
    F --> F1[Block until operator review]
```

## Trust Score Movement

Trust movement is asymmetric.

```mermaid
flowchart LR
    A[Clean Evidence] -->|small positive delta| B[Slow Recovery]
    C[Policy / Drift / Audit Failure] -->|full negative delta| D[Fast Trust Loss]
    B --> E[Normal Verification Only]
    D --> F[Constrain / Quarantine / Block]
```

Positive evidence includes:

- clean drift assessment
- policy-compliant execution
- audit-safe payload
- passing CI
- reproducible output shape

Negative evidence includes:

- policy violation
- adversarial drift
- structural drift
- behavioral drift
- failed audit safety check
- CI or deployment failure

## Drift to Trust Mapping

```mermaid
flowchart TD
    A[Drift Vector] --> B{Dominant Drift Type}
    B -->|None / Modeled Variation| C[OBSERVE]
    B -->|Statistical / Operational| D[OBSERVE or CONSTRAIN]
    B -->|Adversarial| E[CONSTRAIN]
    B -->|Behavioral / Structural| F[REVERT]
    B -->|Policy| G[FAIL_CLOSED]

    C --> H[Small positive or neutral TrustDelta]
    D --> I[Small negative TrustDelta]
    E --> J[Negative TrustDelta + constrained scope]
    F --> K[Negative TrustDelta + rollback recommendation]
    G --> L[Collapsed TrustState + blocked scope]
```

## Runtime Integration Point

The scheduler should accept trust state explicitly:

```python
schedule_decision(
    packet=decision_packet,
    state=system_state,
    trust_state=trust_state,
)
```

Routing should follow:

```text
high trust + low risk → FAST
medium trust → DELIBERATIVE
low trust → CONTAINMENT
collapsed trust → FAIL_CLOSED
```

## Current Implementation Boundary

Implemented in the first trust layer:

- `TrustDelta`
- `TrustState`
- `calculate_trust_delta()`
- `apply_trust_delta()`
- `derive_verification_depth()`
- `derive_permission_scope()`
- scheduler route derivation
- asymmetric trust recovery tests
- drift model documentation

Not implemented yet:

- automatic authority expansion
- autonomous policy mutation
- hardware trust propagation
- cross-component trust graph routing
- repair execution beyond observe/constrain/quarantine/rollback recommendation

## Control Rule

The trust fabric can make the system safer without granting new authority:

```text
High trust can preserve the current path.
Low trust can reduce scope.
Collapsed trust can fail closed.
No trust score can automatically grant a broader permission scope.
```
