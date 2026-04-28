# Drift Model

## Core Definition

In this system, drift is not merely change.

Drift is unexplained deviation from declared intent under policy and constraints.

```text
Drift = Observed Behavior - Expected Behavior
```

More specifically:

```text
Drift = Observed Behavior - Expected Behavior under intent + policy + constraints
```

If a difference is expected, modeled, or explicitly approved, it is not drift. It is ordinary variation, nondeterminism, or authorized adaptation.

If a difference is unexplained, outside declared bounds, or violates policy, it is drift.

## Runtime Position

Drift is computed after observation, not during execution.

```text
Intent → Policy → Scheduler → Execution → Observer → Drift → Reconciliation
```

Drift answers:

```text
Did reality evolve in the shape both the intent circuit and policy circuit expected?
```

## Alignment Contract

The system treats each run as an alignment contract:

- intent declares what should happen
- policy declares what may happen
- constraints declare what must not happen
- execution produces what did happen
- observation records what can be measured
- drift measures the alignment gap

Drift is therefore the measurable failure of alignment between intent, policy, and reality.

## Drift Vector

The drift vector has six dimensions.

### 1. Structural Drift

Structural drift is a mismatch in what was executed.

Example:

```text
Intent:    ["DNS Records"]
Observed:  ["DNS Records", "HTTP Headers"]
```

This indicates unauthorized capability expansion.

### 2. Policy Drift

Policy drift is violation of explicit policy boundaries.

Example:

```text
HTTP Headers executed without authorized_target=true
```

This indicates a policy boundary breach.

### 3. Behavioral Drift

Behavioral drift happens when the correct module runs but produces behavior outside its contract.

Example:

```text
DNS module executes, but returns malformed schema.
```

This indicates implementation deviation.

### 4. Statistical Drift

Statistical drift is a distribution shift over time.

Example:

```text
DNS responses begin varying wildly across repeated runs.
```

This may indicate instability, environmental change, or upstream behavior shift.

### 5. Operational Drift

Operational drift is runtime instability under load, time, or degraded conditions.

Examples:

- timeouts
- retries
- latency spikes
- degraded execution paths
- repeated error thresholds

### 6. Adversarial Drift

Adversarial drift is evidence that input or environment is attempting to manipulate the system.

Examples:

- crafted input designed to bypass validation
- encoded traversal attempts
- metadata endpoint probes
- command separators in user input
- attempts to trigger forbidden execution paths

## What Drift Is Not

Drift is not:

- normal variation
- expected nondeterminism
- approved policy changes
- intentional constraint-driven adaptation
- reordered output where ordering is not part of the contract
- known transient infrastructure behavior inside accepted bounds

This distinction prevents the system from confusing noise with signal.

## Conceptual Computation

The core calculation compares expected and observed behavior:

```python
expected = intent.requested_modules
observed = execution_trace.results.keys()

structural_drift = observed - expected
policy_drift = blocked_modules & observed
behavioral_drift = schema_mismatch(observed_outputs)
```

The result is normalized into a drift vector:

```json
{
  "structural": 0.2,
  "policy": 0.5,
  "behavioral": 0.1,
  "statistical": 0.0,
  "operational": 0.0,
  "adversarial": 0.0
}
```

## Why Drift Exists

Drift emerges from four forces:

1. incomplete intent specification
2. imperfect execution
3. environmental change
4. adversarial pressure

The architecture assumes all four forces are always present.

## Control Response

Drift is causal, not merely diagnostic.

```text
Low drift       → OBSERVE
Moderate drift  → CONSTRAIN
High drift      → REVERT
Critical drift  → FAIL_CLOSED
```

In the trust fabric:

```text
Drift → TrustDelta → TrustState → Future Scheduler Route
```

This means drift directly influences future verification depth and permission scope.

## Relationship to Trust

Drift reduces trust when it reveals unexplained divergence from declared intent.

Clean runs may increase trust slowly, but trust recovery is intentionally asymmetric:

```text
Trust loss is fast.
Trust recovery is slow.
```

A component with recurring drift moves toward:

```text
normal → elevated → strict → quarantined
```

And permission scope moves toward:

```text
conditional/passive → restricted → blocked
```

Trust may reduce authority automatically. Trust may not increase authority automatically.

## Relationship to Signal vs. Noise

Not every deviation should trigger repair.

The signal-vs-noise discriminator separates meaningful drift from expected variation:

- modeled variation is noise
- unexplained divergence is signal
- policy breach is high-priority signal
- adversarial pattern is containment signal

## System Role

Drift is the system's way of detecting when its internal model of reality is wrong.

It sits between observation and reconciliation:

```text
Observer → Drift → Reconciliation
```

The system is therefore built to:

```text
detect → classify → respond → learn
```

Drift is the central control signal because logs, outputs, and errors only become meaningful once compared against declared intent, policy, and constraints.
