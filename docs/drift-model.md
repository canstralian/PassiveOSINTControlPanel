# Drift Model

## Core Definition

In this system, drift is not merely change.

Drift is unexplained deviation from declared intent under policy and constraints.

```text
Drift = Observed Behavior - Expected Behavior
```

The `-` symbol is conceptual, not a single arithmetic operator. It means measured deviation beyond the tolerance model for the relevant dimension.

Depending on the dimension, deviation may be computed as:

- set difference, such as observed modules minus expected modules
- set intersection, such as blocked modules that nevertheless executed
- predicate failure, such as schema mismatch
- bounded numeric distance, such as latency or distribution shift

More specifically:

```text
Drift = Observed Behavior - Expected Behavior under intent + policy + constraints
```

Each drift dimension is normalized to a score in `[0.0, 1.0]`:

```text
0.0 = no unexplained deviation
1.0 = maximum observed deviation or hard boundary breach
```

Tolerances are dimension-specific. Expected variation inside tolerance is not drift. Deviation outside tolerance becomes drift and contributes to the drift vector.

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

## Core Axis: Invariant Violation vs Distribution Shift

The deepest distinction in the drift model is not merely severity. It is causal meaning.

```text
Structural Drift   ←──────────────→   Statistical Drift
Invariant Broken                      Distribution Changed
```

Structural drift means:

```text
This should never happen, but it did.
```

Statistical drift means:

```text
This usually happens differently now.
```

This difference drives the control response. Structural drift challenges the system's constraints. Statistical drift challenges the system's model.

## Classification Precedence

Drift categories can overlap. A single run may contain Policy drift, Structural drift, Behavioral drift, and Statistical drift at the same time. The system chooses the dominant control response using this precedence:

```text
Policy > Structural > Behavioral > Adversarial > Operational > Statistical
```

Policy drift overrides Structural drift because an explicit boundary was breached. Structural drift overrides Behavioral drift because the system grammar changed before module behavior can be trusted. Behavioral drift overrides Statistical drift because contract failure is more serious than distribution movement.

When multiple categories co-occur, the system selects the most restrictive control response implied by the highest-precedence category, then records the remaining categories as supporting signals rather than double-counting them as independent primary causes.

## Drift Vector

The drift vector has six dimensions.

### 1. Structural Drift

Structural drift is a control-plane violation: a mismatch in what was executed or what capability boundary was crossed.

It means execution violated one or more of:

- intent contract
- policy boundary
- capability scope
- trust invariant

Example:

```text
Intent:    ["DNS Records"]
Observed:  ["DNS Records", "HTTP Headers"]
```

This indicates unauthorized capability expansion.

Other examples:

- module executed outside intent
- unauthorized HTTP call
- forbidden operation appears, such as scanning
- policy bypass changes the execution path

Structural drift means the system can no longer fully trust its own control loop. The response is immediate containment, not slow analysis.

Correct mental model:

```text
Structural drift = control-plane corruption
```

Typical response:

```text
FAIL_CLOSED → BLOCKED → trust collapse → rollback or quarantine
```

### 2. Policy Drift

Policy drift is violation of explicit policy boundaries.

Example:

```text
HTTP Headers executed without authorized_target=true
```

This indicates a policy boundary breach.

Policy drift is closely related to Structural Drift. Structural drift asks whether the system's grammar was violated. Policy drift identifies which explicit policy rule failed.

Policy Drift is treated as a subtype of Structural Drift when the policy violation manifests as a grammar or capability-structure breach, such as a blocked module executing. If the policy issue is purely declarative, such as a missing approval record with no forbidden execution, it remains an orthogonal policy dimension with its own control response.

### Relationship to Structural Drift

Policy Drift and Behavioral Drift can either be subtypes of Structural Drift or orthogonal dimensions, depending on how the incident manifests:

- Policy Drift is structural when a policy boundary breach changes what executed.
- Behavioral Drift is structural when a contract violation changes the shape, schema, or capability grammar of the run.
- Otherwise, Policy Drift and Behavioral Drift remain separate dimensions with distinct control responses.

To avoid double-counting, classify the dominant cause using the precedence rule, then attach overlapping categories as evidence on the same incident.

### 3. Behavioral Drift

Behavioral drift happens when the correct module runs but produces behavior outside its contract.

Example:

```text
DNS module executes, but returns malformed schema.
```

This indicates implementation deviation.

Behavioral drift is not automatically structural. It becomes structural only when the behavior violates the execution grammar itself, such as returning an output shape that downstream components cannot interpret.

### 4. Statistical Drift

Statistical drift is signal-plane variation: a distribution shift over time.

It means outputs differ from the historical baseline while remaining:

- within policy
- within intent
- structurally valid

Example:

```text
DNS responses begin varying wildly across repeated runs.
```

Other examples:

- response timing shifts
- output frequency distribution changes
- DNS results vary more than expected
- minor schema variation remains valid but becomes more common

Statistical drift does not mean the system is broken. It means the model of the world may be outdated.

Correct mental model:

```text
Statistical drift = model mismatch, not system failure
```

Typical response:

```text
OBSERVE → accumulate evidence → adapt baseline slowly
```

### 5. Operational Drift

Operational drift is runtime instability under load, time, or degraded conditions.

Examples:

- timeouts
- retries
- latency spikes
- degraded execution paths
- repeated error thresholds

Operational drift may be noise when it stays inside tolerance. It becomes signal when instability repeats, exceeds thresholds, or combines with behavioral, structural, or adversarial evidence.

### 6. Adversarial Drift

Adversarial drift is evidence that input or environment is attempting to manipulate the system.

Examples:

- crafted input designed to bypass validation
- encoded traversal attempts
- metadata endpoint probes
- command separators in user input
- attempts to trigger forbidden execution paths

Adversarial drift follows a containment-first rule:

```text
CONSTRAIN before ADAPT
```

The system should first reduce authority or isolate the run. It may adapt only after containment proves the signal is safe to learn from.

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

The core calculation compares expected and observed behavior.

Definitions:

```python
expected = set(intent.requested_modules)
allowed = set(policy_result.allowed_modules)
blocked = set(policy_result.blocked_modules)
observed = set(execution_trace.results.keys())
observed_outputs = {module: execution_trace.results[module] for module in observed}
```

`expected` may be further narrowed by policy and constraints before execution:

```python
expected_effective = expected & allowed
```

Set operators:

```text
A \ B = set difference: elements in A that are not in B
A ∩ B = set intersection: elements present in both A and B
A ∪ B = set union: elements present in either A or B
```

Raw drift components:

```python
structural_raw = observed - expected_effective
policy_raw = blocked & observed
behavioral_raw = schema_mismatch(
    observed_outputs=observed_outputs,
    expected_schema=expected_schema,
    tolerance=tolerance,
)
```

`schema_mismatch(...)` returns the count of observed outputs that violate `expected_schema` beyond the configured tolerance. A tolerance may allow harmless variation such as optional fields, unordered collections, or documented nullable values.

Normalization maps raw deviations to `[0.0, 1.0]`:

```python
universe = expected_effective | observed
structural_score = len(structural_raw) / max(len(universe), 1)
policy_score = len(policy_raw) / max(len(observed), 1)
behavioral_score = behavioral_raw / max(len(observed), 1)
```

Other dimensions are computed separately:

```python
statistical_score = distribution_distance(current_distribution, baseline_distribution, tolerance)
operational_score = runtime_threshold_score(latency, errors, timeouts, baseline)
adversarial_score = adversarial_pattern_score(input_trace, environment_trace)
```

Scores at or below tolerance are normalized to `0.0`. Scores above tolerance are scaled toward `1.0` using the dimension's scoring function.

The result is assembled into a drift vector:

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

## Time Behavior

Different drift types operate on different clocks.

| Drift Type | Time Sensitivity | Action Window | Control Meaning |
|---|---:|---:|---|
| Policy | Immediate | Must act before propagation | Boundary breached |
| Structural | Immediate | Must act before propagation | Invariant broken |
| Behavioral | Fast to moderate | Verify before repeated execution | Contract deviation |
| Adversarial | Fast | Contain before manipulation spreads | Hostile influence |
| Operational | Moderate | Keep functioning while isolating instability | Execution degradation |
| Statistical | Deferred | Requires accumulation | Distribution changed |

Structural drift interrupts. Statistical drift trends.

## Control Response

Drift is causal, not merely diagnostic.

Thresholds are derived from the aggregated drift vector. The aggregate score is a weighted maximum rather than a simple average, so high-priority types cannot be diluted by low-priority noise.

```text
Policy and Structural weight highest
Behavioral and Adversarial weight high
Operational weight moderate
Statistical weight lowest
```

Response mapping:

```text
Low drift       → OBSERVE
Moderate drift  → CONSTRAIN
High drift      → REVERT
Critical drift  → FAIL_CLOSED
```

Interpretation:

- Critical drift → FAIL_CLOSED, driven first by Policy or Structural T1 signals.
- High drift → REVERT, typically triggered by Behavioral failure, Structural evidence below fail-closed threshold, or combined severe Operational signals.
- Moderate drift → CONSTRAIN, used for Adversarial indicators, Behavioral uncertainty, or repeated Operational degradation.
- Low drift → OBSERVE, used for Statistical variation and modeled operational noise.

Tie-breaker rule:

```text
Policy/Structural overrides Behavioral/Adversarial/Operational/Statistical.
If multiple high-severity types are present, choose the most restrictive response and escalate repair tiers accordingly.
```

A sharper repair hierarchy:

```text
T1 Policy / Structural → Stop the system from lying to itself
T2 Adversarial         → Stop the system from being manipulated
T3 Operational         → Keep the system functioning
T4 Statistical         → Keep the system calibrated
```

In the trust fabric:

```text
Drift → TrustDelta → TrustState → Future Scheduler Route
```

This means drift directly influences future verification depth and permission scope.

## Drift as a Routing Signal

Drift is not only classification. It is a control switch.

A classified drift event feeds three subsystems at the same time:

```text
Drift → Reconciliation
Drift → Trust Fabric
Drift → Scheduler
```

The runtime loop therefore becomes:

```text
Intent → Policy → Scheduler → Execution → Observer → Drift → Reconciliation → Trust → Next Scheduler Decision
```

Structural and statistical drift change different parts of the system.

Structural drift changes what the system is allowed to do:

- modules may be removed from the candidate set
- permission scope may be reduced
- routes may be blocked
- execution authority may collapse
- audit flags may be raised immediately

Statistical drift changes how the system decides:

- verification depth may increase
- the scheduler may choose a slower path
- observer evidence may receive more weight
- baseline recalibration may happen gradually
- repeated runs may compare more sources before accepting output

In compact form:

```text
Structural Drift  → fast response → large trust drop → authority reduction
Statistical Drift → slow response → small trust adjustment → verification increase
```

For passive OSINT, this produces the core safety rule:

```text
Drift never increases capability.
Drift only reduces or stabilizes capability.
```

Example structural route:

```text
HTTP Headers executed without authorization
→ REVERT or FAIL_CLOSED
→ trust collapse
→ HTTP Headers removed from allowed execution path
→ future runs require explicit authorization and stricter verification
```

Example statistical route:

```text
DNS results fluctuate beyond baseline
→ OBSERVE
→ slight trust friction
→ increase verification through repeat query or source comparison
→ update baseline slowly only if the shift remains inside policy and intent
```

## Relationship to Trust

Drift reduces trust when it reveals unexplained divergence from declared intent.

Clean runs may increase trust slowly, but trust recovery is intentionally asymmetric:

```text
Trust loss is fast.
Trust recovery is slow.
```

Structural drift is a trust shock:

```text
large negative delta → fast decay → authority collapse
```

Statistical drift is trust friction:

```text
small negative deltas over time → slow decay → increased verification depth
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
- policy breach is high-priority structural signal
- adversarial pattern is containment signal
- operational drift is noise while inside tolerance and signal when repeated or threshold-breaking

Mapping:

```text
Policy drift      → high-priority structural signal → FAIL_CLOSED or REVERT
Structural drift  → invariant breach → immediate containment
Behavioral drift  → contract deviation → REVERT or CONSTRAIN
Adversarial drift → containment first → CONSTRAIN before ADAPT
Operational drift → tolerate while bounded → CONSTRAIN if repeated or severe
Statistical drift → expectation shift → OBSERVE and adapt slowly
```

Misclassification is the hard problem:

- repeated statistical anomalies may look like noise while actually being coordinated adversarial shaping
- transient statistical spikes may look structural and cause unnecessary halts
- structural drift treated as statistical drift can produce silent policy erosion
- statistical drift treated as structural drift can produce paralysis

The discriminator exists to preserve the distinction:

```text
If the system's rules are violated → structural drift → act immediately
If only the system's expectations are violated → statistical drift → learn slowly
Adversarial drift → CONSTRAIN first, then ADAPT only if safe
```

## System Role

Drift is the interface between reality and control.

```text
Observer → Drift → Reconciliation → Trust → Scheduler
```

The observer tells the system what happened. Drift tells the system whether that difference matters. Trust decides how that difference should influence future authority and verification depth.

The system is therefore built to:

```text
detect → classify → route → constrain → learn
```

At runtime, that becomes:

```text
Act → Compare → Classify → Adjust Authority → Repeat
```

Drift is the central control signal because logs, outputs, and errors only become meaningful once compared against declared intent, policy, and constraints.

## Final Compression

Structural drift tests constraints. Statistical drift tests models.

```text
Constraints must hold under pressure → enforce rigidly
Models must evolve under pressure   → update gradually
```

The system therefore needs both:

- a spine: policy and invariants
- a memory: baseline and adaptation

Drift tells the system which one is being challenged.
