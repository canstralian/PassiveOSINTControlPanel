"""
osint_core/drift.py

Purpose:
    Convert execution telemetry into a drift vector.

Principles:
    - Drift is a vector, not a scalar.
    - Detection does not mutate state.
    - Correction is separate.
    - Policy drift outranks statistical drift.
    - Adversarial drift constrains before adapting.
"""

DEFINE DriftType:
    statistical
    behavioral
    structural
    adversarial
    operational
    policy


DEFINE DriftVector:
    statistical: float 0.0 to 1.0
    behavioral: float 0.0 to 1.0
    structural: float 0.0 to 1.0
    adversarial: float 0.0 to 1.0
    operational: float 0.0 to 1.0
    policy: float 0.0 to 1.0


DEFINE DriftSignal:
    name
    drift_type
    score
    reason
    tier
    evidence


DEFINE DriftAssessment:
    drift_vector
    signals
    dominant_type
    recommended_correction
    confidence

FUNCTION assess_drift(telemetry, baseline, manifest, policy_result):

    signals = []

    signals += check_policy_drift(policy_result)

    signals += check_adversarial_drift(telemetry)

    signals += check_operational_drift(telemetry, baseline)

    signals += check_structural_drift(telemetry, manifest)

    signals += check_behavioral_drift(telemetry, baseline)

    signals += check_statistical_drift(telemetry, baseline)

    drift_vector = aggregate_signals(signals)

    dominant_type = choose_dominant_drift_type(drift_vector)

    correction = recommend_correction(drift_vector, signals)

    confidence = estimate_confidence(signals)

    RETURN DriftAssessment(
        drift_vector=drift_vector,
        signals=signals,
        dominant_type=dominant_type,
        recommended_correction=correction,
        confidence=confidence
    )

FUNCTION check_adversarial_drift(telemetry):

    suspicious_patterns = [
        "../",
        "%2e%2e",
        "<script",
        "javascript:",
        "file:",
        "localhost",
        "127.0.0.1",
        "169.254.169.254",
        "$(",
        "`",
        ";",
        "|"
    ]

    FOR pattern IN suspicious_patterns:
        IF pattern appears in rejected_input_reason OR sanitized_input_trace:
            ADD signal(
                type=adversarial,
                score=0.7,
                tier=T2,
                reason="Suspicious input pattern detected"
            )

    IF repeated rejected inputs exceed baseline:
        ADD signal(
            type=adversarial,
            score=0.5,
            tier=T2,
            reason="Rejected input rate elevated"
        )

    RETURN signals

FUNCTION check_operational_drift(telemetry, baseline):

    IF runtime_ms > baseline.runtime_p95 * 2:
        ADD signal(
            type=operational,
            score=0.5,
            tier=T3,
            reason="Runtime exceeded expected boundary"
        )

    IF error_count > baseline.error_rate_threshold:
        ADD signal(
            type=operational,
            score=0.6,
            tier=T3,
            reason="Error rate exceeded baseline"
        )

    IF timeout_count increased:
        ADD signal(
            type=operational,
            score=0.4,
            tier=T3,
            reason="Timeout rate elevated"
        )

    RETURN signals

FUNCTION check_structural_drift(telemetry, manifest):

    IF telemetry.manifest_hash != manifest.hash:
        RETURN signal(
            type=structural,
            score=1.0,
            tier=T1,
            reason="Execution manifest mismatch"
        )

    IF dependency_hash changed without approved manifest:
        RETURN signal(
            type=structural,
            score=0.9,
            tier=T1,
            reason="Dependency graph changed"
        )

    IF runtime_python_version changed:
        RETURN signal(
            type=structural,
            score=0.6,
            tier=T2,
            reason="Runtime version changed"
        )

    RETURN []

FUNCTION check_behavioral_drift(telemetry, baseline):

    IF same_input_hash existed before:
        previous_output_hash = baseline.output_hash_for(input_hash)

        IF current_output_hash != previous_output_hash:
            ADD signal(
                type=behavioral,
                score=0.9,
                tier=T1,
                reason="Same input produced different output"
            )

    IF output_schema_invalid:
        ADD signal(
            type=behavioral,
            score=0.8,
            tier=T1,
            reason="Output schema invalid"
        )

    RETURN signals

FUNCTION check_statistical_drift(telemetry, baseline):

    IF input_type_distribution changed:
        ADD signal(
            type=statistical,
            score=0.4,
            tier=T4,
            reason="Input type distribution shifted"
        )

    IF module_usage_distribution changed:
        ADD signal(
            type=statistical,
            score=0.3,
            tier=T4,
            reason="Module usage distribution shifted"
        )

    IF average_input_entropy changed:
        ADD signal(
            type=statistical,
            score=0.4,
            tier=T4,
            reason="Input entropy shifted"
        )

    RETURN signals

FUNCTION aggregate_signals(signals):

    vector = DriftVector(all zeros)

    FOR each drift_type:
        matching = signals where signal.type == drift_type

        IF no matching:
            vector[drift_type] = 0.0
        ELSE:
            vector[drift_type] = max(signal.score for matching)

    RETURN vector

FUNCTION choose_dominant_drift_type(vector):

    priority_order = [
        policy,
        structural,
        behavioral,
        adversarial,
        operational,
        statistical
    ]

    FOR type IN priority_order:
        IF vector[type] > 0:
            RETURN type

    RETURN none

FUNCTION recommend_correction(vector, signals):

    IF vector.policy >= 0.6:
        RETURN REVERT

    IF vector.structural >= 0.5:
        RETURN REVERT

    IF vector.behavioral >= 0.7:
        RETURN REVERT

    IF vector.adversarial >= 0.3:
        RETURN CONSTRAIN

    IF vector.operational >= 0.7:
        RETURN CONSTRAIN

    IF vector.statistical >= 0.5:
        RETURN ADAPT

    RETURN OBSERVE

FUNCTION passes_noise_filter(signal, history):

    IF signal.tier == T1:
        RETURN True

    persistence = signal appears N times across M windows

    ensemble_agreement = at least two detectors agree

    causal_hypothesis = signal.reason is not empty

    IF persistence AND ensemble_agreement AND causal_hypothesis:
        RETURN True

    RETURN False

