/**
 * Internal state-mutation control chain.
 *
 * InputValidator -> ScopePolicy -> AuditLogger -> DomainService ->
 * ResultValidator -> EventLogger
 *
 * State mutation MUST NOT occur before the audit event is written.
 */
import { z } from "zod";
import type { AuditLogger } from "../audit/logger.js";
import type { EventLogger } from "../audit/events.js";
import type {
  DomainEvent,
  ValidationFailure,
  ValidationResult,
} from "../domain/types.js";
import { newEventId } from "../domain/ids.js";

export type ScopeCheckResult =
  | { allowed: true }
  | { allowed: false; reason: string };

export type StateMutationRequest<I, O> = {
  actor: string;
  investigationId: string;
  operation: Parameters<AuditLogger["record"]>[0]["operation"];
  inputSchema: z.ZodType<I>;
  input: unknown;
  // ScopePolicy stage. Per the spec contract, every state mutation must
  // pass an explicit scope check between input validation and audit.
  // Callers MUST provide one — there is no implicit allow.
  scopeCheck: (input: I) => ScopeCheckResult;
  // Service that performs the actual mutation. It is invoked AFTER audit.
  // The service return type is `unknown` so the outputSchema can coerce /
  // strip / apply defaults to produce the validated O.
  service: (input: I) => unknown | Promise<unknown>;
  outputSchema: z.ZodType<O, z.ZodTypeDef, unknown>;
  // Optional event emitted on success.
  eventKind?: DomainEvent["kind"];
  eventPayload?: (output: O) => Record<string, unknown>;
  previousStateRef?: string;
  newStateRef?: (output: O) => string;
};

export type StateMutationOutcome<O> =
  | { ok: true; output: O; validation: ValidationResult }
  | {
      ok: false;
      stage: "input" | "scope" | "audit" | "service" | "output_validation";
      failClosed: boolean;
      validation: ValidationFailure;
    };

export async function runStateMutation<I, O>(
  deps: { auditLogger: AuditLogger; eventLogger: EventLogger },
  req: StateMutationRequest<I, O>
): Promise<StateMutationOutcome<O>> {
  // 1. Input validation.
  const parsed = req.inputSchema.safeParse(req.input);
  if (!parsed.success) {
    return {
      ok: false,
      stage: "input",
      failClosed: false,
      validation: {
        ok: false,
        errorCode: "schema_invalid",
        message: parsed.error.message,
      },
    };
  }

  // 2. Scope check. Per spec contract: InputValidator -> ScopePolicy ->
  // AuditLogger -> ... Mutations cannot bypass policy.
  const scopeResult = req.scopeCheck(parsed.data);
  if (!scopeResult.allowed) {
    return {
      ok: false,
      stage: "scope",
      failClosed: false,
      validation: {
        ok: false,
        errorCode: "scope_denied",
        message: scopeResult.reason,
      },
    };
  }

  // 3. Audit BEFORE service. Fail closed on audit error.
  try {
    await deps.auditLogger.record({
      actor: req.actor,
      investigationId: req.investigationId,
      operation: req.operation,
      inputRefs: [],
      scopeDecision: "n/a",
      riskDecision: "n/a",
      ...(req.previousStateRef !== undefined
        ? { previousStateRef: req.previousStateRef }
        : {}),
    });
  } catch {
    return {
      ok: false,
      stage: "audit",
      failClosed: true,
      validation: {
        ok: false,
        errorCode: "audit_unavailable",
        message: "audit unavailable; mutation refused",
      },
    };
  }

  // 4. Domain service.
  let output: unknown;
  try {
    output = await req.service(parsed.data);
  } catch (err) {
    return {
      ok: false,
      stage: "service",
      failClosed: false,
      validation: {
        ok: false,
        errorCode: "result_invalid",
        message: err instanceof Error ? err.message : String(err),
      },
    };
  }

  // 5. Output validation.
  // If this fails, the domain service has ALREADY mutated state, but we
  // cannot describe the result. Per spec point 4 ("transactional where
  // possible") we have no rollback, so the system is potentially
  // inconsistent — fail closed so callers treat this as a critical
  // incident, not a routine error.
  const outParsed = req.outputSchema.safeParse(output);
  if (!outParsed.success) {
    return {
      ok: false,
      stage: "output_validation",
      failClosed: true,
      validation: {
        ok: false,
        errorCode: "result_invalid",
        message: outParsed.error.message,
      },
    };
  }
  const validatedOutput = outParsed.data;

  // 6. Event log (low-cost).
  if (req.eventKind) {
    deps.eventLogger.emit({
      id: newEventId(),
      investigationId: req.investigationId,
      kind: req.eventKind,
      payload: req.eventPayload ? req.eventPayload(validatedOutput) : {},
      timestamp: new Date().toISOString(),
    });
  }

  return { ok: true, output: validatedOutput, validation: { ok: true } };
}
