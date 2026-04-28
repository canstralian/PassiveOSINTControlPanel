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
import type { DomainEvent, ValidationResult } from "../domain/types.js";
import { newEventId } from "../domain/ids.js";

export type StateMutationRequest<I, O> = {
  actor: string;
  investigationId: string;
  operation: Parameters<AuditLogger["record"]>[0]["operation"];
  inputSchema: z.ZodType<I>;
  input: unknown;
  // Service that performs the actual mutation. It is invoked AFTER audit.
  service: (input: I) => O | Promise<O>;
  outputSchema: z.ZodType<O>;
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
      stage: "input" | "audit" | "service" | "output_validation";
      failClosed: boolean;
      validation: ValidationResult;
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

  // 2. Audit BEFORE service. Fail closed on audit error.
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

  // 3. Domain service.
  let output: O;
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

  // 4. Output validation.
  const outParsed = req.outputSchema.safeParse(output);
  if (!outParsed.success) {
    return {
      ok: false,
      stage: "output_validation",
      failClosed: false,
      validation: {
        ok: false,
        errorCode: "result_invalid",
        message: outParsed.error.message,
      },
    };
  }

  // 5. Event log (low-cost).
  if (req.eventKind) {
    deps.eventLogger.emit({
      id: newEventId(),
      investigationId: req.investigationId,
      kind: req.eventKind,
      payload: req.eventPayload ? req.eventPayload(output) : {},
      timestamp: new Date().toISOString(),
    });
  }

  return { ok: true, output, validation: { ok: true } };
}
