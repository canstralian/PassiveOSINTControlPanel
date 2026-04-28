/**
 * Result validator.
 *
 * Validates tool outputs against a per-tool zod schema before they are
 * allowed to influence belief or graph state.
 */
import type { ZodSchema } from "zod";
import type { ToolResultEnvelope } from "./gateway.js";
import type { ValidationResult } from "../domain/types.js";

export class ResultValidator {
  private readonly schemas = new Map<string, ZodSchema>();

  register(toolId: string, schema: ZodSchema): void {
    this.schemas.set(toolId, schema);
  }

  validate(envelope: ToolResultEnvelope): ValidationResult {
    if (!envelope.ok) {
      return {
        ok: false,
        errorCode: "tool_failure",
        message: envelope.errorMessage ?? "tool reported failure",
      };
    }
    const schema = this.schemas.get(envelope.toolId);
    if (!schema) {
      return {
        ok: false,
        errorCode: "result_invalid",
        message: `no schema registered for tool ${envelope.toolId}`,
      };
    }
    const parsed = schema.safeParse(envelope.output);
    if (!parsed.success) {
      return {
        ok: false,
        errorCode: "result_invalid",
        message: parsed.error.message,
      };
    }
    return { ok: true };
  }
}
