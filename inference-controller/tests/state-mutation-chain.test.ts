import { describe, it, expect } from "vitest";
import { z } from "zod";
import { runStateMutation } from "../src/chains/state-mutation.js";
import { AuditLogger, InMemoryAuditSink } from "../src/audit/logger.js";
import { EventLogger } from "../src/audit/events.js";

const allowAll = () => ({ allowed: true } as const);

describe("state-mutation chain", () => {
  it("audits BEFORE the service runs (verified by ordered side effects)", async () => {
    const order: string[] = [];
    const sink = new InMemoryAuditSink();
    const originalWrite = sink.write.bind(sink);
    sink.write = async (event) => {
      order.push("audit");
      return originalWrite(event);
    };
    const auditLogger = new AuditLogger(sink);
    const eventLogger = new EventLogger();

    const out = await runStateMutation(
      { auditLogger, eventLogger },
      {
        actor: "tester",
        investigationId: "inv_1",
        operation: "hypothesis_created",
        inputSchema: z.object({ statement: z.string() }),
        input: { statement: "x" },
        scopeCheck: allowAll,
        service: async (input) => {
          order.push("service");
          return input;
        },
        outputSchema: z.object({ statement: z.string() }),
      }
    );
    expect(out.ok).toBe(true);
    expect(order).toEqual(["audit", "service"]);
  });

  it("rejects invalid input without invoking scope, audit, or the service", async () => {
    const auditLogger = new AuditLogger(new InMemoryAuditSink());
    const eventLogger = new EventLogger();
    let scopeCalled = false;
    let serviceCalled = false;
    const out = await runStateMutation(
      { auditLogger, eventLogger },
      {
        actor: "tester",
        investigationId: "inv_1",
        operation: "hypothesis_created",
        inputSchema: z.object({ statement: z.string() }),
        input: { statement: 42 } as unknown,
        scopeCheck: () => {
          scopeCalled = true;
          return { allowed: true };
        },
        service: async (i) => {
          serviceCalled = true;
          return i;
        },
        outputSchema: z.unknown(),
      }
    );
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.stage).toBe("input");
      expect(out.validation.ok).toBe(false);
      if (!out.validation.ok) expect(out.validation.errorCode).toBe("schema_invalid");
    }
    expect(scopeCalled).toBe(false);
    expect(serviceCalled).toBe(false);
  });

  it("denies when ScopePolicy stage rejects, before audit and service", async () => {
    const sink = new InMemoryAuditSink();
    const order: string[] = [];
    const originalWrite = sink.write.bind(sink);
    sink.write = async (event) => {
      order.push("audit");
      return originalWrite(event);
    };
    const auditLogger = new AuditLogger(sink);
    const eventLogger = new EventLogger();
    let serviceCalled = false;
    const out = await runStateMutation(
      { auditLogger, eventLogger },
      {
        actor: "tester",
        investigationId: "inv_1",
        operation: "hypothesis_created",
        inputSchema: z.object({ statement: z.string() }),
        input: { statement: "x" },
        scopeCheck: () => ({ allowed: false, reason: "out of scope" }),
        service: async (i) => {
          serviceCalled = true;
          return i;
        },
        outputSchema: z.unknown(),
      }
    );
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.stage).toBe("scope");
      expect(out.validation.ok).toBe(false);
      if (!out.validation.ok) expect(out.validation.errorCode).toBe("scope_denied");
    }
    expect(order).toEqual([]);
    expect(serviceCalled).toBe(false);
  });

  it("fails closed when audit fails", async () => {
    const sink = new InMemoryAuditSink({ failOnWrite: true });
    const auditLogger = new AuditLogger(sink);
    const eventLogger = new EventLogger();
    let serviceCalled = false;
    const out = await runStateMutation(
      { auditLogger, eventLogger },
      {
        actor: "tester",
        investigationId: "inv_1",
        operation: "hypothesis_created",
        inputSchema: z.unknown(),
        input: {},
        scopeCheck: allowAll,
        service: async (i) => {
          serviceCalled = true;
          return i;
        },
        outputSchema: z.unknown(),
      }
    );
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.stage).toBe("audit");
      expect(out.failClosed).toBe(true);
    }
    expect(serviceCalled).toBe(false);
  });

  it("fails closed when output validation fails after the service ran", async () => {
    const auditLogger = new AuditLogger(new InMemoryAuditSink());
    const eventLogger = new EventLogger();
    let serviceCalled = false;
    const out = await runStateMutation(
      { auditLogger, eventLogger },
      {
        actor: "tester",
        investigationId: "inv_1",
        operation: "hypothesis_created",
        inputSchema: z.object({}),
        input: {},
        scopeCheck: allowAll,
        service: async () => {
          serviceCalled = true;
          return { wrong_shape: true };
        },
        outputSchema: z.object({ count: z.number() }),
      }
    );
    expect(serviceCalled).toBe(true);
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.stage).toBe("output_validation");
      // Service mutated state but the result is unverifiable — caller
      // must treat the system as potentially inconsistent.
      expect(out.failClosed).toBe(true);
    }
  });

  it("returns the validated/coerced output, not the raw service output", async () => {
    const auditLogger = new AuditLogger(new InMemoryAuditSink());
    const eventLogger = new EventLogger();
    let observedInPayload: unknown;
    // Schema applies a default for `count` when the service omits it.
    const outSchema = z.object({ count: z.number().default(7) });
    type Out = z.infer<typeof outSchema>;
    const out = await runStateMutation<Record<string, never>, Out>(
      { auditLogger, eventLogger },
      {
        actor: "tester",
        investigationId: "inv_1",
        operation: "hypothesis_created",
        inputSchema: z.object({}),
        input: {},
        scopeCheck: allowAll,
        // Cast through unknown: we deliberately omit `count` so the schema's
        // default kicks in. The chain must surface the schema's output, not
        // the literal service return value.
        service: async () => ({}) as unknown as Out,
        outputSchema: outSchema,
        eventKind: "graph_node_added",
        eventPayload: (output) => {
          observedInPayload = output;
          return output as Record<string, unknown>;
        },
      }
    );
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.output).toEqual({ count: 7 });
    }
    expect(observedInPayload).toEqual({ count: 7 });
  });
});
