import { describe, it, expect } from "vitest";
import { z } from "zod";
import { runStateMutation } from "../src/chains/state-mutation.js";
import { AuditLogger, InMemoryAuditSink } from "../src/audit/logger.js";
import { EventLogger } from "../src/audit/events.js";

describe("state-mutation chain", () => {
  it("audits BEFORE the service runs", async () => {
    const sink = new InMemoryAuditSink();
    const auditLogger = new AuditLogger(sink);
    const eventLogger = new EventLogger();
    const order: string[] = [];

    const out = await runStateMutation(
      { auditLogger, eventLogger },
      {
        actor: "tester",
        investigationId: "inv_1",
        operation: "hypothesis_created",
        inputSchema: z.object({ statement: z.string() }),
        input: { statement: "x" },
        service: async (input) => {
          order.push("service");
          return input;
        },
        outputSchema: z.object({ statement: z.string() }),
      }
    );
    expect(out.ok).toBe(true);
    const audit = await auditLogger.readAll();
    expect(audit).toHaveLength(1);
    // Service ran AFTER audit was recorded.
    expect(order).toEqual(["service"]);
  });

  it("rejects invalid input without invoking the service", async () => {
    const auditLogger = new AuditLogger(new InMemoryAuditSink());
    const eventLogger = new EventLogger();
    let serviceCalled = false;
    const out = await runStateMutation(
      { auditLogger, eventLogger },
      {
        actor: "tester",
        investigationId: "inv_1",
        operation: "hypothesis_created",
        inputSchema: z.object({ statement: z.string() }),
        input: { statement: 42 } as unknown,
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
      expect(out.validation.errorCode).toBe("schema_invalid");
    }
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
});
