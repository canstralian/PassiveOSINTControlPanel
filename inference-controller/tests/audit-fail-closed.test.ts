import { describe, it, expect } from "vitest";
import {
  AuditLogger,
  InMemoryAuditSink,
  verifyAuditChain,
} from "../src/audit/logger.js";

describe("audit logger", () => {
  it("writes events with chained integrity markers", async () => {
    const sink = new InMemoryAuditSink();
    const logger = new AuditLogger(sink);
    const e1 = await logger.record({
      actor: "tester",
      investigationId: "inv_1",
      operation: "investigation_created",
      inputRefs: [],
      scopeDecision: "n/a",
      riskDecision: "n/a",
    });
    const e2 = await logger.record({
      actor: "tester",
      investigationId: "inv_1",
      operation: "hypothesis_created",
      inputRefs: ["hyp_a"],
      scopeDecision: "n/a",
      riskDecision: "n/a",
    });
    expect(e1.integrityMarker).not.toEqual(e2.integrityMarker);
    const events = await logger.readAll();
    expect(events).toHaveLength(2);
    expect(verifyAuditChain(events).ok).toBe(true);
  });

  it("enters fail-closed mode when sink rejects a write", async () => {
    const sink = new InMemoryAuditSink({ failOnWrite: true });
    const logger = new AuditLogger(sink);
    await expect(
      logger.record({
        actor: "tester",
        investigationId: "inv_1",
        operation: "investigation_created",
        inputRefs: [],
        scopeDecision: "n/a",
        riskDecision: "n/a",
      })
    ).rejects.toThrow();
    expect(logger.failClosed).toBe(true);

    // Subsequent writes also fail.
    await expect(
      logger.record({
        actor: "tester",
        investigationId: "inv_1",
        operation: "hypothesis_created",
        inputRefs: [],
        scopeDecision: "n/a",
        riskDecision: "n/a",
      })
    ).rejects.toThrow(/fail-closed/);
  });

  it("verifyAuditChain detects tampering", async () => {
    const sink = new InMemoryAuditSink();
    const logger = new AuditLogger(sink);
    await logger.record({
      actor: "tester",
      investigationId: "inv_1",
      operation: "investigation_created",
      inputRefs: [],
      scopeDecision: "n/a",
      riskDecision: "n/a",
    });
    await logger.record({
      actor: "tester",
      investigationId: "inv_1",
      operation: "hypothesis_created",
      inputRefs: [],
      scopeDecision: "n/a",
      riskDecision: "n/a",
    });
    const events = await logger.readAll();
    // Tamper with the actor on event 1 — chain should break at index 0.
    const tampered = [...events];
    tampered[0] = { ...events[0]!, actor: "attacker" };
    const result = verifyAuditChain(tampered);
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(0);
  });
});
