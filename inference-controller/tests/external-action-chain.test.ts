import { describe, it, expect } from "vitest";
import { z } from "zod";
import { runExternalAction } from "../src/chains/external-action.js";
import { ScopePolicy } from "../src/safety/scope.js";
import { RiskClassifier } from "../src/safety/risk.js";
import { ApprovalGate } from "../src/safety/approval.js";
import { AuditLogger, InMemoryAuditSink } from "../src/audit/logger.js";
import { EventLogger } from "../src/audit/events.js";
import { ToolGateway } from "../src/tools/gateway.js";
import { ResultValidator } from "../src/tools/validator.js";
import { makeAction, makeInvestigation } from "./_helpers.js";

function buildDeps(opts: { auditFails?: boolean } = {}) {
  const auditSink = new InMemoryAuditSink({
    ...(opts.auditFails ? { failOnWrite: true } : {}),
  });
  const auditLogger = new AuditLogger(auditSink);
  const eventLogger = new EventLogger();
  const toolGateway = new ToolGateway();
  toolGateway.register("whois", async () => ({
    ok: true,
    toolId: "whois",
    output: { registrar: "test" },
    latencyMs: 5,
  }));
  toolGateway.register("badjson", async () => ({
    ok: true,
    toolId: "badjson",
    output: { unexpected: 42 },
    latencyMs: 5,
  }));
  const resultValidator = new ResultValidator();
  resultValidator.register(
    "whois",
    z.object({ registrar: z.string() })
  );
  resultValidator.register("badjson", z.object({ expected: z.string() }));
  return {
    deps: {
      scopePolicy: new ScopePolicy(),
      riskClassifier: new RiskClassifier(),
      approvalGate: new ApprovalGate(),
      auditLogger,
      toolGateway,
      resultValidator,
      eventLogger,
    },
    auditLogger,
    eventLogger,
  };
}

describe("external-action control chain", () => {
  it("happy path: scope -> risk -> audit -> tool -> result -> event", async () => {
    const { deps, auditLogger, eventLogger } = buildDeps();
    const inv = makeInvestigation();
    const action = makeAction({
      kind: "external_tool_call",
      toolRef: { toolId: "whois", input: { domain: "target.example" } },
      targets: [{ kind: "external_target", refId: "target.example" }],
      estimatedRiskClass: "low",
    });
    const out = await runExternalAction(deps, {
      investigation: inv,
      action,
      actor: "test",
    });
    expect(out.ok).toBe(true);
    const audit = await auditLogger.readAll();
    expect(audit.map((e) => e.operation)).toContain("tool_call_attempted");
    expect(audit.map((e) => e.operation)).toContain("tool_call_validated");
    expect(eventLogger.all().length).toBeGreaterThan(0);
  });

  it("denies out-of-scope tool and never invokes the gateway", async () => {
    const { deps, auditLogger } = buildDeps();
    const inv = makeInvestigation();
    const action = makeAction({
      kind: "external_tool_call",
      toolRef: { toolId: "evil", input: {} },
      estimatedRiskClass: "low",
    });
    const out = await runExternalAction(deps, {
      investigation: inv,
      action,
      actor: "test",
    });
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.stage).toBe("scope");
    }
    const audit = await auditLogger.readAll();
    expect(audit.some((e) => e.operation === "scope_decision")).toBe(true);
    expect(audit.every((e) => e.operation !== "tool_call_attempted")).toBe(true);
  });

  it("blocks when approval is required but not granted", async () => {
    const { deps } = buildDeps();
    const inv = makeInvestigation({
      scope: {
        authorizedTargets: ["target.example"],
        authorizedToolIds: ["whois"],
        allowExternalActions: true,
        maxRiskWithoutApproval: "low",
      },
    });
    const action = makeAction({
      kind: "external_tool_call",
      toolRef: { toolId: "whois", input: {} },
      targets: [{ kind: "external_target", refId: "target.example" }],
      estimatedRiskClass: "high",
    });
    const out = await runExternalAction(deps, {
      investigation: inv,
      action,
      actor: "test",
    });
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.stage).toBe("approval");
      expect(out.validation.errorCode).toBe("approval_missing");
    }
  });

  it("proceeds when approval is pre-registered", async () => {
    const { deps } = buildDeps();
    const inv = makeInvestigation();
    const action = makeAction({
      kind: "external_tool_call",
      toolRef: { toolId: "whois", input: {} },
      targets: [{ kind: "external_target", refId: "target.example" }],
      estimatedRiskClass: "high",
    });
    deps.approvalGate.preApprove(action.id, "operator");
    const out = await runExternalAction(deps, {
      investigation: inv,
      action,
      actor: "test",
    });
    expect(out.ok).toBe(true);
  });

  it("fails closed when audit logging fails before tool call", async () => {
    const { deps } = buildDeps({ auditFails: true });
    const inv = makeInvestigation();
    const action = makeAction({
      kind: "external_tool_call",
      toolRef: { toolId: "whois", input: {} },
      targets: [{ kind: "external_target", refId: "target.example" }],
      estimatedRiskClass: "low",
    });
    const out = await runExternalAction(deps, {
      investigation: inv,
      action,
      actor: "test",
    });
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.failClosed).toBe(true);
      expect(out.validation.errorCode).toBe("audit_unavailable");
    }
  });

  it("rejects when tool result fails the registered schema", async () => {
    const { deps } = buildDeps();
    const inv = makeInvestigation({
      scope: {
        authorizedTargets: ["target.example"],
        authorizedToolIds: ["badjson"],
        allowExternalActions: true,
        maxRiskWithoutApproval: "low",
      },
    });
    const action = makeAction({
      kind: "external_tool_call",
      toolRef: { toolId: "badjson", input: {} },
      targets: [{ kind: "external_target", refId: "target.example" }],
      estimatedRiskClass: "low",
    });
    const out = await runExternalAction(deps, {
      investigation: inv,
      action,
      actor: "test",
    });
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.stage).toBe("result_validation");
    }
  });
});
