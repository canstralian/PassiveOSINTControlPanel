import { describe, it, expect } from "vitest";
import { ScopePolicy } from "../src/safety/scope.js";
import { RiskClassifier } from "../src/safety/risk.js";
import { makeAction, makeInvestigation } from "./_helpers.js";

describe("ScopePolicy", () => {
  const policy = new ScopePolicy();

  it("denies external_tool_call when allowExternalActions is false", () => {
    const inv = makeInvestigation({
      scope: {
        authorizedTargets: [],
        authorizedToolIds: ["whois"],
        allowExternalActions: false,
        maxRiskWithoutApproval: "low",
      },
    });
    const action = makeAction({
      kind: "external_tool_call",
      toolRef: { toolId: "whois", input: {} },
    });
    const dec = policy.evaluate(action, inv.scope);
    expect(dec.allowed).toBe(false);
  });

  it("denies tool not in authorized list", () => {
    const inv = makeInvestigation();
    const action = makeAction({
      kind: "external_tool_call",
      toolRef: { toolId: "evil_tool", input: {} },
    });
    const dec = policy.evaluate(action, inv.scope);
    expect(dec.allowed).toBe(false);
  });

  it("denies external target not in authorized list", () => {
    const inv = makeInvestigation();
    const action = makeAction({
      kind: "external_tool_call",
      toolRef: { toolId: "whois", input: {} },
      targets: [{ kind: "external_target", refId: "unauthorized.example" }],
    });
    const dec = policy.evaluate(action, inv.scope);
    expect(dec.allowed).toBe(false);
  });

  it("permits authorized tool + authorized target", () => {
    const inv = makeInvestigation();
    const action = makeAction({
      kind: "external_tool_call",
      toolRef: { toolId: "whois", input: {} },
      targets: [{ kind: "external_target", refId: "target.example" }],
    });
    const dec = policy.evaluate(action, inv.scope);
    expect(dec.allowed).toBe(true);
  });

  it("never infers permission for missing toolRef", () => {
    const inv = makeInvestigation();
    const action = makeAction({ kind: "external_tool_call" });
    const dec = policy.evaluate(action, inv.scope);
    expect(dec.allowed).toBe(false);
  });
});

describe("RiskClassifier", () => {
  const rc = new RiskClassifier();

  it("requires approval for actions above the threshold", () => {
    const action = makeAction({ estimatedRiskClass: "high" });
    const dec = rc.classify(action, "low");
    expect("needsApproval" in dec && dec.needsApproval).toBe(true);
  });

  it("does not require approval at or below the threshold", () => {
    const action = makeAction({ estimatedRiskClass: "low" });
    const dec = rc.classify(action, "low");
    expect("needsApproval" in dec && dec.needsApproval).toBe(false);
  });

  it("destructive ALWAYS requires approval, even if ceiling is destructive", () => {
    const action = makeAction({ estimatedRiskClass: "destructive" });
    const dec = rc.classify(action, "destructive");
    expect("needsApproval" in dec && dec.needsApproval).toBe(true);
  });
});
