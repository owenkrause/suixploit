import { describe, it, expect } from "vitest";
import { filterConfirmed } from "./index.js";
import { buildValidatorAgentPrompt, buildOtherFindingsSummary } from "./prompt.js";
import type { Finding, ValidatedFinding } from "../types.js";

const sampleFinding: Finding = {
  id: "f1",
  module: "test::vault",
  severity: "critical",
  category: "capability_misuse",
  title: "AdminCap leak",
  description: "Anyone can get an AdminCap",
  exploitTransaction: "// exploit code",
  oracleResult: {
    signal: "abort",
    status: "EXPLOIT_CONFIRMED",
    preTxState: {},
    postTxState: {},
  },
  iterations: 2,
};

const sampleFinding2: Finding = {
  ...sampleFinding,
  id: "f2",
  title: "Duplicate of AdminCap leak",
};

describe("buildValidatorAgentPrompt", () => {
  it("includes finding details", () => {
    const prompt = buildValidatorAgentPrompt(sampleFinding, "No other findings.");
    expect(prompt).toContain("AdminCap leak");
    expect(prompt).toContain("test::vault");
    // oracleResult is intentionally excluded from validator prompt (validator assesses independently)
    expect(prompt).not.toContain("EXPLOIT_CONFIRMED");
    expect(prompt).toContain("verdict-f1.json");
  });

  it("contains the exploit transaction code", () => {
    const prompt = buildValidatorAgentPrompt(sampleFinding, "No other findings.");
    expect(prompt).toContain("// exploit code");
  });

  it("contains severity information", () => {
    const prompt = buildValidatorAgentPrompt(sampleFinding, "No other findings.");
    expect(prompt).toContain("critical");
    expect(prompt).toContain("Severity:");
  });

  it("verdict file path uses 'in the current directory'", () => {
    const prompt = buildValidatorAgentPrompt(sampleFinding, "No other findings.");
    expect(prompt).toContain("in the current directory");
    expect(prompt).not.toContain("/workspace/");
  });
});

describe("buildOtherFindingsSummary", () => {
  it("lists other findings excluding current", () => {
    const summary = buildOtherFindingsSummary([sampleFinding, sampleFinding2], "f1");
    expect(summary).toContain("f2");
    expect(summary).not.toContain("f1:");
  });

  it("returns message when no other findings", () => {
    const summary = buildOtherFindingsSummary([sampleFinding], "f1");
    expect(summary).toContain("No other findings");
  });

  it("lists multiple other findings with severity and module info", () => {
    const sampleFinding3: Finding = {
      ...sampleFinding,
      id: "f3",
      title: "Reentrancy bug",
      severity: "high",
      module: "test::pool",
    };
    const summary = buildOtherFindingsSummary([sampleFinding, sampleFinding2, sampleFinding3], "f1");
    expect(summary).toContain("f2");
    expect(summary).toContain("f3");
    // Verify severity and module info are present
    expect(summary).toContain("critical");
    expect(summary).toContain("high");
    expect(summary).toContain("test::vault");
    expect(summary).toContain("test::pool");
  });
});

describe("filterConfirmed", () => {
  it("removes rejected findings", () => {
    const findings: ValidatedFinding[] = [
      { ...sampleFinding, validatorVerdict: "confirmed", validatorNote: "good" },
      { ...sampleFinding2, validatorVerdict: "rejected", validatorNote: "false positive" },
    ];
    const result = filterConfirmed(findings);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("f1");
  });

  it("keeps adjusted findings", () => {
    const findings: ValidatedFinding[] = [
      { ...sampleFinding, validatorVerdict: "adjusted", validatorNote: "downgraded", adjustedSeverity: "low" },
    ];
    expect(filterConfirmed(findings)).toHaveLength(1);
  });

  it("keeps confirmed and adjusted, rejects rejected — all three verdicts in one array", () => {
    const findings: ValidatedFinding[] = [
      { ...sampleFinding, id: "f1", validatorVerdict: "confirmed", validatorNote: "legit" },
      { ...sampleFinding, id: "f2", validatorVerdict: "adjusted", validatorNote: "downgraded", adjustedSeverity: "low" },
      { ...sampleFinding, id: "f3", validatorVerdict: "rejected", validatorNote: "false positive" },
    ];
    const result = filterConfirmed(findings);
    expect(result).toHaveLength(2);
    expect(result.map((f) => f.id)).toEqual(["f1", "f2"]);
  });
});

// mergeVerdicts is not exported — tested indirectly via runValidators integration tests.
// Key behavior: when a finding has no corresponding verdict, it defaults to "rejected"
// (bug fix — previously it would have been undefined).

// deduplicateFindings is async (makes an LLM call) — tested via integration tests
