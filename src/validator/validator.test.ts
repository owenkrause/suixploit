import { describe, it, expect } from "vitest";
import { filterConfirmed, deduplicateFindings } from "./index.js";
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
    expect(prompt).toContain("EXPLOIT_CONFIRMED");
    expect(prompt).toContain("verdict-f1.json");
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
});

describe("deduplicateFindings", () => {
  it("removes findings marked as duplicates", () => {
    const findings: ValidatedFinding[] = [
      { ...sampleFinding, validatorVerdict: "confirmed", validatorNote: "original" },
      { ...sampleFinding2, validatorVerdict: "confirmed", validatorNote: "dupe", duplicateOf: "f1" },
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("f1");
  });

  it("keeps all findings when no duplicates", () => {
    const findings: ValidatedFinding[] = [
      { ...sampleFinding, validatorVerdict: "confirmed", validatorNote: "good" },
      { ...sampleFinding2, validatorVerdict: "confirmed", validatorNote: "also good" },
    ];
    expect(deduplicateFindings(findings)).toHaveLength(2);
  });
});
