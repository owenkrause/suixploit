import { describe, it, expect } from "vitest";
import { buildValidatorPrompt, parseValidatorResponse } from "./index.js";
import type { Finding, ModuleInfo } from "../types.js";

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

describe("buildValidatorPrompt", () => {
  it("includes findings and source code", () => {
    const prompt = buildValidatorPrompt(
      [sampleFinding],
      [{ name: "test::vault", source: "module code", path: "/p" }]
    );
    expect(prompt).toContain("AdminCap leak");
    expect(prompt).toContain("module code");
  });
});

describe("parseValidatorResponse", () => {
  it("parses validated findings with verdict", () => {
    const response = JSON.stringify([
      {
        ...sampleFinding,
        validatorVerdict: "confirmed",
        validatorNote: "Verified — real vulnerability",
      },
    ]);
    const validated = parseValidatorResponse(response);
    expect(validated).toHaveLength(1);
    expect(validated[0].validatorVerdict).toBe("confirmed");
  });

  it("handles adjusted severity", () => {
    const response = JSON.stringify([
      {
        ...sampleFinding,
        validatorVerdict: "adjusted",
        validatorNote: "Not critical, downgraded",
        adjustedSeverity: "medium",
      },
    ]);
    const validated = parseValidatorResponse(response);
    expect(validated[0].adjustedSeverity).toBe("medium");
  });
});
