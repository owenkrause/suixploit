import { describe, it, expect } from "vitest";
import type {
  ModuleScore,
  OracleResult,
  Finding,
  ValidatedFinding,
  ScanResult,
  ModuleInfo,
  DevnetConfig,
} from "./types.js";

describe("types", () => {
  it("OracleResult accepts valid signals", () => {
    const result: OracleResult = {
      signal: "balance",
      status: "EXPLOIT_CONFIRMED",
      preTxState: { balance: "1000" },
      postTxState: { balance: "2000" },
    };
    expect(result.status).toBe("EXPLOIT_CONFIRMED");
  });

  it("Finding accepts all categories", () => {
    const categories = [
      "capability_misuse",
      "shared_object_race",
      "integer_overflow",
      "ownership_violation",
      "hot_potato_misuse",
      "otw_abuse",
      "other",
    ] as const;
    for (const category of categories) {
      const finding: Finding = {
        id: "test",
        module: "test::mod",
        severity: "high",
        category,
        title: "test",
        description: "test",
        exploitTransaction: "// code",
        oracleResult: {
          signal: "balance",
          status: "EXPLOIT_CONFIRMED",
          preTxState: {},
          postTxState: {},
        },
        iterations: 1,
      };
      expect(finding.category).toBe(category);
    }
  });

  it("ValidatedFinding extends Finding with verdict", () => {
    const validated: ValidatedFinding = {
      id: "test",
      module: "test::mod",
      severity: "high",
      category: "other",
      title: "test",
      description: "test",
      exploitTransaction: "// code",
      oracleResult: {
        signal: "balance",
        status: "EXPLOIT_CONFIRMED",
        preTxState: {},
        postTxState: {},
      },
      iterations: 1,
      validatorVerdict: "adjusted",
      validatorNote: "severity downgraded",
      adjustedSeverity: "medium",
    };
    expect(validated.validatorVerdict).toBe("adjusted");
    expect(validated.adjustedSeverity).toBe("medium");
  });
});
