import { describe, it, expect } from "vitest";
import { buildSuiStartArgs, parsePortFromArgs } from "./lifecycle.js";

describe("buildSuiStartArgs", () => {
  it("builds correct args for a given port", () => {
    const args = buildSuiStartArgs({ port: 9100, faucetPort: 9123 });
    expect(args).toContain("--with-faucet");
    expect(args).toContain("--force-regenesis");
    expect(args).toContain("9100");
    expect(args).toContain("9123");
  });
});

describe("parsePortFromArgs", () => {
  it("extracts port from args", () => {
    const args = buildSuiStartArgs({ port: 9200, faucetPort: 9223 });
    expect(parsePortFromArgs(args)).toBe(9200);
  });
});
