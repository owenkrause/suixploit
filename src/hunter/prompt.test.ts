import { describe, it, expect } from "vitest";
import { buildHunterPrompt } from "./prompt.js";

describe("buildHunterPrompt", () => {
  it("includes module name and source", () => {
    const prompt = buildHunterPrompt({
      moduleName: "test::vault",
      moduleSource: "module test::vault { }",
      protocolDescription: "A vault contract",
      invariants: ["only admin can withdraw"],
      attackerAddress: "0xattacker",
      adminAddress: "0xadmin",
      userAddress: "0xuser",
      rpcUrl: "http://127.0.0.1:9100",
      packageId: "0xpkg",
    });
    expect(prompt).toContain("test::vault");
    expect(prompt).toContain("module test::vault { }");
    expect(prompt).toContain("only admin can withdraw");
    expect(prompt).toContain("0xattacker");
    expect(prompt).toContain("http://127.0.0.1:9100");
    expect(prompt).toContain("0xpkg");
  });

  it("formats multiple invariants as a list", () => {
    const prompt = buildHunterPrompt({
      moduleName: "test::mod",
      moduleSource: "source",
      protocolDescription: "desc",
      invariants: ["inv1", "inv2", "inv3"],
      attackerAddress: "0xa",
      adminAddress: "0xb",
      userAddress: "0xc",
      rpcUrl: "http://127.0.0.1:9100",
      packageId: "0xpkg",
    });
    expect(prompt).toContain("- inv1");
    expect(prompt).toContain("- inv2");
    expect(prompt).toContain("- inv3");
  });
});
