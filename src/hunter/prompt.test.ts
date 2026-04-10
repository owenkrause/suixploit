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
      network: "devnet",
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
      network: "devnet",
    });
    expect(prompt).toContain("- inv1");
    expect(prompt).toContain("- inv2");
    expect(prompt).toContain("- inv3");
  });

  it("shows 'None specified' when invariants are empty", () => {
    const prompt = buildHunterPrompt({
      moduleName: "test::mod",
      moduleSource: "source",
      protocolDescription: "desc",
      invariants: [],
      attackerAddress: "0xa",
      adminAddress: "0xb",
      userAddress: "0xc",
      rpcUrl: "http://127.0.0.1:9100",
      packageId: "0xpkg",
      network: "devnet",
    });
    expect(prompt).toContain("None specified");
  });

  it("includes Related Modules section when relatedModuleSignatures is provided", () => {
    const prompt = buildHunterPrompt({
      moduleName: "test::mod",
      moduleSource: "source",
      protocolDescription: "desc",
      invariants: [],
      attackerAddress: "0xa",
      adminAddress: "0xb",
      userAddress: "0xc",
      rpcUrl: "http://127.0.0.1:9100",
      packageId: "0xpkg",
      network: "devnet",
      relatedModuleSignatures: "module test::helper { public fun do_thing() }",
    });
    expect(prompt).toContain("Related modules");
    expect(prompt).toContain("module test::helper");
  });

  it("does NOT include Related Modules section when relatedModuleSignatures is undefined", () => {
    const prompt = buildHunterPrompt({
      moduleName: "test::mod",
      moduleSource: "source",
      protocolDescription: "desc",
      invariants: [],
      attackerAddress: "0xa",
      adminAddress: "0xb",
      userAddress: "0xc",
      rpcUrl: "http://127.0.0.1:9100",
      packageId: "0xpkg",
      network: "devnet",
    });
    expect(prompt).not.toContain("Related modules");
  });

  it("contains oracle section with check.ts command", () => {
    const prompt = buildHunterPrompt({
      moduleName: "test::mod",
      moduleSource: "source",
      protocolDescription: "desc",
      invariants: [],
      attackerAddress: "0xa",
      adminAddress: "0xb",
      userAddress: "0xc",
      rpcUrl: "http://127.0.0.1:9100",
      packageId: "0xpkg",
      network: "devnet",
    });
    expect(prompt).toContain("npx tsx src/oracle/check.ts");
  });

  it("contains foundational security context", () => {
    const prompt = buildHunterPrompt({
      moduleName: "test::mod",
      moduleSource: "source",
      protocolDescription: "desc",
      invariants: [],
      attackerAddress: "0xa",
      adminAddress: "0xb",
      userAddress: "0xc",
      rpcUrl: "http://127.0.0.1:9100",
      packageId: "0xpkg",
      network: "devnet",
    });
    expect(prompt).toContain("Capability Pattern");
    expect(prompt).toContain("abort-before-checkpoint");
  });

  it("contains reference tools section", () => {
    const prompt = buildHunterPrompt({
      moduleName: "test::mod",
      moduleSource: "source",
      protocolDescription: "desc",
      invariants: [],
      attackerAddress: "0xa",
      adminAddress: "0xb",
      userAddress: "0xc",
      rpcUrl: "http://127.0.0.1:9100",
      packageId: "0xpkg",
      network: "devnet",
    });
    expect(prompt).toContain("list_references");
    expect(prompt).toContain("read_reference");
  });

  it("does NOT contain validation criteria (owned by validator)", () => {
    const prompt = buildHunterPrompt({
      moduleName: "test::mod",
      moduleSource: "source",
      protocolDescription: "desc",
      invariants: [],
      attackerAddress: "0xa",
      adminAddress: "0xb",
      userAddress: "0xc",
      rpcUrl: "http://127.0.0.1:9100",
      packageId: "0xpkg",
      network: "devnet",
    });
    expect(prompt).not.toContain("What counts as a finding");
  });

  it("contains two-phase hunting methodology", () => {
    const prompt = buildHunterPrompt({
      moduleName: "test::mod",
      moduleSource: "source",
      protocolDescription: "desc",
      invariants: [],
      attackerAddress: "0xa",
      adminAddress: "0xb",
      userAddress: "0xc",
      rpcUrl: "http://127.0.0.1:9100",
      packageId: "0xpkg",
      network: "devnet",
    });
    expect(prompt).toContain("Phase 1: Independent Analysis");
    expect(prompt).toContain("Phase 2: Reference Cross-Check");
  });

  it("contains output format with vulns.json and findings.json", () => {
    const prompt = buildHunterPrompt({
      moduleName: "test::mod",
      moduleSource: "source",
      protocolDescription: "desc",
      invariants: [],
      attackerAddress: "0xa",
      adminAddress: "0xb",
      userAddress: "0xc",
      rpcUrl: "http://127.0.0.1:9100",
      packageId: "0xpkg",
      network: "devnet",
    });
    expect(prompt).toContain("vulns.json");
    expect(prompt).toContain("findings.json");
  });

  // ── Devnet-specific ──────────────────────────────────────────

  it("devnet prompt contains Sui devnet RPC and addresses", () => {
    const prompt = buildHunterPrompt({
      moduleName: "test::mod",
      moduleSource: "source",
      protocolDescription: "desc",
      invariants: [],
      attackerAddress: "0xattacker",
      adminAddress: "0xadmin",
      userAddress: "0xuser",
      rpcUrl: "http://127.0.0.1:9100",
      packageId: "0xpkg",
      network: "devnet",
    });
    expect(prompt).toContain("devnet");
    expect(prompt).toContain("0xattacker");
    expect(prompt).toContain("signAndExecuteTransaction");
  });

  // ── Mainnet-specific ─────────────────────────────────────────

  const mainnetInput = {
    moduleName: "test::pool",
    moduleSource: "module test::pool { }",
    protocolDescription: "A DEX pool",
    invariants: ["k = x * y"],
    packageId: "0xpkg",
    rpcUrl: "https://fullnode.mainnet.sui.io:443",
    network: "mainnet" as const,
  };

  it("mainnet prompt contains simulateTransaction", () => {
    const prompt = buildHunterPrompt(mainnetInput);
    expect(prompt).toContain("simulateTransaction");
  });

  it("mainnet prompt contains SuiJsonRpcClient", () => {
    const prompt = buildHunterPrompt(mainnetInput);
    expect(prompt).toContain("SuiJsonRpcClient");
  });

  it("mainnet prompt contains dry-run", () => {
    const prompt = buildHunterPrompt(mainnetInput);
    expect(prompt).toContain("dry-run");
  });

  it("mainnet prompt does NOT contain attacker address in environment section", () => {
    const prompt = buildHunterPrompt(mainnetInput);
    // Mainnet prompt should not have a devnet "Environment" section with attacker address
    expect(prompt).not.toContain("Attacker address:");
  });

  it("mainnet prompt includes the package ID and RPC in target block", () => {
    const prompt = buildHunterPrompt(mainnetInput);
    expect(prompt).toContain("0xpkg");
    expect(prompt).toContain("https://fullnode.mainnet.sui.io:443");
  });

  it("mainnet prompt includes invariants", () => {
    const prompt = buildHunterPrompt(mainnetInput);
    expect(prompt).toContain("- k = x * y");
  });
});
