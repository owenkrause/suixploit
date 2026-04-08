import { describe, it, expect } from "vitest";
import { generateAccounts, buildPublishCommand } from "./seed.js";

describe("generateAccounts", () => {
  it("creates three distinct keypairs", () => {
    const accounts = generateAccounts();
    expect(accounts.admin.address).not.toBe(accounts.attacker.address);
    expect(accounts.admin.address).not.toBe(accounts.user.address);
    expect(accounts.attacker.address).not.toBe(accounts.user.address);
  });
});

describe("buildPublishCommand", () => {
  it("builds a sui move publish command for a contract path", () => {
    const cmd = buildPublishCommand("/path/to/contract");
    expect(cmd).toContain("sui client publish");
    expect(cmd).toContain("/path/to/contract");
  });
});
