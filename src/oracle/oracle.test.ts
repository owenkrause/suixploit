import { describe, it, expect } from "vitest";
import { checkAbort } from "./abort.js";
import { checkBalance } from "./balance.js";
import { checkOwnership } from "./ownership.js";
import { checkCustom } from "./custom.js";

describe("checkAbort", () => {
  it("confirms exploit when tx succeeds but should have aborted", () => {
    const result = checkAbort(
      { effects: { status: { status: "success" } } },
      "should_abort"
    );
    expect(result.status).toBe("EXPLOIT_CONFIRMED");
    expect(result.signal).toBe("abort");
  });

  it("returns no exploit when tx correctly aborts", () => {
    const result = checkAbort(
      { effects: { status: { status: "failure" } } },
      "should_abort"
    );
    expect(result.status).toBe("NO_EXPLOIT");
  });
});

describe("checkBalance", () => {
  it("confirms exploit when attacker balance increased", () => {
    const result = checkBalance("0xattacker", [
      {
        owner: { AddressOwner: "0xattacker" },
        coinType: "0x2::sui::SUI",
        amount: "1000",
      },
    ]);
    expect(result.status).toBe("EXPLOIT_CONFIRMED");
    expect(result.signal).toBe("balance");
  });

  it("returns no exploit when attacker balance decreased", () => {
    const result = checkBalance("0xattacker", [
      {
        owner: { AddressOwner: "0xattacker" },
        coinType: "0x2::sui::SUI",
        amount: "-500",
      },
    ]);
    expect(result.status).toBe("NO_EXPLOIT");
  });

  it("returns no exploit when no balance changes for attacker", () => {
    const result = checkBalance("0xattacker", [
      {
        owner: { AddressOwner: "0xother" },
        coinType: "0x2::sui::SUI",
        amount: "1000",
      },
    ]);
    expect(result.status).toBe("NO_EXPLOIT");
  });
});

describe("checkOwnership", () => {
  it("confirms exploit when attacker gains existing object", () => {
    const result = checkOwnership("0xattacker", [
      {
        type: "mutated",
        objectId: "0xobj1",
        owner: { AddressOwner: "0xattacker" },
        sender: "0xattacker",
      },
    ]);
    expect(result.status).toBe("EXPLOIT_CONFIRMED");
    expect(result.signal).toBe("ownership");
  });

  it("returns no exploit when attacker only owns objects they created", () => {
    const result = checkOwnership("0xattacker", [
      {
        type: "created",
        objectId: "0xobj1",
        owner: { AddressOwner: "0xattacker" },
        sender: "0xattacker",
      },
    ]);
    expect(result.status).toBe("NO_EXPLOIT");
  });

  it("returns no exploit when objects go to someone else", () => {
    const result = checkOwnership("0xattacker", [
      {
        type: "mutated",
        objectId: "0xobj1",
        owner: { AddressOwner: "0xother" },
        sender: "0xattacker",
      },
    ]);
    expect(result.status).toBe("NO_EXPLOIT");
  });
});

describe("checkCustom", () => {
  it("confirms exploit when post-condition returns true", async () => {
    const result = await checkCustom({
      description: "pool balance decreased without withdrawal",
      preCondition: async () => ({ balance: 1000 }),
      postCondition: async (pre) => {
        const { balance } = pre as { balance: number };
        return balance > 500;
      },
    });
    expect(result.status).toBe("EXPLOIT_CONFIRMED");
    expect(result.signal).toBe("custom");
  });

  it("returns no exploit when post-condition returns false", async () => {
    const result = await checkCustom({
      description: "test",
      preCondition: async () => ({ balance: 1000 }),
      postCondition: async () => false,
    });
    expect(result.status).toBe("NO_EXPLOIT");
  });
});
