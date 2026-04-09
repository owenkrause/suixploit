import { describe, it, expect } from "vitest";
import {
  buildRankerPrompt,
  parseRankerResponse,
  extractSignatures,
  filterHighPriority,
  HIGH_PRIORITY_SCORE,
} from "./index.js";
import type { ModuleScore } from "../types.js";

describe("buildRankerPrompt", () => {
  it("includes all module sources with headers", () => {
    const prompt = buildRankerPrompt([
      { name: "mod_a", source: "module a {}", path: "/a" },
      { name: "mod_b", source: "module b {}", path: "/b" },
    ]);
    expect(prompt).toContain("mod_a");
    expect(prompt).toContain("module a {}");
    expect(prompt).toContain("mod_b");
    expect(prompt).toContain("module b {}");
  });
});

describe("parseRankerResponse", () => {
  it("parses valid JSON array of ModuleScore", () => {
    const response = JSON.stringify([
      {
        module: "test::vault",
        score: 5,
        rationale: "handles coin transfers",
        attackSurface: ["coin transfers", "admin cap"],
      },
    ]);
    const scores = parseRankerResponse(response);
    expect(scores).toHaveLength(1);
    expect(scores[0].module).toBe("test::vault");
    expect(scores[0].score).toBe(5);
  });

  it("extracts JSON from markdown code blocks", () => {
    const response = `Here are the scores:\n\`\`\`json\n[{"module":"a","score":3,"rationale":"low risk","attackSurface":[]}]\n\`\`\``;
    const scores = parseRankerResponse(response);
    expect(scores).toHaveLength(1);
    expect(scores[0].score).toBe(3);
  });

  it("throws on invalid response", () => {
    expect(() => parseRankerResponse("not json")).toThrow();
  });
});

// ── extractSignatures ────────────────────────────────────────────

describe("extractSignatures", () => {
  const input = `module test::vault {
  use sui::coin;
  const MAX: u64 = 100;
  struct Vault has key { id: UID, balance: u64 }
  public fun deposit(vault: &mut Vault, amount: u64) {
    vault.balance = vault.balance + amount;
  }
  fun internal_helper(x: u64): u64 {
    x + 1
  }
}`;

  it("keeps module declaration", () => {
    const sig = extractSignatures(input);
    expect(sig).toContain("module test::vault");
  });

  it("keeps use statements", () => {
    const sig = extractSignatures(input);
    expect(sig).toContain("use sui::coin");
  });

  it("keeps const declarations", () => {
    const sig = extractSignatures(input);
    expect(sig).toContain("const MAX: u64 = 100");
  });

  it("keeps struct definitions with fields", () => {
    const sig = extractSignatures(input);
    expect(sig).toContain("struct Vault has key { id: UID, balance: u64 }");
  });

  it("keeps function signatures", () => {
    const sig = extractSignatures(input);
    expect(sig).toContain("public fun deposit(vault: &mut Vault, amount: u64)");
    expect(sig).toContain("fun internal_helper(x: u64): u64");
  });

  it("strips function bodies", () => {
    const sig = extractSignatures(input);
    expect(sig).not.toContain("vault.balance = vault.balance + amount");
    expect(sig).not.toContain("x + 1");
  });

  it("handles multi-line function signatures", () => {
    // extractSignatures captures the function keyword line and the first
    // continuation line (detected by checking if the previous result line
    // starts with a function keyword). Subsequent parameter lines are
    // not captured because the heuristic no longer matches.
    const multiLineInput = `module test::multi {
  public fun long_fn(
    a: u64,
    b: u64,
    c: u64
  ): u64 {
    a + b + c
  }
}`;
    const sig = extractSignatures(multiLineInput);
    expect(sig).toContain("public fun long_fn(");
    expect(sig).toContain("a: u64,");
    // Body must be stripped
    expect(sig).not.toContain("a + b + c");
  });
});

// ── filterHighPriority ───────────────────────────────────────────

describe("filterHighPriority", () => {
  function makeScore(module: string, score: number): ModuleScore {
    return { module, score, rationale: "test", attackSurface: [] };
  }

  it("HIGH_PRIORITY_SCORE is 3", () => {
    expect(HIGH_PRIORITY_SCORE).toBe(3);
  });

  it("filters scores >= HIGH_PRIORITY_SCORE", () => {
    const scores = [
      makeScore("a", 5),
      makeScore("b", 3),
      makeScore("c", 1),
      makeScore("d", 4),
    ];
    const result = filterHighPriority(scores);
    expect(result.map((s) => s.module).sort()).toEqual(["a", "b", "d"]);
  });

  it("includes score exactly equal to 3", () => {
    const scores = [makeScore("x", 3)];
    const result = filterHighPriority(scores);
    expect(result).toHaveLength(1);
    expect(result[0].module).toBe("x");
  });

  it("excludes score of 2", () => {
    const scores = [makeScore("y", 2)];
    const result = filterHighPriority(scores);
    expect(result).toHaveLength(0);
  });

  it("returns empty array for empty input", () => {
    expect(filterHighPriority([])).toEqual([]);
  });
});
