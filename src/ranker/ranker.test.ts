import { describe, it, expect } from "vitest";
import { buildRankerPrompt, parseRankerResponse } from "./index.js";

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
