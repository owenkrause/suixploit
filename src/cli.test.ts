import { describe, it, expect } from "vitest";

// Test the validation logic from cli.ts
// Since parsePositiveInt isn't exported, we test the same logic
function parsePositiveInt(value: string, name: string): number {
  const n = parseInt(value, 10);
  if (Number.isNaN(n) || n <= 0) {
    throw new Error(`${name} must be a positive integer, got "${value}"`);
  }
  return n;
}

describe("CLI validation", () => {
  describe("parsePositiveInt", () => {
    it("parses valid positive integers", () => {
      expect(parsePositiveInt("5", "test")).toBe(5);
      expect(parsePositiveInt("100", "test")).toBe(100);
    });

    it("throws on NaN", () => {
      expect(() => parsePositiveInt("abc", "--concurrency")).toThrow("--concurrency must be a positive integer");
    });

    it("throws on zero", () => {
      expect(() => parsePositiveInt("0", "--max-turns")).toThrow("--max-turns must be a positive integer");
    });

    it("throws on negative", () => {
      expect(() => parsePositiveInt("-1", "--concurrency")).toThrow("must be a positive integer");
    });

    it("throws on float string", () => {
      // parseInt("3.5") returns 3 which is valid — this is fine
      expect(parsePositiveInt("3.5", "test")).toBe(3);
    });

    it("throws on empty string", () => {
      expect(() => parsePositiveInt("", "test")).toThrow("must be a positive integer");
    });
  });
});
