import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  resolveModules,
  shouldSkipRanker,
  buildScanResult,
  buildPipelineContext,
} from "./pipeline.js";
import type { ModuleInfo, ValidatedFinding, Finding, ModuleScore } from "./types.js";

// ── Helpers ──────────────────────────────────────────────────────

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "suixploit-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  for (const d of tempDirs) {
    await rm(d, { recursive: true, force: true });
  }
  tempDirs.length = 0;
});

function fakeModule(name: string): ModuleInfo {
  return { name, source: `module ${name} {}`, path: `/fake/${name}.move` };
}

// ── resolveModules ───────────────────────────────────────────────

describe("resolveModules", () => {
  it("finds .move files inside a sources/ subdirectory", async () => {
    const root = await makeTempDir();
    const sources = join(root, "sources");
    await mkdir(sources, { recursive: true });
    await writeFile(
      join(sources, "vault.move"),
      "module test::vault {\n  public fun deposit() {}\n}\n"
    );

    const modules = await resolveModules(root);
    expect(modules).toHaveLength(1);
    expect(modules[0].name).toBe("test::vault");
    expect(modules[0].source).toContain("public fun deposit");
    expect(modules[0].path).toBe(join(sources, "vault.move"));
  });

  it("skips files in tests/ and build/ directories", async () => {
    const root = await makeTempDir();
    await mkdir(join(root, "sources"), { recursive: true });
    await mkdir(join(root, "tests"), { recursive: true });
    await mkdir(join(root, "build"), { recursive: true });

    await writeFile(
      join(root, "sources", "real.move"),
      "module test::real {}"
    );
    await writeFile(
      join(root, "tests", "test_file.move"),
      "module test::test_file {}"
    );
    await writeFile(
      join(root, "build", "built.move"),
      "module test::built {}"
    );

    const modules = await resolveModules(root);
    expect(modules).toHaveLength(1);
    expect(modules[0].name).toBe("test::real");
  });

  it("returns correct module names from 'module foo::bar' declarations", async () => {
    const root = await makeTempDir();
    const sources = join(root, "sources");
    await mkdir(sources, { recursive: true });
    await writeFile(
      join(sources, "pool.move"),
      "module deepbook::pool {\n  struct Pool {}\n}\n"
    );
    await writeFile(
      join(sources, "math.move"),
      "module deepbook::math {\n  fun add() {}\n}\n"
    );

    const modules = await resolveModules(root);
    const names = modules.map((m) => m.name).sort();
    expect(names).toEqual(["deepbook::math", "deepbook::pool"]);
  });

  it("reads protocol.md description and invariants", async () => {
    const root = await makeTempDir();
    const sources = join(root, "sources");
    await mkdir(sources, { recursive: true });
    await writeFile(join(sources, "a.move"), "module test::a {}");
    await writeFile(
      join(root, "protocol.md"),
      `## Description
A lending protocol for Sui.

## Invariants
- total_borrows <= total_deposits
- interest_rate > 0
`
    );

    const modules = await resolveModules(root);
    expect(modules).toHaveLength(1);
    expect(modules[0].protocolDescription).toBe(
      "A lending protocol for Sui."
    );
    expect(modules[0].invariants).toEqual([
      "total_borrows <= total_deposits",
      "interest_rate > 0",
    ]);
  });

  it("handles missing protocol.md gracefully", async () => {
    const root = await makeTempDir();
    const sources = join(root, "sources");
    await mkdir(sources, { recursive: true });
    await writeFile(join(sources, "a.move"), "module test::a {}");

    const modules = await resolveModules(root);
    expect(modules).toHaveLength(1);
    expect(modules[0].protocolDescription).toBeUndefined();
    expect(modules[0].invariants).toBeUndefined();
  });

  it("returns empty array for a missing path", async () => {
    const modules = await resolveModules("/nonexistent/path/xyz123");
    expect(modules).toEqual([]);
  });

  it("falls back when targetPath itself is a sources/ directory", async () => {
    const root = await makeTempDir();
    const sources = join(root, "sources");
    await mkdir(sources, { recursive: true });
    await writeFile(join(sources, "x.move"), "module test::x {}");

    // Point directly at the sources/ directory
    const modules = await resolveModules(sources);
    expect(modules).toHaveLength(1);
    expect(modules[0].name).toBe("test::x");
  });

  it("uses filename as module name when no module declaration exists", async () => {
    const root = await makeTempDir();
    const sources = join(root, "sources");
    await mkdir(sources, { recursive: true });
    await writeFile(join(sources, "orphan.move"), "// no module declaration\nfun helper() {}");

    const modules = await resolveModules(root);
    expect(modules).toHaveLength(1);
    expect(modules[0].name).toBe("orphan");
  });

  it("finds .move files in nested sources/ directories", async () => {
    const root = await makeTempDir();
    const nested = join(root, "packages", "core", "sources");
    await mkdir(nested, { recursive: true });
    await writeFile(join(nested, "core.move"), "module pkg::core {}");

    const modules = await resolveModules(root);
    expect(modules).toHaveLength(1);
    expect(modules[0].name).toBe("pkg::core");
  });
});

// ── shouldSkipRanker ─────────────────────────────────────────────

describe("shouldSkipRanker", () => {
  it("returns true when modules.length is 0", () => {
    expect(shouldSkipRanker([])).toBe(true);
  });

  it("returns true when modules.length is 3 (boundary)", () => {
    const modules = [fakeModule("a"), fakeModule("b"), fakeModule("c")];
    expect(shouldSkipRanker(modules)).toBe(true);
  });

  it("returns false when modules.length is 4", () => {
    const modules = [
      fakeModule("a"),
      fakeModule("b"),
      fakeModule("c"),
      fakeModule("d"),
    ];
    expect(shouldSkipRanker(modules)).toBe(false);
  });
});

// ── buildPipelineContext ─────────────────────────────────────────

describe("buildPipelineContext", () => {
  it("initializes with empty arrays", () => {
    const modules: ModuleInfo[] = [fakeModule("test::a")];
    const ctx = buildPipelineContext("/my/target", modules);

    expect(ctx.target).toBe("/my/target");
    expect(ctx.modules).toBe(modules);
    expect(ctx.rankerScores).toEqual([]);
    expect(ctx.hunterTargets).toEqual([]);
    expect(ctx.rawFindings).toEqual([]);
    expect(ctx.findings).toEqual([]);
  });
});

// ── buildScanResult ──────────────────────────────────────────────

describe("buildScanResult", () => {
  it("constructs ScanResult from a populated PipelineContext", () => {
    const rawFinding: Finding = {
      id: "vuln-001",
      module: "test::vault",
      severity: "critical",
      category: "capability_misuse",
      title: "Admin cap leak",
      description: "Anyone can mint",
      exploitTransaction: "const tx = ...",
      iterations: 3,
    };

    const validatedFinding: ValidatedFinding = {
      ...rawFinding,
      validatorVerdict: "confirmed",
      validatorNote: "Confirmed by validator",
    };

    const score: ModuleScore = {
      module: "test::vault",
      score: 5,
      rationale: "handles funds",
      attackSurface: ["coin transfers"],
    };

    const ctx = buildPipelineContext("/target", [fakeModule("test::vault")]);
    ctx.rankerScores = [score];
    ctx.hunterTargets = [fakeModule("test::vault")];
    ctx.rawFindings = [rawFinding];
    ctx.findings = [validatedFinding];

    const result = buildScanResult(ctx);

    expect(result.target).toBe("/target");
    expect(result.timestamp).toBeTruthy();
    expect(result.modulesScanned).toBe(1);
    expect(result.modulesHunted).toBe(1);
    expect(result.findings).toEqual([validatedFinding]);
    expect(result.rawFindings).toEqual([rawFinding]);
    expect(result.rankerScores).toEqual([score]);
  });

  it("produces a valid ISO timestamp", () => {
    const ctx = buildPipelineContext("/t", []);
    const result = buildScanResult(ctx);
    // Should not throw
    const date = new Date(result.timestamp);
    expect(date.getTime()).not.toBeNaN();
  });
});
