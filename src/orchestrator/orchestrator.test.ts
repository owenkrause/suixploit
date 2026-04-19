import { describe, it, expect } from "vitest";
import { Semaphore } from "./semaphore.js";
import { ResourceTracker } from "./tracker.js";
import { buildToolDefinition, buildWriteFileTool, buildReferenceTools, buildSystemPrompt, buildMainnetSystemPrompt } from "./agent.js";
import { generateRunId, buildScanPaths, safeName, hunterWorkspace, hunterScratch } from "./paths.js";
import { makeLocalExec } from "./exec.js";

describe("Semaphore", () => {
  it("limits concurrency", async () => {
    const sem = new Semaphore(2);
    let running = 0;
    let maxRunning = 0;

    const task = async () => {
      const release = await sem.acquire();
      running++;
      maxRunning = Math.max(maxRunning, running);
      await new Promise((r) => setTimeout(r, 50));
      running--;
      release();
    };

    await Promise.all([task(), task(), task(), task()]);
    expect(maxRunning).toBe(2);
  });

  it("releases blocked tasks in FIFO order", async () => {
    const sem = new Semaphore(1);
    const order: number[] = [];

    // Acquire first lock to block subsequent acquires
    const release1 = await sem.acquire();

    // Queue up 3 more acquires — they will wait
    const p2 = sem.acquire().then((release) => {
      order.push(2);
      release();
    });
    const p3 = sem.acquire().then((release) => {
      order.push(3);
      release();
    });
    const p4 = sem.acquire().then((release) => {
      order.push(4);
      release();
    });

    // Release the first lock, which should unblock in FIFO order
    release1();

    await Promise.all([p2, p3, p4]);

    expect(order).toEqual([2, 3, 4]);
  });
});

describe("ResourceTracker", () => {
  it("tracks and lists container IDs", () => {
    const tracker = new ResourceTracker();
    tracker.add("abc123");
    tracker.add("def456");
    expect(tracker.list()).toEqual(["abc123", "def456"]);
  });

  it("removes container IDs", () => {
    const tracker = new ResourceTracker();
    tracker.add("abc123");
    tracker.remove("abc123");
    expect(tracker.list()).toEqual([]);
  });
});

describe("buildToolDefinition", () => {
  it("returns a bash tool with command parameter", () => {
    const tool = buildToolDefinition();
    expect(tool.name).toBe("bash");
    expect(tool.input_schema.properties).toHaveProperty("command");
  });
});

describe("buildWriteFileTool", () => {
  it("returns a write_file tool with path and content parameters", () => {
    const tool = buildWriteFileTool();
    expect(tool.name).toBe("write_file");
    expect(tool.input_schema.properties).toHaveProperty("path");
    expect(tool.input_schema.properties).toHaveProperty("content");
  });
});

describe("buildReferenceTools", () => {
  it("returns list_references and read_reference tools", () => {
    const tools = buildReferenceTools();
    expect(tools).toHaveLength(2);
    expect(tools[0].name).toBe("list_references");
    expect(tools[1].name).toBe("read_reference");
    expect(tools[1].input_schema.properties).toHaveProperty("name");
  });
});

describe("buildSystemPrompt", () => {
  it("includes hunter parts and context", () => {
    const prompt = buildSystemPrompt(
      { stable: "stable-body", dynamic: "Find vulns in vault" },
      {
        rpcUrl: "http://127.0.0.1:9000",
        packageId: "0xabc",
        attackerAddress: "0x123",
        adminAddress: "0x456",
        userAddress: "0x789",
      },
    );
    // Devnet puts the per-hunter env section in `dynamic`.
    expect(prompt.stable).toBe("stable-body");
    expect(prompt.dynamic).toContain("Find vulns in vault");
    expect(prompt.dynamic).toContain("0xabc");
    expect(prompt.dynamic).toContain("0x123");
  });
});

describe("generateRunId", () => {
  it("has no colons in the output", () => {
    const id = generateRunId();
    expect(id).not.toContain(":");
  });

  it("is parseable by new Date()", () => {
    const id = generateRunId();
    // Replace dashes back to colons in the time portion so Date can parse it
    // But the raw ID itself should also be roughly parseable (ISO-ish)
    const asIso = id.replace(/T(\d{2})-(\d{2})-(\d{2})/, "T$1:$2:$3");
    const date = new Date(asIso);
    expect(date.getTime()).not.toBeNaN();
  });

  it("matches YYYY-MM-DDTHH-MM-SS format", () => {
    const id = generateRunId();
    expect(id).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}$/);
  });
});

describe("buildScanPaths", () => {
  it("all paths are under the provided root dir", () => {
    const root = "/tmp/test-run";
    const paths = buildScanPaths(root);
    expect(paths.root).toBe(root);
    expect(paths.scanMeta).toContain(root);
    expect(paths.findingsDir).toContain(root);
    expect(paths.allRawFindings).toContain(root);
    expect(paths.validatedFindings).toContain(root);
    expect(paths.huntersDir).toContain(root);
    expect(paths.validatorsDir).toContain(root);
  });

  it("has expected sub-paths", () => {
    const paths = buildScanPaths("/tmp/run");
    expect(paths.scanMeta).toContain("scan.json");
    expect(paths.findingsDir).toContain("findings");
    expect(paths.allRawFindings).toContain("all-raw.json");
    expect(paths.validatedFindings).toContain("validated.json");
    expect(paths.huntersDir).toContain("hunters");
    expect(paths.validatorsDir).toContain("validators");
  });
});

describe("safeName", () => {
  it("converts double-colon separators to dashes", () => {
    expect(safeName("foo::bar")).toBe("foo-bar");
  });

  it("handles single segment unchanged", () => {
    expect(safeName("foo")).toBe("foo");
  });

  it("handles multiple double-colon separators", () => {
    expect(safeName("a::b::c")).toBe("a-b-c");
  });
});

describe("hunterWorkspace", () => {
  it("produces correct nested path", () => {
    const paths = buildScanPaths("/tmp/run");
    const ws = hunterWorkspace(paths, "deepbook_margin::oracle");
    expect(ws).toBe("/tmp/run/hunters/deepbook_margin-oracle");
  });
});

describe("hunterScratch", () => {
  it("produces correct nested path with scratch dir", () => {
    const paths = buildScanPaths("/tmp/run");
    const scratch = hunterScratch(paths, "deepbook_margin::oracle");
    expect(scratch).toBe("/tmp/run/hunters/deepbook_margin-oracle/scratch");
  });
});

describe("makeLocalExec", () => {
  it("returns stdout, empty stderr, and exitCode 0 for successful command", async () => {
    const exec = makeLocalExec("/tmp");
    const result = await exec("echo hello");
    expect(result).toEqual({ stdout: "hello\n", stderr: "", exitCode: 0 });
  });

  it("returns exitCode 1 for failed command", async () => {
    const exec = makeLocalExec("/tmp");
    const result = await exec("exit 1");
    expect(result.exitCode).toBe(1);
  });

  it("captures stderr output", async () => {
    const exec = makeLocalExec("/tmp");
    const result = await exec("echo err >&2");
    expect(result.stderr).toContain("err");
  });
});

describe("buildMainnetSystemPrompt", () => {
  it("contains the hunter parts and context values", () => {
    const prompt = buildMainnetSystemPrompt(
      { stable: "Analyze this contract", dynamic: "target-body" },
      { rpcUrl: "https://fullnode.mainnet.sui.io:443", packageId: "0xdeadbeef" },
    );
    // Mainnet env values are stable within a scan, so they live in `stable`.
    expect(prompt.stable).toContain("Analyze this contract");
    expect(prompt.stable).toContain("0xdeadbeef");
    expect(prompt.stable).toContain("https://fullnode.mainnet.sui.io:443");
    expect(prompt.dynamic).toBe("target-body");
  });

  it("contains dry-run and mainnet references", () => {
    const prompt = buildMainnetSystemPrompt(
      { stable: "Hunt bugs", dynamic: "" },
      { rpcUrl: "https://fullnode.mainnet.sui.io:443", packageId: "0x123" },
    );
    expect(prompt.stable).toContain("dry-run");
    expect(prompt.stable).toContain("mainnet");
  });
});
