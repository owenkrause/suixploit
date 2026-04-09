import { describe, it, expect } from "vitest";
import { Semaphore } from "./semaphore.js";
import { ResourceTracker } from "./tracker.js";
import { buildToolDefinition, buildSystemPrompt, buildMainnetSystemPrompt } from "./agent.js";
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

describe("buildSystemPrompt", () => {
  it("includes hunter prompt and context", () => {
    const prompt = buildSystemPrompt("Find vulns in vault", {
      rpcUrl: "http://127.0.0.1:9000",
      packageId: "0xabc",
      attackerAddress: "0x123",
      adminAddress: "0x456",
      userAddress: "0x789",
    });
    expect(prompt).toContain("Find vulns in vault");
    expect(prompt).toContain("0xabc");
    expect(prompt).toContain("0x123");
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
  it("contains the hunter prompt and context values", () => {
    const prompt = buildMainnetSystemPrompt("Analyze this contract", {
      rpcUrl: "https://fullnode.mainnet.sui.io:443",
      packageId: "0xdeadbeef",
    });
    expect(prompt).toContain("Analyze this contract");
    expect(prompt).toContain("0xdeadbeef");
    expect(prompt).toContain("https://fullnode.mainnet.sui.io:443");
  });

  it("contains dry-run and mainnet references", () => {
    const prompt = buildMainnetSystemPrompt("Hunt bugs", {
      rpcUrl: "https://fullnode.mainnet.sui.io:443",
      packageId: "0x123",
    });
    expect(prompt).toContain("dry-run");
    expect(prompt).toContain("mainnet");
  });
});
