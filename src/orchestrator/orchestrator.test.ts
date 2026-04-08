import { describe, it, expect } from "vitest";
import { Semaphore } from "./semaphore.js";
import { ResourceTracker } from "./tracker.js";
import { buildToolDefinition, buildSystemPrompt } from "./agent.js";

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
