import { describe, it, expect } from "vitest";
import { Semaphore } from "./semaphore.js";
import { ResourceTracker } from "./tracker.js";

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
