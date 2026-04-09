import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export class ResourceTracker {
  private containers = new Set<string>();
  private cleanupRegistered = false;

  add(containerId: string): void {
    this.containers.add(containerId);
  }

  remove(containerId: string): void {
    this.containers.delete(containerId);
  }

  list(): string[] {
    return [...this.containers];
  }

  registerCleanupHandlers(keepContainers: boolean): void {
    if (this.cleanupRegistered) return;
    this.cleanupRegistered = true;

    const cleanup = async () => {
      if (keepContainers) {
        if (this.containers.size > 0) {
          console.error(`Keeping ${this.containers.size} containers: ${this.list().join(", ")}`);
        }
        return;
      }
      await this.killAll();
    };

    for (const [signal, code] of [["SIGINT", 130], ["SIGTERM", 143]] as const) {
      process.on(signal, () => {
        setTimeout(() => process.exit(code), 10_000).unref();
        cleanup().finally(() => process.exit(code));
      });
    }
  }

  async killAll(): Promise<void> {
    const ids = this.list();
    if (ids.length === 0) return;

    console.error(`Cleaning up ${ids.length} containers...`);
    await Promise.allSettled(
      ids.map(async (id) => {
        try {
          await execFileAsync("docker", ["kill", id]);
        } catch { /* container may already be stopped */ }
        try {
          await execFileAsync("docker", ["rm", "-f", id]);
        } catch { /* container may already be removed */ }
        this.containers.delete(id);
      })
    );
  }
}
