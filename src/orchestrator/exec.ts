import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { dockerExec } from "./docker.js";
import type { ExecFn } from "./agent.js";

const execFileAsync = promisify(execFile);

export function makeDockerExec(containerId: string): ExecFn {
  return (command: string) => dockerExec(containerId, command);
}

export function makeLocalExec(cwd: string): ExecFn {
  return async (command: string) => {
    try {
      const { stdout, stderr } = await execFileAsync("bash", ["-c", command], {
        cwd,
        maxBuffer: 10 * 1024 * 1024,
        timeout: 120_000,
      });
      return { stdout, stderr, exitCode: 0 };
    } catch (err: unknown) {
      const e = err as { stdout?: string; stderr?: string; code?: number };
      return {
        stdout: e.stdout ?? "",
        stderr: e.stderr ?? String(err),
        exitCode: e.code ?? 1,
      };
    }
  };
}
