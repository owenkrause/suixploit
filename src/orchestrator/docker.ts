import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export async function buildImage(dockerfilePath: string, contextPath: string): Promise<void> {
  console.error("Building suixploit-hunter image...");
  const proc = spawn("docker", ["build", "-t", "suixploit-hunter", "-f", dockerfilePath, contextPath], {
    stdio: ["ignore", "pipe", "pipe"],
  });

  let stderr = "";
  proc.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString();
  });

  await new Promise<void>((resolve, reject) => {
    proc.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`Docker build failed (exit ${code}):\n${stderr}`));
    });
    proc.on("error", reject);
  });

  console.error("Image built successfully.");
}

export interface ContainerOptions {
  targetContract: string;
  network: "devnet" | "mainnet";
  packageId?: string;
}

export async function startContainer(opts: ContainerOptions): Promise<string> {
  const args = [
    "run", "-d",
    "-e", `TARGET_CONTRACT=${opts.targetContract}`,
    "-e", `NETWORK=${opts.network}`,
  ];
  if (opts.packageId) {
    args.push("-e", `PACKAGE_ID=${opts.packageId}`);
  }
  args.push("suixploit-hunter");

  const { stdout } = await execFileAsync("docker", args);
  return stdout.trim();
}

export async function waitForReady(containerId: string, timeoutMs = 120_000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const { stdout } = await execFileAsync("docker", [
        "exec", containerId, "test", "-f", "/workspace/.ready",
      ]);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  throw new Error(`Container ${containerId.slice(0, 12)} not ready after ${timeoutMs / 1000}s`);
}

export async function readContextJson(containerId: string): Promise<Record<string, string>> {
  const { stdout } = await execFileAsync("docker", [
    "exec", containerId, "cat", "/workspace/context.json",
  ]);
  return JSON.parse(stdout);
}

export async function dockerExec(containerId: string, command: string): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  try {
    const { stdout, stderr } = await execFileAsync("docker", [
      "exec", containerId, "bash", "-c", command,
    ], { maxBuffer: 10 * 1024 * 1024, timeout: 120_000 });
    return { stdout, stderr, exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; code?: number };
    return {
      stdout: e.stdout ?? "",
      stderr: e.stderr ?? String(err),
      exitCode: e.code ?? 1,
    };
  }
}

export async function readFindings(containerId: string): Promise<string> {
  try {
    const { stdout } = await execFileAsync("docker", [
      "exec", containerId, "cat", "/workspace/findings.json",
    ]);
    return stdout;
  } catch {
    return "[]";
  }
}

export async function readVerdict(containerId: string, findingId: string): Promise<string> {
  try {
    const { stdout } = await execFileAsync("docker", [
      "exec", containerId, "cat", `/workspace/verdict-${findingId}.json`,
    ]);
    return stdout;
  } catch {
    return "{}";
  }
}
