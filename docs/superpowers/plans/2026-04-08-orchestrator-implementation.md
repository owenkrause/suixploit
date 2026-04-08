# Orchestrator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the `scan` CLI command into a fully automated pipeline that spawns parallel hunter agents in isolated Docker containers, collects findings, validates them, and outputs a final ScanResult JSON.

**Architecture:** Each hunter agent runs inside its own Docker container with a pre-booted Sui devnet, deployed contract, and funded accounts. The orchestrator (in-process) manages container lifecycle, runs the agent tool-use loop via the raw Anthropic API, and enforces cleanup on all exit paths. A semaphore limits concurrency.

**Tech Stack:** TypeScript, @anthropic-ai/sdk, Docker, Sui CLI, existing suixploit modules

---

## File Structure

| File | Responsibility |
|------|---------------|
| `Dockerfile` (create) | Hunter container image — Sui CLI + Node + project source |
| `entrypoint.sh` (create) | Container boot — start devnet, deploy contract, write context.json |
| `src/orchestrator/docker.ts` (create) | Docker operations — build image, start/stop containers, exec commands |
| `src/orchestrator/agent.ts` (create) | Agent tool-use loop — Anthropic API conversation with bash tool |
| `src/orchestrator/semaphore.ts` (create) | Concurrency limiter |
| `src/orchestrator/tracker.ts` (create) | Resource tracker — registers containers, cleanup on exit/signal |
| `src/orchestrator/index.ts` (create) | Pipeline orchestration — ties everything together |
| `src/orchestrator/orchestrator.test.ts` (create) | Unit tests for semaphore, tracker, agent message building |
| `src/cli.ts` (modify) | Wire scan command to orchestrator |
| `package.json` (modify) | Add `@anthropic-ai/sdk` dependency |

---

### Task 1: Add Anthropic SDK Dependency

**Files:**
- Modify: `package.json`

- [ ] **Step 1: Install the SDK**

```bash
pnpm add @anthropic-ai/sdk
```

- [ ] **Step 2: Verify it installed**

Run: `pnpm ls @anthropic-ai/sdk`
Expected: Shows the installed version.

- [ ] **Step 3: Commit**

```bash
git add package.json pnpm-lock.yaml
git commit -m "chore: add @anthropic-ai/sdk dependency"
```

---

### Task 2: Semaphore and Resource Tracker

**Files:**
- Create: `src/orchestrator/semaphore.ts`
- Create: `src/orchestrator/tracker.ts`
- Test: `src/orchestrator/orchestrator.test.ts`

- [ ] **Step 1: Write tests**

Write `src/orchestrator/orchestrator.test.ts`:

```typescript
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/orchestrator/orchestrator.test.ts`
Expected: FAIL — modules don't exist yet.

- [ ] **Step 3: Implement Semaphore**

Write `src/orchestrator/semaphore.ts`:

```typescript
export class Semaphore {
  private queue: (() => void)[] = [];
  private active = 0;

  constructor(private readonly limit: number) {}

  acquire(): Promise<() => void> {
    return new Promise<() => void>((resolve) => {
      const tryRun = () => {
        if (this.active < this.limit) {
          this.active++;
          resolve(() => {
            this.active--;
            if (this.queue.length > 0) {
              this.queue.shift()!();
            }
          });
        } else {
          this.queue.push(tryRun);
        }
      };
      tryRun();
    });
  }
}
```

- [ ] **Step 4: Implement ResourceTracker**

Write `src/orchestrator/tracker.ts`:

```typescript
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

    process.on("SIGINT", async () => {
      await cleanup();
      process.exit(130);
    });
    process.on("SIGTERM", async () => {
      await cleanup();
      process.exit(143);
    });
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
```

- [ ] **Step 5: Run tests**

Run: `npx vitest run src/orchestrator/orchestrator.test.ts`
Expected: 3 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/orchestrator/semaphore.ts src/orchestrator/tracker.ts src/orchestrator/orchestrator.test.ts
git commit -m "feat: semaphore concurrency limiter and resource tracker"
```

---

### Task 3: Docker Operations

**Files:**
- Create: `src/orchestrator/docker.ts`

This module wraps Docker CLI commands. No tests — these are thin wrappers around `docker` commands that can only be tested with Docker running.

- [ ] **Step 1: Implement Docker operations**

Write `src/orchestrator/docker.ts`:

```typescript
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

export async function startContainer(targetContract: string): Promise<string> {
  const { stdout } = await execFileAsync("docker", [
    "run", "-d",
    "-e", `TARGET_CONTRACT=${targetContract}`,
    "suixploit-hunter",
  ]);
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
```

- [ ] **Step 2: Verify types compile**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add src/orchestrator/docker.ts
git commit -m "feat: Docker operations — build, start, exec, read context/findings"
```

---

### Task 4: Agent Tool-Use Loop

**Files:**
- Create: `src/orchestrator/agent.ts`
- Modify: `src/orchestrator/orchestrator.test.ts`

- [ ] **Step 1: Add tests for message building helpers**

Append to `src/orchestrator/orchestrator.test.ts`:

```typescript
import { buildToolDefinition, buildSystemPrompt } from "./agent.js";

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/orchestrator/orchestrator.test.ts`
Expected: FAIL — `buildToolDefinition` and `buildSystemPrompt` don't exist.

- [ ] **Step 3: Implement agent module**

Write `src/orchestrator/agent.ts`:

```typescript
import Anthropic from "@anthropic-ai/sdk";
import { dockerExec } from "./docker.js";

export interface AgentOptions {
  containerId: string;
  systemPrompt: string;
  model: string;
  maxTurns: number;
  moduleName: string;
}

export interface AgentResult {
  moduleName: string;
  turns: number;
  inputTokens: number;
  outputTokens: number;
  stopped: "end_turn" | "max_turns" | "error";
  error?: string;
}

export function buildToolDefinition(): Anthropic.Tool {
  return {
    name: "bash",
    description: "Run a shell command in the container. Use this to read files, run the Sui CLI, execute TypeScript exploit scripts with `npx tsx`, and invoke the oracle with `npx tsx src/oracle/check.ts`.",
    input_schema: {
      type: "object" as const,
      properties: {
        command: {
          type: "string",
          description: "The bash command to execute",
        },
      },
      required: ["command"],
    },
  };
}

export function buildSystemPrompt(
  hunterPrompt: string,
  context: Record<string, string>
): string {
  return `${hunterPrompt}

## Environment (pre-configured — do NOT modify)

The Sui devnet is already running. The contract is already deployed. Accounts are funded. Use these values directly:

- RPC URL: ${context.rpcUrl}
- Faucet URL: ${context.faucetUrl ?? "http://127.0.0.1:9123"}
- Package ID: ${context.packageId}
- Attacker address: ${context.attackerAddress}
- Admin address: ${context.adminAddress}
- User address: ${context.userAddress}

You have a \`bash\` tool to run shell commands. The project source is at /workspace.
Working directory is /workspace. Write your exploit files there.

When you are done, write your findings to /workspace/findings.json.`;
}

export async function runAgent(
  client: Anthropic,
  options: AgentOptions
): Promise<AgentResult> {
  const { containerId, systemPrompt, model, maxTurns, moduleName } = options;
  const tool = buildToolDefinition();

  let messages: Anthropic.MessageParam[] = [
    { role: "user", content: "Begin your security analysis. Find vulnerabilities and confirm them with the oracle." },
  ];

  let turns = 0;
  let totalInputTokens = 0;
  let totalOutputTokens = 0;

  while (turns < maxTurns) {
    turns++;

    let response: Anthropic.Message;
    try {
      response = await client.messages.create({
        model,
        max_tokens: 16384,
        system: systemPrompt,
        tools: [tool],
        messages,
      });
    } catch (err) {
      return {
        moduleName,
        turns,
        inputTokens: totalInputTokens,
        outputTokens: totalOutputTokens,
        stopped: "error",
        error: String(err),
      };
    }

    totalInputTokens += response.usage.input_tokens;
    totalOutputTokens += response.usage.output_tokens;

    // Add assistant response to conversation
    messages.push({ role: "assistant", content: response.content });

    if (response.stop_reason !== "tool_use") {
      return {
        moduleName,
        turns,
        inputTokens: totalInputTokens,
        outputTokens: totalOutputTokens,
        stopped: "end_turn",
      };
    }

    // Execute all tool calls in parallel
    const toolUseBlocks = response.content.filter(
      (block): block is Anthropic.ToolUseBlock => block.type === "tool_use"
    );

    const toolResults = await Promise.all(
      toolUseBlocks.map(async (block) => {
        const input = block.input as { command: string };
        console.error(`[${moduleName}] $ ${input.command.slice(0, 100)}`);

        const result = await dockerExec(containerId, input.command);
        const output = [result.stdout, result.stderr].filter(Boolean).join("\n").slice(0, 50_000);

        return {
          type: "tool_result" as const,
          tool_use_id: block.id,
          content: output || "(no output)",
        };
      })
    );

    messages.push({ role: "user", content: toolResults });
  }

  return {
    moduleName,
    turns,
    inputTokens: totalInputTokens,
    outputTokens: totalOutputTokens,
    stopped: "max_turns",
  };
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/orchestrator/orchestrator.test.ts`
Expected: All 5 tests PASS (3 from Task 2 + 2 new).

- [ ] **Step 5: Commit**

```bash
git add src/orchestrator/agent.ts src/orchestrator/orchestrator.test.ts
git commit -m "feat: agent tool-use loop with Anthropic API"
```

---

### Task 5: Pipeline Orchestrator

**Files:**
- Create: `src/orchestrator/index.ts`

- [ ] **Step 1: Implement the orchestrator**

Write `src/orchestrator/index.ts`:

```typescript
import Anthropic from "@anthropic-ai/sdk";
import { resolve } from "node:path";
import type { ModuleInfo, Finding, ValidatedFinding, ScanResult } from "../types.js";
import { resolveModules, buildPipelineContext, shouldSkipRanker, buildScanResult } from "../pipeline.js";
import { buildRankerPrompt, parseRankerResponse, filterHighPriority } from "../ranker/index.js";
import { buildValidatorPrompt, parseValidatorResponse, filterConfirmed } from "../validator/index.js";
import { prepareHunterPrompt } from "../hunter/index.js";
import { buildImage, startContainer, waitForReady, readContextJson, readFindings } from "./docker.js";
import { buildSystemPrompt, runAgent } from "./agent.js";
import { Semaphore } from "./semaphore.js";
import { ResourceTracker } from "./tracker.js";

export interface ScanOptions {
  target: string;
  concurrency: number;
  model: string;
  maxTurns: number;
  keepContainers: boolean;
  protocol?: string;
  invariants?: string[];
}

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const { target, concurrency, model, maxTurns, keepContainers } = options;

  const tracker = new ResourceTracker();
  tracker.registerCleanupHandlers(keepContainers);

  const client = new Anthropic();

  // Step 1: Resolve modules
  console.error(`Resolving modules from ${target}...`);
  const modules = await resolveModules(resolve(target));
  if (modules.length === 0) {
    throw new Error("No Move modules found in target path.");
  }
  console.error(`Found ${modules.length} module(s).`);

  // Apply overrides
  if (options.protocol || options.invariants) {
    for (const mod of modules) {
      if (options.protocol) mod.protocolDescription = options.protocol;
      if (options.invariants) mod.invariants = options.invariants;
    }
  }

  const ctx = buildPipelineContext(target, modules);

  // Step 2: Rank (if needed)
  if (shouldSkipRanker(modules)) {
    console.error(`Skipping ranker (${modules.length} modules <= 3). Hunting all.`);
    ctx.hunterTargets = modules;
  } else {
    console.error("Running ranker...");
    const rankerPrompt = buildRankerPrompt(modules);
    const rankerResponse = await client.messages.create({
      model,
      max_tokens: 4096,
      messages: [{ role: "user", content: rankerPrompt }],
    });
    const rankerText = rankerResponse.content
      .filter((b): b is Anthropic.TextBlock => b.type === "text")
      .map((b) => b.text)
      .join("");
    ctx.rankerScores = parseRankerResponse(rankerText);
    ctx.hunterTargets = filterHighPriority(ctx.rankerScores).length > 0
      ? modules.filter((m) => filterHighPriority(ctx.rankerScores).some((s) => s.module === m.name))
      : modules;
    console.error(`Ranker selected ${ctx.hunterTargets.length} module(s) for hunting.`);
  }

  // Step 3: Build Docker image
  const projectRoot = resolve(import.meta.dirname, "../..");
  await buildImage(resolve(projectRoot, "Dockerfile"), projectRoot);

  // Step 4: Spawn containers and run hunters
  console.error(`Spawning ${ctx.hunterTargets.length} hunter(s) (concurrency: ${concurrency})...`);
  const sem = new Semaphore(concurrency);

  const hunterResults = await Promise.all(
    ctx.hunterTargets.map(async (mod) => {
      const release = await sem.acquire();
      try {
        return await runHunterForModule(client, tracker, mod, target, model, maxTurns);
      } finally {
        release();
      }
    })
  );

  // Step 5: Collect findings
  ctx.rawFindings = hunterResults.flat();
  console.error(`Collected ${ctx.rawFindings.length} raw finding(s).`);

  // Step 6: Validate (if any findings)
  if (ctx.rawFindings.length > 0) {
    console.error("Running validator...");
    const validatorPrompt = buildValidatorPrompt(ctx.rawFindings, modules);
    const validatorResponse = await client.messages.create({
      model,
      max_tokens: 8192,
      messages: [{ role: "user", content: validatorPrompt }],
    });
    const validatorText = validatorResponse.content
      .filter((b): b is Anthropic.TextBlock => b.type === "text")
      .map((b) => b.text)
      .join("");
    ctx.findings = filterConfirmed(parseValidatorResponse(validatorText));
    console.error(`Validator confirmed ${ctx.findings.length} finding(s).`);
  } else {
    ctx.findings = [];
    console.error("No findings to validate.");
  }

  // Step 7: Cleanup
  if (!keepContainers) {
    await tracker.killAll();
  }

  return buildScanResult(ctx);
}

async function runHunterForModule(
  client: Anthropic,
  tracker: ResourceTracker,
  mod: ModuleInfo,
  target: string,
  model: string,
  maxTurns: number
): Promise<Finding[]> {
  console.error(`[${mod.name}] Starting container...`);

  // Determine the contract path relative to the container
  // The target is copied into the image at /workspace/contracts/...
  // We pass the path as seen inside the container
  const containerId = await startContainer(target);
  tracker.add(containerId);

  console.error(`[${mod.name}] Container ${containerId.slice(0, 12)} — waiting for ready...`);
  await waitForReady(containerId);

  const context = await readContextJson(containerId);

  const hunterPrompt = prepareHunterPrompt({
    module: mod,
    devnetConfig: {
      rpcUrl: context.rpcUrl,
      faucetUrl: context.faucetUrl,
      port: 9000,
      faucetPort: 9123,
      adminAddress: context.adminAddress,
      attackerAddress: context.attackerAddress,
      userAddress: context.userAddress,
      adminKeyPair: context.adminKeyPair ?? "",
      attackerKeyPair: context.attackerKeyPair ?? "",
      userKeyPair: context.userKeyPair ?? "",
    },
    packageId: context.packageId,
  });

  const systemPrompt = buildSystemPrompt(hunterPrompt, context);

  console.error(`[${mod.name}] Running agent (model: ${model}, max turns: ${maxTurns})...`);
  const result = await runAgent(client, {
    containerId,
    systemPrompt,
    model,
    maxTurns,
    moduleName: mod.name,
  });

  console.error(`[${mod.name}] Agent finished: ${result.stopped} after ${result.turns} turns (${result.inputTokens + result.outputTokens} tokens)`);

  // Collect findings
  const findingsJson = await readFindings(containerId);
  try {
    return JSON.parse(findingsJson) as Finding[];
  } catch {
    return [];
  }
}
```

- [ ] **Step 2: Verify types compile**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add src/orchestrator/index.ts
git commit -m "feat: pipeline orchestrator — Docker + agents + ranker + validator"
```

---

### Task 6: Dockerfile and Entrypoint

**Files:**
- Create: `Dockerfile`
- Create: `entrypoint.sh`

- [ ] **Step 1: Write entrypoint.sh**

Write `entrypoint.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

TARGET_CONTRACT="${TARGET_CONTRACT:?TARGET_CONTRACT env var must be set}"

echo "=== Starting Sui devnet ==="
sui start --with-faucet --force-regenesis &
SUI_PID=$!

# Wait for RPC to be ready
echo "Waiting for RPC..."
for i in $(seq 1 60); do
  if curl -s -X POST http://127.0.0.1:9000 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"sui_getLatestCheckpointSequenceNumber","id":1}' \
    2>/dev/null | grep -q '"result"'; then
    echo "RPC ready after ${i}s"
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "ERROR: RPC not ready after 60s" >&2
    exit 1
  fi
  sleep 1
done

# Generate keypairs
echo "=== Generating accounts ==="
ADMIN_OUTPUT=$(sui client new-address ed25519 admin 2>&1)
ADMIN_ADDRESS=$(echo "$ADMIN_OUTPUT" | grep -oP '0x[a-f0-9]{64}' | head -1)

ATTACKER_OUTPUT=$(sui client new-address ed25519 attacker 2>&1)
ATTACKER_ADDRESS=$(echo "$ATTACKER_OUTPUT" | grep -oP '0x[a-f0-9]{64}' | head -1)

USER_OUTPUT=$(sui client new-address ed25519 user 2>&1)
USER_ADDRESS=$(echo "$USER_OUTPUT" | grep -oP '0x[a-f0-9]{64}' | head -1)

echo "Admin:    $ADMIN_ADDRESS"
echo "Attacker: $ATTACKER_ADDRESS"
echo "User:     $USER_ADDRESS"

# Fund accounts
echo "=== Funding accounts ==="
for ADDR in "$ADMIN_ADDRESS" "$ATTACKER_ADDRESS" "$USER_ADDRESS"; do
  curl -s -X POST http://127.0.0.1:9123/v2/gas \
    -H 'Content-Type: application/json' \
    -d "{\"FixedAmountRequest\":{\"recipient\":\"${ADDR}\"}}" \
    > /dev/null
  echo "Funded $ADDR"
done

# Publish contract
echo "=== Publishing contract: $TARGET_CONTRACT ==="
sui client switch --address "$ADMIN_ADDRESS" 2>/dev/null

PUBLISH_OUTPUT=$(sui client publish "/workspace/${TARGET_CONTRACT}" \
  --skip-dependency-verification \
  --gas-budget 500000000 \
  --json 2>&1)

PACKAGE_ID=$(echo "$PUBLISH_OUTPUT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for change in data.get('objectChanges', []):
    if change.get('type') == 'published':
        print(change['packageId'])
        break
" 2>/dev/null || echo "")

if [ -z "$PACKAGE_ID" ]; then
  echo "ERROR: Failed to extract package ID from publish output" >&2
  echo "$PUBLISH_OUTPUT" >&2
  exit 1
fi

echo "Package ID: $PACKAGE_ID"

# Export private keys
ADMIN_KEY=$(sui keytool export "$ADMIN_ADDRESS" --json 2>&1 | python3 -c "import sys,json; print(json.load(sys.stdin)['key']['suiPrivateKey'])" 2>/dev/null || echo "")
ATTACKER_KEY=$(sui keytool export "$ATTACKER_ADDRESS" --json 2>&1 | python3 -c "import sys,json; print(json.load(sys.stdin)['key']['suiPrivateKey'])" 2>/dev/null || echo "")
USER_KEY=$(sui keytool export "$USER_ADDRESS" --json 2>&1 | python3 -c "import sys,json; print(json.load(sys.stdin)['key']['suiPrivateKey'])" 2>/dev/null || echo "")

# Write context
cat > /workspace/context.json <<CONTEXT
{
  "rpcUrl": "http://127.0.0.1:9000",
  "faucetUrl": "http://127.0.0.1:9123",
  "packageId": "$PACKAGE_ID",
  "adminAddress": "$ADMIN_ADDRESS",
  "attackerAddress": "$ATTACKER_ADDRESS",
  "userAddress": "$USER_ADDRESS",
  "adminKeyPair": "$ADMIN_KEY",
  "attackerKeyPair": "$ATTACKER_KEY",
  "userKeyPair": "$USER_KEY"
}
CONTEXT

echo "=== Container ready ==="
touch /workspace/.ready

# Keep container alive
exec tail -f /dev/null
```

- [ ] **Step 2: Make entrypoint executable**

```bash
chmod +x entrypoint.sh
```

- [ ] **Step 3: Write Dockerfile**

Write `Dockerfile`:

```dockerfile
FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
  curl \
  git \
  python3 \
  build-essential \
  pkg-config \
  libssl-dev \
  && rm -rf /var/lib/apt/lists/*

# Install Sui CLI
RUN curl -fsSL https://sui.io/install.sh | bash
ENV PATH="/root/.sui/bin:${PATH}"

# Install Node.js 22
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
  && apt-get install -y nodejs \
  && rm -rf /var/lib/apt/lists/*

# Install pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

# Set up workspace
WORKDIR /workspace

# Copy package files and install dependencies
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# Copy project source
COPY tsconfig.json ./
COPY src/ ./src/
COPY contracts/ ./contracts/
COPY entrypoint.sh ./

ENTRYPOINT ["./entrypoint.sh"]
```

- [ ] **Step 4: Verify Docker build works**

Run: `docker build -t suixploit-hunter .`
Expected: Build completes successfully. (This may take a few minutes the first time.)

- [ ] **Step 5: Commit**

```bash
git add Dockerfile entrypoint.sh
git commit -m "feat: Dockerfile and entrypoint for hunter containers"
```

---

### Task 7: Wire CLI to Orchestrator

**Files:**
- Modify: `src/cli.ts`

- [ ] **Step 1: Replace the scan command implementation**

Replace the contents of `src/cli.ts` with:

```typescript
#!/usr/bin/env node
import { Command } from "commander";
import { writeFileSync } from "node:fs";
import { runScan } from "./orchestrator/index.js";

const program = new Command();

program
  .name("suixploit")
  .description("Multi-agent Sui Move vulnerability discovery pipeline")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a Move project for vulnerabilities")
  .argument("<target>", "Path to Move project directory")
  .option("--concurrency <n>", "Max parallel agents", "5")
  .option("--model <model>", "Model for agents", "claude-sonnet-4-6")
  .option("--max-turns <n>", "Max turns per hunter agent", "50")
  .option("--output <path>", "Write ScanResult JSON to file (default: stdout)")
  .option("--keep-containers", "Don't remove containers after run", false)
  .option("--protocol <description>", "Protocol description override")
  .option("--invariants <invariants...>", "Invariants to test against")
  .action(async (target: string, options) => {
    const result = await runScan({
      target,
      concurrency: parseInt(options.concurrency, 10),
      model: options.model,
      maxTurns: parseInt(options.maxTurns, 10),
      keepContainers: options.keepContainers,
      protocol: options.protocol,
      invariants: options.invariants,
    });

    const json = JSON.stringify(result, null, 2);

    if (options.output) {
      writeFileSync(options.output, json);
      console.error(`Results written to ${options.output}`);
    } else {
      console.log(json);
    }
  });

program.parse();
```

- [ ] **Step 2: Verify types compile**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Verify all tests still pass**

Run: `npx vitest run`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/cli.ts
git commit -m "feat: wire scan CLI to orchestrator pipeline"
```

---

### Task 8: End-to-End Smoke Test

**Files:**
- None created — validation task

This requires Docker running and an `ANTHROPIC_API_KEY` set.

- [ ] **Step 1: Build the Docker image**

Run: `docker build -t suixploit-hunter .`
Expected: Build succeeds.

- [ ] **Step 2: Test a single container boots correctly**

Run:
```bash
docker run -d -e TARGET_CONTRACT=contracts/easy/capability_leak suixploit-hunter
```

Wait ~30s, then:
```bash
docker exec <container_id> cat /workspace/context.json
```

Expected: JSON with rpcUrl, packageId, addresses.

Then clean up:
```bash
docker kill <container_id> && docker rm <container_id>
```

- [ ] **Step 3: Run a minimal scan**

Run:
```bash
ANTHROPIC_API_KEY=<your-key> npx tsx src/cli.ts scan contracts/easy/capability_leak --concurrency 1 --max-turns 10 --output results.json
```

Expected: Pipeline runs, outputs a ScanResult JSON. The agent may or may not find the vulnerability in 10 turns, but the pipeline should complete without errors and `results.json` should be valid JSON with the ScanResult shape.

- [ ] **Step 4: Verify cleanup**

Run: `docker ps -a --filter ancestor=suixploit-hunter`
Expected: No containers running (unless `--keep-containers` was used).

- [ ] **Step 5: Commit any fixes**

If any issues were found and fixed:
```bash
git add -A
git commit -m "fix: adjustments from end-to-end smoke test"
```

---

### Task 9: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update CLAUDE.md with new usage**

Add the automated pipeline section to `CLAUDE.md`. Replace the manual pipeline instructions with:

```markdown
## Automated Pipeline

Run a full scan:
```bash
ANTHROPIC_API_KEY=<key> npx suixploit scan <target> [options]
```

Options:
- `--concurrency <n>` — Max parallel agents (default: 5)
- `--model <model>` — Model for agents (default: claude-sonnet-4-6)
- `--max-turns <n>` — Max turns per hunter (default: 50)
- `--output <path>` — Write results to file (default: stdout)
- `--keep-containers` — Keep Docker containers for debugging

Example:
```bash
ANTHROPIC_API_KEY=sk-ant-... npx suixploit scan contracts/easy/capability_leak --concurrency 1 --output results.json
```

Requires: Docker running, ANTHROPIC_API_KEY set.
```

Keep the existing manual pipeline, oracle usage, and project structure sections unchanged — they're still useful for understanding the system.

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md with automated pipeline usage"
```
