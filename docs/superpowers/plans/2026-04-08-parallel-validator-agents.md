# Parallel Validator Agents Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single-call validator with parallel agentic validators that deeply investigate each finding using the hunter containers.

**Architecture:** One validator agent per finding, running in parallel via the existing Semaphore. Each agent gets bash access to the hunter container (which already has source code), traces code paths, assesses real-world impact, and writes a structured verdict. The agent loop adds a turn-limit warning on the second-to-last turn so output is never lost.

**Tech Stack:** TypeScript, @anthropic-ai/sdk, vitest, existing Docker infrastructure

---

### Task 1: Update types with new ValidatedFinding fields

**Files:**
- Modify: `src/types.ts:40-44`
- Test: `src/types.test.ts`

- [ ] **Step 1: Update ValidatedFinding interface**

In `src/types.ts`, replace lines 40-44:

```typescript
export interface ValidatedFinding extends Finding {
  validatorVerdict: "confirmed" | "adjusted" | "rejected";
  validatorNote: string;
  adjustedSeverity?: Severity;
  impact?: string;
  duplicateOf?: string;
}
```

- [ ] **Step 2: Run tests to confirm nothing breaks**

Run: `pnpm test`
Expected: All existing tests pass (the new fields are optional so nothing breaks)

- [ ] **Step 3: Commit**

```bash
git add src/types.ts
git commit -m "feat: add impact and duplicateOf fields to ValidatedFinding"
```

---

### Task 2: Add turn-limit warning to the agent loop

**Files:**
- Modify: `src/orchestrator/agent.ts:82-175`
- Test: `src/orchestrator/orchestrator.test.ts`

- [ ] **Step 1: Read the current agent loop**

Read `src/orchestrator/agent.ts` to understand the full `runAgent` function. The loop is at line 101: `while (!maxTurns || turns < maxTurns)`. After executing tool calls and pushing tool results to messages (line 164), we need to inject a warning when `turns === maxTurns - 1`.

- [ ] **Step 2: Add the turn-limit warning injection**

In `src/orchestrator/agent.ts`, after the line `messages.push({ role: "user", content: toolResults });` (line 164), add the turn-limit warning. The modified section should look like:

```typescript
    messages.push({ role: "user", content: toolResults });

    // Warn agent on second-to-last turn to flush output
    if (maxTurns && turns === maxTurns - 1) {
      const lastToolResult = toolResults[toolResults.length - 1];
      messages[messages.length - 1] = {
        role: "user",
        content: [
          ...toolResults,
          {
            type: "text" as const,
            text: `WARNING: You are about to hit your turn limit. This is your LAST turn. Write your output file NOW with whatever analysis you have so far. Note that you hit the turn limit.`,
          },
        ],
      };
    }
```

- [ ] **Step 3: Run tests**

Run: `pnpm test`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/orchestrator/agent.ts
git commit -m "feat: warn agent on last turn to flush output before hitting limit"
```

---

### Task 3: Add readVerdict helper to docker.ts

**Files:**
- Modify: `src/orchestrator/docker.ts`

- [ ] **Step 1: Add readVerdict function**

Add this function at the bottom of `src/orchestrator/docker.ts`:

```typescript
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
```

- [ ] **Step 2: Run tests**

Run: `pnpm test`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add src/orchestrator/docker.ts
git commit -m "feat: add readVerdict helper for validator agents"
```

---

### Task 4: Build the validator agent prompt

**Files:**
- Create: `src/validator/prompt.ts`

- [ ] **Step 1: Create the validator prompt builder**

Create `src/validator/prompt.ts`:

```typescript
import type { Finding } from "../types.js";

export function buildValidatorAgentPrompt(
  finding: Finding,
  otherFindingsSummary: string
): string {
  return `You are a senior smart contract security auditor performing a deep review of a single vulnerability finding.

## Finding Under Review

ID: ${finding.id}
Module: ${finding.module}
Severity: ${finding.severity}
Category: ${finding.category}
Title: ${finding.title}

### Description
${finding.description}

### Exploit Transaction
\`\`\`typescript
${finding.exploitTransaction}
\`\`\`

### Oracle / Dry-Run Result
\`\`\`json
${JSON.stringify(finding.oracleResult, null, 2)}
\`\`\`

## Other Findings In This Batch
${otherFindingsSummary}

## Your Task

You have bash access to the container with all source code at /workspace. Use it to:

1. **Trace the code path**: Read the relevant source files. Find the exact functions mentioned in the finding. Verify the described vulnerability exists — check function signatures, access control modifiers, data flow.

2. **Assess real-world impact**: Could this cause fund loss? Griefing? DoS? What's the blast radius? How much does it cost the attacker vs. how much damage does it cause? Think about cascading effects — does this broken state feed into other calculations?

3. **Evaluate severity**: Is the current severity rating accurate given the real-world impact? Adjust if needed.

4. **Check for duplicates**: Review the other findings in this batch. If this finding describes the same root cause as another finding, note which one it duplicates.

5. **Write your verdict**: When done, write your verdict to /workspace/verdict-${finding.id}.json:

\`\`\`json
{
  "id": "${finding.id}",
  "validatorVerdict": "confirmed | adjusted | rejected",
  "adjustedSeverity": "critical | high | medium | low",
  "impact": "Detailed real-world impact analysis. Who is affected, what can an attacker gain, what does it cost them, is it practically exploitable.",
  "validatorNote": "Technical verification: which code paths were traced, what was confirmed or refuted.",
  "duplicateOf": null
}
\`\`\`

Be thorough. Read the actual source code — don't just trust the description. If the finding claims a function has no access control, go read that function and confirm.`;
}

export function buildOtherFindingsSummary(
  allFindings: Finding[],
  currentId: string
): string {
  const others = allFindings.filter((f) => f.id !== currentId);
  if (others.length === 0) return "No other findings in this batch.";
  return others
    .map((f) => `- ${f.id}: [${f.severity}] ${f.title} (module: ${f.module})`)
    .join("\n");
}
```

- [ ] **Step 2: Run tests**

Run: `pnpm test`
Expected: All tests pass (no tests for this file yet — it's a new file)

- [ ] **Step 3: Commit**

```bash
git add src/validator/prompt.ts
git commit -m "feat: add validator agent prompt builder"
```

---

### Task 5: Build the parallel validator runner

**Files:**
- Rewrite: `src/validator/index.ts`

This is the core change. Replace the single-call validator with a parallel agent-based approach.

- [ ] **Step 1: Rewrite src/validator/index.ts**

Replace the entire contents of `src/validator/index.ts` with:

```typescript
import Anthropic from "@anthropic-ai/sdk";
import type { Finding, ModuleInfo, ValidatedFinding } from "../types.js";
import { buildValidatorAgentPrompt, buildOtherFindingsSummary } from "./prompt.js";
import { buildToolDefinition, runAgent } from "../orchestrator/agent.js";
import { readVerdict } from "../orchestrator/docker.js";
import { Semaphore } from "../orchestrator/semaphore.js";

export interface ValidatorOptions {
  client: Anthropic;
  findings: Finding[];
  containerIds: string[];
  model: string;
  concurrency: number;
  maxTurns?: number;
}

interface ValidatorVerdict {
  id: string;
  validatorVerdict: "confirmed" | "adjusted" | "rejected";
  validatorNote: string;
  adjustedSeverity?: string;
  impact?: string;
  duplicateOf?: string | null;
}

export async function runValidators(options: ValidatorOptions): Promise<ValidatedFinding[]> {
  const { client, findings, containerIds, model, concurrency, maxTurns = 30 } = options;

  if (findings.length === 0) return [];

  const sem = new Semaphore(concurrency);

  // Use the first available container for all validators (they just read files)
  const containerId = containerIds[0];

  const verdicts = await Promise.all(
    findings.map(async (finding) => {
      const release = await sem.acquire();
      try {
        return await runValidatorForFinding(client, finding, findings, containerId, model, maxTurns);
      } finally {
        release();
      }
    })
  );

  return mergeVerdicts(findings, verdicts);
}

async function runValidatorForFinding(
  client: Anthropic,
  finding: Finding,
  allFindings: Finding[],
  containerId: string,
  model: string,
  maxTurns: number
): Promise<ValidatorVerdict> {
  const otherSummary = buildOtherFindingsSummary(allFindings, finding.id);
  const prompt = buildValidatorAgentPrompt(finding, otherSummary);

  const systemPrompt = `${prompt}

## Environment

You have a \`bash\` tool to run shell commands. Source code is at /workspace.
Use it to read .move files, grep for functions, trace code paths.

When you are done, write your verdict to /workspace/verdict-${finding.id}.json`;

  console.error(`[validator:${finding.id}] Starting review...`);

  const result = await runAgent(client, {
    containerId,
    systemPrompt,
    model,
    maxTurns,
    moduleName: `validator:${finding.id}`,
  });

  console.error(`[validator:${finding.id}] Finished: ${result.stopped} after ${result.turns} turns (${result.inputTokens + result.outputTokens} tokens)`);

  // Read verdict
  const verdictJson = await readVerdict(containerId, finding.id);
  try {
    return JSON.parse(verdictJson) as ValidatorVerdict;
  } catch {
    console.error(`[validator:${finding.id}] Failed to parse verdict, defaulting to confirmed`);
    return {
      id: finding.id,
      validatorVerdict: "confirmed",
      validatorNote: `Validator agent completed (${result.stopped}) but did not write a parseable verdict.`,
    };
  }
}

function mergeVerdicts(findings: Finding[], verdicts: ValidatorVerdict[]): ValidatedFinding[] {
  const verdictMap = new Map(verdicts.map((v) => [v.id, v]));
  return findings.map((f) => {
    const verdict = verdictMap.get(f.id);
    return {
      ...f,
      validatorVerdict: verdict?.validatorVerdict ?? "confirmed",
      validatorNote: verdict?.validatorNote ?? "No verdict returned",
      adjustedSeverity: verdict?.adjustedSeverity as ValidatedFinding["adjustedSeverity"],
      impact: verdict?.impact,
      duplicateOf: verdict?.duplicateOf ?? undefined,
    };
  });
}

export function filterConfirmed(findings: ValidatedFinding[]): ValidatedFinding[] {
  return findings.filter((f) => f.validatorVerdict !== "rejected");
}

export function deduplicateFindings(findings: ValidatedFinding[]): ValidatedFinding[] {
  const dominated = new Set<string>();
  for (const f of findings) {
    if (f.duplicateOf) {
      dominated.add(f.id);
    }
  }
  return findings.filter((f) => !dominated.has(f.id));
}
```

- [ ] **Step 2: Run build to check for type errors**

Run: `pnpm build`
Expected: Compiles without errors

- [ ] **Step 3: Commit**

```bash
git add src/validator/index.ts
git commit -m "feat: replace single-call validator with parallel agent-based validators"
```

---

### Task 6: Wire the new validator into the orchestrator

**Files:**
- Modify: `src/orchestrator/index.ts:1-10` (imports) and `src/orchestrator/index.ts:82-123` (steps 4-7)

- [ ] **Step 1: Update imports in orchestrator/index.ts**

Replace the imports at the top of `src/orchestrator/index.ts`. The old imports:

```typescript
import { buildValidatorPrompt, parseValidatorResponse, filterConfirmed } from "../validator/index.js";
```

Replace with:

```typescript
import { runValidators, filterConfirmed, deduplicateFindings } from "../validator/index.js";
```

- [ ] **Step 2: Track container IDs from hunters**

In `runHunterForModule`, the function currently returns `Finding[]`. We need it to also return the `containerId` so validators can reuse it. Change the return type and the calling code.

First, modify `runHunterForModule` to return both findings and containerId. Change the return type to `Promise<{ findings: Finding[]; containerId: string }>`:

```typescript
async function runHunterForModule(
  client: Anthropic,
  tracker: ResourceTracker,
  mod: ModuleInfo,
  target: string,
  model: string,
  maxTurns?: number,
  network: "devnet" | "mainnet" = "devnet",
  packageId?: string
): Promise<{ findings: Finding[]; containerId: string }> {
```

And change the end of the function (the return after `readFindings`) to:

```typescript
  // Collect findings
  const findingsJson = await readFindings(containerId);
  try {
    return { findings: JSON.parse(findingsJson) as Finding[], containerId };
  } catch {
    return { findings: [], containerId };
  }
}
```

- [ ] **Step 3: Update steps 4-7 in runScan**

Replace the section from `// Step 4: Spawn containers and run hunters` through `// Step 7: Cleanup` (lines 78-122) with:

```typescript
  // Step 4: Spawn containers and run hunters
  console.error(`Spawning ${ctx.hunterTargets.length} hunter(s) (concurrency: ${concurrency})...`);
  const sem = new Semaphore(concurrency);

  const hunterResults = await Promise.all(
    ctx.hunterTargets.map(async (mod) => {
      const release = await sem.acquire();
      try {
        return await runHunterForModule(client, tracker, mod, target, model, maxTurns, network, packageId);
      } finally {
        release();
      }
    })
  );

  // Step 5: Collect findings and container IDs
  ctx.rawFindings = hunterResults.flatMap((r) => r.findings);
  const containerIds = hunterResults.map((r) => r.containerId);
  console.error(`Collected ${ctx.rawFindings.length} raw finding(s).`);

  // Step 6: Validate (parallel agents reusing hunter containers)
  if (ctx.rawFindings.length > 0 && containerIds.length > 0) {
    console.error(`Running ${ctx.rawFindings.length} validator agent(s) (concurrency: ${concurrency})...`);
    const validated = await runValidators({
      client,
      findings: ctx.rawFindings,
      containerIds,
      model,
      concurrency,
    });
    ctx.findings = deduplicateFindings(filterConfirmed(validated));
    console.error(`Validator confirmed ${ctx.findings.length} finding(s) after dedup.`);
  } else {
    ctx.findings = [];
    console.error("No findings to validate.");
  }

  // Step 7: Cleanup
  if (!keepContainers) {
    await tracker.killAll();
  }
```

- [ ] **Step 4: Remove unused Anthropic import usage**

The orchestrator no longer calls `client.messages.create` for the validator step directly. Check that the `Anthropic` import and `client` are still used (they are — for the ranker and passed to `runValidators`). No changes needed here, just verify.

- [ ] **Step 5: Run build**

Run: `pnpm build`
Expected: Compiles without errors

- [ ] **Step 6: Run tests**

Run: `pnpm test`
Expected: Tests pass. The validator test file (`src/validator/validator.test.ts`) will need updating in the next task since the old `buildValidatorPrompt` and `parseValidatorResponse` no longer exist.

- [ ] **Step 7: Commit**

```bash
git add src/orchestrator/index.ts
git commit -m "feat: wire parallel validator agents into the scan pipeline"
```

---

### Task 7: Update validator tests

**Files:**
- Rewrite: `src/validator/validator.test.ts`

The old tests tested `buildValidatorPrompt` and `parseValidatorResponse` which no longer exist. Replace with tests for the new exports.

- [ ] **Step 1: Rewrite the validator tests**

Replace the entire contents of `src/validator/validator.test.ts` with:

```typescript
import { describe, it, expect } from "vitest";
import { filterConfirmed, deduplicateFindings } from "./index.js";
import { buildValidatorAgentPrompt, buildOtherFindingsSummary } from "./prompt.js";
import type { Finding, ValidatedFinding } from "../types.js";

const sampleFinding: Finding = {
  id: "f1",
  module: "test::vault",
  severity: "critical",
  category: "capability_misuse",
  title: "AdminCap leak",
  description: "Anyone can get an AdminCap",
  exploitTransaction: "// exploit code",
  oracleResult: {
    signal: "abort",
    status: "EXPLOIT_CONFIRMED",
    preTxState: {},
    postTxState: {},
  },
  iterations: 2,
};

const sampleFinding2: Finding = {
  ...sampleFinding,
  id: "f2",
  title: "Duplicate of AdminCap leak",
};

describe("buildValidatorAgentPrompt", () => {
  it("includes finding details", () => {
    const prompt = buildValidatorAgentPrompt(sampleFinding, "No other findings.");
    expect(prompt).toContain("AdminCap leak");
    expect(prompt).toContain("test::vault");
    expect(prompt).toContain("EXPLOIT_CONFIRMED");
    expect(prompt).toContain("verdict-f1.json");
  });
});

describe("buildOtherFindingsSummary", () => {
  it("lists other findings excluding current", () => {
    const summary = buildOtherFindingsSummary([sampleFinding, sampleFinding2], "f1");
    expect(summary).toContain("f2");
    expect(summary).not.toContain("f1:");
  });

  it("returns message when no other findings", () => {
    const summary = buildOtherFindingsSummary([sampleFinding], "f1");
    expect(summary).toContain("No other findings");
  });
});

describe("filterConfirmed", () => {
  it("removes rejected findings", () => {
    const findings: ValidatedFinding[] = [
      { ...sampleFinding, validatorVerdict: "confirmed", validatorNote: "good" },
      { ...sampleFinding2, validatorVerdict: "rejected", validatorNote: "false positive" },
    ];
    const result = filterConfirmed(findings);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("f1");
  });

  it("keeps adjusted findings", () => {
    const findings: ValidatedFinding[] = [
      { ...sampleFinding, validatorVerdict: "adjusted", validatorNote: "downgraded", adjustedSeverity: "low" },
    ];
    expect(filterConfirmed(findings)).toHaveLength(1);
  });
});

describe("deduplicateFindings", () => {
  it("removes findings marked as duplicates", () => {
    const findings: ValidatedFinding[] = [
      { ...sampleFinding, validatorVerdict: "confirmed", validatorNote: "original" },
      { ...sampleFinding2, validatorVerdict: "confirmed", validatorNote: "dupe", duplicateOf: "f1" },
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("f1");
  });

  it("keeps all findings when no duplicates", () => {
    const findings: ValidatedFinding[] = [
      { ...sampleFinding, validatorVerdict: "confirmed", validatorNote: "good" },
      { ...sampleFinding2, validatorVerdict: "confirmed", validatorNote: "also good" },
    ];
    expect(deduplicateFindings(findings)).toHaveLength(2);
  });
});
```

- [ ] **Step 2: Run tests**

Run: `pnpm test`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add src/validator/validator.test.ts
git commit -m "test: update validator tests for parallel agent architecture"
```

---

### Task 8: Update the validate-findings script

**Files:**
- Rewrite: `scripts/validate-findings.ts`

The standalone script needs to start a container (or reuse one) since validators now need bash access.

- [ ] **Step 1: Rewrite scripts/validate-findings.ts**

Replace the entire contents of `scripts/validate-findings.ts` with:

```typescript
#!/usr/bin/env npx tsx
/**
 * Run just the validator step on previously recovered findings.
 *
 * If --container-id is provided, reuses that container.
 * Otherwise, finds running suixploit-hunter containers automatically.
 *
 * Usage:
 *   npx tsx scripts/validate-findings.ts <findings.json> <target-dir> [options]
 *
 * Options:
 *   --model <model>          Model to use (default: claude-sonnet-4-6)
 *   --output <path>          Write results to file (default: stdout)
 *   --container-id <id>      Reuse a specific container
 *   --concurrency <n>        Max parallel validators (default: 5)
 */
import Anthropic from "@anthropic-ai/sdk";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { resolveModules } from "../src/pipeline.js";
import { runValidators, filterConfirmed, deduplicateFindings } from "../src/validator/index.js";

const args = process.argv.slice(2);
const findingsPath = args[0];
const targetDir = args[1];

function getFlag(flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx !== -1 ? args[idx + 1] : undefined;
}

const model = getFlag("--model") ?? "claude-sonnet-4-6";
const outputPath = getFlag("--output");
const concurrency = parseInt(getFlag("--concurrency") ?? "5", 10);
let containerId = getFlag("--container-id");

if (!findingsPath || !targetDir) {
  console.error("Usage: npx tsx scripts/validate-findings.ts <findings.json> <target-dir> [--model <model>] [--output <path>] [--container-id <id>] [--concurrency <n>]");
  process.exit(1);
}

// Auto-detect a running hunter container if none specified
if (!containerId) {
  try {
    const out = execFileSync("docker", [
      "ps", "--filter", "ancestor=suixploit-hunter", "--format", "{{.ID}}",
    ]).toString().trim();
    const ids = out.split("\n").filter(Boolean);
    if (ids.length > 0) {
      containerId = ids[0];
      console.error(`Auto-detected container: ${containerId.slice(0, 12)}`);
    } else {
      console.error("Error: No running suixploit-hunter containers found. Pass --container-id or start a container.");
      process.exit(1);
    }
  } catch {
    console.error("Error: Failed to detect containers. Pass --container-id explicitly.");
    process.exit(1);
  }
}

const findings = JSON.parse(readFileSync(findingsPath, "utf-8"));
console.error(`Loaded ${findings.length} findings from ${findingsPath}`);

const modules = await resolveModules(resolve(targetDir));
console.error(`Resolved ${modules.length} modules from ${targetDir}`);

console.error(`Running ${findings.length} validator agent(s) (concurrency: ${concurrency}, model: ${model})...`);
const client = new Anthropic();

const validated = await runValidators({
  client,
  findings,
  containerIds: [containerId],
  model,
  concurrency,
});

const confirmed = deduplicateFindings(filterConfirmed(validated));
console.error(`Validator confirmed ${confirmed.length} / ${findings.length} findings after dedup`);

const json = JSON.stringify(confirmed, null, 2);
if (outputPath) {
  writeFileSync(outputPath, json);
  console.error(`Written to ${outputPath}`);
} else {
  console.log(json);
}
```

- [ ] **Step 2: Run build**

Run: `pnpm build`
Expected: Compiles without errors

- [ ] **Step 3: Commit**

```bash
git add scripts/validate-findings.ts
git commit -m "feat: update validate-findings script to use parallel validator agents"
```

---

### Task 9: Final integration test

**Files:**
- No file changes — this is a verification task

- [ ] **Step 1: Run full build**

Run: `pnpm build`
Expected: Clean compilation

- [ ] **Step 2: Run all tests**

Run: `pnpm test`
Expected: All tests pass

- [ ] **Step 3: Verify the validate-findings script works against recovered findings**

If you have recovered findings and a running container:

Run: `ANTHROPIC_API_KEY=<key> npx tsx scripts/validate-findings.ts /tmp/recovered-findings.json contracts/lending_core --concurrency 3 --output /tmp/validated.json`

Expected: Validator agents run in parallel, write verdicts, output merged validated findings.

- [ ] **Step 4: Commit any fixes needed**

If any issues were found, fix and commit.
