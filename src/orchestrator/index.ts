import Anthropic from "@anthropic-ai/sdk";
import { resolve } from "node:path";
import type { ModuleInfo, Finding, ValidatedFinding, ScanResult } from "../types.js";
import { resolveModules, buildPipelineContext, shouldSkipRanker, buildScanResult } from "../pipeline.js";
import { buildRankerPrompt, parseRankerResponse, filterHighPriority } from "../ranker/index.js";
import { runValidators, filterConfirmed, deduplicateFindings } from "../validator/index.js";
import { prepareHunterPrompt } from "../hunter/index.js";
import { buildImage, startContainer, waitForReady, readContextJson, readFindings } from "./docker.js";
import { buildSystemPrompt, buildMainnetSystemPrompt, runAgent } from "./agent.js";
import { Semaphore } from "./semaphore.js";
import { ResourceTracker } from "./tracker.js";

export interface ScanOptions {
  target: string;
  concurrency: number;
  model: string;
  maxTurns?: number;
  keepContainers: boolean;
  network: "devnet" | "mainnet";
  packageId?: string;
  protocol?: string;
  invariants?: string[];
}

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const { target, concurrency, model, maxTurns, keepContainers, network, packageId } = options;

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

  return buildScanResult(ctx);
}

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
  console.error(`[${mod.name}] Starting container (${network})...`);

  const containerId = await startContainer({
    targetContract: target,
    network,
    packageId,
  });
  tracker.add(containerId);

  console.error(`[${mod.name}] Container ${containerId.slice(0, 12)} — waiting for ready...`);
  await waitForReady(containerId);

  const context = await readContextJson(containerId);

  let hunterPrompt: string;
  let systemPrompt: string;

  if (network === "mainnet") {
    hunterPrompt = buildMainnetHunterPrompt(mod, context.packageId, context.rpcUrl);
    systemPrompt = buildMainnetSystemPrompt(hunterPrompt, context);
  } else {
    hunterPrompt = prepareHunterPrompt({
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
    systemPrompt = buildSystemPrompt(hunterPrompt, context);
  }

  console.error(`[${mod.name}] Running agent (model: ${model}${maxTurns ? `, max turns: ${maxTurns}` : ''})...`);
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
    return { findings: JSON.parse(findingsJson) as Finding[], containerId };
  } catch {
    return { findings: [], containerId };
  }
}

function buildMainnetHunterPrompt(
  mod: ModuleInfo,
  packageId: string,
  rpcUrl: string
): string {
  const invariantList = (mod.invariants ?? []).map((inv) => `- ${inv}`).join("\n");

  return `You are auditing a live Sui Move smart contract on mainnet for security vulnerabilities.

## Target
Module: ${mod.name}
Package ID: ${packageId}
RPC: ${rpcUrl}
Protocol description: ${mod.protocolDescription ?? "No description provided."}

Invariants:
${invariantList || "- None specified"}

## Source
\`\`\`move
${mod.source}
\`\`\`

## How to test exploits (dry-run only — nothing executes on-chain)

Use \`sui_devInspectTransactionBlock\` or \`sui_dryRunTransactionBlock\` to simulate transactions against real mainnet state. This lets you test any exploit scenario without risk.

### Using the TypeScript SDK:
\`\`\`typescript
import { SuiClient } from "@mysten/sui/client";
import { Transaction } from "@mysten/sui/transactions";

const client = new SuiClient({ url: "${rpcUrl}" });

// Build your exploit transaction
const tx = new Transaction();
tx.moveCall({
  target: "${packageId}::module::function",
  arguments: [/* ... */],
});

// Dry-run: simulate against real mainnet state, no signature needed
const result = await client.devInspectTransactionBlock({
  transactionBlock: tx,
  sender: "0x0000000000000000000000000000000000000000000000000000000000000000",
});

console.log("Status:", result.effects.status);
console.log("Events:", result.events);
\`\`\`

### Reading on-chain state:
\`\`\`typescript
// Query objects, balances, events on mainnet
const obj = await client.getObject({ id: "0x...", options: { showContent: true } });
const events = await client.queryEvents({ query: { MoveModule: { package: "${packageId}", module: "${mod.name}" } } });
\`\`\`

Save exploit scripts as .ts files and run with \`npx tsx <file>\`.

## Task
1. Read and analyze the source code for vulnerabilities
2. Query mainnet state to understand the contract's current deployment (objects, pools, balances)
3. Craft exploit transactions and dry-run them to prove they work
4. A successful dry-run with status "success" that violates an invariant = confirmed vulnerability

When done, write findings to /workspace/findings.json:
\`\`\`json
[{
  "id": "unique-id",
  "module": "${mod.name}",
  "severity": "critical|high|medium|low",
  "category": "capability_misuse|shared_object_race|integer_overflow|ownership_violation|hot_potato_misuse|otw_abuse|other",
  "title": "Short title",
  "description": "What the bug is and how to exploit it",
  "exploitTransaction": "// the TS exploit code",
  "oracleResult": { "signal": "dry_run", "status": "EXPLOIT_CONFIRMED", "dryRunResult": "paste dry-run output" },
  "iterations": 3
}]
\`\`\``;
}
