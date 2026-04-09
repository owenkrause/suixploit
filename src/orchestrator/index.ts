import Anthropic from "@anthropic-ai/sdk";
import { resolve } from "node:path";
import { mkdirSync, writeFileSync, readFileSync, symlinkSync, lstatSync } from "node:fs";
import type { ModuleInfo, Finding, ValidatedFinding, ScanResult } from "../types.js";
import { resolveModules, buildPipelineContext, shouldSkipRanker, buildScanResult } from "../pipeline.js";
import { buildRankerPrompt, parseRankerResponse, filterHighPriority, extractSignatures } from "../ranker/index.js";
import { runValidators, filterConfirmed, deduplicateFindings } from "../validator/index.js";
import { prepareHunterPrompt } from "../hunter/index.js";
import { buildImage, startContainer, waitForReady, readContextJson, readFindings } from "./docker.js";
import { buildSystemPrompt, buildMainnetSystemPrompt, runAgent } from "./agent.js";
import type { ExecFn } from "./agent.js";
import { makeDockerExec, makeLocalExec } from "./exec.js";
import { Semaphore } from "./semaphore.js";
import { ResourceTracker } from "./tracker.js";
import { StatusDisplay } from "./display.js";

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
  checkpointDir?: string;
}

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const { target, concurrency, model, maxTurns, keepContainers, network, packageId } = options;

  // Set up checkpoint directory
  const checkpointDir = options.checkpointDir ?? resolve(target, ".suixploit");
  mkdirSync(checkpointDir, { recursive: true });
  const checkpoint = (name: string, data: unknown) => {
    const path = resolve(checkpointDir, name);
    writeFileSync(path, JSON.stringify(data, null, 2));
    console.error(`Checkpoint saved: ${path}`);
  };

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
      max_tokens: 16384,
      messages: [{ role: "user", content: rankerPrompt }],
    });
    const rankerText = rankerResponse.content
      .filter((b): b is Anthropic.TextBlock => b.type === "text")
      .map((b) => b.text)
      .join("");
    ctx.rankerScores = parseRankerResponse(rankerText);

    // Log all scores sorted by rank
    const sorted = [...ctx.rankerScores].sort((a, b) => b.score - a.score);
    for (const s of sorted) {
      const marker = s.score >= 3 ? ">>>" : "   ";
      console.error(`  ${marker} [${s.score}/5] ${s.module}`);
    }

    const highPri = filterHighPriority(ctx.rankerScores);
    ctx.hunterTargets = highPri.length > 0
      ? modules.filter((m) => highPri.some((s) => s.module === m.name))
      : modules;
    console.error(`Ranker selected ${ctx.hunterTargets.length} module(s) for hunting.`);
  }

  // Step 3-5: Hunt (strategy depends on network mode)
  const sem = new Semaphore(concurrency);
  const allFindings: Finding[] = [];
  const display = new StatusDisplay();

  // Build cross-module context for each hunter (signatures of sibling modules)
  function buildRelatedSignatures(targetMod: ModuleInfo): string {
    const others = modules.filter((m) => m.name !== targetMod.name);
    if (others.length === 0) return "";
    return others
      .map((m) => `### ${m.name}\n\`\`\`move\n${extractSignatures(m.source)}\n\`\`\``)
      .join("\n\n");
  }

  if (network === "mainnet") {
    // Mainnet: no Docker, run agents locally
    console.error(`Running ${ctx.hunterTargets.length} hunter(s) locally (concurrency: ${concurrency})...`);

    const workDir = resolve(target);
    await Promise.all(
      ctx.hunterTargets.map(async (mod) => {
        const release = await sem.acquire();
        try {
          const relatedSigs = buildRelatedSignatures(mod);
          const findings = await runMainnetHunter(client, mod, workDir, checkpointDir, model, maxTurns, packageId!, display, relatedSigs);
          if (findings.length > 0) {
            checkpoint(`hunter-${mod.name.replace(/::/g, "-")}.json`, findings);
            allFindings.push(...findings);
            checkpoint("all-findings.json", allFindings);
          }
        } finally {
          release();
        }
      })
    );
    ctx.rawFindings = allFindings;
    display.done();
  } else {
    // Devnet: Docker containers
    console.error("Building Docker image...");
    const projectRoot = resolve(import.meta.dirname, "../..");
    await buildImage(resolve(projectRoot, "Dockerfile"), projectRoot);

    console.error(`Spawning ${ctx.hunterTargets.length} hunter(s) in Docker (concurrency: ${concurrency})...`);
    const hunterResults = await Promise.all(
      ctx.hunterTargets.map(async (mod) => {
        const release = await sem.acquire();
        try {
          const relatedSigs = buildRelatedSignatures(mod);
          const result = await runDevnetHunter(client, tracker, mod, target, model, maxTurns, display, relatedSigs);
          if (result.findings.length > 0) {
            checkpoint(`hunter-${mod.name.replace(/::/g, "-")}.json`, result.findings);
            allFindings.push(...result.findings);
            checkpoint("all-findings.json", allFindings);
          }
          return result;
        } finally {
          release();
        }
      })
    );
    ctx.rawFindings = hunterResults.flatMap((r) => r.findings);
    display.done();
  }

  console.error(`Collected ${ctx.rawFindings.length} raw finding(s).`);

  // Step 6: Validate (always local — just reads source files and reasons)
  if (ctx.rawFindings.length > 0) {
    console.error(`Running ${ctx.rawFindings.length} validator agent(s) (concurrency: ${concurrency})...`);
    const validated = await runValidators({
      client,
      findings: ctx.rawFindings,
      exec: makeLocalExec(resolve(target)),
      model,
      concurrency,
      checkpointDir,
    });
    const confirmed = filterConfirmed(validated);
    ctx.findings = await deduplicateFindings(client, confirmed, model);
    checkpoint("validated-findings.json", ctx.findings);
    console.error(`Validator confirmed ${ctx.findings.length} finding(s) after dedup.`);
  } else {
    ctx.findings = [];
    console.error("No findings to validate.");
  }

  // Step 7: Cleanup (only relevant for devnet containers)
  if (!keepContainers) {
    await tracker.killAll();
  }

  return buildScanResult(ctx);
}

async function runMainnetHunter(
  client: Anthropic,
  mod: ModuleInfo,
  workDir: string,
  checkpointDir: string,
  model: string,
  maxTurns: number | undefined,
  packageId: string,
  display: StatusDisplay,
  relatedModuleSignatures: string
): Promise<Finding[]> {
  const rpcUrl = "https://fullnode.mainnet.sui.io:443";
  const hunterPrompt = buildMainnetHunterPrompt(mod, packageId, rpcUrl, relatedModuleSignatures);
  const systemPrompt = buildMainnetSystemPrompt(hunterPrompt, { rpcUrl, packageId });

  // Create isolated workspace per hunter so scripts don't pollute source dir
  const safeName = mod.name.replace(/::/g, "-");
  const workspace = resolve(checkpointDir, `workspace-${safeName}`);
  mkdirSync(workspace, { recursive: true });

  function safeSymlink(target: string, link: string) {
    try { lstatSync(link); return; } catch { /* doesn't exist */ }
    symlinkSync(target, link);
  }

  // Symlink entire target dir so agent can read .move files at any depth
  safeSymlink(resolve(workDir), resolve(workspace, "target"));

  // Symlink node_modules so agent can run npx tsx
  const projectRoot = resolve(import.meta.dirname, "../..");
  safeSymlink(resolve(projectRoot, "node_modules"), resolve(workspace, "node_modules"));

  const result = await runAgent(client, {
    exec: makeLocalExec(workspace),
    systemPrompt,
    model,
    maxTurns,
    moduleName: mod.name,
    logFile: resolve(workspace, "agent.log"),
    display,
  });

  // Copy vulns tracker to checkpoint dir if it exists
  try {
    const vulnsJson = readFileSync(resolve(workspace, "vulns.json"), "utf-8");
    writeFileSync(resolve(checkpointDir, `vulns-${safeName}.json`), vulnsJson);
  } catch { /* no vulns.json — agent may not have written it */ }

  try {
    const findingsJson = readFileSync(resolve(workspace, "findings.json"), "utf-8");
    return JSON.parse(findingsJson) as Finding[];
  } catch {
    return [];
  }
}

async function runDevnetHunter(
  client: Anthropic,
  tracker: ResourceTracker,
  mod: ModuleInfo,
  target: string,
  model: string,
  maxTurns: number | undefined,
  display: StatusDisplay,
  relatedModuleSignatures: string
): Promise<{ findings: Finding[] }> {
  console.error(`[${mod.name}] Starting container (devnet)...`);

  const containerId = await startContainer({
    targetContract: target,
    network: "devnet",
  });
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
    relatedModuleSignatures,
  });
  const systemPrompt = buildSystemPrompt(hunterPrompt, context);

  const result = await runAgent(client, {
    exec: makeDockerExec(containerId),
    systemPrompt,
    model,
    maxTurns,
    moduleName: mod.name,
    display,
  });

  const findingsJson = await readFindings(containerId);
  try {
    return { findings: JSON.parse(findingsJson) as Finding[] };
  } catch {
    return { findings: [] };
  }
}

function buildMainnetHunterPrompt(
  mod: ModuleInfo,
  packageId: string,
  rpcUrl: string,
  relatedModuleSignatures: string
): string {
  const invariantList = (mod.invariants ?? []).map((inv) => `- ${inv}`).join("\n");

  const relatedSection = relatedModuleSignatures
    ? `\n## Related Modules (signatures only — for understanding cross-module interactions)\n\n${relatedModuleSignatures}\n`
    : "";

  return `You are an expert smart contract security researcher. Your goal is to find EXPLOITABLE vulnerabilities in this live Sui Move contract — real bugs that an unprivileged attacker can trigger to steal funds, corrupt protocol state, or violate invariants.

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
${relatedSection}
## What counts as a real finding
A vulnerability where an unprivileged external user can cause damage. This includes:
- Fund theft or value extraction (direct drain, rounding exploits, oracle manipulation, share inflation)
- Permanent fund locking (putting pools/positions into irrecoverable states)
- State corruption (breaking accounting so future operations compute wrong values)
- Invariant violations (minting unbacked shares, creating undercollateralized positions)
- Liquidation manipulation (avoiding liquidation when underwater, forcing unfair liquidations)
- Privilege escalation (gaining admin/governance capabilities from an unprivileged starting point)
- Protocol DoS (making core functions permanently uncallable for all users)

The key test: can an UNPRIVILEGED USER trigger this without admin cooperation?

## What does NOT count — do not report these
- Admin misconfiguration risks ("admin could set a bad parameter")
- Governance centralization ("admin has too much power")
- Missing events, logging, or documentation
- Theoretical bugs requiring admin key compromise
- Gas optimizations or code style
- Design choices that are intentional trade-offs

## Severity calibration
- Critical: Direct value extraction, permanent fund locking, or protocol insolvency. Any user can trigger unconditionally.
- High: Significant economic damage, privilege escalation, or breaking core invariants. Any user can trigger.
- Medium: Economic damage or state corruption under specific but realistic conditions (timing, state alignment, multi-step setup).
- Low: Limited impact, requires unlikely conditions, or griefing with no economic benefit to attacker.

Focus on Critical and High. If you've only found admin misconfiguration issues, those do NOT belong in findings — log them as failed hypotheses in vulns.json and keep looking for real bugs.

## Methodology
1. READ the entire module. Understand every function, struct, capability, and type constraint.
2. MAP trust boundaries: who can call what? What capabilities gate access? Which objects are shared vs owned?
3. TRACE fund flows: where do coins move? Where do balances, shares, or debt change?
4. IDENTIFY invariants the code assumes but doesn't enforce — these are your targets.
5. LOOK for cross-module interactions: does this module trust inputs from other modules without validation?
6. QUERY mainnet state to understand the contract's current deployment (objects, pools, balances, TVL).
7. For each potential vulnerability:
   a. Can an unprivileged user trigger it?
   b. What's the concrete impact (quantify using real on-chain values)?
   c. Write an exploit transaction and dry-run it to prove it.
   d. If the exploit fails, analyze WHY and try a different approach. The best bugs require multiple iterations.
8. ITERATE aggressively. Don't give up after one failed exploit attempt. Try different parameter values, object IDs, call sequences.

## How to test exploits (dry-run only — nothing executes on-chain)

Use \`devInspectTransactionBlock\` to simulate transactions against real mainnet state. This lets you test any exploit scenario without risk.

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
const obj = await client.getObject({ id: "0x...", options: { showContent: true } });
const events = await client.queryEvents({ query: { MoveModule: { package: "${packageId}", module: "${mod.name}" } } });
\`\`\`

Save exploit scripts as .ts files and run with \`npx tsx <file>\`.

## Quality over quantity

Your output is evaluated on ACCURACY, not quantity. Every finding goes to a validator agent that will reject weak findings.

Before adding anything to findings.json, ask yourself:
- Does this exploit actually cause damage from an unprivileged user's position?
- Would a senior auditor consider this a real vulnerability, or a design observation / admin footgun?
- If you're unsure, it belongs in vulns.json as a hypothesis, NOT in findings.json.

An empty findings.json with a thorough vulns.json showing deep analysis is a GOOD outcome. Well-written code exists. Inflated findings waste everyone's time.

## Output files — update these as you go

### vulns.json — running vulnerability tracker (your primary output)
Write this file EARLY and update after each hypothesis you investigate. This is how we measure analysis quality — we want to see every attack vector you considered and why it did or didn't work.
\`\`\`json
[{
  "id": "unique-id",
  "title": "Short title",
  "status": "confirmed|failed|untested",
  "severity": "critical|high|medium|low",
  "reason": "One line: why it works, or why the exploit attempt failed"
}]
\`\`\`

### findings.json — ONLY genuinely exploitable vulnerabilities
This file should be EMPTY unless you have a working exploit that demonstrates real damage from an unprivileged user. Do NOT pad this with design observations or admin misconfiguration issues.
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
\`\`\`

IMPORTANT: Update vulns.json after EVERY hypothesis, even failed ones. A thorough vulns.json with 10 failed hypotheses is more valuable than a findings.json with 3 inflated non-issues.`;
}
