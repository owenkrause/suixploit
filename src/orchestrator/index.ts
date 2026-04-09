import Anthropic from "@anthropic-ai/sdk";
import { resolve } from "node:path";
import { mkdirSync, writeFileSync, readFileSync, symlinkSync, lstatSync, renameSync } from "node:fs";
import type { ModuleInfo, Finding, ValidatedFinding, ScanResult, ScanMeta } from "../types.js";
import { buildScanPaths, generateRunId, hunterWorkspace, hunterScratch, type ScanPaths } from "./paths.js";
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
import { StatusDisplay, logStep, logResult, logDetail, logWarn } from "./display.js";

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
  include?: string[];
}

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const { target, concurrency, model, maxTurns, keepContainers, network, packageId } = options;

  // Set up checkpoint directory structure: .suixploit/<timestamp>/ at project root
  const projectRoot = resolve(import.meta.dirname, "../..");
  const checkpointDir = options.checkpointDir ?? resolve(projectRoot, ".suixploit", generateRunId());
  const paths = buildScanPaths(checkpointDir);
  for (const dir of [paths.root, paths.findingsDir, paths.huntersDir, paths.validatorsDir]) {
    mkdirSync(dir, { recursive: true });
  }

  // Write initial scan metadata
  const scanMeta: ScanMeta = {
    version: 1,
    target,
    model,
    network,
    concurrency,
    maxTurns: maxTurns ?? null,
    packageId: packageId ?? null,
    startedAt: new Date().toISOString(),
    completedAt: null,
    modulesResolved: 0,
    modulesHunted: 0,
    findingsRaw: 0,
    findingsValidated: 0,
  };
  writeFileSync(paths.scanMeta, JSON.stringify(scanMeta, null, 2));

  const tracker = new ResourceTracker();
  tracker.registerCleanupHandlers(keepContainers);

  const client = new Anthropic();

  // Step 1: Resolve modules
  logStep(`Resolving modules from ${target}`);
  const modules = await resolveModules(resolve(target));
  if (modules.length === 0) {
    throw new Error("No Move modules found in target path.");
  }
  logDetail(`found ${modules.length} module(s)`);
  scanMeta.modulesResolved = modules.length;
  writeFileSync(paths.scanMeta, JSON.stringify(scanMeta, null, 2));

  // Filter modules if --include is specified (keep full list for cross-module context)
  let candidates = modules;
  if (options.include && options.include.length > 0) {
    candidates = modules.filter((m) =>
      options.include!.some((pattern) => m.name.includes(pattern))
    );
    logDetail(`filtered to ${candidates.length} candidate(s) matching: ${options.include.join(", ")}`);
    if (candidates.length === 0) {
      throw new Error(`No modules match --include patterns: ${options.include.join(", ")}`);
    }
  }

  // Apply overrides
  if (options.protocol || options.invariants) {
    for (const mod of candidates) {
      if (options.protocol) mod.protocolDescription = options.protocol;
      if (options.invariants) mod.invariants = options.invariants;
    }
  }

  const ctx = buildPipelineContext(target, modules);

  // Step 2: Rank (if needed)
  if (shouldSkipRanker(candidates)) {
    logStep(`Skipping ranker (${candidates.length} modules ≤ 3), hunting all`);
    ctx.hunterTargets = candidates;
  } else {
    logStep("Running ranker...");
    const rankerPrompt = buildRankerPrompt(candidates);
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

    const highPri = filterHighPriority(ctx.rankerScores);
    ctx.hunterTargets = highPri.length > 0
      ? candidates.filter((m) => highPri.some((s) => s.module === m.name))
      : candidates;

    // Compact ranker summary
    const selected = [...ctx.rankerScores]
      .filter((s) => s.score >= 3)
      .sort((a, b) => b.score - a.score);
    const skipped = ctx.rankerScores.length - selected.length;
    for (const s of selected) {
      logDetail(`[${s.score}/5] ${s.module}`);
    }
    if (skipped > 0) logDetail(`${skipped} module(s) scored < 3, skipped`);
    logResult(`Ranker: ${ctx.hunterTargets.length} selected, ${skipped} skipped`);
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
    logStep(`Hunting ${ctx.hunterTargets.length} module(s) locally (concurrency: ${concurrency})`);

    const workDir = resolve(target);
    await Promise.all(
      ctx.hunterTargets.map(async (mod) => {
        const release = await sem.acquire();
        try {
          const relatedSigs = buildRelatedSignatures(mod);
          const findings = await runMainnetHunter(client, mod, workDir, paths, model, maxTurns, packageId!, display, relatedSigs);
          if (findings.length > 0) {
            allFindings.push(...findings);
            writeFileSync(paths.allRawFindings, JSON.stringify(allFindings, null, 2));
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
    logStep("Building Docker image...");
    await buildImage(resolve(projectRoot, "Dockerfile"), projectRoot);

    logStep(`Hunting ${ctx.hunterTargets.length} module(s) in Docker (concurrency: ${concurrency})`);
    const hunterResults = await Promise.all(
      ctx.hunterTargets.map(async (mod) => {
        const release = await sem.acquire();
        try {
          const relatedSigs = buildRelatedSignatures(mod);
          const result = await runDevnetHunter(client, tracker, mod, target, model, maxTurns, display, relatedSigs);
          if (result.findings.length > 0) {
            allFindings.push(...result.findings);
            writeFileSync(paths.allRawFindings, JSON.stringify(allFindings, null, 2));
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

  // Assign global sequential IDs (vuln-001, vuln-002, ...)
  for (let i = 0; i < allFindings.length; i++) {
    allFindings[i].id = `vuln-${String(i + 1).padStart(3, "0")}`;
  }
  if (allFindings.length > 0) {
    writeFileSync(paths.allRawFindings, JSON.stringify(allFindings, null, 2));
  }

  logResult(`Collected ${ctx.rawFindings.length} raw finding(s)`);

  // Step 6: Validate (always local — just reads source files and reasons)
  if (ctx.rawFindings.length > 0) {
    logStep(`Validating ${ctx.rawFindings.length} finding(s) (concurrency: ${concurrency})`);
    const validated = await runValidators({
      client,
      findings: ctx.rawFindings,
      model,
      concurrency,
      scanPaths: paths,
      targetDir: resolve(target),
    });
    const confirmed = filterConfirmed(validated);
    ctx.findings = await deduplicateFindings(client, confirmed, model);
    writeFileSync(paths.validatedFindings, JSON.stringify(ctx.findings, null, 2));
    logResult(`${ctx.findings.length} finding(s) confirmed after validation + dedup`);
  } else {
    ctx.findings = [];
    logDetail("no findings to validate");
  }

  // Step 7: Cleanup (only relevant for devnet containers)
  if (!keepContainers) {
    await tracker.killAll();
  }

  // Update scan metadata with final results
  scanMeta.completedAt = new Date().toISOString();
  scanMeta.modulesHunted = ctx.hunterTargets.length;
  scanMeta.findingsRaw = ctx.rawFindings.length;
  scanMeta.findingsValidated = ctx.findings.length;
  writeFileSync(paths.scanMeta, JSON.stringify(scanMeta, null, 2));

  // Write full result to run directory
  const result = buildScanResult(ctx);
  writeFileSync(resolve(paths.root, "result.json"), JSON.stringify(result, null, 2));

  logStep(`Scan complete — ${ctx.findings.length} finding(s)`);
  logDetail(`results: ${paths.root}`);

  return result;
}

async function runMainnetHunter(
  client: Anthropic,
  mod: ModuleInfo,
  workDir: string,
  paths: ScanPaths,
  model: string,
  maxTurns: number | undefined,
  packageId: string,
  display: StatusDisplay,
  relatedModuleSignatures: string
): Promise<Finding[]> {
  const rpcUrl = "https://fullnode.mainnet.sui.io:443";
  const hunterPrompt = buildMainnetHunterPrompt(mod, packageId, rpcUrl, relatedModuleSignatures);
  const systemPrompt = buildMainnetSystemPrompt(hunterPrompt, { rpcUrl, packageId });

  // Create isolated workspace with scratch dir for agent scripts
  const workspace = hunterWorkspace(paths, mod.name);
  const scratch = hunterScratch(paths, mod.name);
  mkdirSync(scratch, { recursive: true });

  function safeSymlink(target: string, link: string) {
    try { lstatSync(link); return; } catch { /* doesn't exist */ }
    symlinkSync(target, link);
  }

  // Symlinks go in scratch/ — agent's cwd
  safeSymlink(resolve(workDir), resolve(scratch, "target"));
  const projectRoot = resolve(import.meta.dirname, "../..");
  safeSymlink(resolve(projectRoot, "node_modules"), resolve(scratch, "node_modules"));

  const result = await runAgent(client, {
    exec: makeLocalExec(scratch),
    systemPrompt,
    model,
    maxTurns,
    moduleName: mod.name,
    logFile: resolve(workspace, "agent.log"),
    display,
  });

  // Lift output files from scratch/ to workspace root
  for (const file of ["findings.json", "vulns.json"]) {
    try {
      renameSync(resolve(scratch, file), resolve(workspace, file));
    } catch { /* agent may not have written it */ }
  }

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
  logDetail(`[${mod.name}] starting container`);

  const containerId = await startContainer({
    targetContract: target,
    network: "devnet",
  });
  tracker.add(containerId);

  logDetail(`[${mod.name}] container ${containerId.slice(0, 12)} — waiting for ready`);
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

Use \`simulateTransaction\` to simulate transactions against real mainnet state. This lets you test any exploit scenario without risk.

IMPORTANT: The installed SDK is @mysten/sui v2. Do NOT use \`SuiClient\` — it does not exist in v2. Use \`SuiJsonRpcClient\` from \`@mysten/sui/jsonRpc\`.

### Creating the client:
\`\`\`typescript
import { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import { Transaction } from "@mysten/sui/transactions";

const client = new SuiJsonRpcClient({ url: "${rpcUrl}", network: "mainnet" });
const SENDER = "0x0000000000000000000000000000000000000000000000000000000000000000";
\`\`\`

### Dry-run a moveCall:
\`\`\`typescript
const tx = new Transaction();
tx.setSender(SENDER);
tx.moveCall({
  target: "${packageId}::module::function",
  typeArguments: ["0x2::sui::SUI"], // if generic
  arguments: [tx.object("0xOBJECT_ID"), tx.pure.u64(1000)],
});

const result = await client.core.simulateTransaction({
  transaction: tx,
  checksEnabled: false, // skip signature/gas checks
  include: { effects: true, events: true, commandResults: true },
});

if (result.$kind === "Transaction") {
  console.log("Success:", result.Transaction.status);
  console.log("Events:", result.Transaction.events);
  console.log("Return values:", result.commandResults);
} else {
  console.log("Failed:", result.FailedTransaction.effects?.status);
}
\`\`\`

### Reading on-chain state:
\`\`\`typescript
// Get an object
const obj = await client.core.getObject({ objectId: "0x...", include: { json: true } });
console.log(obj);

// List objects owned by an address
const owned = await client.core.listOwnedObjects({ owner: "0x..." });

// List dynamic fields on a shared object
const fields = await client.core.listDynamicFields({ parentId: "0x..." });
\`\`\`

### Useful patterns:
\`\`\`typescript
// Read Clock timestamp
tx.moveCall({ target: "0x2::clock::timestamp_ms", arguments: [tx.object.clock()] });

// Split coins for function arguments
const [coin] = tx.splitCoins(tx.gas, [tx.pure.u64(1000000)]);

// Pure value types
tx.pure.u64(100)
tx.pure.u8(1)
tx.pure.bool(true)
tx.pure.address("0x...")
tx.pure.string("hello")
tx.pure.vector("u8", [1, 2, 3])
\`\`\`

### Alternative: curl for RPC calls (if SDK issues arise)
\`\`\`bash
# Read an object
curl -s -X POST ${rpcUrl} -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"sui_getObject",
  "params":["0xOBJECT_ID",{"showContent":true}]
}' | jq .result.data
\`\`\`

Save exploit scripts as .mts files and run with \`npx tsx <file>\`.

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
