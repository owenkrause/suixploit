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
