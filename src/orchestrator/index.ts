import Anthropic from "@anthropic-ai/sdk";
import { resolve } from "node:path";
import { mkdirSync, writeFileSync, readFileSync, symlinkSync, lstatSync, renameSync } from "node:fs";
import type { ModuleInfo, Finding, ValidatedFinding, ScanResult, ScanMeta } from "../types.js";
import { buildScanPaths, generateRunId, hunterWorkspace, hunterScratch, type ScanPaths } from "./paths.js";
import { resolveModules, buildPipelineContext, shouldSkipRanker, buildScanResult } from "../pipeline.js";
import { buildRankerPrompt, parseRankerResponse, filterHighPriority, extractSignatures } from "../ranker/index.js";
import { runValidators, filterConfirmed, deduplicateFindings } from "../validator/index.js";
import { buildHunterPrompt } from "../hunter/index.js";
import { buildImage, startContainer, waitForReady, readContextJson, readFindings, readContainerFile, copyFromContainer } from "./docker.js";
import { buildSystemPrompt, buildMainnetSystemPrompt, runAgent } from "./agent.js";
import { makeDockerExec, makeLocalExec } from "./exec.js";
import { Semaphore } from "./semaphore.js";
import { ResourceTracker } from "./tracker.js";
import { StatusDisplay, logStep, logResult, logDetail, logWarn } from "./display.js";

const DEFAULT_MAINNET_RPC = "https://fullnode.mainnet.sui.io:443";

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
  outputDir?: string;
  include?: string[];
}

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const { target, concurrency, model, maxTurns, keepContainers, network, packageId } = options;

  // Set up checkpoint directory structure: .suixploit/<timestamp>/ at project root
  const projectRoot = resolve(import.meta.dirname, "../..");
  const outputDir = options.outputDir ?? resolve(projectRoot, ".suixploit", generateRunId());
  const paths = buildScanPaths(outputDir);
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

  try {
    if (network === "mainnet") {
      if (!packageId) throw new Error("--package-id is required for mainnet scans");

      logStep(`Hunting ${ctx.hunterTargets.length} module(s) locally (concurrency: ${concurrency})`);

      const workDir = resolve(target);
      await Promise.all(
        ctx.hunterTargets.map(async (mod) => {
          const release = await sem.acquire();
          try {
            const relatedSigs = buildRelatedSignatures(mod);
            const findings = await runMainnetHunter(client, mod, workDir, paths, model, maxTurns, packageId, display, relatedSigs);
            if (findings.length > 0) {
              allFindings.push(...findings);
            }
          } finally {
            release();
          }
        })
      );
      ctx.rawFindings = allFindings;
    } else {
      // Devnet: Docker containers
      logStep("Building Docker image...");
      await buildImage(resolve(projectRoot, "Dockerfile"), projectRoot);

      logStep(`Hunting ${ctx.hunterTargets.length} module(s) in Docker (concurrency: ${concurrency})`);
      await Promise.all(
        ctx.hunterTargets.map(async (mod) => {
          const release = await sem.acquire();
          try {
            const relatedSigs = buildRelatedSignatures(mod);
            const findings = await runDevnetHunter(client, tracker, mod, target, paths, model, maxTurns, display, relatedSigs);
            if (findings.length > 0) {
              allFindings.push(...findings);
            }
          } finally {
            release();
          }
        })
      );
      ctx.rawFindings = allFindings;
    }
  } finally {
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

function safeSymlink(target: string, link: string) {
  try { lstatSync(link); return; } catch { /* doesn't exist */ }
  symlinkSync(target, link);
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
  const rpcUrl = DEFAULT_MAINNET_RPC;
  const hunterPrompt = buildHunterPrompt({
    moduleName: mod.name,
    moduleSource: mod.source,
    protocolDescription: mod.protocolDescription ?? "No description provided.",
    invariants: mod.invariants ?? [],
    packageId,
    rpcUrl,
    relatedModuleSignatures,
    network: "mainnet",
  });
  const systemPrompt = buildMainnetSystemPrompt(hunterPrompt, { rpcUrl, packageId });

  // Create isolated workspace with scratch dir for agent scripts
  const workspace = hunterWorkspace(paths, mod.name);
  const scratch = hunterScratch(paths, mod.name);
  mkdirSync(scratch, { recursive: true });

  // Symlinks go in scratch/ — agent's cwd
  safeSymlink(resolve(workDir), resolve(scratch, "target"));
  const projectRoot = resolve(import.meta.dirname, "../..");
  safeSymlink(resolve(projectRoot, "node_modules"), resolve(scratch, "node_modules"));

  await runAgent(client, {
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

  return readFindingsFromFile(resolve(workspace, "findings.json"), mod.name);
}

async function runDevnetHunter(
  client: Anthropic,
  tracker: ResourceTracker,
  mod: ModuleInfo,
  target: string,
  paths: ScanPaths,
  model: string,
  maxTurns: number | undefined,
  display: StatusDisplay,
  relatedModuleSignatures: string
): Promise<Finding[]> {
  logDetail(`[${mod.name}] starting container`);

  const containerId = await startContainer({
    targetContract: target,
    network: "devnet",
  });
  tracker.add(containerId);

  logDetail(`[${mod.name}] container ${containerId.slice(0, 12)} — waiting for ready`);
  await waitForReady(containerId);

  const context = await readContextJson(containerId);

  // Derive ports from context URLs instead of hardcoding
  const rpcPort = parsePort(context.rpcUrl, 9000);
  const faucetPort = parsePort(context.faucetUrl, 9123);

  const hunterPrompt = buildHunterPrompt({
    moduleName: mod.name,
    moduleSource: mod.source,
    protocolDescription: mod.protocolDescription ?? "No description provided.",
    invariants: mod.invariants ?? [],
    packageId: context.packageId,
    rpcUrl: context.rpcUrl,
    attackerAddress: context.attackerAddress,
    adminAddress: context.adminAddress,
    userAddress: context.userAddress,
    relatedModuleSignatures,
    network: "devnet",
  });
  const systemPrompt = buildSystemPrompt(hunterPrompt, context);

  // Create local workspace for parity with mainnet output structure
  const workspace = hunterWorkspace(paths, mod.name);
  const scratch = hunterScratch(paths, mod.name);
  mkdirSync(scratch, { recursive: true });

  await runAgent(client, {
    exec: makeDockerExec(containerId),
    systemPrompt,
    model,
    maxTurns,
    moduleName: mod.name,
    logFile: resolve(workspace, "agent.log"),
    display,
  });

  // Copy output files from container to local workspace
  const findingsJson = await readFindings(containerId);
  if (findingsJson && findingsJson !== "[]") {
    writeFileSync(resolve(workspace, "findings.json"), findingsJson);
  }
  const vulnsJson = await readContainerFile(containerId, "/workspace/vulns.json");
  if (vulnsJson) {
    writeFileSync(resolve(workspace, "vulns.json"), vulnsJson);
  }

  // Copy agent-created scripts from container into scratch/
  await copyFromContainer(containerId, "/workspace/.", scratch);

  try {
    const parsed = JSON.parse(findingsJson);
    if (!Array.isArray(parsed)) return [];
    return parsed as Finding[];
  } catch {
    return [];
  }
}

function readFindingsFromFile(filePath: string, moduleName: string): Finding[] {
  try {
    const raw = readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      logWarn(`[${moduleName}] findings.json is not an array, skipping`);
      return [];
    }
    return parsed as Finding[];
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "ENOENT") {
      logWarn(`[${moduleName}] failed to read findings.json: ${String(err)}`);
    }
    return [];
  }
}

function parsePort(url: string | undefined, fallback: number): number {
  if (!url) return fallback;
  try {
    const port = new URL(url).port;
    return port ? Number(port) : fallback;
  } catch {
    return fallback;
  }
}
