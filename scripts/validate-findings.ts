#!/usr/bin/env npx tsx
/**
 * Run just the validator step on previously recovered findings.
 * No Docker required — runs locally.
 *
 * Usage:
 *   npx tsx scripts/validate-findings.ts <findings.json> <target-dir> [options]
 *
 * Options:
 *   --model <model>          Model to use (default: claude-sonnet-4-6)
 *   --output <path>          Write results to file (default: stdout)
 *   --concurrency <n>        Max parallel validators (default: 5)
 */
import Anthropic from "@anthropic-ai/sdk";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { resolveModules } from "../src/pipeline.js";
import { runValidators, filterConfirmed, deduplicateFindings } from "../src/validator/index.js";
import { makeLocalExec } from "../src/orchestrator/exec.js";

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

if (!findingsPath || !targetDir) {
  console.error("Usage: npx tsx scripts/validate-findings.ts <findings.json> <target-dir> [--model <model>] [--output <path>] [--concurrency <n>]");
  process.exit(1);
}

const findings = JSON.parse(readFileSync(findingsPath, "utf-8"));
console.error(`Loaded ${findings.length} findings from ${findingsPath}`);

const modules = await resolveModules(resolve(targetDir));
console.error(`Resolved ${modules.length} modules from ${targetDir}`);

console.error(`Running ${findings.length} validator agent(s) locally (concurrency: ${concurrency}, model: ${model})...`);
const client = new Anthropic();

const validated = await runValidators({
  client,
  findings,
  exec: makeLocalExec(resolve(targetDir)),
  model,
  concurrency,
});

const confirmed = await deduplicateFindings(client, filterConfirmed(validated), model);
console.error(`Validator confirmed ${confirmed.length} / ${findings.length} findings after dedup`);

const json = JSON.stringify(confirmed, null, 2);
if (outputPath) {
  writeFileSync(outputPath, json);
  console.error(`Written to ${outputPath}`);
} else {
  console.log(json);
}
