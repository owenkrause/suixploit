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
