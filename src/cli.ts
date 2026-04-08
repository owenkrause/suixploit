#!/usr/bin/env node
import { Command } from "commander";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  resolveModules,
  buildPipelineContext,
  shouldSkipRanker,
  buildScanResult,
} from "./pipeline.js";
import { buildRankerPrompt } from "./ranker/index.js";
import { prepareHunterPrompt } from "./hunter/index.js";
import { buildValidatorPrompt } from "./validator/index.js";

const program = new Command();

program
  .name("suixploit")
  .description("Multi-agent Sui Move vulnerability discovery pipeline")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a Move project or deployed package for vulnerabilities")
  .argument("<target>", "Path to Move project or on-chain package address")
  .option("--network <network>", "Network for on-chain targets (mainnet, testnet)")
  .option("--protocol <description>", "Protocol description for closed-source targets")
  .option("--invariants <invariants...>", "Invariants to test against")
  .option("--config <path>", "Path to config file with protocol and invariants")
  .action(async (target: string, options) => {
    // Load config file if provided
    let protocol = options.protocol;
    let invariants = options.invariants;
    if (options.config) {
      const config = JSON.parse(readFileSync(resolve(options.config), "utf-8"));
      protocol = protocol ?? config.protocol;
      invariants = invariants ?? config.invariants;
    }

    // Resolve modules
    const modules = await resolveModules(resolve(target));
    if (modules.length === 0) {
      console.error("No Move modules found in target path.");
      process.exit(1);
    }

    // Apply config overrides to modules
    if (protocol || invariants) {
      for (const mod of modules) {
        if (protocol) mod.protocolDescription = protocol;
        if (invariants) mod.invariants = invariants;
      }
    }

    const ctx = buildPipelineContext(target, modules);

    // Output pipeline context for Claude Code orchestration
    console.log("=== SUIXPLOIT PIPELINE ===");
    console.log(`Target: ${target}`);
    console.log(`Modules found: ${modules.length}`);
    console.log();

    if (shouldSkipRanker(modules)) {
      console.log("Skipping ranker (<=3 modules). Hunting all modules.");
      ctx.hunterTargets = modules;
    } else {
      console.log("=== RANKER PROMPT ===");
      console.log(buildRankerPrompt(modules));
      console.log("=== END RANKER PROMPT ===");
      console.log();
      console.log("Feed the ranker prompt to Claude, then set hunterTargets to modules scoring 4-5.");
    }

    console.log();
    console.log("=== HUNTER PROMPTS ===");
    for (const mod of ctx.hunterTargets.length > 0 ? ctx.hunterTargets : modules) {
      console.log(`\n--- Hunter for: ${mod.name} ---`);
      console.log("Prompt preview (first 200 chars):");
      const prompt = prepareHunterPrompt({
        module: mod,
        devnetConfig: {
          rpcUrl: "http://127.0.0.1:9100",
          faucetUrl: "http://127.0.0.1:9123",
          port: 9100,
          faucetPort: 9123,
          adminAddress: "<to be generated>",
          attackerAddress: "<to be generated>",
          userAddress: "<to be generated>",
          adminKeyPair: "",
          attackerKeyPair: "",
          userKeyPair: "",
        },
        packageId: "<to be set after deploy>",
      });
      console.log(prompt.slice(0, 200) + "...");
    }

    console.log("\n=== PIPELINE READY ===");
    console.log("Use Claude Code with CLAUDE.md to orchestrate the full pipeline.");
  });

program.parse();
