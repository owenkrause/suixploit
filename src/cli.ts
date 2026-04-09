#!/usr/bin/env node
import { Command } from "commander";
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
  .option("--package-id <id>", "On-chain package ID (required for mainnet)")
  .option("--concurrency <n>", "Max parallel agents", "5")
  .option("--model <model>", "Model for agents", "claude-opus-4-6")
  .option("--max-turns <n>", "Max turns per hunter agent (default: unlimited)")
  .option("--keep-containers", "Don't remove containers after run", false)
  .option("--network <network>", "Network mode: devnet or mainnet", "mainnet")
  .option(
    "--checkpoint-dir <path>",
    "Override run output directory (default: .suixploit/<timestamp>)",
  )
  .option("--protocol <description>", "Protocol description override")
  .option("--invariants <invariants...>", "Invariants to test against")
  .option("--include <patterns...>", "Only hunt modules whose names contain these strings (all modules still available as cross-module context)")
  .action(async (target: string, options) => {
    if (options.network === "mainnet" && !options.packageId) {
      console.error("Error: --package-id is required for mainnet mode");
      process.exit(1);
    }

    await runScan({
      target,
      concurrency: parseInt(options.concurrency, 10),
      model: options.model,
      maxTurns: options.maxTurns ? parseInt(options.maxTurns, 10) : undefined,
      keepContainers: options.keepContainers,
      network: options.network as "devnet" | "mainnet",
      packageId: options.packageId,
      checkpointDir: options.checkpointDir,
      protocol: options.protocol,
      invariants: options.invariants,
      include: options.include,
    });
  });

program.parse();
