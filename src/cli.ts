#!/usr/bin/env node
import { existsSync } from "node:fs";
import { Command } from "commander";
import { runScan } from "./orchestrator/index.js";

function parsePositiveInt(value: string, name: string): number {
  const n = parseInt(value, 10);
  if (Number.isNaN(n) || n <= 0) {
    throw new Error(`${name} must be a positive integer, got "${value}"`);
  }
  return n;
}

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
    // Validate target exists
    if (!existsSync(target)) {
      console.error(`Error: target path does not exist: ${target}`);
      process.exit(1);
    }

    // Validate network
    if (!["devnet", "mainnet"].includes(options.network)) {
      console.error(`Error: --network must be "devnet" or "mainnet", got "${options.network}"`);
      process.exit(1);
    }

    // Validate package-id for mainnet
    if (options.network === "mainnet" && !options.packageId) {
      console.error("Error: --package-id is required for mainnet mode");
      process.exit(1);
    }
    if (options.packageId && !options.packageId.startsWith("0x")) {
      console.error(`Error: --package-id must be a hex address starting with 0x, got "${options.packageId}"`);
      process.exit(1);
    }

    // Validate numeric options
    const concurrency = parsePositiveInt(options.concurrency, "--concurrency");
    const maxTurns = options.maxTurns ? parsePositiveInt(options.maxTurns, "--max-turns") : undefined;

    await runScan({
      target,
      concurrency,
      model: options.model,
      maxTurns,
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
