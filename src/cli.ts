#!/usr/bin/env node
import { Command } from "commander";
import { writeFileSync } from "node:fs";
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
  .option("--concurrency <n>", "Max parallel agents", "5")
  .option("--model <model>", "Model for agents", "claude-sonnet-4-6")
  .option("--max-turns <n>", "Max turns per hunter agent (default: unlimited)")
  .option("--output <path>", "Write ScanResult JSON to file (default: stdout)")
  .option("--keep-containers", "Don't remove containers after run", false)
  .option("--network <network>", "Network mode: devnet or mainnet", "devnet")
  .option("--package-id <id>", "On-chain package ID (required for mainnet)")
  .option("--checkpoint-dir <path>", "Directory for checkpoint files (default: <target>/.suixploit)")
  .option("--protocol <description>", "Protocol description override")
  .option("--invariants <invariants...>", "Invariants to test against")
  .action(async (target: string, options) => {
    if (options.network === "mainnet" && !options.packageId) {
      console.error("Error: --package-id is required when --network is mainnet");
      process.exit(1);
    }

    const result = await runScan({
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
    });

    const json = JSON.stringify(result, null, 2);

    if (options.output) {
      writeFileSync(options.output, json);
      console.error(`Results written to ${options.output}`);
    } else {
      console.log(json);
    }
  });

program.parse();
