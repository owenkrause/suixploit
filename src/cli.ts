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
  .option("--max-turns <n>", "Max turns per hunter agent", "50")
  .option("--output <path>", "Write ScanResult JSON to file (default: stdout)")
  .option("--keep-containers", "Don't remove containers after run", false)
  .option("--protocol <description>", "Protocol description override")
  .option("--invariants <invariants...>", "Invariants to test against")
  .action(async (target: string, options) => {
    const result = await runScan({
      target,
      concurrency: parseInt(options.concurrency, 10),
      model: options.model,
      maxTurns: parseInt(options.maxTurns, 10),
      keepContainers: options.keepContainers,
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
