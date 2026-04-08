import { parseArgs } from "node:util";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { getFullnodeUrl, SuiClient } from "@mysten/sui/client";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { checkAbort } from "./abort.js";
import { checkBalance } from "./balance.js";
import { checkOwnership } from "./ownership.js";
import type { OracleResult } from "../types.js";

const { values } = parseArgs({
  options: {
    signal: { type: "string", short: "s" },
    tx: { type: "string", short: "t" },
    attacker: { type: "string", short: "a" },
    "rpc-url": { type: "string", default: "http://127.0.0.1:9000" },
    expected: { type: "string" },
  },
});

if (!values.signal || !values.tx || !values.attacker) {
  console.error("Usage: npx tsx src/oracle/check.ts --signal <abort|balance|ownership> --tx <path> --attacker <address>");
  console.error("  --signal    Oracle signal to check (abort, balance, ownership)");
  console.error("  --tx        Path to TS file that exports a buildTx(client, attacker) function");
  console.error("  --attacker  Attacker address");
  console.error("  --rpc-url   Sui RPC URL (default: http://127.0.0.1:9000)");
  console.error("  --expected  Expected behavior for abort signal (should_abort)");
  process.exit(1);
}

const client = new SuiClient({ url: values["rpc-url"]! });

// Dynamically import the exploit transaction module
const txModulePath = resolve(process.cwd(), values.tx!);
const txModule = await import(txModulePath);

if (typeof txModule.buildTx !== "function") {
  console.error(`Error: ${values.tx} must export a buildTx(client: SuiClient, attackerAddress: string) function`);
  process.exit(1);
}

const txBlock = await txModule.buildTx(client, values.attacker!);

// Dry run the transaction
const attackerKeypair = txModule.attackerKeypair as Ed25519Keypair | undefined;
if (!attackerKeypair) {
  console.error(`Error: ${values.tx} must export an attackerKeypair (Ed25519Keypair)`);
  process.exit(1);
}

const dryRunResult = await client.dryRunTransactionBlock({
  transactionBlock: await txBlock.build({ client }),
});

let result: OracleResult;

switch (values.signal) {
  case "abort":
    result = checkAbort(
      { effects: { status: { status: dryRunResult.effects.status.status as "success" | "failure" } } },
      (values.expected as "should_abort") ?? "should_abort"
    );
    break;

  case "balance":
    result = checkBalance(values.attacker!, dryRunResult.balanceChanges);
    break;

  case "ownership":
    result = checkOwnership(
      values.attacker!,
      dryRunResult.objectChanges.map((c) => ({
        ...c,
        type: c.type as "created" | "mutated" | "deleted" | "wrapped" | "published",
        objectId: "objectId" in c ? (c as Record<string, string>).objectId : "",
        owner: "owner" in c ? (c as Record<string, unknown>).owner as Record<string, unknown> : undefined,
        sender: ("sender" in c ? (c as Record<string, string>).sender : values.attacker!) as string,
      }))
    );
    break;

  default:
    console.error(`Unknown signal: ${values.signal}. Use abort, balance, or ownership.`);
    process.exit(1);
}

// Output the result
console.log(result.status);
if (result.status === "EXPLOIT_CONFIRMED") {
  console.log(JSON.stringify(result, null, 2));
}

process.exit(result.status === "EXPLOIT_CONFIRMED" ? 0 : 1);
