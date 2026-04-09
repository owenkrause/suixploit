import { parseArgs } from "node:util";
import { resolve } from "node:path";
import { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { checkAbort } from "./abort.js";
import { checkBalance, type BalanceChange } from "./balance.js";
import { checkOwnership } from "./ownership.js";
import type { OracleResult, OracleSignal } from "../types.js";

const VALID_SIGNALS: OracleSignal[] = ["abort", "balance", "ownership", "custom"];

const { values } = parseArgs({
  options: {
    signal: { type: "string", short: "s" },
    tx: { type: "string", short: "t" },
    attacker: { type: "string", short: "a" },
    "rpc-url": { type: "string", default: "http://127.0.0.1:9000" },
    network: { type: "string", short: "n" },
    expected: { type: "string" },
  },
});

if (!values.signal || !values.tx || !values.attacker) {
  console.error("Usage: npx tsx src/oracle/check.ts --signal <abort|balance|ownership> --tx <path> --attacker <address>");
  console.error("  --signal    Oracle signal to check (abort, balance, ownership)");
  console.error("  --tx        Path to TS file that exports a buildTx(client, attacker) function");
  console.error("  --attacker  Attacker address");
  console.error("  --rpc-url   Sui RPC URL (default: http://127.0.0.1:9000)");
  console.error("  --network   Network hint: localnet, devnet, mainnet (auto-detected from rpc-url if omitted)");
  console.error("  --expected  Expected behavior for abort signal (should_abort)");
  process.exit(1);
}

if (!VALID_SIGNALS.includes(values.signal as OracleSignal)) {
  console.error(`Unknown signal: ${values.signal}. Use one of: ${VALID_SIGNALS.join(", ")}`);
  process.exit(1);
}

// Detect network from RPC URL if not explicitly provided
function detectNetwork(rpcUrl: string): "localnet" | "devnet" | "testnet" | "mainnet" {
  if (rpcUrl.includes("mainnet")) return "mainnet";
  if (rpcUrl.includes("testnet")) return "testnet";
  if (rpcUrl.includes("devnet")) return "devnet";
  return "localnet";
}

const rpcUrl = values["rpc-url"]!;
const network = (values.network as "localnet" | "devnet" | "testnet" | "mainnet") ?? detectNetwork(rpcUrl);

const client = new SuiJsonRpcClient({
  url: rpcUrl,
  network,
});

// Dynamically import the exploit transaction module
const txModulePath = resolve(process.cwd(), values.tx!);
const txModule = await import(txModulePath);

if (typeof txModule.buildTx !== "function") {
  console.error(`Error: ${values.tx} must export a buildTx(client, attackerAddress: string) function`);
  process.exit(1);
}

const txBlock = await txModule.buildTx(client, values.attacker!);

// Simulate the transaction via dry run
const attackerKeypair = txModule.attackerKeypair as Ed25519Keypair | undefined;
if (!attackerKeypair) {
  console.error(`Error: ${values.tx} must export an attackerKeypair (Ed25519Keypair)`);
  process.exit(1);
}

const dryRunResult = await client.dryRunTransactionBlock({
  transactionBlock: await txBlock.build({ client }),
});

let result!: OracleResult;

const VALID_OBJECT_CHANGE_TYPES = new Set(["created", "mutated", "deleted", "wrapped", "published"]);

switch (values.signal) {
  case "abort":
    result = checkAbort(
      { effects: { status: { status: dryRunResult.effects.status.status as "success" | "failure" } } },
      (values.expected as "should_abort") ?? "should_abort"
    );
    break;

  case "balance":
    result = checkBalance(values.attacker!, dryRunResult.balanceChanges as BalanceChange[]);
    break;

  case "ownership":
    result = checkOwnership(
      values.attacker!,
      (dryRunResult.objectChanges ?? [])
        .filter((c: Record<string, unknown>) => typeof c.type === "string" && VALID_OBJECT_CHANGE_TYPES.has(c.type))
        .map((c: Record<string, unknown>) => ({
          type: c.type as "created" | "mutated" | "deleted" | "wrapped" | "published",
          objectId: String(c.objectId ?? ""),
          owner: c.owner as Record<string, unknown> | undefined,
          sender: String(c.sender ?? values.attacker!),
        }))
    );
    break;

  default:
    console.error(`Unknown signal: ${values.signal}. Use one of: ${VALID_SIGNALS.join(", ")}`);
    process.exit(1);
}

// Output the result
console.log(result.status);
if (result.status === "EXPLOIT_CONFIRMED") {
  console.log(JSON.stringify(result, null, 2));
}

process.exit(result.status === "EXPLOIT_CONFIRMED" ? 0 : 1);
