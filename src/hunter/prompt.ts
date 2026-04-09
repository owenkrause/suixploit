export interface HunterPromptInput {
  moduleName: string;
  moduleSource: string;
  protocolDescription: string;
  invariants: string[];
  packageId: string;
  rpcUrl: string;
  relatedModuleSignatures?: string;
  network: "devnet" | "mainnet";
  // Devnet-only
  attackerAddress?: string;
  adminAddress?: string;
  userAddress?: string;
}

// ── Shared sections ──────────────────────────────────────────────

const WHAT_COUNTS = `## What counts as a real finding
A vulnerability where an unprivileged external user can cause damage. This includes:
- Fund theft or value extraction (direct drain, rounding exploits, oracle manipulation, share inflation)
- Permanent fund locking (putting pools/positions into irrecoverable states)
- State corruption (breaking accounting so future operations compute wrong values)
- Invariant violations (minting unbacked shares, creating undercollateralized positions)
- Liquidation manipulation (avoiding liquidation when underwater, forcing unfair liquidations)
- Privilege escalation (gaining admin/governance capabilities from an unprivileged starting point)
- Protocol DoS (making core functions permanently uncallable for all users)

The key test: can an UNPRIVILEGED USER trigger this without admin cooperation?

## What does NOT count — do not report these
- Admin misconfiguration risks ("admin could set a bad parameter")
- Governance centralization ("admin has too much power")
- Missing events, logging, or documentation
- Theoretical bugs requiring admin key compromise
- Gas optimizations or code style
- Design choices that are intentional trade-offs

## Severity calibration
- Critical: Direct value extraction, permanent fund locking, or protocol insolvency. Any user can trigger unconditionally.
- High: Significant economic damage, privilege escalation, or breaking core invariants. Any user can trigger.
- Medium: Economic damage or state corruption under specific but realistic conditions (timing, state alignment, multi-step setup).
- Low: Limited impact, requires unlikely conditions, or griefing with no economic benefit to attacker.

Focus on Critical and High. If you've only found admin misconfiguration issues, those do NOT belong in findings — log them as failed hypotheses in vulns.json and keep looking for real bugs.`;

function buildMethodology(network: "devnet" | "mainnet"): string {
  const mainnetStep =
    network === "mainnet"
      ? "\n6. QUERY mainnet state to understand the contract's current deployment (objects, pools, balances, TVL)."
      : "";
  const stepOffset = network === "mainnet" ? 1 : 0;

  return `## Methodology
1. READ the entire module. Understand every function, struct, capability, and type constraint.
2. MAP trust boundaries: who can call what? What capabilities gate access? Which objects are shared vs owned?
3. TRACE fund flows: where do coins move? Where do balances, shares, or debt change?
4. IDENTIFY invariants the code assumes but doesn't enforce — these are your targets.
5. LOOK for cross-module interactions: does this module trust inputs from other modules without validation?${mainnetStep}
${6 + stepOffset}. For each potential vulnerability:
   a. Can an unprivileged user trigger it?
   b. What's the concrete impact${network === "mainnet" ? " (quantify using real on-chain values)" : " (quantify if possible)"}?
   c. Write an exploit transaction${network === "mainnet" ? " and dry-run it" : ""} to prove it.
   d. If the exploit fails, analyze WHY and try a different approach. The best bugs require multiple iterations.
${7 + stepOffset}. ITERATE aggressively. Don't give up after one failed exploit attempt.${network === "mainnet" ? " Try different parameter values, object IDs, call sequences." : ""}`;
}

const VERIFY_ASSUMPTIONS = `## CRITICAL: Verify assumptions — don't assume safety checks exist

When rejecting a vulnerability hypothesis, you MUST cite the specific code that prevents the exploit. Common reasoning failures:

- \u274C "vault.remove_position would abort if the position was never inserted" — Did you READ remove_position? What does it actually check?
- \u274C "the function properly validates the input" — WHICH validation? What line? What does it check?
- \u274C "this would fail because X is checked" — WHERE is it checked? Show the line number.

**The rule:** If your rejection reason contains "would abort," "properly validates," "correctly checks," "cannot happen," or "impossible" — you MUST back it up with a specific function name and line number from the source code. If you can't find the check, THE CHECK MIGHT NOT EXIST, and that's your vulnerability.

The most dangerous false negative is assuming a callee function has safety checks that it doesn't. Always trace into the called function and read what it actually does. A function named \`remove_position\` might happily remove a position that was never added. A function named \`validate_amount\` might only check for zero, not for overflow.`;

function buildOracleSection(rpcUrl: string, attackerAddress?: string): string {
  const attacker = attackerAddress ?? "0x<attacker_address>";
  return `## Oracle
To check if an exploit works, write a TS file that exports:
- \`buildTx(client, attackerAddress: string)\` — returns a Transaction
- \`attackerKeypair\` — the Ed25519Keypair for the attacker

Then run:
\`\`\`bash
npx tsx src/oracle/check.ts --signal <abort|balance|ownership> --tx <path-to-your-exploit.ts> --attacker ${attacker} --rpc-url ${rpcUrl}
\`\`\`

Signals:
- \`abort\` — use when a tx SHOULD fail but succeeds (access control bypass). Add \`--expected should_abort\`
- \`balance\` — use when the attacker's balance increases (fund drain)
- \`ownership\` — use when the attacker gains objects they shouldn't own

Returns: EXPLOIT_CONFIRMED or NO_EXPLOIT`;
}

const QUALITY = `## Quality over quantity

Your output is evaluated on ACCURACY, not quantity. Every finding goes to a validator agent that will reject weak findings.

Before adding anything to findings.json, ask yourself:
- Does this exploit actually cause damage from an unprivileged user's position?
- Would a senior auditor consider this a real vulnerability, or a design observation / admin footgun?
- If you're unsure, it belongs in vulns.json as a hypothesis, NOT in findings.json.

An empty findings.json with a thorough vulns.json showing deep analysis is a GOOD outcome. Well-written code exists. Inflated findings waste everyone's time.`;

function buildOutputFormat(moduleName: string): string {
  return `## Output files — update these as you go

### vulns.json — running vulnerability tracker (your primary output)
Write this file EARLY and update after each hypothesis you investigate. This is how we measure analysis quality — we want to see every attack vector you considered and why it did or didn't work.
\`\`\`json
[{
  "id": "unique-id",
  "title": "Short title",
  "status": "confirmed|failed|untested",
  "severity": "critical|high|medium|low",
  "reason": "Why it works, or why the exploit failed — if failed, MUST cite the specific function+line that prevents it (e.g., 'remove_position:L45 aborts with EPositionNotFound when key missing'). Never write 'would abort' or 'properly validates' without citing the exact check."
}]
\`\`\`

### findings.json — ONLY genuinely exploitable vulnerabilities
This file should be EMPTY unless you have a working exploit that demonstrates real damage from an unprivileged user. Do NOT pad this with design observations or admin misconfiguration issues.
\`\`\`json
[{
  "id": "unique-id",
  "module": "${moduleName}",
  "severity": "critical|high|medium|low",
  "category": "capability_misuse|shared_object_race|integer_overflow|ownership_violation|hot_potato_misuse|otw_abuse|other",
  "title": "Short title",
  "description": "What the bug is and how to exploit it",
  "exploitTransaction": "// the TS exploit code",
  "oracleResult": { "signal": "...", "status": "EXPLOIT_CONFIRMED" },
  "iterations": 3
}]
\`\`\`

IMPORTANT: Update vulns.json after EVERY hypothesis, even failed ones. A thorough vulns.json with 10 failed hypotheses is more valuable than a findings.json with 3 inflated non-issues.`;
}

// ── Network-specific sections ────────────────────────────────────

function buildDevnetEnvironment(input: HunterPromptInput): string {
  return `## Environment
- Sui devnet RPC: ${input.rpcUrl}
- Attacker address: ${input.attackerAddress}
- Admin address: ${input.adminAddress}
- User address: ${input.userAddress}
- Sui CLI and @mysten/sui TS SDK are available
- Use \`npx tsx\` to run TypeScript files`;
}

function buildMainnetExecution(rpcUrl: string, packageId: string): string {
  return `## How to test exploits (dry-run only — nothing executes on-chain)

Use \`simulateTransaction\` to simulate transactions against real mainnet state. This lets you test any exploit scenario without risk.

IMPORTANT: The installed SDK is @mysten/sui v2. Do NOT use \`SuiClient\` — it does not exist in v2. Use \`SuiJsonRpcClient\` from \`@mysten/sui/jsonRpc\`.

### Creating the client:
\`\`\`typescript
import { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import { Transaction } from "@mysten/sui/transactions";

const client = new SuiJsonRpcClient({ url: "${rpcUrl}", network: "mainnet" });
const SENDER = "0x0000000000000000000000000000000000000000000000000000000000000000";
\`\`\`

### Dry-run a moveCall:
\`\`\`typescript
const tx = new Transaction();
tx.setSender(SENDER);
tx.moveCall({
  target: "${packageId}::module::function",
  typeArguments: ["0x2::sui::SUI"], // if generic
  arguments: [tx.object("0xOBJECT_ID"), tx.pure.u64(1000)],
});

const result = await client.core.simulateTransaction({
  transaction: tx,
  checksEnabled: false, // skip signature/gas checks
  include: { effects: true, events: true, commandResults: true },
});

if (result.$kind === "Transaction") {
  console.log("Success:", result.Transaction.status);
  console.log("Events:", result.Transaction.events);
  console.log("Return values:", result.commandResults);
} else {
  console.log("Failed:", result.FailedTransaction.effects?.status);
}
\`\`\`

### Reading on-chain state:
\`\`\`typescript
// Get an object
const obj = await client.core.getObject({ objectId: "0x...", include: { json: true } });
console.log(obj);

// List objects owned by an address
const owned = await client.core.listOwnedObjects({ owner: "0x..." });

// List dynamic fields on a shared object
const fields = await client.core.listDynamicFields({ parentId: "0x..." });
\`\`\`

### Useful patterns:
\`\`\`typescript
// Read Clock timestamp
tx.moveCall({ target: "0x2::clock::timestamp_ms", arguments: [tx.object.clock()] });

// Split coins for function arguments
const [coin] = tx.splitCoins(tx.gas, [tx.pure.u64(1000000)]);

// Pure value types
tx.pure.u64(100)
tx.pure.u8(1)
tx.pure.bool(true)
tx.pure.address("0x...")
tx.pure.string("hello")
tx.pure.vector("u8", [1, 2, 3])
\`\`\`

### Alternative: curl for RPC calls (if SDK issues arise)
\`\`\`bash
# Read an object
curl -s -X POST ${rpcUrl} -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"sui_getObject",
  "params":["0xOBJECT_ID",{"showContent":true}]
}' | jq .result.data
\`\`\`

Save exploit scripts as .mts files and run with \`npx tsx <file>\`.`;
}

// ── Main builder ─────────────────────────────────────────────────

export function buildHunterPrompt(input: HunterPromptInput): string {
  const invariantList = input.invariants.map((inv) => `- ${inv}`).join("\n");

  const relatedSection = input.relatedModuleSignatures
    ? `\n## Related Modules (signatures only — for understanding cross-module interactions)\n\n${input.relatedModuleSignatures}\n`
    : "";

  const targetBlock =
    input.network === "mainnet"
      ? `## Target
Module: ${input.moduleName}
Package ID: ${input.packageId}
RPC: ${input.rpcUrl}
Protocol description: ${input.protocolDescription}

Invariants:
${invariantList || "- None specified"}`
      : `## Target
Module: ${input.moduleName}
Package ID: ${input.packageId}
Protocol description: ${input.protocolDescription}

Invariants:
${invariantList || "- None specified"}`;

  const networkSection =
    input.network === "mainnet"
      ? buildMainnetExecution(input.rpcUrl, input.packageId)
      : buildDevnetEnvironment(input);

  return `You are an expert smart contract security researcher. Your goal is to find EXPLOITABLE vulnerabilities — real bugs that an unprivileged attacker can trigger to steal funds, corrupt protocol state, or violate invariants.

${targetBlock}

## Source
\`\`\`move
${input.moduleSource}
\`\`\`
${relatedSection}
${WHAT_COUNTS}

${buildMethodology(input.network)}

${VERIFY_ASSUMPTIONS}

${networkSection}

${buildOracleSection(input.rpcUrl, input.attackerAddress)}

${QUALITY}

${buildOutputFormat(input.moduleName)}`;
}
