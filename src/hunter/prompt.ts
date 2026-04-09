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

// ── Sui platform context ────────────────────────────────────────

const SUI_CONTEXT = `## Sui platform — security-relevant properties

### Object ownership
- Address-owned: only the owner can use in transactions. Processed via fast path (no consensus, <500ms finality).
- Shared: anyone can reference in transactions. Must go through consensus for ordering. All access control must be implemented in Move code.
- Immutable: cannot be mutated or deleted. No contention.

### Programmable Transaction Blocks (PTBs)
Up to 1,024 commands execute sequentially in ONE atomic transaction. If any command fails, all effects revert. Results from earlier commands can be passed as inputs to later ones. This means users can batch complex multi-step operations (e.g. withdraw + repay + claim) atomically.

### Transaction ordering
- Sui has no public mempool. Transactions are sent directly to validators.
- Shared-object transactions are ordered by Mysticeti consensus (DAG-based). Validators collectively determine ordering — there is no single block proposer who controls tx order.
- Owned-object transactions bypass consensus entirely.

### Move safety
- Integer overflow/underflow aborts by default (no wrapping arithmetic).
- Resources without \`drop\` must be consumed.
- \`public(friend)\` restricts callers to declared friend modules.`;

// ── Shared sections ──────────────────────────────────────────────

const WHAT_COUNTS = `## What counts as a finding

A vulnerability where an unprivileged user causes economic damage. For every finding you MUST answer:
1. What does the attacker gain, or what damage is caused?
2. What does the attack cost? (it must be net-profitable OR cause damage far exceeding its cost)
3. Why can't the victim mitigate it? (consider that victims can batch operations atomically in a single PTB)
4. Is the damage persistent or a temporary inconvenience?

Do NOT report:
- Admin misconfiguration ("admin could set a bad parameter")
- Governance centralization or missing events
- Theoretical bugs requiring admin key compromise
- Griefing where attacker pays more than the damage caused`;

function buildSdkReference(
  network: "devnet" | "mainnet",
  rpcUrl: string,
  packageId: string,
  attackerAddress?: string
): string {
  const clientSetup = `### Client setup
\`\`\`typescript
import { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import { Transaction } from "@mysten/sui/transactions";

const client = new SuiJsonRpcClient({ url: "${rpcUrl}", network: "${network}" });
\`\`\``;

  const buildingTx = `### Building transactions
\`\`\`typescript
const tx = new Transaction();

// Move call
tx.moveCall({
  target: "${packageId}::module::function",
  typeArguments: ["0x2::sui::SUI"],  // if generic
  arguments: [tx.object("0xOBJECT_ID"), tx.pure.u64(1000)],
});

// Pure value types
tx.pure.u64(100)
tx.pure.u8(1)
tx.pure.bool(true)
tx.pure.address("0x...")
tx.pure.string("hello")
tx.pure.vector("u8", [1, 2, 3])

// Object references
tx.object("0xOBJECT_ID")
tx.object.clock()    // 0x6
tx.object.system()   // 0x5

// Split coins for arguments
const [coin] = tx.splitCoins(tx.gas, [tx.pure.u64(1_000_000_000)]);

// Use results from previous commands
const [result] = tx.moveCall({ target: "..." });
tx.moveCall({ target: "...", arguments: [result] });

// Transfer objects
tx.transferObjects([coin], tx.pure.address("0x..."));
\`\`\``;

  const readingState = `### Reading on-chain state
\`\`\`typescript
// Get an object (with parsed JSON content)
const { object } = await client.core.getObject({
  objectId: "0x...",
  include: { json: true },
});

// List objects owned by an address
const result = await client.core.listOwnedObjects({
  owner: "0x...",
  filter: { StructType: "0x2::coin::Coin<0x2::sui::SUI>" },
});

// List dynamic fields on a shared object
const result = await client.core.listDynamicFields({ parentId: "0x..." });

// Get balance
const balance = await client.core.getBalance({
  owner: "0x...",
  coinType: "0x2::sui::SUI",
});
\`\`\``;

  if (network === "mainnet") {
    return `## Sui SDK reference (@mysten/sui v2)

IMPORTANT: Use \`SuiJsonRpcClient\` — NOT \`SuiClient\` (does not exist in v2).

${clientSetup}

${buildingTx}

### Simulating transactions (dry-run — nothing executes on-chain)
\`\`\`typescript
const tx = new Transaction();
tx.setSender("0x0000000000000000000000000000000000000000000000000000000000000000");
tx.moveCall({ target: "${packageId}::module::function", arguments: [...] });

const result = await client.core.simulateTransaction({
  transaction: tx,
  checksEnabled: false,  // skip signature/gas checks
  include: { effects: true, events: true, balanceChanges: true, commandResults: true },
});

if (result.$kind === "Transaction") {
  console.log("Status:", result.Transaction.status);
  console.log("Events:", result.Transaction.events);
} else {
  console.log("Failed:", result.FailedTransaction.effects?.status);
}
\`\`\`

${readingState}

Save exploit scripts as .mts files and run with \`npx tsx <file>\`.`;
  }

  // devnet
  const attacker = attackerAddress ?? "0x<attacker_address>";
  return `## Sui SDK reference (@mysten/sui v2)

IMPORTANT: Use \`SuiJsonRpcClient\` — NOT \`SuiClient\` (does not exist in v2).

${clientSetup}

### Keypairs and funding
\`\`\`typescript
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { requestSuiFromFaucetV2, getFaucetHost } from "@mysten/sui/faucet";

// Create or import a keypair
const keypair = Ed25519Keypair.fromSecretKey("suiprivkey1...");
// Or generate: const keypair = Ed25519Keypair.generate();

// Fund the address on devnet
await requestSuiFromFaucetV2({
  host: getFaucetHost("devnet"),
  recipient: keypair.getPublicKey().toSuiAddress(),
});
\`\`\`

${buildingTx}

### Executing transactions (devnet — real execution)
\`\`\`typescript
const result = await client.core.signAndExecuteTransaction({
  transaction: tx,
  signer: keypair,
  include: { effects: true, events: true, balanceChanges: true },
});

if (result.$kind === "FailedTransaction") {
  console.log("Failed:", result.FailedTransaction.status);
} else {
  console.log("Success:", result.Transaction.digest);
}

// Wait for transaction to be indexed
await client.core.waitForTransaction({ result });
\`\`\`

### Simulating before executing
\`\`\`typescript
const result = await client.core.simulateTransaction({
  transaction: tx,
  include: { effects: true, events: true, balanceChanges: true },
});
\`\`\`

${readingState}

### Deploying and calling contracts
The target contract is already deployed. Attacker address: ${attacker}
Use the attacker keypair to sign exploit transactions.

Save exploit scripts as .mts files and run with \`npx tsx <file>\`.`;
}

function buildOracleSection(rpcUrl: string, attackerAddress?: string): string {
  const attacker = attackerAddress ?? "0x<attacker_address>";
  return `## Oracle (exploit verification tool)
Write a TS file that exports:
- \`buildTx(client, attackerAddress: string)\` — returns a Transaction
- \`attackerKeypair\` — the Ed25519Keypair for the attacker

Then run:
\`\`\`bash
npx tsx src/oracle/check.ts --signal <abort|balance|ownership> --tx <path-to-your-exploit.ts> --attacker ${attacker} --rpc-url ${rpcUrl}
\`\`\`

Signals:
- \`abort\` — tx SHOULD fail but succeeds (access control bypass). Add \`--expected should_abort\`
- \`balance\` — attacker's balance increases
- \`ownership\` — attacker gains objects they shouldn't own

Returns: EXPLOIT_CONFIRMED or NO_EXPLOIT`;
}

function buildOutputFormat(moduleName: string): string {
  return `## Output files

### vulns.json — every hypothesis you investigated
Update after each hypothesis. This is how we measure analysis quality.
\`\`\`json
[{
  "id": "unique-id",
  "title": "Short title",
  "status": "confirmed|failed|untested",
  "severity": "critical|high|medium|low",
  "reason": "Why it works, or the specific code (function:line) that prevents it."
}]
\`\`\`

### findings.json — only exploitable vulnerabilities with working exploits
Leave EMPTY unless you have a confirmed exploit. Do NOT pad with weak findings.
\`\`\`json
[{
  "id": "unique-id",
  "module": "${moduleName}",
  "severity": "critical|high|medium|low",
  "category": "capability_misuse|shared_object_race|integer_overflow|ownership_violation|hot_potato_misuse|otw_abuse|other",
  "title": "Short title",
  "description": "What the bug is, the exploit flow, attacker cost vs damage, and why the victim cannot mitigate it.",
  "exploitTransaction": "// the TS exploit code",
  "oracleResult": { "signal": "...", "status": "EXPLOIT_CONFIRMED" },
  "iterations": 3
}]
\`\`\``;
}

// ── Main builder ─────────────────────────────────────────────────

export function buildHunterPrompt(input: HunterPromptInput): string {
  const invariantList = input.invariants.map((inv) => `- ${inv}`).join("\n");

  const relatedSection = input.relatedModuleSignatures
    ? `\n## Related modules (signatures only)\n\n${input.relatedModuleSignatures}\n`
    : "";

  return `You are a smart contract security researcher. Find vulnerabilities in this Sui Move module that an unprivileged attacker can exploit for economic gain or to cause permanent, unmitigable damage to other users.

## Target
Module: ${input.moduleName}
Package ID: ${input.packageId}${input.network === "mainnet" ? `\nRPC: ${input.rpcUrl}` : ""}
Network: ${input.network}
Protocol description: ${input.protocolDescription}

Invariants:
${invariantList || "- None specified"}

## Source
\`\`\`move
${input.moduleSource}
\`\`\`
${relatedSection}
${SUI_CONTEXT}

${WHAT_COUNTS}

${buildSdkReference(input.network, input.rpcUrl, input.packageId, input.attackerAddress)}

${buildOracleSection(input.rpcUrl, input.attackerAddress)}

${buildOutputFormat(input.moduleName)}`;
}
