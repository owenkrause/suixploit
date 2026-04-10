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

// ── Sui/Move/DeFi foundational context ─────────────────────────

export const FOUNDATIONAL_CONTEXT = `## Sui/Move Security Foundations

### Object Ownership & Access Control
- **Address-owned**: only the owner can use in transactions. Fast path (no consensus, <500ms finality). Passing an owned object as a function parameter IS the access control — no separate signer check needed.
- **Shared**: anyone can reference in transactions. Must go through consensus for ordering. ALL access control must be implemented in Move code — there is no implicit owner gate.
- **Immutable**: cannot be mutated or deleted. No contention.
- **Wrapped**: objects stored inside other objects. Not directly accessible — must unwrap first. Can be used to hide state or create escrow patterns.
- **Dynamic fields**: key-value storage on objects. Namespace collisions possible if keys aren't unique. Orphaned dynamic fields persist after parent deletion.

### Capability Pattern
The primary access gate on Sui. If a function takes \`&AdminCap\` (owned), only the cap holder can call it.
- Capabilities with \`copy\` ability are dangerous: allows duplication, breaking uniqueness assumptions.
- Capabilities with \`store\` ability can be wrapped/transferred outside protocol control.
- Capabilities should typically have only \`key\` (or \`key, store\` if intentionally transferable).
- Check for consistency: if function A requires AdminCap but function B doing similar privileged work does not, that's a finding.

### Witness & One-Time Witness (OTW)
- Witness pattern: struct with only \`drop\` proves type ownership. Must NOT have \`copy\`.
- OTW: created once in \`init()\`, consumed immediately. Has uppercase module name. Must have \`drop\` only.
- If a witness type has \`copy\`, it can be duplicated to bypass one-time guarantees.

### Ability System
- \`key\`: object can be stored in global storage, has an \`id: UID\` field.
- \`store\`: can be stored inside other objects or transferred freely.
- \`copy\`: can be duplicated. Dangerous for capabilities, witnesses, or anything representing unique authority.
- \`drop\`: can be silently destroyed. Without \`drop\`, a value MUST be explicitly consumed (hot potato pattern).
- Linear types (no \`copy\` + no \`drop\`) enforce exactly-once consumption — used for flash loan receipts.
- \`Coin<T>\` has no \`copy\` — linear types prevent double-spend at the type system level.

### PTBs (Programmable Transaction Blocks)
- Up to 1,024 commands execute sequentially in ONE atomic transaction.
- Results from earlier commands can be inputs to later ones — enables composing arbitrary multi-step attacks atomically.
- If any command fails, ALL effects revert.
- \`public fun\` (not just \`entry\`) are PTB-callable. Attackers can call any public function, not just entry points.
- \`entry fun\` can only appear as the entry point of a PTB command (cannot chain results).
- **State inconsistency within PTBs**: if function A partially updates a shared object, function B in the same PTB sees the intermediate state. This enables attacks where per-call limits are bypassed by calling N times (e.g. close factor bypass via repeated liquidation in one PTB).
- Flash loans via PTBs: deposit → manipulate → withdraw atomically, with no hot potato needed if the protocol doesn't enforce it.

### Transaction Ordering
- No public mempool. Transactions are sent directly to validators.
- Shared-object transactions are ordered by Mysticeti consensus (DAG-based). No single block proposer controls order — front-running requires validator collusion.
- Owned-object transactions bypass consensus entirely (fast path).
- Race conditions between concurrent shared-object transactions ARE possible — order is non-deterministic.

### Move Type System Security
- **Integer overflow/underflow aborts by default** (no wrapping arithmetic). This is DoS, not corruption.
  BUT: if overflow occurs in an accumulator/reward update BEFORE a checkpoint write, the transaction aborts, the checkpoint never advances, and the time delta grows — causing PERMANENT deadlock on retry. This is the **abort-before-checkpoint pattern**, the #1 missed Critical/High bug class in Move audits.
- No dynamic dispatch, no callbacks, no reentrancy in the Solidity sense.
- Generics are monomorphized at compile time. Types must satisfy ability constraints.
- \`public(package)\` restricts callers to the same package — but within a package, all modules can call each other.
- Division truncates toward zero. Precision loss in integer division is real and exploitable (especially in share/rate calculations).

### DeFi Security Primitives
- **Oracle manipulation**: spot price derived from pool ratio is flash-loan manipulable. Require TWAP/EMA with staleness checks + confidence intervals.
- **Flash loans**: hot potato pattern (no drop/store/copy/key) guarantees same-tx repayment. Verify the receipt struct actually lacks all four abilities. If it has any, the flash loan can be circumvented.
- **Share/rate math**: first-depositor inflation attacks when vault starts at 0 shares. Check initial share minting, rounding direction (should favor the protocol), and dead share mechanisms.
- **Accumulator patterns**: reward_per_share, interest indices, checkpoint timestamps. If these overflow or skip updates on certain code paths, accounting diverges permanently.
- **Slippage**: any swap/withdrawal without min_amount_out is sandwich-attackable.
- **Pause symmetry**: pausing borrow without unblocking liquidation creates bad debt. Pausing repay locks user funds.

### Key False Positive Traps
- Owned object parameter = access control. Don't report "missing auth check" when a function takes an owned capability.
- Move overflow = abort, not corruption. Only report if attacker profits from DoS or if abort-before-checkpoint bricks state.
- Linear types prevent double-spend (\`Coin<T>\` has no \`copy\`).
- Hot potato is compiler-enforced — no runtime bypass is possible.
- "Pattern looks dangerous" is not analysis. Trace the actual data flow and write the exact PTB exploit sequence. If you can't write the exploit, it probably doesn't exist.`;

// ── Reference tools section ─────────────────────────────────────

const REFERENCE_TOOLS_SECTION = `## Reference Library

You have access to a library of detailed vulnerability pattern references via two tools:

- \`list_references\` — shows all available reference files with descriptions and approximate token sizes
- \`read_reference\` — loads a specific reference file by name

**When to use references:**
- After your initial analysis, load relevant references to find additional attack vectors
- If the module involves DeFi (lending, staking, oracles, DEX), load \`defi-vectors\` first — it routes you to the right deep-dive files
- Load \`sui-protocol-checklists\` if you can identify the protocol type (lending, AMM, vault, staking, bridge, governance, NFT, upgrade)
- Load \`sui-patterns\` or \`common-move\` for detailed pattern matching with code examples

**Do NOT** load all references upfront. Be selective based on what the module actually does. Each reference shows its approximate token size — budget accordingly.`;

// ── Shared sections ──────────────────────────────────────────────

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

### findings.json — vulnerabilities with working exploits
Leave EMPTY unless you have a confirmed exploit.
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

## Methodology — Two-Phase Hunting

### Phase 1: Independent Analysis
Read the module source carefully. Using the foundational knowledge below, develop vulnerability hypotheses from first principles. Think about:
- What does each public/entry function do? Who can call it? What objects does it take?
- What are the shared objects? What invariants must they maintain?
- Where does value flow? Can an attacker redirect, amplify, or destroy it?
- Are there cross-function state dependencies exploitable within a single PTB?
- What assumptions does the code make that an attacker could violate?

### Phase 2: Reference Cross-Check
After forming your initial hypotheses, use the reference tools to find additional attack vectors:
1. Load relevant pattern files and check if known attack patterns apply to what you're seeing
2. For DeFi modules, load \`defi-vectors\` first, then the appropriate deep-dive file(s)

Do NOT skip Phase 1. Reference patterns supplement your analysis, not replace it.

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
${FOUNDATIONAL_CONTEXT}

${REFERENCE_TOOLS_SECTION}

${buildSdkReference(input.network, input.rpcUrl, input.packageId, input.attackerAddress)}

${buildOracleSection(input.rpcUrl, input.attackerAddress)}

${buildOutputFormat(input.moduleName)}`;
}
