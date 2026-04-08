# Suixploit — Multi-Agent Sui Move Vulnerability Discovery Pipeline

## Overview

A TypeScript CLI tool that autonomously finds and confirms vulnerabilities in Sui Move smart contracts using a multi-agent pipeline: ranker scores modules by attack surface, parallel hunter agents exploit high-priority modules against a local devnet with oracle confirmation, and a validator filters false positives before human review.

Core insight: a minimal prompt with a deterministic oracle and real execution environment beats a complex prompt with no feedback loop. The model hypothesizes, tests, and iterates autonomously.

## Architecture

```
scan target
    │
    ▼
┌─────────┐
│ RANKER   │  Single Opus call. Scores every module 1-5.
└────┬────┘
     │ modules scoring 4-5
     ▼
┌─────────────────────────────┐
│ HUNTERS (parallel)          │
│ ┌───────┐ ┌───────┐ ┌────┐ │  One Claude Code Agent per module.
│ │ mod A │ │ mod B │ │ .. │ │  Each gets own devnet + worktree.
│ └───────┘ └───────┘ └────┘ │
└────────────┬────────────────┘
             │ Finding[]
             ▼
┌───────────┐
│ VALIDATOR  │  Single Opus call. Filters false positives.
└────┬──────┘
     │ ValidatedFinding[]
     ▼
  JSON output
```

## Project Structure

```
suixploit/
├── src/
│   ├── cli.ts                    # CLI entry — parses args, kicks off pipeline
│   ├── pipeline.ts               # orchestrates ranker → hunters → validator
│   ├── ranker/
│   │   └── index.ts              # feeds code to Opus, parses scores
│   ├── hunter/
│   │   ├── index.ts              # spawns a Claude Code agent per module
│   │   └── prompt.ts             # minimal hunter prompt template
│   ├── validator/
│   │   └── index.ts              # reads findings, filters false positives
│   ├── oracle/
│   │   ├── index.ts              # unified oracle entry point
│   │   ├── abort.ts              # access control — tx should abort but didn't
│   │   ├── balance.ts            # fund drain — attacker balance increased
│   │   ├── ownership.ts          # object theft — attacker gained objects
│   │   └── custom.ts             # freeform pre/post condition check
│   ├── devnet/
│   │   ├── lifecycle.ts          # start devnet, stop, regenesis
│   │   └── seed.ts               # deploy contracts, fund accounts, reset state
│   └── types.ts                  # Finding, ModuleScore, OracleResult, etc.
├── contracts/
│   ├── easy/                     # capability leak, unchecked arithmetic
│   ├── medium/                   # ownership escape, flash loan misuse
│   └── hard/                     # shared object race, OTW abuse
├── scripts/
│   └── setup-devnet.sh           # quick-start script for manual testing
├── tsconfig.json
├── package.json
└── CLAUDE.md                     # instructions for hunter agents
```

## CLI Interface

```bash
# scan a local Move project
npx suixploit scan ./path/to/move/project

# scan a deployed package (closed-source)
npx suixploit scan 0x<package_id> --network mainnet

# closed-source with manual context
npx suixploit scan 0x<package_id> --network mainnet \
  --protocol "DEX with AMM pools" \
  --invariants "only pool creator can set fees" "LPs can always withdraw"

# or via config file
npx suixploit scan 0x<package_id> --network mainnet --config audit.json
```

Config file format:
```json
{
  "protocol": "DEX with AMM pools",
  "invariants": [
    "only pool creator can set fees",
    "LPs can always withdraw their share"
  ]
}
```

## Pipeline Flow

1. **Resolve target** — get list of Move modules with source. For on-chain packages: fetch bytecode via Sui RPC, decompile, pair decompiled source with raw bytecode.
2. **Ranker** — scores all modules → `ModuleScore[]`. Skip for projects with 1-3 modules.
3. **Filter** — modules scoring 4-5 proceed to hunting.
4. **Spawn hunters** — one Claude Code Agent per module (via Agent tool with `isolation: "worktree"`). Each gets its own devnet on a unique port.
5. **Collect findings** — each hunter writes `findings.json` in its worktree. Orchestrator reads these files after each agent completes, merges into `Finding[]`.
6. **Validator** — filters false positives → `ValidatedFinding[]`.
7. **Output** — write `ScanResult` as JSON to stdout.

## Data Types

```typescript
interface ModuleScore {
  module: string;
  score: number;                    // 1-5
  rationale: string;
  attackSurface: string[];
}

interface Finding {
  id: string;
  module: string;
  severity: "critical" | "high" | "medium" | "low";
  category:
    | "capability_misuse"
    | "shared_object_race"
    | "integer_overflow"
    | "ownership_violation"
    | "hot_potato_misuse"
    | "otw_abuse"
    | "other";
  title: string;
  description: string;
  exploitTransaction: string;       // TS code that triggers the bug
  oracleResult: OracleResult;
  iterations: number;
}

interface ValidatedFinding extends Finding {
  validatorVerdict: "confirmed" | "adjusted" | "rejected";
  validatorNote: string;
  adjustedSeverity?: Finding["severity"];
}

interface OracleResult {
  signal: "abort" | "balance" | "ownership" | "custom";
  status: "EXPLOIT_CONFIRMED" | "NO_EXPLOIT";
  preTxState: Record<string, unknown>;
  postTxState: Record<string, unknown>;
}

interface ScanResult {
  target: string;
  timestamp: string;
  modulesScanned: number;
  modulesHunted: number;
  findings: ValidatedFinding[];
  rawFindings: Finding[];
  rankerScores: ModuleScore[];
}
```

## Oracle System

Three built-in deterministic signals plus a freeform custom check. No LLM involvement.

### Abort Signal
Detects access control bugs. The hunter specifies that a transaction should abort (e.g. unauthorized caller). If it succeeds instead, exploit confirmed.

```typescript
function checkAbort(dryRunResult: DryRunResult, expected: "should_abort"): OracleResult
```

### Balance Signal
Detects fund draining. Compares the attacker's coin balances before and after the transaction. If any balance increased, exploit confirmed.

```typescript
function checkBalance(
  attackerAddress: string,
  preTxBalances: CoinBalance[],
  postTxBalances: CoinBalance[]
): OracleResult
```

### Ownership Signal
Detects object theft. Checks `objectChanges` from the transaction for objects newly owned by the attacker that weren't created by the attacker in this transaction.

```typescript
function checkOwnership(
  attackerAddress: string,
  objectChanges: ObjectChange[]
): OracleResult
```

### Custom Signal
Freeform check for bugs that don't fit the three built-in signals. The hunter defines a pre-condition reader and a post-condition validator.

```typescript
function checkCustom(opts: {
  description: string;
  preCondition: () => Promise<unknown>;
  postCondition: (pre: unknown) => Promise<boolean>;
}): Promise<OracleResult>
```

### Unified Entry Point

```typescript
async function checkExploit(opts: {
  signal: "abort" | "balance" | "ownership" | "custom";
  txBlock: TransactionBlock;
  attackerAddress: string;
  expected?: "should_abort";
  customCheck?: {
    description: string;
    preCondition: () => Promise<unknown>;
    postCondition: (pre: unknown) => Promise<boolean>;
  };
  suiClient: SuiClient;
}): Promise<OracleResult>
```

All three built-in signals can be checked from the `dryRunTransactionBlock` response alone. Real execution is only for final confirmation in the report.

## Hunter Agent Design

Minimal prompt, rich environment. Each hunter receives:

- Target module source code
- Protocol description and invariants (from ranker rationale or user-provided)
- CLAUDE.md context with oracle and devnet tools
- Its own devnet on a unique port
- Its own worktree for writing exploit files

### Prompt Template

```
You are auditing a Sui Move smart contract module for security vulnerabilities.

## Target
Module: {moduleName}
Protocol description: {protocolDescription}
Invariants: {invariants}

## Source
{moduleSource}

## Environment
- You have a running Sui devnet with the contract deployed
- Attacker address: {attackerAddress}
- Admin address: {adminAddress}
- User address: {userAddress}
- Sui CLI and TS SDK are available

## Oracle
Run: npx tsx src/oracle/check.ts --signal <abort|balance|ownership> --tx <path-to-tx.ts> --attacker {attackerAddress}
Returns: EXPLOIT_CONFIRMED or NO_EXPLOIT

## Task
Find a vulnerability in this module and confirm it with the oracle.
Write exploit transactions as TS files, run them via dry-run, check with the oracle.
Iterate until you find something or exhaust your ideas.
When done, write your findings to findings.json.
```

### Emergent Behavior

The agent autonomously: reads source → identifies potential bugs → writes exploit transactions → runs oracle → refines based on feedback → reports findings. No scripted steps.

### Isolation

- **Worktree:** `isolation: "worktree"` on the Agent tool call gives each hunter its own repo copy.
- **Devnet:** Orchestrator starts a devnet on a unique port per hunter. Agent's `SuiClient` points to its own port.
- **State reset:** Seed script re-deploys contracts and re-funds accounts between attempts. Dry-run iterations need no reset since `dryRunTransactionBlock` doesn't mutate state.

## Ranker Agent

Single Opus call. Scores all modules by attack surface.

### Prompt

```
You are a smart contract security analyst. Score each module in this Sui Move
project from 1-5 for attack surface. Consider:

- Coin/token transfers or minting
- Shared objects (concurrent access)
- Admin capabilities or access control
- External inputs / user-supplied arguments
- Object ownership transfers
- Arithmetic on balances or amounts
- Flash loan / hot potato patterns
- One-time witness usage

For each module, return a JSON object with: module name, score (1-5),
rationale, and list of attack surface areas.

Return ONLY a JSON array of ModuleScore objects.
```

### Behavior

- Modules scoring 4-5 get hunted.
- Rationale and attack surface from the ranker feed into the hunter's protocol description.
- For projects with 1-3 modules, skip the ranker and hunt all modules.

## Validator Agent

Single Opus call. Reads all findings and filters false positives.

### Prompt

```
You are a senior smart contract security auditor performing final review.

## Findings
{findingsJson}

## Source Code
{allModuleSources}

For each finding, evaluate:
1. Is the exploit transaction valid Move/Sui TS code?
2. Does the oracle result actually confirm the claimed vulnerability?
3. Is the severity rating accurate?
4. Is this a real bug or a test artifact (e.g. exploiting the test setup, not the contract)?
5. Could this be triggered in a real deployment or only in the test environment?

Return a JSON array of validated findings. For each:
- Keep, adjust severity, or reject
- Add a "validatorNote" explaining your decision

Return ONLY a JSON array.
```

### What Gets Filtered

- Exploits that abuse the test seed setup rather than the contract logic
- Oracle confirmations that rely on attacker having privileges unavailable in production
- Duplicate findings across hunters (keep the clearest exploit)
- Low-severity / informational findings (unless opted in)

## Vulnerable Test Contracts

Six contracts covering the target bug classes at graduated difficulty. Used to validate that the pipeline works before pointing it at real targets.

### Easy

1. **`capability_leak`** — Admin-gated `withdraw` accepts `&AdminCap`, but a separate public function accidentally returns an `AdminCap` to any caller. Oracle signal: abort.

2. **`unchecked_arithmetic`** — Token reward calculator multiplies `amount * multiplier` without overflow checks. Craft inputs where multiplication wraps to mint excess tokens. Oracle signal: balance.

### Medium

3. **`ownership_escape`** — Marketplace where `cancel_listing` checks ownership by a stored address field rather than Sui's ownership model. Attacker manipulates the address field to steal listed items. Oracle signal: ownership.

4. **`flash_loan_misuse`** — Lending pool using hot potato pattern. `repay` checks amount >= borrowed but doesn't verify same coin type. Borrow SUI, repay with worthless custom coin. Oracle signal: balance.

### Hard

5. **`shared_object_race`** — Shared auction where `bid` and `settle` don't properly sequence. Concurrent bid slips in between read and transfer. Oracle signal: balance.

6. **`otw_abuse`** — Token contract with OTW pattern for `init`, but exposes `create_treasury_cap` that checks `has_key` rather than validating actual OTW. Create fake witness, mint unlimited. Oracle signal: balance.

Each contract includes:
- `Move.toml` and valid module structure
- Seed script for deployment and initial state
- `protocol.md` with intended behavior and invariants

These contracts validate the pipeline. They do not constrain what hunters look for — when scanning real contracts, hunters use the general prompt and can report any category including `"other"`.

## Closed-Source Support

Secondary priority — build after core pipeline is validated.

1. Receive package address + network flag
2. Fetch published bytecode via `sui_getObject`
3. Decompile via Move decompiler
4. Feed both decompiled source AND raw bytecode to ranker/hunters
5. Protocol description and invariants come from user (CLI flags or config file) since they can't be derived from decompiled code
6. Oracle and devnet work identically — deploy a local copy and test against it

Constraint: re-deploying closed-source packages requires their dependencies. Seed script must publish dependencies first.

## Devnet Lifecycle

- **Per agent:** Full regenesis when hunter agent starts (`sui start --with-faucet --force-regenesis` on unique port)
- **Per attempt:** Seed script re-deploys contracts and re-funds accounts (no regenesis)
- **Dry runs:** No reset needed — `dryRunTransactionBlock` doesn't mutate state
- **Cleanup:** Orchestrator kills devnet process when hunter agent completes

## Technology

- **Language:** TypeScript end-to-end
- **Sui SDK:** `@mysten/sui` for all on-chain interaction
- **Orchestration:** Claude Code Agent tool with `isolation: "worktree"`
- **Runtime:** Node.js with `tsx` for direct TS execution
- **Devnet:** Local `sui start` instances
- **Output:** Structured JSON (`ScanResult`)
