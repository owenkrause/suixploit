# Suixploit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a multi-agent pipeline that autonomously finds and confirms vulnerabilities in Sui Move contracts using oracle-confirmed exploit feedback loops.

**Architecture:** CLI orchestrator spawns Claude Code subagents (hunters) per module. Each hunter gets an isolated devnet + worktree, writes exploit transactions, and checks them against a deterministic oracle. A ranker prioritizes modules and a validator filters false positives.

**Tech Stack:** TypeScript, `@mysten/sui` SDK, `vitest`, `commander`, `tsx`, local `sui` devnet instances

**Prerequisites:** `sui` CLI installed and on PATH. Node.js 20+.

---

### Task 1: Project Scaffolding

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `.gitignore`

- [ ] **Step 1: Initialize npm project and install dependencies**

```bash
cd /Users/owenkrause/projects/suixploit
npm init -y
npm install @mysten/sui commander
npm install -D typescript tsx vitest @types/node
```

- [ ] **Step 2: Configure TypeScript**

Write `tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "Node16",
    "moduleResolution": "Node16",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "declaration": true
  },
  "include": ["src"],
  "exclude": ["node_modules", "dist"]
}
```

- [ ] **Step 3: Configure package.json scripts and type**

Add to `package.json`:

```json
{
  "type": "module",
  "bin": {
    "suixploit": "./dist/cli.js"
  },
  "scripts": {
    "build": "tsc",
    "test": "vitest run",
    "test:watch": "vitest"
  }
}
```

- [ ] **Step 4: Write .gitignore**

```
node_modules/
dist/
*.log
.sui/
```

- [ ] **Step 5: Create directory structure**

```bash
mkdir -p src/{ranker,hunter,validator,oracle,devnet}
mkdir -p contracts/{easy,medium,hard}
mkdir -p scripts
```

- [ ] **Step 6: Commit**

```bash
git add package.json tsconfig.json .gitignore package-lock.json
git commit -m "feat: project scaffolding with dependencies"
```

---

### Task 2: Core Types

**Files:**
- Create: `src/types.ts`
- Test: `src/types.test.ts`

- [ ] **Step 1: Write types**

Write `src/types.ts`:

```typescript
export type Severity = "critical" | "high" | "medium" | "low";

export type FindingCategory =
  | "capability_misuse"
  | "shared_object_race"
  | "integer_overflow"
  | "ownership_violation"
  | "hot_potato_misuse"
  | "otw_abuse"
  | "other";

export type OracleSignal = "abort" | "balance" | "ownership" | "custom";

export interface ModuleScore {
  module: string;
  score: number;
  rationale: string;
  attackSurface: string[];
}

export interface OracleResult {
  signal: OracleSignal;
  status: "EXPLOIT_CONFIRMED" | "NO_EXPLOIT";
  preTxState: Record<string, unknown>;
  postTxState: Record<string, unknown>;
}

export interface Finding {
  id: string;
  module: string;
  severity: Severity;
  category: FindingCategory;
  title: string;
  description: string;
  exploitTransaction: string;
  oracleResult: OracleResult;
  iterations: number;
}

export interface ValidatedFinding extends Finding {
  validatorVerdict: "confirmed" | "adjusted" | "rejected";
  validatorNote: string;
  adjustedSeverity?: Severity;
}

export interface ScanResult {
  target: string;
  timestamp: string;
  modulesScanned: number;
  modulesHunted: number;
  findings: ValidatedFinding[];
  rawFindings: Finding[];
  rankerScores: ModuleScore[];
}

export interface ModuleInfo {
  name: string;
  source: string;
  path: string;
  protocolDescription?: string;
  invariants?: string[];
}

export interface DevnetConfig {
  rpcUrl: string;
  faucetUrl: string;
  port: number;
  faucetPort: number;
  adminAddress: string;
  attackerAddress: string;
  userAddress: string;
  adminKeyPair: string;
  attackerKeyPair: string;
  userKeyPair: string;
}
```

- [ ] **Step 2: Write a smoke test to verify types compile and export correctly**

Write `src/types.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import type {
  ModuleScore,
  OracleResult,
  Finding,
  ValidatedFinding,
  ScanResult,
  ModuleInfo,
  DevnetConfig,
} from "./types.js";

describe("types", () => {
  it("OracleResult accepts valid signals", () => {
    const result: OracleResult = {
      signal: "balance",
      status: "EXPLOIT_CONFIRMED",
      preTxState: { balance: "1000" },
      postTxState: { balance: "2000" },
    };
    expect(result.status).toBe("EXPLOIT_CONFIRMED");
  });

  it("Finding accepts all categories", () => {
    const categories = [
      "capability_misuse",
      "shared_object_race",
      "integer_overflow",
      "ownership_violation",
      "hot_potato_misuse",
      "otw_abuse",
      "other",
    ] as const;
    for (const category of categories) {
      const finding: Finding = {
        id: "test",
        module: "test::mod",
        severity: "high",
        category,
        title: "test",
        description: "test",
        exploitTransaction: "// code",
        oracleResult: {
          signal: "balance",
          status: "EXPLOIT_CONFIRMED",
          preTxState: {},
          postTxState: {},
        },
        iterations: 1,
      };
      expect(finding.category).toBe(category);
    }
  });

  it("ValidatedFinding extends Finding with verdict", () => {
    const validated: ValidatedFinding = {
      id: "test",
      module: "test::mod",
      severity: "high",
      category: "other",
      title: "test",
      description: "test",
      exploitTransaction: "// code",
      oracleResult: {
        signal: "balance",
        status: "EXPLOIT_CONFIRMED",
        preTxState: {},
        postTxState: {},
      },
      iterations: 1,
      validatorVerdict: "adjusted",
      validatorNote: "severity downgraded",
      adjustedSeverity: "medium",
    };
    expect(validated.validatorVerdict).toBe("adjusted");
    expect(validated.adjustedSeverity).toBe("medium");
  });
});
```

- [ ] **Step 3: Run tests**

Run: `npx vitest run src/types.test.ts`
Expected: 3 tests PASS

- [ ] **Step 4: Commit**

```bash
git add src/types.ts src/types.test.ts
git commit -m "feat: core type definitions"
```

---

### Task 3: Oracle System

**Files:**
- Create: `src/oracle/abort.ts`
- Create: `src/oracle/balance.ts`
- Create: `src/oracle/ownership.ts`
- Create: `src/oracle/custom.ts`
- Create: `src/oracle/index.ts`
- Test: `src/oracle/oracle.test.ts`

- [ ] **Step 1: Write oracle tests**

Write `src/oracle/oracle.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { checkAbort } from "./abort.js";
import { checkBalance } from "./balance.js";
import { checkOwnership } from "./ownership.js";
import { checkCustom } from "./custom.js";

describe("checkAbort", () => {
  it("confirms exploit when tx succeeds but should have aborted", () => {
    const result = checkAbort(
      { effects: { status: { status: "success" } } },
      "should_abort"
    );
    expect(result.status).toBe("EXPLOIT_CONFIRMED");
    expect(result.signal).toBe("abort");
  });

  it("returns no exploit when tx correctly aborts", () => {
    const result = checkAbort(
      { effects: { status: { status: "failure" } } },
      "should_abort"
    );
    expect(result.status).toBe("NO_EXPLOIT");
  });
});

describe("checkBalance", () => {
  it("confirms exploit when attacker balance increased", () => {
    const result = checkBalance("0xattacker", [
      {
        owner: { AddressOwner: "0xattacker" },
        coinType: "0x2::sui::SUI",
        amount: "1000",
      },
    ]);
    expect(result.status).toBe("EXPLOIT_CONFIRMED");
    expect(result.signal).toBe("balance");
  });

  it("returns no exploit when attacker balance decreased", () => {
    const result = checkBalance("0xattacker", [
      {
        owner: { AddressOwner: "0xattacker" },
        coinType: "0x2::sui::SUI",
        amount: "-500",
      },
    ]);
    expect(result.status).toBe("NO_EXPLOIT");
  });

  it("returns no exploit when no balance changes for attacker", () => {
    const result = checkBalance("0xattacker", [
      {
        owner: { AddressOwner: "0xother" },
        coinType: "0x2::sui::SUI",
        amount: "1000",
      },
    ]);
    expect(result.status).toBe("NO_EXPLOIT");
  });
});

describe("checkOwnership", () => {
  it("confirms exploit when attacker gains existing object", () => {
    const result = checkOwnership("0xattacker", [
      {
        type: "mutated",
        objectId: "0xobj1",
        owner: { AddressOwner: "0xattacker" },
        sender: "0xattacker",
      },
    ]);
    expect(result.status).toBe("EXPLOIT_CONFIRMED");
    expect(result.signal).toBe("ownership");
  });

  it("returns no exploit when attacker only owns objects they created", () => {
    const result = checkOwnership("0xattacker", [
      {
        type: "created",
        objectId: "0xobj1",
        owner: { AddressOwner: "0xattacker" },
        sender: "0xattacker",
      },
    ]);
    expect(result.status).toBe("NO_EXPLOIT");
  });

  it("returns no exploit when objects go to someone else", () => {
    const result = checkOwnership("0xattacker", [
      {
        type: "mutated",
        objectId: "0xobj1",
        owner: { AddressOwner: "0xother" },
        sender: "0xattacker",
      },
    ]);
    expect(result.status).toBe("NO_EXPLOIT");
  });
});

describe("checkCustom", () => {
  it("confirms exploit when post-condition returns true", async () => {
    const result = await checkCustom({
      description: "pool balance decreased without withdrawal",
      preCondition: async () => ({ balance: 1000 }),
      postCondition: async (pre) => {
        const { balance } = pre as { balance: number };
        return balance > 500; // simulating the check passed
      },
    });
    expect(result.status).toBe("EXPLOIT_CONFIRMED");
    expect(result.signal).toBe("custom");
  });

  it("returns no exploit when post-condition returns false", async () => {
    const result = await checkCustom({
      description: "test",
      preCondition: async () => ({ balance: 1000 }),
      postCondition: async () => false,
    });
    expect(result.status).toBe("NO_EXPLOIT");
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/oracle/oracle.test.ts`
Expected: FAIL — modules don't exist yet

- [ ] **Step 3: Implement abort oracle**

Write `src/oracle/abort.ts`:

```typescript
import type { OracleResult } from "../types.js";

export interface DryRunEffects {
  effects: {
    status: { status: "success" | "failure" };
  };
}

export function checkAbort(
  dryRunResult: DryRunEffects,
  expected: "should_abort"
): OracleResult {
  const txSucceeded = dryRunResult.effects.status.status === "success";

  if (expected === "should_abort" && txSucceeded) {
    return {
      signal: "abort",
      status: "EXPLOIT_CONFIRMED",
      preTxState: { expected },
      postTxState: { txStatus: dryRunResult.effects.status.status },
    };
  }

  return {
    signal: "abort",
    status: "NO_EXPLOIT",
    preTxState: { expected },
    postTxState: { txStatus: dryRunResult.effects.status.status },
  };
}
```

- [ ] **Step 4: Implement balance oracle**

Write `src/oracle/balance.ts`:

```typescript
import type { OracleResult } from "../types.js";

export interface BalanceChange {
  owner: { AddressOwner: string } | { ObjectOwner: string } | Record<string, unknown>;
  coinType: string;
  amount: string;
}

export function checkBalance(
  attackerAddress: string,
  balanceChanges: BalanceChange[]
): OracleResult {
  const attackerGains = balanceChanges.filter((change) => {
    const ownerAddr =
      "AddressOwner" in change.owner
        ? (change.owner as { AddressOwner: string }).AddressOwner
        : null;
    return ownerAddr === attackerAddress && BigInt(change.amount) > 0n;
  });

  const gained = attackerGains.length > 0;

  return {
    signal: "balance",
    status: gained ? "EXPLOIT_CONFIRMED" : "NO_EXPLOIT",
    preTxState: { attackerAddress },
    postTxState: {
      balanceChanges: attackerGains.map((g) => ({
        coinType: g.coinType,
        amount: g.amount,
      })),
    },
  };
}
```

- [ ] **Step 5: Implement ownership oracle**

Write `src/oracle/ownership.ts`:

```typescript
import type { OracleResult } from "../types.js";

export interface ObjectChange {
  type: "created" | "mutated" | "deleted" | "wrapped" | "published";
  objectId: string;
  owner?: { AddressOwner: string } | { Shared: unknown } | Record<string, unknown>;
  sender: string;
}

export function checkOwnership(
  attackerAddress: string,
  objectChanges: ObjectChange[]
): OracleResult {
  const stolenObjects = objectChanges.filter((change) => {
    if (change.type === "created") return false;
    if (change.type === "deleted" || change.type === "wrapped" || change.type === "published") return false;
    if (!change.owner || !("AddressOwner" in change.owner)) return false;
    const ownerAddr = (change.owner as { AddressOwner: string }).AddressOwner;
    return ownerAddr === attackerAddress;
  });

  const gained = stolenObjects.length > 0;

  return {
    signal: "ownership",
    status: gained ? "EXPLOIT_CONFIRMED" : "NO_EXPLOIT",
    preTxState: { attackerAddress },
    postTxState: {
      gainedObjects: stolenObjects.map((o) => o.objectId),
    },
  };
}
```

- [ ] **Step 6: Implement custom oracle**

Write `src/oracle/custom.ts`:

```typescript
import type { OracleResult } from "../types.js";

export interface CustomCheckOpts {
  description: string;
  preCondition: () => Promise<unknown>;
  postCondition: (pre: unknown) => Promise<boolean>;
}

export async function checkCustom(opts: CustomCheckOpts): Promise<OracleResult> {
  const preState = await opts.preCondition();
  const exploitConfirmed = await opts.postCondition(preState);

  return {
    signal: "custom",
    status: exploitConfirmed ? "EXPLOIT_CONFIRMED" : "NO_EXPLOIT",
    preTxState: { description: opts.description, preState },
    postTxState: { exploitConfirmed },
  };
}
```

- [ ] **Step 7: Implement unified entry point**

Write `src/oracle/index.ts`:

```typescript
export { checkAbort } from "./abort.js";
export type { DryRunEffects } from "./abort.js";
export { checkBalance } from "./balance.js";
export type { BalanceChange } from "./balance.js";
export { checkOwnership } from "./ownership.js";
export type { ObjectChange } from "./ownership.js";
export { checkCustom } from "./custom.js";
export type { CustomCheckOpts } from "./custom.js";
```

- [ ] **Step 8: Run tests**

Run: `npx vitest run src/oracle/oracle.test.ts`
Expected: All 8 tests PASS

- [ ] **Step 9: Commit**

```bash
git add src/oracle/ src/oracle/oracle.test.ts
git commit -m "feat: oracle system with abort, balance, ownership, and custom signals"
```

---

### Task 4: Oracle CLI Script

**Files:**
- Create: `src/oracle/check.ts`

This is the CLI script that hunter agents invoke from the command line.

- [ ] **Step 1: Write the oracle CLI script**

Write `src/oracle/check.ts`:

```typescript
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
```

- [ ] **Step 2: Verify it parses args correctly**

Run: `npx tsx src/oracle/check.ts`
Expected: Usage error message printed, exit code 1

- [ ] **Step 3: Commit**

```bash
git add src/oracle/check.ts
git commit -m "feat: oracle CLI script for hunter agents"
```

---

### Task 5: Devnet Lifecycle Management

**Files:**
- Create: `src/devnet/lifecycle.ts`
- Test: `src/devnet/lifecycle.test.ts`

- [ ] **Step 1: Write lifecycle tests**

Write `src/devnet/lifecycle.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { buildSuiStartArgs, parsePortFromArgs } from "./lifecycle.js";

describe("buildSuiStartArgs", () => {
  it("builds correct args for a given port", () => {
    const args = buildSuiStartArgs({ port: 9100, faucetPort: 9123 });
    expect(args).toContain("--with-faucet");
    expect(args).toContain("--force-regenesis");
    expect(args).toContain("9100");
    expect(args).toContain("9123");
  });
});

describe("parsePortFromArgs", () => {
  it("extracts port from args", () => {
    const args = buildSuiStartArgs({ port: 9200, faucetPort: 9223 });
    expect(parsePortFromArgs(args)).toBe(9200);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/devnet/lifecycle.test.ts`
Expected: FAIL — module doesn't exist yet

- [ ] **Step 3: Implement devnet lifecycle**

Write `src/devnet/lifecycle.ts`:

```typescript
import { spawn, type ChildProcess } from "node:child_process";

export interface DevnetPorts {
  port: number;
  faucetPort: number;
}

export interface DevnetProcess {
  process: ChildProcess;
  rpcUrl: string;
  faucetUrl: string;
  port: number;
  faucetPort: number;
  kill: () => void;
}

let nextPort = 9100;

export function allocatePorts(): DevnetPorts {
  const port = nextPort;
  const faucetPort = port + 23; // sui convention: faucet = rpc + 23
  nextPort += 100; // space out for safety
  return { port, faucetPort };
}

export function buildSuiStartArgs(ports: DevnetPorts): string[] {
  return [
    "start",
    "--with-faucet",
    "--force-regenesis",
    "--fullnode-rpc-port",
    String(ports.port),
    "--faucet-port",
    String(ports.faucetPort),
  ];
}

export function parsePortFromArgs(args: string[]): number {
  const idx = args.indexOf("--fullnode-rpc-port");
  if (idx === -1 || idx + 1 >= args.length) throw new Error("No port in args");
  return parseInt(args[idx + 1], 10);
}

export async function startDevnet(ports?: DevnetPorts): Promise<DevnetProcess> {
  const { port, faucetPort } = ports ?? allocatePorts();
  const args = buildSuiStartArgs({ port, faucetPort });

  const child = spawn("sui", args, {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env },
  });

  const rpcUrl = `http://127.0.0.1:${port}`;
  const faucetUrl = `http://127.0.0.1:${faucetPort}`;

  // Wait for devnet to be ready by polling the RPC endpoint
  await waitForRpc(rpcUrl);

  return {
    process: child,
    rpcUrl,
    faucetUrl,
    port,
    faucetPort,
    kill: () => {
      child.kill("SIGTERM");
    },
  };
}

async function waitForRpc(url: string, timeoutMs = 30000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "sui_getLatestCheckpointSequenceNumber", id: 1 }),
      });
      if (res.ok) return;
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`Devnet at ${url} failed to start within ${timeoutMs}ms`);
}

export function stopDevnet(devnet: DevnetProcess): void {
  devnet.kill();
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/devnet/lifecycle.test.ts`
Expected: 2 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/devnet/lifecycle.ts src/devnet/lifecycle.test.ts
git commit -m "feat: devnet lifecycle management with port allocation"
```

---

### Task 6: Seed Infrastructure

**Files:**
- Create: `src/devnet/seed.ts`
- Test: `src/devnet/seed.test.ts`

- [ ] **Step 1: Write seed tests**

Write `src/devnet/seed.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { generateAccounts, buildPublishCommand } from "./seed.js";

describe("generateAccounts", () => {
  it("creates three distinct keypairs", () => {
    const accounts = generateAccounts();
    expect(accounts.admin.address).not.toBe(accounts.attacker.address);
    expect(accounts.admin.address).not.toBe(accounts.user.address);
    expect(accounts.attacker.address).not.toBe(accounts.user.address);
  });
});

describe("buildPublishCommand", () => {
  it("builds a sui move publish command for a contract path", () => {
    const cmd = buildPublishCommand("/path/to/contract");
    expect(cmd).toContain("sui client publish");
    expect(cmd).toContain("/path/to/contract");
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/devnet/seed.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement seed infrastructure**

Write `src/devnet/seed.ts`:

```typescript
import { execSync } from "node:child_process";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { SuiClient } from "@mysten/sui/client";
import { requestSuiFromFaucetV0 } from "@mysten/sui/faucet";
import type { DevnetConfig } from "../types.js";

export interface AccountSet {
  admin: { keypair: Ed25519Keypair; address: string };
  attacker: { keypair: Ed25519Keypair; address: string };
  user: { keypair: Ed25519Keypair; address: string };
}

export function generateAccounts(): AccountSet {
  const admin = Ed25519Keypair.generate();
  const attacker = Ed25519Keypair.generate();
  const user = Ed25519Keypair.generate();
  return {
    admin: { keypair: admin, address: admin.getPublicKey().toSuiAddress() },
    attacker: { keypair: attacker, address: attacker.getPublicKey().toSuiAddress() },
    user: { keypair: user, address: user.getPublicKey().toSuiAddress() },
  };
}

export function buildPublishCommand(contractPath: string): string {
  return `sui client publish ${contractPath} --skip-dependency-verification --gas-budget 500000000`;
}

export async function fundAccount(
  faucetUrl: string,
  address: string
): Promise<void> {
  await requestSuiFromFaucetV0({ host: faucetUrl, recipient: address });
}

export async function seedDevnet(opts: {
  rpcUrl: string;
  faucetUrl: string;
  contractPath: string;
  accounts: AccountSet;
}): Promise<{ packageId: string; devnetConfig: DevnetConfig }> {
  const { rpcUrl, faucetUrl, contractPath, accounts } = opts;

  // Fund all accounts
  await Promise.all([
    fundAccount(faucetUrl, accounts.admin.address),
    fundAccount(faucetUrl, accounts.attacker.address),
    fundAccount(faucetUrl, accounts.user.address),
  ]);

  // Publish the contract as admin
  const publishCmd = buildPublishCommand(contractPath);
  const envWithClient = {
    ...process.env,
    SUI_RPC_URL: rpcUrl,
  };

  // Export admin key and set as active address
  const adminB64 = accounts.admin.keypair.getSecretKey();
  const importResult = execSync(
    `sui keytool import "${adminB64}" ed25519 --json`,
    { env: envWithClient, encoding: "utf-8" }
  );

  execSync(
    `sui client switch --address ${accounts.admin.address}`,
    { env: envWithClient, encoding: "utf-8" }
  );

  const publishResult = execSync(publishCmd, {
    env: envWithClient,
    encoding: "utf-8",
  });

  // Parse package ID from publish output
  const packageIdMatch = publishResult.match(/"packageId":\s*"(0x[a-fA-F0-9]+)"/);
  if (!packageIdMatch) {
    throw new Error(`Failed to parse packageId from publish output:\n${publishResult}`);
  }

  const packageId = packageIdMatch[1];
  const port = parseInt(new URL(rpcUrl).port, 10);
  const faucetPort = parseInt(new URL(faucetUrl).port, 10);

  return {
    packageId,
    devnetConfig: {
      rpcUrl,
      faucetUrl,
      port,
      faucetPort,
      adminAddress: accounts.admin.address,
      attackerAddress: accounts.attacker.address,
      userAddress: accounts.user.address,
      adminKeyPair: adminB64,
      attackerKeyPair: accounts.attacker.keypair.getSecretKey(),
      userKeyPair: accounts.user.keypair.getSecretKey(),
    },
  };
}

export async function resetState(opts: {
  rpcUrl: string;
  faucetUrl: string;
  contractPath: string;
  accounts: AccountSet;
}): Promise<{ packageId: string }> {
  // Re-publish the contract and re-fund accounts
  // This gives a fresh contract state without full regenesis
  const { packageId } = await seedDevnet(opts);
  return { packageId };
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/devnet/seed.test.ts`
Expected: 2 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/devnet/seed.ts src/devnet/seed.test.ts
git commit -m "feat: devnet seed infrastructure with account generation and contract publishing"
```

---

### Task 7: Easy Test Contracts

**Files:**
- Create: `contracts/easy/capability_leak/sources/vault.move`
- Create: `contracts/easy/capability_leak/Move.toml`
- Create: `contracts/easy/capability_leak/protocol.md`
- Create: `contracts/easy/unchecked_arithmetic/sources/reward_pool.move`
- Create: `contracts/easy/unchecked_arithmetic/Move.toml`
- Create: `contracts/easy/unchecked_arithmetic/protocol.md`

- [ ] **Step 1: Create capability_leak contract structure**

```bash
mkdir -p contracts/easy/capability_leak/sources
```

- [ ] **Step 2: Write capability_leak Move.toml**

Write `contracts/easy/capability_leak/Move.toml`:

```toml
[package]
name = "capability_leak"
edition = "2024.beta"

[dependencies]
Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "framework/testnet" }

[addresses]
capability_leak = "0x0"
```

- [ ] **Step 3: Write capability_leak Move source**

Write `contracts/easy/capability_leak/sources/vault.move`:

```move
module capability_leak::vault {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;

    /// Admin capability — only the deployer should have this.
    public struct AdminCap has key, store {
        id: UID,
    }

    /// Shared vault holding SUI tokens.
    public struct Vault has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// Module initializer — creates one AdminCap for the deployer
    /// and a shared Vault.
    fun init(ctx: &mut TxContext) {
        transfer::transfer(
            AdminCap { id: object::new(ctx) },
            ctx.sender(),
        );
        transfer::share_object(Vault {
            id: object::new(ctx),
            balance: balance::zero(),
        });
    }

    /// Anyone can deposit SUI into the vault.
    public fun deposit(vault: &mut Vault, coin: Coin<SUI>) {
        balance::join(&mut vault.balance, coin::into_balance(coin));
    }

    /// Only admin can withdraw. Requires a reference to AdminCap.
    public fun withdraw(
        _admin: &AdminCap,
        vault: &mut Vault,
        amount: u64,
        ctx: &mut TxContext,
    ): Coin<SUI> {
        coin::take(&mut vault.balance, amount, ctx)
    }

    // ========================================================
    // BUG: This function was intended to return admin "status"
    // (e.g. a boolean), but it accidentally creates and returns
    // a brand new AdminCap to any caller.
    // ========================================================
    public fun request_admin_status(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    /// View the vault balance.
    public fun vault_balance(vault: &Vault): u64 {
        balance::value(&vault.balance)
    }
}
```

- [ ] **Step 4: Write capability_leak protocol.md**

Write `contracts/easy/capability_leak/protocol.md`:

```markdown
# Capability Leak Vault

## Description
A shared vault that holds SUI tokens. Anyone can deposit. Only the admin
(the account that deployed the contract) can withdraw, by presenting their
`AdminCap` capability object.

## Intended Behavior
- `deposit`: Any user can deposit SUI into the vault.
- `withdraw`: Only the holder of an `AdminCap` can withdraw SUI.
- `request_admin_status`: Should return the admin status of the caller.
- `vault_balance`: Anyone can check the vault balance.

## Invariants
- Only the deployer should possess an `AdminCap`.
- No unprivileged user should be able to withdraw funds from the vault.
- The vault balance should only decrease via authorized `withdraw` calls.
```

- [ ] **Step 5: Create unchecked_arithmetic contract structure**

```bash
mkdir -p contracts/easy/unchecked_arithmetic/sources
```

- [ ] **Step 6: Write unchecked_arithmetic Move.toml**

Write `contracts/easy/unchecked_arithmetic/Move.toml`:

```toml
[package]
name = "unchecked_arithmetic"
edition = "2024.beta"

[dependencies]
Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "framework/testnet" }

[addresses]
unchecked_arithmetic = "0x0"
```

- [ ] **Step 7: Write unchecked_arithmetic Move source**

Write `contracts/easy/unchecked_arithmetic/sources/reward_pool.move`:

```move
module unchecked_arithmetic::reward_pool {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;

    /// A pool that accepts deposits and issues shares.
    /// Rewards are added separately by the admin, increasing
    /// the value of each share.
    public struct RewardPool has key {
        id: UID,
        balance: Balance<SUI>,
        total_shares: u64,
    }

    /// Represents a depositor's share of the pool.
    public struct ShareToken has key, store {
        id: UID,
        shares: u64,
    }

    /// Admin capability for adding rewards.
    public struct PoolAdmin has key, store {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(
            PoolAdmin { id: object::new(ctx) },
            ctx.sender(),
        );
        transfer::share_object(RewardPool {
            id: object::new(ctx),
            balance: balance::zero(),
            total_shares: 0,
        });
    }

    /// Deposit SUI and receive proportional shares.
    public fun deposit(
        pool: &mut RewardPool,
        coin: Coin<SUI>,
        ctx: &mut TxContext,
    ): ShareToken {
        let amount = coin::value(&coin);

        let shares = if (pool.total_shares == 0) {
            amount
        } else {
            // BUG: Integer division truncates. If an attacker inflates the
            // share price via add_rewards before other users deposit,
            // new depositors can receive 0 shares while their SUI is
            // still added to the pool. Classic share-inflation / donation attack.
            (amount * pool.total_shares) / balance::value(&pool.balance)
        };

        balance::join(&mut pool.balance, coin::into_balance(coin));
        pool.total_shares = pool.total_shares + shares;

        ShareToken { id: object::new(ctx), shares }
    }

    /// Burn shares and withdraw proportional SUI.
    public fun withdraw(
        pool: &mut RewardPool,
        token: ShareToken,
        ctx: &mut TxContext,
    ): Coin<SUI> {
        let ShareToken { id, shares } = token;
        object::delete(id);

        let amount = (shares * balance::value(&pool.balance)) / pool.total_shares;
        pool.total_shares = pool.total_shares - shares;

        coin::take(&mut pool.balance, amount, ctx)
    }

    /// Admin adds rewards to the pool. Increases value of existing shares.
    /// BUG: Any AdminCap holder can call this, and it does not mint new
    /// shares — so if a single shareholder calls this, they capture
    /// 100% of the added rewards AND can use the inflated share price
    /// to steal from future depositors via truncation.
    public fun add_rewards(
        _admin: &PoolAdmin,
        pool: &mut RewardPool,
        coin: Coin<SUI>,
    ) {
        balance::join(&mut pool.balance, coin::into_balance(coin));
    }

    public fun pool_balance(pool: &RewardPool): u64 {
        balance::value(&pool.balance)
    }

    public fun pool_shares(pool: &RewardPool): u64 {
        pool.total_shares
    }

    public fun share_value(token: &ShareToken): u64 {
        token.shares
    }
}
```

- [ ] **Step 8: Write unchecked_arithmetic protocol.md**

Write `contracts/easy/unchecked_arithmetic/protocol.md`:

```markdown
# Reward Pool

## Description
A staking pool where users deposit SUI and receive share tokens
proportional to their deposit. An admin can add reward tokens to the
pool, increasing the value of each share.

## Intended Behavior
- `deposit`: User deposits SUI, receives shares proportional to their
  contribution relative to the pool's total value.
- `withdraw`: User burns shares, receives proportional SUI back.
- `add_rewards`: Admin adds SUI rewards to increase share value for
  all depositors.

## Invariants
- A depositor should always receive shares proportional to their deposit.
- No depositor should be able to extract more value than they deposited
  plus their fair share of rewards.
- The pool should never lose funds except via legitimate withdrawals.
```

- [ ] **Step 9: Verify contracts compile**

Run: `sui move build --path contracts/easy/capability_leak && sui move build --path contracts/easy/unchecked_arithmetic`
Expected: Both compile successfully. If `sui` CLI dependency resolution differs on the local machine, adjust `Move.toml` `rev` field to match the installed Sui version (`sui --version` to check).

- [ ] **Step 10: Commit**

```bash
git add contracts/easy/
git commit -m "feat: easy tier test contracts — capability_leak and unchecked_arithmetic"
```

---

### Task 8: Medium Test Contracts

**Files:**
- Create: `contracts/medium/ownership_escape/sources/marketplace.move`
- Create: `contracts/medium/ownership_escape/Move.toml`
- Create: `contracts/medium/ownership_escape/protocol.md`
- Create: `contracts/medium/flash_loan_misuse/sources/lending_pool.move`
- Create: `contracts/medium/flash_loan_misuse/Move.toml`
- Create: `contracts/medium/flash_loan_misuse/protocol.md`

- [ ] **Step 1: Create ownership_escape structure**

```bash
mkdir -p contracts/medium/ownership_escape/sources
```

- [ ] **Step 2: Write ownership_escape Move.toml**

Write `contracts/medium/ownership_escape/Move.toml`:

```toml
[package]
name = "ownership_escape"
edition = "2024.beta"

[dependencies]
Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "framework/testnet" }

[addresses]
ownership_escape = "0x0"
```

- [ ] **Step 3: Write ownership_escape Move source**

Write `contracts/medium/ownership_escape/sources/marketplace.move`:

```move
module ownership_escape::marketplace {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;

    /// A generic item that users can list for sale.
    public struct Item has key, store {
        id: UID,
        name: vector<u8>,
        value: u64,
    }

    /// A listing in the marketplace. Holds the item and metadata.
    public struct Listing has key {
        id: UID,
        item_id: ID,
        seller: address,
        price: u64,
        item: Item,
    }

    /// Shared marketplace state.
    public struct Marketplace has key {
        id: UID,
        fee_bps: u64, // basis points
        balance: Balance<SUI>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Marketplace {
            id: object::new(ctx),
            fee_bps: 250, // 2.5% fee
            balance: balance::zero(),
        });
    }

    /// Mint a new item (for testing).
    public fun mint_item(
        name: vector<u8>,
        value: u64,
        ctx: &mut TxContext,
    ): Item {
        Item {
            id: object::new(ctx),
            name,
            value,
        }
    }

    /// List an item for sale. Transfers the item into the listing.
    public fun list_item(
        item: Item,
        price: u64,
        ctx: &mut TxContext,
    ): Listing {
        let item_id = object::id(&item);
        Listing {
            id: object::new(ctx),
            item_id,
            seller: ctx.sender(),
            price,
            item,
        }
    }

    /// Buy a listed item. Pays the seller minus marketplace fee.
    public fun buy_item(
        marketplace: &mut Marketplace,
        listing: Listing,
        payment: Coin<SUI>,
        ctx: &mut TxContext,
    ): Item {
        let Listing { id, item_id: _, seller, price, item } = listing;
        object::delete(id);

        assert!(coin::value(&payment) >= price, 0);

        let fee = (price * marketplace.fee_bps) / 10000;
        let fee_coin = coin::split(&mut payment, fee, ctx);
        balance::join(&mut marketplace.balance, coin::into_balance(fee_coin));

        transfer::public_transfer(payment, seller);
        item
    }

    /// Cancel a listing and get the item back.
    /// BUG: Checks seller by the stored address field instead of
    /// using Sui's object ownership model. Since listings are
    /// objects (not owned — they're created then shared/transferred),
    /// an attacker can call cancel_listing on any listing if they
    /// can get a reference to it, because the "sender == seller"
    /// check can be bypassed: the attacker just needs to be the
    /// tx sender, and the function doesn't actually verify ownership
    /// of the Listing object through Sui's type system.
    /// 
    /// The real fix would be to make Listing an owned object
    /// transferred to the seller, so only the owner can pass it
    /// as a function argument.
    public fun cancel_listing(
        listing: Listing,
        ctx: &mut TxContext,
    ): Item {
        let Listing { id, item_id: _, seller: _, price: _, item } = listing;
        object::delete(id);
        // BUG: No ownership check at all! Anyone who can reference
        // this listing can cancel it and take the item.
        // Should be: assert!(ctx.sender() == seller, ENotSeller);
        item
    }
}
```

- [ ] **Step 4: Write ownership_escape protocol.md**

Write `contracts/medium/ownership_escape/protocol.md`:

```markdown
# Marketplace

## Description
A peer-to-peer marketplace where users list items for sale. Buyers pay
SUI to purchase listed items. The marketplace takes a 2.5% fee.

## Intended Behavior
- `mint_item`: Create a new item (for testing purposes).
- `list_item`: Seller lists an item at a price. Item is held by the listing.
- `buy_item`: Buyer pays the listed price. Seller receives payment minus fee.
- `cancel_listing`: Only the original seller can cancel and reclaim their item.

## Invariants
- Only the seller who listed an item can cancel that listing.
- A buyer must pay at least the listed price to purchase an item.
- Items in active listings cannot be taken without paying or being the seller.
```

- [ ] **Step 5: Create flash_loan_misuse structure**

```bash
mkdir -p contracts/medium/flash_loan_misuse/sources
```

- [ ] **Step 6: Write flash_loan_misuse Move.toml**

Write `contracts/medium/flash_loan_misuse/Move.toml`:

```toml
[package]
name = "flash_loan_misuse"
edition = "2024.beta"

[dependencies]
Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "framework/testnet" }

[addresses]
flash_loan_misuse = "0x0"
```

- [ ] **Step 7: Write flash_loan_misuse Move source**

Write `contracts/medium/flash_loan_misuse/sources/lending_pool.move`:

```move
module flash_loan_misuse::lending_pool {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;

    /// The lending pool holding SUI.
    public struct LendingPool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// Hot potato — must be consumed by `repay` in the same transaction.
    /// Cannot be stored, copied, or dropped.
    public struct FlashLoanReceipt {
        pool_id: ID,
        borrow_amount: u64,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(LendingPool {
            id: object::new(ctx),
            balance: balance::zero(),
        });
    }

    /// Deposit SUI into the pool (liquidity provision).
    public fun provide_liquidity(
        pool: &mut LendingPool,
        coin: Coin<SUI>,
    ) {
        balance::join(&mut pool.balance, coin::into_balance(coin));
    }

    /// Borrow SUI via flash loan. Returns borrowed coin + receipt.
    /// Receipt MUST be consumed by `repay` in the same transaction.
    public fun borrow(
        pool: &mut LendingPool,
        amount: u64,
        ctx: &mut TxContext,
    ): (Coin<SUI>, FlashLoanReceipt) {
        assert!(balance::value(&pool.balance) >= amount, 0);

        let coin = coin::take(&mut pool.balance, amount, ctx);
        let receipt = FlashLoanReceipt {
            pool_id: object::id(pool),
            borrow_amount: amount,
        };

        (coin, receipt)
    }

    /// Repay a flash loan. Consumes the receipt (hot potato).
    /// BUG: Checks that repaid amount >= borrowed amount, but does NOT
    /// verify the coin type. The function accepts Coin<SUI> in the type
    /// signature, but due to how the pool_id check works, an attacker
    /// could potentially construct a scenario where they repay with
    /// coins obtained from elsewhere while keeping the borrowed funds.
    ///
    /// More critically: the function doesn't verify that the pool's
    /// balance actually increased by the borrow amount. It just checks
    /// the repayment coin value.
    public fun repay(
        pool: &mut LendingPool,
        receipt: FlashLoanReceipt,
        repayment: Coin<SUI>,
    ) {
        let FlashLoanReceipt { pool_id, borrow_amount } = receipt;
        assert!(object::id(pool) == pool_id, 1);
        // BUG: Only checks value, not that pool balance is restored.
        // An attacker who borrows X and already has Y >= X in SUI
        // can repay with their existing Y, keeping the borrowed X.
        assert!(coin::value(&repayment) >= borrow_amount, 2);
        balance::join(&mut pool.balance, coin::into_balance(repayment));
    }

    public fun pool_balance(pool: &LendingPool): u64 {
        balance::value(&pool.balance)
    }
}
```

- [ ] **Step 8: Write flash_loan_misuse protocol.md**

Write `contracts/medium/flash_loan_misuse/protocol.md`:

```markdown
# Flash Loan Lending Pool

## Description
A lending pool that supports flash loans using the hot potato pattern.
Users can borrow SUI within a single transaction as long as they repay
the full amount before the transaction completes.

## Intended Behavior
- `provide_liquidity`: Anyone can deposit SUI to grow the pool.
- `borrow`: Borrow SUI and receive a receipt (hot potato). Must repay
  in the same transaction.
- `repay`: Return borrowed SUI and consume the receipt. Pool balance
  must be at least as large after repayment as before borrowing.

## Invariants
- The pool balance after a flash loan transaction must be >= the balance before.
- The borrower must return at least the borrowed amount from the loan itself.
- No user should be able to profit from a flash loan without an external
  arbitrage source — the pool itself should never lose funds.
```

- [ ] **Step 9: Verify contracts compile**

Run: `sui move build --path contracts/medium/ownership_escape && sui move build --path contracts/medium/flash_loan_misuse`
Expected: Both compile. Adjust Move.toml rev if needed.

- [ ] **Step 10: Commit**

```bash
git add contracts/medium/
git commit -m "feat: medium tier test contracts — ownership_escape and flash_loan_misuse"
```

---

### Task 9: Hard Test Contracts

**Files:**
- Create: `contracts/hard/shared_object_race/sources/auction.move`
- Create: `contracts/hard/shared_object_race/Move.toml`
- Create: `contracts/hard/shared_object_race/protocol.md`
- Create: `contracts/hard/otw_abuse/sources/token.move`
- Create: `contracts/hard/otw_abuse/Move.toml`
- Create: `contracts/hard/otw_abuse/protocol.md`

- [ ] **Step 1: Create shared_object_race structure**

```bash
mkdir -p contracts/hard/shared_object_race/sources
```

- [ ] **Step 2: Write shared_object_race Move.toml**

Write `contracts/hard/shared_object_race/Move.toml`:

```toml
[package]
name = "shared_object_race"
edition = "2024.beta"

[dependencies]
Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "framework/testnet" }

[addresses]
shared_object_race = "0x0"
```

- [ ] **Step 3: Write shared_object_race Move source**

Write `contracts/hard/shared_object_race/sources/auction.move`:

```move
module shared_object_race::auction {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::clock::Clock;

    /// Shared auction object.
    public struct Auction has key {
        id: UID,
        seller: address,
        end_time_ms: u64,
        highest_bid: u64,
        highest_bidder: address,
        balance: Balance<SUI>,
        settled: bool,
    }

    /// Receipt returned to outbid bidders so they can claim refund.
    public struct BidReceipt has key, store {
        id: UID,
        auction_id: ID,
        bidder: address,
        amount: u64,
    }

    public fun create_auction(
        end_time_ms: u64,
        ctx: &mut TxContext,
    ) {
        transfer::share_object(Auction {
            id: object::new(ctx),
            seller: ctx.sender(),
            end_time_ms,
            highest_bid: 0,
            highest_bidder: @0x0,
            balance: balance::zero(),
            settled: false,
        });
    }

    /// Place a bid. Must be higher than current highest bid.
    public fun bid(
        auction: &mut Auction,
        payment: Coin<SUI>,
        clock: &Clock,
        ctx: &mut TxContext,
    ): Option<BidReceipt> {
        assert!(!auction.settled, 0);
        assert!(clock.timestamp_ms() < auction.end_time_ms, 1);

        let bid_amount = coin::value(&payment);
        assert!(bid_amount > auction.highest_bid, 2);

        // Create refund receipt for the previous highest bidder
        let prev_receipt = if (auction.highest_bid > 0) {
            option::some(BidReceipt {
                id: object::new(ctx),
                auction_id: object::id(auction),
                bidder: auction.highest_bidder,
                amount: auction.highest_bid,
            })
        } else {
            option::none()
        };

        // Accept the new bid
        balance::join(&mut auction.balance, coin::into_balance(payment));
        auction.highest_bid = bid_amount;
        auction.highest_bidder = ctx.sender();

        prev_receipt
    }

    /// Settle the auction. Pays the seller.
    /// BUG: Does not check that the auction time has actually ended.
    /// Also reads highest_bid and then transfers, but since this is
    /// a shared object, a concurrent `bid` transaction could change
    /// highest_bid between when settle reads it and when the transfer
    /// happens. On Sui, shared object txs are sequenced, but the
    /// settle function pays the FULL balance to seller, not just the
    /// winning bid amount. So if a new bid arrives and is sequenced
    /// before settle, the extra bid funds go to the seller too, and
    /// the new bidder has no recourse.
    public fun settle(
        auction: &mut Auction,
        ctx: &mut TxContext,
    ) {
        // BUG: No time check — anyone can settle at any time
        // Should be: assert!(clock.timestamp_ms() >= auction.end_time_ms, 3);
        assert!(!auction.settled, 4);

        auction.settled = true;

        // BUG: Transfers ENTIRE balance, not just highest_bid amount.
        // If a bid was sequenced between reading highest_bid and here,
        // the extra funds are lost to the bidder.
        let total = balance::value(&auction.balance);
        let payment = coin::take(&mut auction.balance, total, ctx);
        transfer::public_transfer(payment, auction.seller);
    }

    /// Claim refund using a bid receipt.
    /// BUG: Doesn't actually refund from the auction's balance —
    /// it would need to, but since settle drains the full balance,
    /// there may be nothing left to refund.
    public fun claim_refund(
        auction: &mut Auction,
        receipt: BidReceipt,
        ctx: &mut TxContext,
    ): Coin<SUI> {
        let BidReceipt { id, auction_id, bidder: _, amount } = receipt;
        object::delete(id);
        assert!(object::id(auction) == auction_id, 5);
        // This will abort if balance is insufficient (drained by settle)
        coin::take(&mut auction.balance, amount, ctx)
    }
}
```

- [ ] **Step 4: Write shared_object_race protocol.md**

Write `contracts/hard/shared_object_race/protocol.md`:

```markdown
# Auction

## Description
A shared-object auction where users place SUI bids. The highest bidder
wins when the auction is settled. Outbid users receive receipts to
claim refunds.

## Intended Behavior
- `create_auction`: Create a new auction with an end time.
- `bid`: Place a bid higher than the current highest. Previous high bidder
  gets a refund receipt.
- `settle`: After the end time, finalize the auction. Pay the seller the
  winning bid amount.
- `claim_refund`: Outbid users redeem their receipt for a refund.

## Invariants
- The auction can only be settled after the end time.
- The seller receives exactly the highest bid amount, no more.
- All outbid users can claim full refunds of their bid amounts.
- No funds should be lost or trapped in the contract.
```

- [ ] **Step 5: Create otw_abuse structure**

```bash
mkdir -p contracts/hard/otw_abuse/sources
```

- [ ] **Step 6: Write otw_abuse Move.toml**

Write `contracts/hard/otw_abuse/Move.toml`:

```toml
[package]
name = "otw_abuse"
edition = "2024.beta"

[dependencies]
Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "framework/testnet" }

[addresses]
otw_abuse = "0x0"
```

- [ ] **Step 7: Write otw_abuse Move source**

Write `contracts/hard/otw_abuse/sources/token.move`:

```move
module otw_abuse::token {
    use sui::coin::{Self, TreasuryCap, CoinMetadata};
    use sui::url;

    /// The one-time witness type. Named after the module.
    public struct TOKEN has drop {}

    /// Wrapper so we can share the treasury cap.
    public struct TreasuryCapHolder has key {
        id: UID,
        cap: TreasuryCap<TOKEN>,
    }

    /// Module initializer — creates the coin using OTW.
    fun init(witness: TOKEN, ctx: &mut TxContext) {
        let (treasury_cap, metadata) = coin::create_currency(
            witness,
            9, // decimals
            b"TKN",
            b"Token",
            b"A sample token",
            option::some(url::new_unsafe_from_bytes(b"https://example.com/icon.png")),
            ctx,
        );

        transfer::public_freeze_object(metadata);

        // Share the treasury cap holder so authorized minters can access it
        transfer::share_object(TreasuryCapHolder {
            id: object::new(ctx),
            cap: treasury_cap,
        });
    }

    /// Mint new tokens.
    /// BUG: This function is supposed to be admin-only, but there is
    /// no access control check at all. Anyone can call this and mint
    /// unlimited tokens because the TreasuryCapHolder is a shared object.
    /// 
    /// The OTW pattern correctly protects `create_currency` (called only
    /// in `init`), but sharing the TreasuryCapHolder without a gating
    /// capability makes the mint function open to everyone.
    public fun mint(
        holder: &mut TreasuryCapHolder,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext,
    ) {
        let coin = coin::mint(&mut holder.cap, amount, ctx);
        transfer::public_transfer(coin, recipient);
    }

    /// Burn tokens.
    public fun burn(
        holder: &mut TreasuryCapHolder,
        coin: coin::Coin<TOKEN>,
    ) {
        coin::burn(&mut holder.cap, coin);
    }

    public fun total_supply(holder: &TreasuryCapHolder): u64 {
        coin::total_supply(&holder.cap)
    }
}
```

- [ ] **Step 8: Write otw_abuse protocol.md**

Write `contracts/hard/otw_abuse/protocol.md`:

```markdown
# Token (OTW Pattern)

## Description
A fungible token created using Sui's one-time witness pattern. The OTW
ensures that `create_currency` can only be called once during module
publication. A TreasuryCapHolder is shared to allow authorized minting.

## Intended Behavior
- `init`: Creates the TOKEN currency using the OTW, freezes metadata,
  shares the treasury cap holder.
- `mint`: Only authorized admins can mint new tokens.
- `burn`: Token holders can burn their tokens.

## Invariants
- Only authorized accounts should be able to mint new tokens.
- The OTW pattern must prevent creation of a second currency.
- Total supply should only increase via authorized mints.
- No unprivileged user should be able to inflate the token supply.
```

- [ ] **Step 9: Verify contracts compile**

Run: `sui move build --path contracts/hard/shared_object_race && sui move build --path contracts/hard/otw_abuse`
Expected: Both compile. Adjust Move.toml rev if needed.

- [ ] **Step 10: Commit**

```bash
git add contracts/hard/
git commit -m "feat: hard tier test contracts — shared_object_race and otw_abuse"
```

---

### Task 10: Hunter Prompt Template

**Files:**
- Create: `src/hunter/prompt.ts`
- Test: `src/hunter/prompt.test.ts`

- [ ] **Step 1: Write prompt template tests**

Write `src/hunter/prompt.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { buildHunterPrompt } from "./prompt.js";

describe("buildHunterPrompt", () => {
  it("includes module name and source", () => {
    const prompt = buildHunterPrompt({
      moduleName: "test::vault",
      moduleSource: "module test::vault { }",
      protocolDescription: "A vault contract",
      invariants: ["only admin can withdraw"],
      attackerAddress: "0xattacker",
      adminAddress: "0xadmin",
      userAddress: "0xuser",
      rpcUrl: "http://127.0.0.1:9100",
      packageId: "0xpkg",
    });
    expect(prompt).toContain("test::vault");
    expect(prompt).toContain("module test::vault { }");
    expect(prompt).toContain("only admin can withdraw");
    expect(prompt).toContain("0xattacker");
    expect(prompt).toContain("http://127.0.0.1:9100");
    expect(prompt).toContain("0xpkg");
  });

  it("formats multiple invariants as a list", () => {
    const prompt = buildHunterPrompt({
      moduleName: "test::mod",
      moduleSource: "source",
      protocolDescription: "desc",
      invariants: ["inv1", "inv2", "inv3"],
      attackerAddress: "0xa",
      adminAddress: "0xb",
      userAddress: "0xc",
      rpcUrl: "http://127.0.0.1:9100",
      packageId: "0xpkg",
    });
    expect(prompt).toContain("- inv1");
    expect(prompt).toContain("- inv2");
    expect(prompt).toContain("- inv3");
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/hunter/prompt.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement hunter prompt template**

Write `src/hunter/prompt.ts`:

```typescript
export interface HunterPromptInput {
  moduleName: string;
  moduleSource: string;
  protocolDescription: string;
  invariants: string[];
  attackerAddress: string;
  adminAddress: string;
  userAddress: string;
  rpcUrl: string;
  packageId: string;
}

export function buildHunterPrompt(input: HunterPromptInput): string {
  const invariantList = input.invariants.map((inv) => `- ${inv}`).join("\n");

  return `You are auditing a Sui Move smart contract module for security vulnerabilities.

## Target
Module: ${input.moduleName}
Package ID: ${input.packageId}
Protocol description: ${input.protocolDescription}

Invariants:
${invariantList}

## Source
\`\`\`move
${input.moduleSource}
\`\`\`

## Environment
- Sui devnet RPC: ${input.rpcUrl}
- Attacker address: ${input.attackerAddress}
- Admin address: ${input.adminAddress}
- User address: ${input.userAddress}
- Sui CLI and @mysten/sui TS SDK are available
- Use \`npx tsx\` to run TypeScript files

## Oracle
To check if an exploit works, write a TS file that exports:
- \`buildTx(client: SuiClient, attackerAddress: string)\` — returns a Transaction
- \`attackerKeypair\` — the Ed25519Keypair for the attacker

Then run:
\`\`\`bash
npx tsx src/oracle/check.ts --signal <abort|balance|ownership> --tx <path-to-your-exploit.ts> --attacker ${input.attackerAddress} --rpc-url ${input.rpcUrl}
\`\`\`

Signals:
- \`abort\` — use when a tx SHOULD fail but succeeds (access control bypass). Add \`--expected should_abort\`
- \`balance\` — use when the attacker's balance increases (fund drain)
- \`ownership\` — use when the attacker gains objects they shouldn't own

Returns: EXPLOIT_CONFIRMED or NO_EXPLOIT

## Task
Find a vulnerability in this module and confirm it with the oracle.
Write exploit transactions as TS files, run them via dry-run, check with the oracle.
Iterate until you find something or exhaust your ideas.
When done, write your findings to findings.json in this format:
\`\`\`json
[{
  "id": "unique-id",
  "module": "${input.moduleName}",
  "severity": "critical|high|medium|low",
  "category": "capability_misuse|shared_object_race|integer_overflow|ownership_violation|hot_potato_misuse|otw_abuse|other",
  "title": "Short title",
  "description": "What the bug is and how to exploit it",
  "exploitTransaction": "// the TS exploit code",
  "oracleResult": { /* paste oracle output */ },
  "iterations": 3
}]
\`\`\``;
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/hunter/prompt.test.ts`
Expected: 2 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/hunter/prompt.ts src/hunter/prompt.test.ts
git commit -m "feat: hunter agent prompt template"
```

---

### Task 11: Ranker Module

**Files:**
- Create: `src/ranker/index.ts`
- Test: `src/ranker/ranker.test.ts`

- [ ] **Step 1: Write ranker tests**

Write `src/ranker/ranker.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { buildRankerPrompt, parseRankerResponse } from "./index.js";

describe("buildRankerPrompt", () => {
  it("includes all module sources with headers", () => {
    const prompt = buildRankerPrompt([
      { name: "mod_a", source: "module a {}", path: "/a" },
      { name: "mod_b", source: "module b {}", path: "/b" },
    ]);
    expect(prompt).toContain("mod_a");
    expect(prompt).toContain("module a {}");
    expect(prompt).toContain("mod_b");
    expect(prompt).toContain("module b {}");
  });
});

describe("parseRankerResponse", () => {
  it("parses valid JSON array of ModuleScore", () => {
    const response = JSON.stringify([
      {
        module: "test::vault",
        score: 5,
        rationale: "handles coin transfers",
        attackSurface: ["coin transfers", "admin cap"],
      },
    ]);
    const scores = parseRankerResponse(response);
    expect(scores).toHaveLength(1);
    expect(scores[0].module).toBe("test::vault");
    expect(scores[0].score).toBe(5);
  });

  it("extracts JSON from markdown code blocks", () => {
    const response = `Here are the scores:\n\`\`\`json\n[{"module":"a","score":3,"rationale":"low risk","attackSurface":[]}]\n\`\`\``;
    const scores = parseRankerResponse(response);
    expect(scores).toHaveLength(1);
    expect(scores[0].score).toBe(3);
  });

  it("throws on invalid response", () => {
    expect(() => parseRankerResponse("not json")).toThrow();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/ranker/ranker.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement ranker module**

Write `src/ranker/index.ts`:

```typescript
import type { ModuleInfo, ModuleScore } from "../types.js";

export function buildRankerPrompt(modules: ModuleInfo[]): string {
  const moduleBlocks = modules
    .map(
      (m) => `### Module: ${m.name}\n\`\`\`move\n${m.source}\n\`\`\``
    )
    .join("\n\n");

  return `You are a smart contract security analyst. Score each module in this Sui Move project from 1-5 for attack surface. Consider:

- Coin/token transfers or minting
- Shared objects (concurrent access)
- Admin capabilities or access control
- External inputs / user-supplied arguments
- Object ownership transfers
- Arithmetic on balances or amounts
- Flash loan / hot potato patterns
- One-time witness usage

For each module, return a JSON object with: module name, score (1-5), rationale, and list of attack surface areas.

Return ONLY a JSON array of ModuleScore objects with this shape:
{ "module": string, "score": number, "rationale": string, "attackSurface": string[] }

## Modules

${moduleBlocks}`;
}

export function parseRankerResponse(response: string): ModuleScore[] {
  // Try to extract JSON from markdown code block
  const codeBlockMatch = response.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  const jsonStr = codeBlockMatch ? codeBlockMatch[1].trim() : response.trim();

  const parsed = JSON.parse(jsonStr);

  if (!Array.isArray(parsed)) {
    throw new Error("Ranker response must be a JSON array");
  }

  return parsed.map((item: Record<string, unknown>) => ({
    module: String(item.module),
    score: Number(item.score),
    rationale: String(item.rationale),
    attackSurface: Array.isArray(item.attackSurface)
      ? item.attackSurface.map(String)
      : [],
  }));
}

export function filterHighPriority(scores: ModuleScore[]): ModuleScore[] {
  return scores.filter((s) => s.score >= 4);
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/ranker/ranker.test.ts`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/ranker/index.ts src/ranker/ranker.test.ts
git commit -m "feat: ranker module with prompt builder and response parser"
```

---

### Task 12: Validator Module

**Files:**
- Create: `src/validator/index.ts`
- Test: `src/validator/validator.test.ts`

- [ ] **Step 1: Write validator tests**

Write `src/validator/validator.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { buildValidatorPrompt, parseValidatorResponse } from "./index.js";
import type { Finding, ModuleInfo } from "../types.js";

const sampleFinding: Finding = {
  id: "f1",
  module: "test::vault",
  severity: "critical",
  category: "capability_misuse",
  title: "AdminCap leak",
  description: "Anyone can get an AdminCap",
  exploitTransaction: "// exploit code",
  oracleResult: {
    signal: "abort",
    status: "EXPLOIT_CONFIRMED",
    preTxState: {},
    postTxState: {},
  },
  iterations: 2,
};

describe("buildValidatorPrompt", () => {
  it("includes findings and source code", () => {
    const prompt = buildValidatorPrompt(
      [sampleFinding],
      [{ name: "test::vault", source: "module code", path: "/p" }]
    );
    expect(prompt).toContain("AdminCap leak");
    expect(prompt).toContain("module code");
  });
});

describe("parseValidatorResponse", () => {
  it("parses validated findings with verdict", () => {
    const response = JSON.stringify([
      {
        ...sampleFinding,
        validatorVerdict: "confirmed",
        validatorNote: "Verified — real vulnerability",
      },
    ]);
    const validated = parseValidatorResponse(response);
    expect(validated).toHaveLength(1);
    expect(validated[0].validatorVerdict).toBe("confirmed");
  });

  it("handles adjusted severity", () => {
    const response = JSON.stringify([
      {
        ...sampleFinding,
        validatorVerdict: "adjusted",
        validatorNote: "Not critical, downgraded",
        adjustedSeverity: "medium",
      },
    ]);
    const validated = parseValidatorResponse(response);
    expect(validated[0].adjustedSeverity).toBe("medium");
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/validator/validator.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement validator module**

Write `src/validator/index.ts`:

```typescript
import type { Finding, ModuleInfo, ValidatedFinding } from "../types.js";

export function buildValidatorPrompt(
  findings: Finding[],
  modules: ModuleInfo[]
): string {
  const moduleBlocks = modules
    .map((m) => `### ${m.name}\n\`\`\`move\n${m.source}\n\`\`\``)
    .join("\n\n");

  return `You are a senior smart contract security auditor performing final review.

## Findings
\`\`\`json
${JSON.stringify(findings, null, 2)}
\`\`\`

## Source Code
${moduleBlocks}

For each finding, evaluate:
1. Is the exploit transaction valid Move/Sui TS code?
2. Does the oracle result actually confirm the claimed vulnerability?
3. Is the severity rating accurate?
4. Is this a real bug or a test artifact (e.g. exploiting the test setup, not the contract)?
5. Could this be triggered in a real deployment or only in the test environment?

Return a JSON array. For each finding include all original fields plus:
- "validatorVerdict": "confirmed" | "adjusted" | "rejected"
- "validatorNote": explanation of your decision
- "adjustedSeverity": (only if verdict is "adjusted") the corrected severity

Return ONLY a JSON array.`;
}

export function parseValidatorResponse(response: string): ValidatedFinding[] {
  const codeBlockMatch = response.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  const jsonStr = codeBlockMatch ? codeBlockMatch[1].trim() : response.trim();

  const parsed = JSON.parse(jsonStr);

  if (!Array.isArray(parsed)) {
    throw new Error("Validator response must be a JSON array");
  }

  return parsed as ValidatedFinding[];
}

export function filterConfirmed(findings: ValidatedFinding[]): ValidatedFinding[] {
  return findings.filter((f) => f.validatorVerdict !== "rejected");
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/validator/validator.test.ts`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/validator/index.ts src/validator/validator.test.ts
git commit -m "feat: validator module with prompt builder and response parser"
```

---

### Task 13: Hunter Agent Spawner

**Files:**
- Create: `src/hunter/index.ts`

- [ ] **Step 1: Implement hunter spawner**

This module provides the function the pipeline calls to spawn a hunter agent. Since we're using Claude Code's Agent tool, this module prepares all the context and writes a launch script.

Write `src/hunter/index.ts`:

```typescript
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildHunterPrompt, type HunterPromptInput } from "./prompt.js";
import type { ModuleInfo, Finding, DevnetConfig } from "../types.js";

export interface HunterInput {
  module: ModuleInfo;
  devnetConfig: DevnetConfig;
  packageId: string;
}

export function prepareHunterPrompt(input: HunterInput): string {
  return buildHunterPrompt({
    moduleName: input.module.name,
    moduleSource: input.module.source,
    protocolDescription: input.module.protocolDescription ?? "No description provided.",
    invariants: input.module.invariants ?? [],
    attackerAddress: input.devnetConfig.attackerAddress,
    adminAddress: input.devnetConfig.adminAddress,
    userAddress: input.devnetConfig.userAddress,
    rpcUrl: input.devnetConfig.rpcUrl,
    packageId: input.packageId,
  });
}

export async function collectFindings(worktreePath: string): Promise<Finding[]> {
  try {
    const findingsPath = resolve(worktreePath, "findings.json");
    const content = await readFile(findingsPath, "utf-8");
    return JSON.parse(content) as Finding[];
  } catch {
    return [];
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/hunter/index.ts
git commit -m "feat: hunter agent spawner with prompt preparation and findings collection"
```

---

### Task 14: Pipeline Orchestrator & CLI

**Files:**
- Create: `src/pipeline.ts`
- Create: `src/cli.ts`

- [ ] **Step 1: Implement the pipeline module**

Write `src/pipeline.ts`:

```typescript
import { readFile, readdir } from "node:fs/promises";
import { resolve, join } from "node:path";
import type {
  ModuleInfo,
  ModuleScore,
  Finding,
  ValidatedFinding,
  ScanResult,
} from "./types.js";
import { buildRankerPrompt, parseRankerResponse, filterHighPriority } from "./ranker/index.js";
import { buildValidatorPrompt, parseValidatorResponse, filterConfirmed } from "./validator/index.js";
import { prepareHunterPrompt } from "./hunter/index.js";

export async function resolveModules(targetPath: string): Promise<ModuleInfo[]> {
  const sourcesDir = resolve(targetPath, "sources");
  const files = await readdir(sourcesDir);
  const moveFiles = files.filter((f) => f.endsWith(".move"));

  const modules: ModuleInfo[] = [];
  for (const file of moveFiles) {
    const filePath = join(sourcesDir, file);
    const source = await readFile(filePath, "utf-8");

    // Extract module name from source
    const moduleMatch = source.match(/module\s+([\w:]+)/);
    const name = moduleMatch ? moduleMatch[1] : file.replace(".move", "");

    // Try to read protocol.md for description and invariants
    let protocolDescription: string | undefined;
    let invariants: string[] | undefined;
    try {
      const protocolPath = resolve(targetPath, "protocol.md");
      const protocol = await readFile(protocolPath, "utf-8");

      const descMatch = protocol.match(/## Description\n([\s\S]*?)(?=\n## )/);
      if (descMatch) protocolDescription = descMatch[1].trim();

      const invMatch = protocol.match(/## Invariants\n([\s\S]*?)$/);
      if (invMatch) {
        invariants = invMatch[1]
          .split("\n")
          .filter((l) => l.startsWith("- "))
          .map((l) => l.replace(/^- /, "").trim());
      }
    } catch {
      // No protocol.md — hunter will work without it
    }

    modules.push({ name, source, path: filePath, protocolDescription, invariants });
  }

  return modules;
}

export interface PipelineContext {
  target: string;
  modules: ModuleInfo[];
  rankerScores: ModuleScore[];
  hunterTargets: ModuleInfo[];
  rawFindings: Finding[];
  findings: ValidatedFinding[];
}

export function buildPipelineContext(target: string, modules: ModuleInfo[]): PipelineContext {
  return {
    target,
    modules,
    rankerScores: [],
    hunterTargets: [],
    rawFindings: [],
    findings: [],
  };
}

export function shouldSkipRanker(modules: ModuleInfo[]): boolean {
  return modules.length <= 3;
}

export function buildScanResult(ctx: PipelineContext): ScanResult {
  return {
    target: ctx.target,
    timestamp: new Date().toISOString(),
    modulesScanned: ctx.modules.length,
    modulesHunted: ctx.hunterTargets.length,
    findings: ctx.findings,
    rawFindings: ctx.rawFindings,
    rankerScores: ctx.rankerScores,
  };
}
```

- [ ] **Step 2: Implement the CLI entry point**

Write `src/cli.ts`:

```typescript
#!/usr/bin/env node
import { Command } from "commander";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  resolveModules,
  buildPipelineContext,
  shouldSkipRanker,
  buildScanResult,
} from "./pipeline.js";
import { buildRankerPrompt } from "./ranker/index.js";
import { prepareHunterPrompt } from "./hunter/index.js";
import { buildValidatorPrompt } from "./validator/index.js";

const program = new Command();

program
  .name("suixploit")
  .description("Multi-agent Sui Move vulnerability discovery pipeline")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a Move project or deployed package for vulnerabilities")
  .argument("<target>", "Path to Move project or on-chain package address")
  .option("--network <network>", "Network for on-chain targets (mainnet, testnet)")
  .option("--protocol <description>", "Protocol description for closed-source targets")
  .option("--invariants <invariants...>", "Invariants to test against")
  .option("--config <path>", "Path to config file with protocol and invariants")
  .action(async (target: string, options) => {
    // Load config file if provided
    let protocol = options.protocol;
    let invariants = options.invariants;
    if (options.config) {
      const config = JSON.parse(readFileSync(resolve(options.config), "utf-8"));
      protocol = protocol ?? config.protocol;
      invariants = invariants ?? config.invariants;
    }

    // Resolve modules
    const modules = await resolveModules(resolve(target));
    if (modules.length === 0) {
      console.error("No Move modules found in target path.");
      process.exit(1);
    }

    // Apply config overrides to modules
    if (protocol || invariants) {
      for (const mod of modules) {
        if (protocol) mod.protocolDescription = protocol;
        if (invariants) mod.invariants = invariants;
      }
    }

    const ctx = buildPipelineContext(target, modules);

    // Output pipeline context for Claude Code orchestration
    console.log("=== SUIXPLOIT PIPELINE ===");
    console.log(`Target: ${target}`);
    console.log(`Modules found: ${modules.length}`);
    console.log();

    if (shouldSkipRanker(modules)) {
      console.log("Skipping ranker (<=3 modules). Hunting all modules.");
      ctx.hunterTargets = modules;
    } else {
      console.log("=== RANKER PROMPT ===");
      console.log(buildRankerPrompt(modules));
      console.log("=== END RANKER PROMPT ===");
      console.log();
      console.log("Feed the ranker prompt to Claude, then set hunterTargets to modules scoring 4-5.");
    }

    console.log();
    console.log("=== HUNTER PROMPTS ===");
    for (const mod of ctx.hunterTargets.length > 0 ? ctx.hunterTargets : modules) {
      console.log(`\n--- Hunter for: ${mod.name} ---`);
      console.log("Prompt preview (first 200 chars):");
      const prompt = prepareHunterPrompt({
        module: mod,
        devnetConfig: {
          rpcUrl: "http://127.0.0.1:9100",
          faucetUrl: "http://127.0.0.1:9123",
          port: 9100,
          faucetPort: 9123,
          adminAddress: "<to be generated>",
          attackerAddress: "<to be generated>",
          userAddress: "<to be generated>",
          adminKeyPair: "",
          attackerKeyPair: "",
          userKeyPair: "",
        },
        packageId: "<to be set after deploy>",
      });
      console.log(prompt.slice(0, 200) + "...");
    }

    console.log("\n=== PIPELINE READY ===");
    console.log("Use Claude Code with CLAUDE.md to orchestrate the full pipeline.");
  });

program.parse();
```

- [ ] **Step 3: Verify CLI runs**

Run: `npx tsx src/cli.ts scan contracts/easy/capability_leak`
Expected: Output showing pipeline context, module found, and hunter prompt preview.

- [ ] **Step 4: Commit**

```bash
git add src/pipeline.ts src/cli.ts
git commit -m "feat: pipeline orchestrator and CLI entry point"
```

---

### Task 15: CLAUDE.md — Orchestration Instructions

**Files:**
- Create: `CLAUDE.md`

- [ ] **Step 1: Write CLAUDE.md**

Write `CLAUDE.md`:

```markdown
# Suixploit — Claude Code Orchestration

This project is a multi-agent pipeline for finding vulnerabilities in Sui Move contracts. You are the orchestrator.

## Quick Start

To scan a contract:
1. Run `npx tsx src/cli.ts scan <path-to-move-project>` to resolve modules
2. Follow the pipeline steps below

## Pipeline

### Step 1: Resolve Modules
```bash
npx tsx src/cli.ts scan <target-path>
```
This outputs the modules found and generates prompts.

### Step 2: Ranker (skip if <=3 modules)
Feed all module sources to the ranker prompt. Score each 1-5. Only hunt modules scoring 4-5.

### Step 3: Start Devnets
For each module to hunt, start an isolated devnet:
```bash
# The devnet lifecycle module handles this, but manually:
sui start --with-faucet --force-regenesis --fullnode-rpc-port <port> --faucet-port <port+23>
```
Each hunter gets a unique port starting at 9100 (increment by 100).

### Step 4: Seed State
For each devnet, deploy the target contract and fund test accounts.
The seed module (`src/devnet/seed.ts`) handles this.

### Step 5: Spawn Hunters
For each high-priority module, spawn a Claude Code Agent with `isolation: "worktree"`:
- Pass the hunter prompt from `src/hunter/prompt.ts`
- The agent gets shell access to its own devnet
- The agent uses `npx tsx src/oracle/check.ts` to verify exploits
- The agent writes findings to `findings.json` in its worktree

### Step 6: Collect Findings
After all hunters complete, read `findings.json` from each worktree.

### Step 7: Validate
Feed all findings + source to the validator prompt. Filter false positives.

### Step 8: Output
Write final `ScanResult` as JSON.

## Oracle Usage (for hunter agents)
```bash
# Check if a transaction bypasses access control
npx tsx src/oracle/check.ts --signal abort --tx exploit.ts --attacker <addr> --expected should_abort

# Check if attacker gained funds
npx tsx src/oracle/check.ts --signal balance --tx exploit.ts --attacker <addr>

# Check if attacker stole objects
npx tsx src/oracle/check.ts --signal ownership --tx exploit.ts --attacker <addr>
```

The exploit TS file must export:
- `buildTx(client: SuiClient, attackerAddress: string)` — returns a Transaction
- `attackerKeypair` — Ed25519Keypair for the attacker

## Project Structure
- `src/oracle/` — deterministic exploit confirmation (no LLM)
- `src/hunter/` — agent prompt templates
- `src/ranker/` — module scoring
- `src/validator/` — false positive filtering
- `src/devnet/` — local devnet lifecycle
- `contracts/` — intentionally vulnerable test contracts
- `src/cli.ts` — CLI entry point
- `src/pipeline.ts` — pipeline orchestration helpers

## Test Contracts
- `contracts/easy/capability_leak` — admin cap leaks to any caller
- `contracts/easy/unchecked_arithmetic` — share inflation via donation attack
- `contracts/medium/ownership_escape` — missing ownership check on cancel
- `contracts/medium/flash_loan_misuse` — flash loan repay doesn't verify source
- `contracts/hard/shared_object_race` — auction settle/bid race condition
- `contracts/hard/otw_abuse` — unprotected mint on shared treasury cap

## Key Dependencies
- `@mysten/sui` — Sui TypeScript SDK
- `commander` — CLI framework
- `vitest` — test runner
- `tsx` — TypeScript execution
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "feat: CLAUDE.md orchestration instructions for hunter agents"
```

---

### Task 16: End-to-End Validation

Manually validate the pipeline against the easiest contract (capability_leak).

**Files:**
- None created — this is a validation task

- [ ] **Step 1: Verify all tests pass**

Run: `npx vitest run`
Expected: All tests pass (types, oracle, lifecycle, seed, prompt, ranker, validator).

- [ ] **Step 2: Verify CLI resolves the test contract**

Run: `npx tsx src/cli.ts scan contracts/easy/capability_leak`
Expected: Output shows 1 module found (`capability_leak::vault`), prints pipeline context and hunter prompt preview.

- [ ] **Step 3: Verify the test contract compiles**

Run: `sui move build --path contracts/easy/capability_leak`
Expected: Build succeeds.

- [ ] **Step 4: Manual smoke test — start a devnet and deploy**

This step verifies the full environment works before running the agent loop. Run each command and verify output:

```bash
# Start a local devnet
sui start --with-faucet --force-regenesis --fullnode-rpc-port 9100 --faucet-port 9123 &

# Wait for it to be ready (check RPC)
curl -s -X POST http://127.0.0.1:9100 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"sui_getLatestCheckpointSequenceNumber","id":1}'

# Publish the contract
sui client publish contracts/easy/capability_leak --skip-dependency-verification --gas-budget 500000000

# Kill the devnet when done
kill %1
```

Expected: Devnet starts, RPC responds, contract publishes successfully.

- [ ] **Step 5: Commit any fixes**

If any issues were found and fixed during validation:
```bash
git add -A
git commit -m "fix: adjustments from end-to-end validation"
```

- [ ] **Step 6: Final commit — mark project as ready for testing**

```bash
git add -A
git commit -m "chore: project ready for pipeline testing"
```
