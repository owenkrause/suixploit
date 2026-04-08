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
