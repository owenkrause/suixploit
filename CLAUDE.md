# Suixploit — Claude Code Orchestration

This project is a multi-agent pipeline for finding vulnerabilities in Sui Move contracts. You are the orchestrator.

## Automated Pipeline

Run a full scan:
```bash
ANTHROPIC_API_KEY=<key> npx suixploit scan <target> [options]
```

Options:
- `--concurrency <n>` — Max parallel agents (default: 5)
- `--model <model>` — Model for agents (default: claude-sonnet-4-6)
- `--max-turns <n>` — Max turns per hunter (default: 50)
- `--output <path>` — Write results to file (default: stdout)
- `--keep-containers` — Keep Docker containers for debugging

Example:
```bash
ANTHROPIC_API_KEY=sk-ant-... npx suixploit scan contracts/easy/capability_leak --concurrency 1 --output results.json
```

Requires: Docker running, ANTHROPIC_API_KEY set.

The pipeline automatically:
1. Resolves Move modules from the target path
2. Ranks modules by attack surface (skipped if <= 3 modules)
3. Builds a Docker image with Sui CLI + Node
4. Spawns one container per module (devnet + contract deployed + accounts funded)
5. Runs parallel hunter agents via Anthropic API
6. Collects and validates findings
7. Outputs a ScanResult JSON
8. Cleans up all containers

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
- `src/orchestrator/` — Docker management, agent loop, concurrency, cleanup
- `src/oracle/` — deterministic exploit confirmation (no LLM)
- `src/hunter/` — agent prompt templates
- `src/ranker/` — module scoring
- `src/validator/` — false positive filtering
- `src/devnet/` — local devnet lifecycle
- `contracts/` — intentionally vulnerable test contracts
- `src/cli.ts` — CLI entry point
- `src/pipeline.ts` — module resolution and pipeline helpers

## Test Contracts
- `contracts/easy/capability_leak` — admin cap leaks to any caller
- `contracts/easy/unchecked_arithmetic` — share inflation via donation attack
- `contracts/medium/ownership_escape` — missing ownership check on cancel
- `contracts/medium/flash_loan_misuse` — flash loan repay doesn't verify source
- `contracts/hard/shared_object_race` — auction settle/bid race condition
- `contracts/hard/otw_abuse` — unprotected mint on shared treasury cap

## Key Dependencies
- `@anthropic-ai/sdk` — Anthropic API client (agent conversations)
- `@mysten/sui` — Sui TypeScript SDK
- `commander` — CLI framework
- `vitest` — test runner
- `tsx` — TypeScript execution
