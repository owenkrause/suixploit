# Suixploit

Multi-agent pipeline for autonomous vulnerability discovery in Sui Move smart contracts.

## Running a Scan

```bash
ANTHROPIC_API_KEY=<key> npx suixploit scan <target> [options]
```

Options:
- `--package-id <id>` — On-chain package ID (required for mainnet)
- `--network <network>` — `mainnet` (default) or `devnet`
- `--concurrency <n>` — Max parallel agents (default: 5)
- `--model <model>` — Model for agents (default: claude-opus-4-6)
- `--max-turns <n>` — Max turns per hunter agent (default: unlimited)
- `--include <patterns...>` — Only hunt modules matching these substrings
- `--output <path>` — Write results to file (default: stdout)
- `--keep-containers` — Keep Docker containers after devnet runs
- `--checkpoint-dir <path>` — Override output directory
- `--protocol <description>` — Protocol description override
- `--invariants <invariants...>` — Invariants to test against

Examples:
```bash
# Mainnet scan (dry-run, no Docker needed)
npx suixploit scan contracts/deepbookv3-main \
  --package-id 0x337f... --include deepbook_predict --concurrency 3

# Devnet scan (Docker required)
npx suixploit scan contracts/examples/easy/capability_leak \
  --network devnet --output results.json
```

## Pipeline

1. Resolves Move modules from target path
2. Ranks modules by attack surface (skipped if <= 3 modules)
3. Runs parallel hunter agents (mainnet: local dry-run, devnet: Docker containers)
4. Assigns global sequential IDs (vuln-001, vuln-002, ...)
5. Validates findings with independent validator agents
6. Deduplicates by root cause
7. Outputs ScanResult JSON

## Output Structure

Each run creates `.suixploit/<timestamp>/` at the project root:
```
.suixploit/
  2026-04-08T22-31-00/
    scan.json                    # config, timing, counts
    findings/
      all-raw.json               # all hunter findings (checkpoint)
      validated.json             # after validation + dedup
    hunters/
      deepbook_margin-oracle/
        agent.log                # full agent conversation
        findings.json            # confirmed exploits
        vulns.json               # all hypotheses tested
        scratch/                 # agent-created scripts
    validators/
      deepbook_margin-oracle/
        vuln-001/
          verdict.json           # validator decision
          agent.log
          scratch/
```

## Project Structure

```
src/
  cli.ts                 # CLI entry point
  pipeline.ts            # module resolution helpers
  types.ts               # shared interfaces (Finding, ScanResult, ScanMeta, etc.)
  orchestrator/
    index.ts             # main scan pipeline, hunter dispatch
    agent.ts             # agent loop (tool calls, retries, display)
    paths.ts             # output directory layout
    display.ts           # live terminal status display
    exec.ts              # command execution (local + Docker)
    docker.ts            # Docker image/container management
    semaphore.ts         # concurrency limiter
    tracker.ts           # container cleanup
  hunter/
    index.ts             # hunter prompt builder (devnet)
    prompt.ts            # hunter prompt builder (mainnet + shared)
  ranker/                # module scoring by attack surface
  validator/             # independent finding re-analysis
  oracle/                # deterministic exploit confirmation (devnet only)
  devnet/                # local devnet lifecycle (Docker)
contracts/examples/      # intentionally vulnerable test contracts
```

## Test Contracts
- `easy/capability_leak` — admin cap leaks to any caller
- `easy/unchecked_arithmetic` — share inflation via donation attack
- `medium/ownership_escape` — missing ownership check on cancel
- `medium/flash_loan_misuse` — flash loan repay doesn't verify source
- `hard/shared_object_race` — auction settle/bid race condition
- `hard/otw_abuse` — unprotected mint on shared treasury cap

## Commands
- `pnpm build` — compile TypeScript
- `pnpm test` — run tests (vitest)

## Key Dependencies
- `@anthropic-ai/sdk` — Anthropic API client
- `@mysten/sui` — Sui TypeScript SDK (v2 — use `SuiJsonRpcClient`, NOT `SuiClient`)
- `commander` — CLI framework
- `vitest` — test runner
- `tsx` — TypeScript execution
