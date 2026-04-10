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
- `--effort <level>` — Agent thinking effort: `low`, `medium` (default), `high`, `max`. Auto-clamped to model's max output tokens.
- `--include <patterns...>` — Only hunt modules matching these substrings
- `--keep-containers` — Keep Docker containers after devnet runs
- `--output <path>` — Override output directory
- `--protocol <description>` — Protocol description override
- `--invariants <invariants...>` — Invariants to test against

Examples:

```bash
# Mainnet scan (dry-run, no Docker needed)
npx suixploit scan contracts/deepbookv3-main \
  --package-id 0x337f... --include deepbook_predict --concurrency 3

# Devnet scan (Docker required)
npx suixploit scan contracts/examples/easy/capability_leak \
  --network devnet
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
  references.ts          # reference catalog + list/read helpers for agent tools
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
    index.ts             # re-exports from prompt.ts
    prompt.ts            # hunter prompt (foundational context, two-phase methodology, SDK, oracle)
  ranker/                # module scoring by attack surface
  validator/
    index.ts             # validator orchestration, deduplication
    prompt.ts            # validator prompt (foundational context, FP catalog, severity criteria)
  oracle/                # deterministic exploit confirmation (CLI tool, works on both networks)
references/              # curated vulnerability patterns, FP catalog, attack vectors, DeFi deep-dives
contracts/examples/      # intentionally vulnerable test contracts
```

## Protocol Description

Place a `protocol.md` file in your target project root to provide context to hunter agents:

```markdown
## Description
Brief description of what the protocol does.

## Invariants
- Invariant 1: total shares == total deposits
- Invariant 2: only admin can withdraw reserves
```

Both sections are optional. Can also be overridden via `--protocol` and `--invariants` CLI flags.

## Test Contracts

- `easy/capability_leak` — admin cap leaks to any caller
- `easy/unchecked_arithmetic` — share inflation via donation attack
- `medium/ownership_escape` — missing ownership check on cancel
- `medium/flash_loan_misuse` — flash loan repay doesn't verify source
- `hard/shared_object_race` — auction settle/bid race condition
- `hard/otw_abuse` — unprotected mint on shared treasury cap

## Agent Tools

All agents (hunters and validators) have access to these tools via `runAgent()`:

- `bash` — run shell commands
- `write_file` — write files via base64 (avoids bash escaping issues for JSON/TS)
- `list_references` — list available reference files with descriptions
- `read_reference` — load a specific reference file by name

## Commands

- `pnpm build` — compile TypeScript
- `pnpm test` — run tests (vitest)

## Key Dependencies

- `@anthropic-ai/sdk` — Anthropic API client
- `@mysten/sui` — Sui TypeScript SDK (v2 — use `SuiJsonRpcClient`, NOT `SuiClient`)
- `commander` — CLI framework
- `vitest` — test runner
- `tsx` — TypeScript execution
