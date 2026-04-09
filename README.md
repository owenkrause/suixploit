# Suixploit

Multi-agent pipeline for autonomous vulnerability discovery in Sui Move smart contracts.

## Background

This project adapts the methodology described in Anthropic's [Mythos Preview cybersecurity evaluation](https://red.anthropic.com/2026/mythos-preview/) — which demonstrated autonomous zero-day discovery across operating systems, browsers, and critical infrastructure — and applies it to smart contract security on Sui.

The Mythos evaluation showed that a multi-agent scaffold with hypothesis generation, empirical validation, and secondary review could find thousands of real vulnerabilities at low cost. Suixploit implements this same pipeline architecture for Move smart contracts, replacing memory sanitizers and crash oracles with on-chain dry-run simulation and deterministic exploit confirmation.

## How it maps from Mythos

The Mythos scaffold works in four stages: hypothesis generation, empirical validation, exploit development, and secondary review. Suixploit mirrors this:

| Mythos scaffold                              | Suixploit                                                                                              |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| File prioritization (1-5 severity rating)    | **Ranker agent** scores modules by attack surface, entry points, fund flows                            |
| Parallel agent invocations per file          | **Hunter agents** run concurrently per module with isolated workspaces                                 |
| Source code reading + instrumented execution | Agents read Move source + execute transactions against local devnet or dry-run against mainnet         |
| Containerized isolation per target           | Each hunter gets its own Docker container (devnet) or isolated workspace (mainnet) with funded accounts |
| Crash oracle (AddressSanitizer, fuzzer)      | **Oracle** confirms exploits deterministically — balance changes, ownership violations, abort signals  |
| Secondary review for severity validation     | **Validator agents** independently re-analyze each finding, reject false positives, calibrate severity |
| Professional contractor review               | **Deduplication** pass groups findings by root cause, picks best writeup per group                     |

## Architecture

```
Target (Move project or mainnet package ID)
    |
    v
Module Resolution --- extracts .move source files
    |
    v
Ranker --- scores modules by attack surface (skipped if <= 3 modules)
    |
    v
Hunters (parallel) --- one agent per module, isolated workspace
    |                   extended thinking, dry-run simulation
    |                   outputs: vulns.json (all hypotheses) + findings.json (confirmed exploits)
    v
Validators (parallel) --- independent re-analysis of each finding
    |                      confirms, adjusts severity, or rejects
    v
Deduplication --- groups by root cause, picks canonical writeup
    |
    v
ScanResult JSON
```

Each hunter agent gets:

- The full Move source of its target module
- Cross-module function signatures for understanding interactions
- Access to mainnet RPC for reading on-chain state and dry-running exploit transactions
- A bash tool for running TypeScript exploit scripts

## Two modes: mainnet analysis and devnet pentesting

**Mainnet mode** (`--network mainnet`) performs read-only analysis against live contracts. Agents use `simulateTransaction` (dry-run) to test exploit hypotheses against real on-chain state without executing anything. This is how you'd scan a deployed protocol like DeepBook V3.

**Devnet mode** (`--network devnet`) goes further — it spins up a full local Sui network inside Docker, deploys the contract, funds attacker/admin/user accounts, and gives each hunter agent a live environment to actually execute exploit transactions against. This is the closest analogue to the Mythos scaffold's containerized execution with instrumented binaries:

1. The pipeline builds a Docker image with the Sui CLI, Node.js, and the contract source
2. For each module, it spawns an isolated container running a local Sui devnet
3. It deploys the contract and funds three accounts (admin, attacker, user)
4. The hunter agent gets the package ID, account addresses, and RPC URL
5. The agent writes and executes real transactions — not simulations — against the local chain
6. A deterministic **oracle** confirms exploit outcomes by checking balance changes, ownership transfers, and abort signals

This means devnet mode can catch bugs that dry-run misses — race conditions on shared objects, multi-transaction attack sequences, and state-dependent exploits that require setting up specific on-chain conditions before triggering the vulnerability.

## Usage

```bash
# Scan a mainnet package
ANTHROPIC_API_KEY=<key> npx suixploit scan <target> \
  --package-id <0x...> \
  --network mainnet \
  --concurrency 5 \
  --model claude-opus-4-6

# Scan specific modules in a large codebase
npx suixploit scan contracts/deepbookv3-main \
  --package-id 0x337f... \
  --include deepbook_margin \
  --concurrency 3

# Scan a local Move project against devnet
npx suixploit scan contracts/examples/easy/capability_leak \
  --network devnet \
  --output results.json
```

Options:

- `--package-id <id>` — On-chain package ID (required for mainnet)
- `--concurrency <n>` — Max parallel agents (default: 5)
- `--model <model>` — Model for agents (default: claude-opus-4-6)
- `--max-turns <n>` — Max turns per hunter agent
- `--include <patterns...>` — Only hunt modules matching these substrings
- `--output <path>` — Write results to file (default: stdout)
- `--keep-containers` — Keep Docker containers after devnet runs
- `--network <network>` — `devnet` or `mainnet`

## What it finds

The pipeline targets vulnerabilities exploitable by unprivileged users:

- Fund theft or value extraction (share inflation, oracle manipulation, rounding exploits)
- Permanent fund locking (irrecoverable pool/position states)
- State corruption (broken accounting affecting future operations)
- Invariant violations (unbacked shares, undercollateralized positions)
- Liquidation manipulation (avoiding or forcing unfair liquidations)
- Privilege escalation (gaining admin capabilities from unprivileged position)
- Protocol DoS (permanently breaking core functions)

It explicitly does **not** report admin misconfiguration, governance centralization, missing events, or design trade-offs.

## Requirements

- Node.js 20+
- Docker (for devnet mode)
- `ANTHROPIC_API_KEY` environment variable
- pnpm

## Project structure

```
src/
  cli.ts              CLI entry point
  orchestrator/       Agent loop, display, concurrency, workspace isolation
  hunter/             Hunter agent prompt templates
  ranker/             Module scoring by attack surface
  validator/          Independent finding re-analysis
  oracle/             Deterministic exploit confirmation (devnet)
  pipeline.ts         Module resolution helpers
  devnet/             Local devnet lifecycle (Docker)
contracts/examples/   Intentionally vulnerable test contracts
```
