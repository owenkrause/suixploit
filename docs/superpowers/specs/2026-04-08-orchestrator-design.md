# Suixploit Orchestrator — Design Spec

## Goal

Replace the current prompt-printing CLI with a fully automated pipeline that spawns parallel hunter agents in isolated Docker containers, collects findings, validates them, and outputs a final ScanResult JSON. The agent never touches infrastructure — it wakes up in a ready environment and hunts.

## Architecture

The `scan` CLI command becomes an end-to-end pipeline:

1. Resolve Move modules from target path (existing `resolveModules`)
2. Rank modules if > 3 (existing ranker — run as API call, not agent)
3. Build Docker image `suixploit-hunter` (once per run)
4. For each target module, start a container that boots a devnet, deploys the contract, funds accounts, and writes `context.json`
5. Run N agent conversations in parallel (capped by `--concurrency`), each talking to its container via `docker exec`
6. Collect `findings.json` from each container
7. Run the validator (API call) against all findings + source
8. Output final `ScanResult` JSON
9. Kill and remove all containers

## Docker Image

A single `Dockerfile` at the project root builds `suixploit-hunter`.

**Contents:**
- Sui CLI (installed from binary or from a base image that has it)
- Node.js + pnpm
- Project source: `src/`, `contracts/`, `package.json`, `tsconfig.json`, `pnpm-lock.yaml`
- `pnpm install` run at build time
- `entrypoint.sh` as the entrypoint

**entrypoint.sh:**
1. Starts `sui start --with-faucet --force-regenesis` in the background on localhost ports (no port mapping needed — the agent runs inside the container)
2. Polls RPC (`curl` to `sui_getLatestCheckpointSequenceNumber`) until ready, 60s timeout
3. Generates 3 keypairs (admin, attacker, user) via `sui client new-address ed25519`
4. Funds all 3 via faucet (`curl` to faucet endpoint)
5. Publishes the target contract (path passed as `TARGET_CONTRACT` env var) via `sui client publish`
6. Writes `/workspace/context.json`:
   ```json
   {
     "rpcUrl": "http://127.0.0.1:9000",
     "faucetUrl": "http://127.0.0.1:9123",
     "packageId": "0x...",
     "adminAddress": "0x...",
     "attackerAddress": "0x...",
     "userAddress": "0x...",
     "adminKeyPair": "suiprivkey...",
     "attackerKeyPair": "suiprivkey...",
     "userKeyPair": "suiprivkey..."
   }
   ```
7. Touches `/workspace/.ready` as a sentinel file
8. Sleeps forever (`tail -f /dev/null`) — container stays alive for `docker exec` calls

The orchestrator polls for `.ready` via `docker exec` before starting the agent conversation.

## Agent Loop

Uses `@anthropic-ai/sdk` directly (raw API, no Agent SDK). Per hunter:

1. **Build prompt**: `prepareHunterPrompt()` with module source, invariants, oracle instructions. Append `context.json` contents so the agent has all addresses/packageId without needing to discover them.

2. **Start conversation**: `client.messages.create()` with:
   - Model: configurable, defaults to `claude-sonnet-4-6`
   - System prompt: hunter prompt + context
   - Tools: one tool defined — `bash`:
     - Parameters: `{ command: string }`
     - Execution: `docker exec -i <container_id> bash -c "<command>"`
     - Returns: `{ stdout, stderr, exit_code }`
   - `max_tokens`: 16384 per turn

3. **Tool loop**: If `stop_reason === "tool_use"`, execute all tool calls via `docker exec`, send results back, repeat. If `stop_reason === "end_turn"`, agent is done.

4. **Caps**: `--max-turns` (default 50) prevents runaway agents. Token usage tracked per agent for cost reporting.

5. **Collect**: After agent finishes, run `docker exec <container> cat /workspace/findings.json`. If missing or invalid, zero findings for that module.

## Concurrency

A semaphore-based concurrency limiter. At most `--concurrency` agents run simultaneously. Others queue up and start as slots free. Default concurrency: 5.

Each agent is fully independent — no shared state between agents.

## Ranker and Validator as API Calls

The ranker and validator don't need shell access or Docker — they're pure prompt-in, JSON-out. Run them as simple `messages.create()` calls (no tool loop):

- **Ranker**: `buildRankerPrompt(modules)` → API call → `parseRankerResponse()`  → `filterHighPriority()`. Skipped if <= 3 modules.
- **Validator**: `buildValidatorPrompt(allFindings, modules)` → API call → `parseValidatorResponse()` → `filterConfirmed()`.

These use the same `--model` as hunters, or could be hardcoded to a stronger model for better judgment. Keep it simple: same model for now.

## CLI Interface

```
npx suixploit scan <target> [options]

Options:
  --concurrency <n>    Max parallel agents (default: 5)
  --model <model>      Model for agents (default: claude-sonnet-4-6)
  --max-turns <n>      Max turns per hunter agent (default: 50)
  --output <path>      Write ScanResult JSON to file (default: stdout)
  --keep-containers    Don't remove containers after run (for debugging)
```

The `<target>` is a path to a Move project directory (must contain a `sources/` directory with `.move` files).

## Resource Tracking and Cleanup

A `ResourceTracker` class maintains a set of active container IDs. Cleanup runs in all exit paths:

- Normal completion
- Unhandled rejection / uncaught exception
- SIGINT / SIGTERM

Cleanup sequence:
1. `docker kill <id>` for every registered container (in parallel)
2. `docker rm <id>` for every registered container (in parallel)
3. Exit

If `--keep-containers` is set, skip kill/rm. Log container IDs so the user can inspect them.

Process handlers:
```
process.on("SIGINT", cleanup)
process.on("SIGTERM", cleanup)
process.on("uncaughtException", cleanup)
process.on("unhandledRejection", cleanup)
```

## File Structure

New files:
- `Dockerfile` — hunter container image
- `entrypoint.sh` — container boot script
- `src/orchestrator.ts` — Docker management, agent loop, concurrency limiter, resource tracker

Modified files:
- `src/cli.ts` — wire `scan` command to orchestrator
- `package.json` — add `@anthropic-ai/sdk` dependency

Unchanged:
- `src/pipeline.ts` — `resolveModules`, `shouldSkipRanker`, `buildScanResult` used as-is
- `src/ranker/` — prompt building and response parsing used as-is
- `src/hunter/` — `prepareHunterPrompt` used as-is
- `src/validator/` — prompt building and response parsing used as-is
- `src/oracle/` — lives inside the container, used by hunter agents directly
- `src/types.ts` — no changes needed

## What's NOT Included

- No Kubernetes, ECS, or cloud orchestration
- No job queues or message brokers
- No persistent storage — results are ephemeral per run
- No retry on agent failure — if an agent errors, its findings are empty for that module
- No web UI or dashboard
- No streaming output during agent execution (could add later)
