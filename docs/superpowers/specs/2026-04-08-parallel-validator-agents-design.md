# Parallel Validator Agents Design

## Goal

Replace the single-call validator step with parallel agentic validators — one per finding — that deeply investigate each vulnerability by tracing code paths, assessing real-world impact, and writing detailed verdicts. Same pattern as the hunter agents but focused on review, not discovery.

## Problem

The current validator is a single LLM API call that receives all findings + all source code and returns verdicts in one shot. This:

1. Hits token limits when findings contain long exploit code (crashed twice on a 14-finding run)
2. Gives shallow analysis — each finding gets a few sentences, not a real investigation
3. Can't trace cross-module code paths or reason about cascading effects
4. Misses the "so what?" — doesn't assess real exploitability or financial impact

## Architecture

### Pipeline Change

Current: `Rank -> Hunt -> Validate (1 LLM call) -> Output`

New: `Rank -> Hunt -> Validate (N parallel agents) -> Deduplicate -> Output`

### Validator Agent

Each validator agent is a multi-turn agent loop (reusing the existing `runAgent` infrastructure) that gets:

- **One finding** (full details: description, exploit code, dry-run output)
- **A list of all other finding IDs + titles** (for duplicate detection)
- **Bash tool** in a container with the source code mounted

The agent's job:
1. Read the relevant source files and trace the vulnerable code path
2. Verify the described vulnerability exists — check function signatures, access control, data flow
3. Assess real-world impact: fund loss? griefing? DoS? What's the blast radius? Is it practically exploitable?
4. Think about cascading effects (e.g., broken accounting -> treasury miscalculation -> what does treasury feed into?)
5. Check if this duplicates another finding in the batch
6. Write a structured verdict to `/workspace/verdict.json`

### Container Strategy

Reuse the hunter containers. They already have the source code, Node.js, and bash. Multiple validator agents can share the same container since they're just reading files and writing their own verdict — no conflicting state.

The orchestrator passes the hunter's `containerId` through to each validator agent. Each validator writes its verdict to a unique path (`/workspace/verdict-<finding-id>.json`) to avoid conflicts when sharing a container.

### Verdict Schema

Each agent writes `/workspace/verdict-<finding-id>.json`:

```json
{
  "id": "NAVI-001",
  "validatorVerdict": "confirmed | adjusted | rejected",
  "adjustedSeverity": "critical | high | medium | low",
  "impact": "Detailed real-world impact analysis. Who is affected, what can an attacker gain, what does it cost them, is it practically exploitable.",
  "validatorNote": "Technical verification: which code paths were traced, what was confirmed/refuted.",
  "duplicateOf": "NAVI-POOL-001 | null"
}
```

### Deduplication

After all validator agents complete, the orchestrator:
1. Collects all verdicts
2. Merges each verdict onto its original finding (preserving all hunter data)
3. Groups findings where `duplicateOf` is set — keeps the one with the best writeup, marks others as dupes
4. Filters out rejected findings
5. Outputs the final `ScanResult`

### Concurrency

Uses the same `Semaphore` class as hunters. Validator agents share the `--concurrency` flag value. Since validators are pure LLM + file reads (no devnet), they're lighter than hunters and can safely run at higher concurrency.

### Cost Expectations

Each validator agent should take 5-15 turns of reading files and reasoning. No tool-heavy work (no dry-runs, no compiling). Estimated ~50K-150K tokens per finding vs. ~500K-2M per hunter. For 14 findings, that's roughly 1-2M total tokens — much cheaper than re-running hunters.

### Max Turns

Validator agents get a default max-turns of 30. They shouldn't need more than 15, but the safety net prevents runaway costs. This is distinct from hunter agents which run unlimited.

When a validator agent reaches its second-to-last turn (turn == maxTurns - 1), the system appends a message to the conversation: "You are about to hit your turn limit. Write your verdict to /workspace/verdict-<id>.json NOW with whatever analysis you have so far. Note in validatorNote that you hit the turn limit." This ensures we always get output even if the agent was mid-investigation.

## Files to Create/Modify

- **Create `src/validator/prompt.ts`** — builds the validator agent system prompt
- **Create `src/validator/agent.ts`** — validator-specific agent runner (calls `runAgent`, reads verdict)
- **Modify `src/validator/index.ts`** — replace `buildValidatorPrompt`/`parseValidatorResponse` with the new parallel approach. Export a `runValidators()` function that takes findings + modules + options and returns `ValidatedFinding[]`
- **Modify `src/orchestrator/index.ts`** — replace the single validator API call in step 6 with `runValidators()`
- **Modify `src/orchestrator/docker.ts`** — add `readVerdict(containerId, findingId)` helper to read verdict files
- **Modify `src/types.ts`** — update `ValidatedFinding` to include `impact` and `duplicateOf` fields
- **Modify `scripts/validate-findings.ts`** — update to use the new parallel validator

## What This Does NOT Change

- Hunter agents, ranker, pipeline resolution — untouched
- The `runAgent` loop in `src/orchestrator/agent.ts` — reused as-is
- Semaphore, ResourceTracker — reused as-is
- CLI flags — no new flags needed (validators inherit `--concurrency` and `--model`)
- Docker image and containers — validators reuse the hunter containers as-is
