import type { ModuleInfo, ModuleScore } from "../types.js";

export function buildRankerPrompt(modules: ModuleInfo[]): string {
  const moduleBlocks = modules
    .map(
      (m) => `### Module: ${m.name}\n\`\`\`move\n${m.source}\n\`\`\``
    )
    .join("\n\n");

  return `You are an elite smart contract security auditor specializing in DeFi exploits. Score each module in this Sui Move project from 1-5 for likelihood of containing an exploitable vulnerability.

Score 5: Directly handles funds, has complex state transitions, or implements core protocol logic (positions, vaults, pools, liquidations, borrowing, repaying). Any module that moves tokens or enforces economic invariants.
Score 4: Implements math used in financial calculations (interest, margins, share accounting, price conversions), access control for privileged operations, or oracle integration.
Score 3: Manages collections/state that feed into higher-risk modules, or has public functions that mutate shared objects.
Score 2: Adapter/wrapper modules that delegate to core logic with minimal added logic.
Score 1: Pure utilities, constants, or data structures with no fund interaction.

Key attack patterns to weight heavily:
- Coin/token transfers, minting, or burning
- Shared objects with mutable access (concurrent manipulation)
- Borrow/lend/repay flows and debt share accounting
- Margin/collateral validation and liquidation logic
- Price oracle usage and staleness checks
- Fixed-point arithmetic (rounding direction, overflow, precision loss)
- Capability-gated functions and access control gaps
- Flash loan / hot potato patterns
- Interest accrual and fee collection

Err on the side of scoring higher. A module that touches funds or enforces invariants should NEVER score below 4.

Return ONLY a JSON array of ModuleScore objects with this shape:
{ "module": string, "score": number, "rationale": string, "attackSurface": string[] }

## Modules

${moduleBlocks}`;
}

export function parseRankerResponse(response: string): ModuleScore[] {
  let parsed: unknown;

  // 1. Code fence extraction
  const codeBlockMatch = response.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  if (codeBlockMatch) {
    try {
      parsed = JSON.parse(codeBlockMatch[1].trim());
    } catch { /* fall through */ }
  }

  // 2. Find first JSON array
  if (!Array.isArray(parsed)) {
    const arrayStart = response.indexOf("[");
    const arrayEnd = response.lastIndexOf("]");
    if (arrayStart !== -1 && arrayEnd > arrayStart) {
      try {
        parsed = JSON.parse(response.slice(arrayStart, arrayEnd + 1));
      } catch { /* fall through */ }
    }
  }

  // 3. Raw parse
  if (!Array.isArray(parsed)) {
    parsed = JSON.parse(response.trim());
  }

  if (!Array.isArray(parsed)) {
    throw new Error("Ranker response must be a JSON array");
  }

  return (parsed as Record<string, unknown>[]).map((item) => ({
    module: String(item.module),
    score: Number(item.score),
    rationale: String(item.rationale),
    attackSurface: Array.isArray(item.attackSurface)
      ? item.attackSurface.map(String)
      : [],
  }));
}

export function filterHighPriority(scores: ModuleScore[]): ModuleScore[] {
  return scores.filter((s) => s.score >= 3);
}
