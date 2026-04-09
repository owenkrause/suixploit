import type { ModuleInfo, ModuleScore } from "../types.js";

/**
 * Extract security-relevant signatures from Move source:
 * struct definitions, public/entry function signatures, friend declarations, use statements.
 * Strips function bodies to keep the ranker prompt small.
 */
export function extractSignatures(source: string): string {
  const lines = source.split("\n");
  const result: string[] = [];
  let braceDepth = 0;
  let inFnBody = false;
  let inStructDef = false;

  for (const line of lines) {
    const trimmed = line.trim();

    // Always keep: module declaration, use, friend, const, struct, has
    if (
      /^module\s/.test(trimmed) ||
      /^use\s/.test(trimmed) ||
      /^friend\s/.test(trimmed) ||
      /^const\s/.test(trimmed)
    ) {
      result.push(line);
      continue;
    }

    // Struct definitions — keep the whole thing (fields show what data is held)
    if (/^(public\s+)?struct\s/.test(trimmed) || /^\bstruct\s/.test(trimmed)) {
      inStructDef = true;
    }
    if (inStructDef) {
      result.push(line);
      if (trimmed.includes("{")) braceDepth += (trimmed.match(/{/g) || []).length;
      if (trimmed.includes("}")) braceDepth -= (trimmed.match(/}/g) || []).length;
      if (braceDepth <= 0) {
        inStructDef = false;
        braceDepth = 0;
      }
      continue;
    }

    // Function signatures — keep the signature line, skip the body
    if (/^(public(\s*\(friend\))?\s+)?(entry\s+)?fun\s/.test(trimmed)) {
      result.push(line);
      // If the body starts on this line, start tracking depth
      if (trimmed.includes("{")) {
        inFnBody = true;
        braceDepth = (trimmed.match(/{/g) || []).length - (trimmed.match(/}/g) || []).length;
        if (braceDepth <= 0) {
          inFnBody = false;
          braceDepth = 0;
        }
      }
      continue;
    }

    // Multi-line function signature (params spanning lines before the body)
    if (!inFnBody && result.length > 0 && /^(public|entry|fun)\s/.test(result[result.length - 1]?.trim() ?? "")) {
      // Still in the signature if we haven't seen { yet
      if (!trimmed.includes("{")) {
        result.push(line);
        continue;
      } else {
        // Signature ends, body begins
        result.push(line.split("{")[0]);
        inFnBody = true;
        braceDepth = (trimmed.match(/{/g) || []).length - (trimmed.match(/}/g) || []).length;
        if (braceDepth <= 0) {
          inFnBody = false;
          braceDepth = 0;
        }
        continue;
      }
    }

    // Skip function body lines
    if (inFnBody) {
      if (trimmed.includes("{")) braceDepth += (trimmed.match(/{/g) || []).length;
      if (trimmed.includes("}")) braceDepth -= (trimmed.match(/}/g) || []).length;
      if (braceDepth <= 0) {
        inFnBody = false;
        braceDepth = 0;
      }
      continue;
    }
  }

  return result.filter(l => l.trim().length > 0).join("\n");
}

export function buildRankerPrompt(modules: ModuleInfo[]): string {
  const moduleBlocks = modules
    .map(
      (m) => `### Module: ${m.name}\n\`\`\`move\n${extractSignatures(m.source)}\n\`\`\``
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

Return ONLY a JSON array. Keep rationale under 20 words. No markdown, no code fences — raw JSON only.
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

export const HIGH_PRIORITY_SCORE = 3;

export function filterHighPriority(scores: ModuleScore[]): ModuleScore[] {
  return scores.filter((s) => s.score >= HIGH_PRIORITY_SCORE);
}
