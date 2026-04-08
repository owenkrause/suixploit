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
  return scores.filter((s) => s.score >= 4);
}
