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
  // Try to extract JSON from markdown code block
  const codeBlockMatch = response.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  const jsonStr = codeBlockMatch ? codeBlockMatch[1].trim() : response.trim();

  const parsed = JSON.parse(jsonStr);

  if (!Array.isArray(parsed)) {
    throw new Error("Ranker response must be a JSON array");
  }

  return parsed.map((item: Record<string, unknown>) => ({
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
