import type { Finding, ModuleInfo, ValidatedFinding } from "../types.js";

export function buildValidatorPrompt(
  findings: Finding[],
  modules: ModuleInfo[]
): string {
  const moduleBlocks = modules
    .map((m) => `### ${m.name}\n\`\`\`move\n${m.source}\n\`\`\``)
    .join("\n\n");

  return `You are a senior smart contract security auditor performing final review.

## Findings
\`\`\`json
${JSON.stringify(findings, null, 2)}
\`\`\`

## Source Code
${moduleBlocks}

For each finding, evaluate:
1. Is the exploit transaction valid Move/Sui TS code?
2. Does the oracle result actually confirm the claimed vulnerability?
3. Is the severity rating accurate?
4. Is this a real bug or a test artifact (e.g. exploiting the test setup, not the contract)?
5. Could this be triggered in a real deployment or only in the test environment?

Return a JSON array. For each finding include all original fields plus:
- "validatorVerdict": "confirmed" | "adjusted" | "rejected"
- "validatorNote": explanation of your decision
- "adjustedSeverity": (only if verdict is "adjusted") the corrected severity

Return ONLY a JSON array.`;
}

export function parseValidatorResponse(response: string): ValidatedFinding[] {
  const codeBlockMatch = response.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  const jsonStr = codeBlockMatch ? codeBlockMatch[1].trim() : response.trim();

  const parsed = JSON.parse(jsonStr);

  if (!Array.isArray(parsed)) {
    throw new Error("Validator response must be a JSON array");
  }

  return parsed as ValidatedFinding[];
}

export function filterConfirmed(findings: ValidatedFinding[]): ValidatedFinding[] {
  return findings.filter((f) => f.validatorVerdict !== "rejected");
}
