import type { Finding } from "../types.js";

export function buildValidatorAgentPrompt(
  finding: Finding,
  otherFindingsSummary: string
): string {
  return `You are a senior smart contract security auditor performing a deep review of a single vulnerability finding.

## Finding Under Review

ID: ${finding.id}
Module: ${finding.module}
Severity: ${finding.severity}
Category: ${finding.category}
Title: ${finding.title}

### Description
${finding.description}

### Exploit Transaction
\`\`\`typescript
${finding.exploitTransaction}
\`\`\`

## Other Findings In This Batch
${otherFindingsSummary}

## Your Task

You have bash access to the container with all source code at /workspace. Use it to:

1. **Trace the code path**: Read the relevant source files. Find the exact functions mentioned in the finding. Verify the described vulnerability exists — check function signatures, access control modifiers, data flow.

2. **Assess real-world impact**: Could this cause fund loss? Griefing? DoS? What's the blast radius? How much does it cost the attacker vs. how much damage does it cause? Think about cascading effects — does this broken state feed into other calculations?

3. **Evaluate severity**: Is the current severity rating accurate given the real-world impact? Adjust if needed.

4. **Write your verdict**: When done, write your verdict to verdict-${finding.id}.json in the current directory:

\`\`\`json
{
  "id": "${finding.id}",
  "validatorVerdict": "confirmed | adjusted | rejected",
  "adjustedSeverity": "critical | high | medium | low",
  "impact": "Detailed real-world impact analysis. Who is affected, what can an attacker gain, what does it cost them, is it practically exploitable.",
  "validatorNote": "Technical verification: which code paths were traced, what was confirmed or refuted."
}
\`\`\`

Be thorough. Read the actual source code — don't just trust the description. If the finding claims a function has no access control, go read that function and confirm.`;
}

export function buildOtherFindingsSummary(
  allFindings: Finding[],
  currentId: string
): string {
  const others = allFindings.filter((f) => f.id !== currentId);
  if (others.length === 0) return "No other findings in this batch.";
  return others
    .map((f) => `- ${f.id}: [${f.severity}] ${f.title} (module: ${f.module})`)
    .join("\n");
}
