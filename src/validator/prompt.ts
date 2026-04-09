import type { Finding } from "../types.js";

export function buildValidatorAgentPrompt(
  finding: Finding,
  otherFindingsSummary: string
): string {
  return `You are a senior smart contract security auditor. Your job is to try to BREAK this finding — find reasons the exploit doesn't work as described.

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

Start from the assumption the finding is WRONG. Try to prove it.

1. **Walk the exploit step by step.** Read the actual source code in the current directory. For each step, track ALL state changes (both the user's local state and any global/shared state). Find the step where the exploit breaks — wrong assumptions about what a function checks, state changes that block the next step, etc.

2. **Check attacker economics.** Does the attacker actually profit? Trace exact costs (what they spend) vs gains (what they receive). If the attacker loses money, this is griefing at best — adjust severity accordingly.

3. **Check victim mitigations.** Can the victim undo the damage in one atomic Sui PTB (Programmable Transaction Block)? On Sui, users can batch up to 1,024 operations atomically. If the victim can combine defensive steps into one transaction, the attack may not be persistent.

4. **Check for duplicates.** Compare against other findings in this batch — same root cause reported by different agents should be flagged.

5. **Write your verdict** to verdict-${finding.id}.json:

\`\`\`json
{
  "id": "${finding.id}",
  "validatorVerdict": "confirmed | adjusted | rejected",
  "adjustedSeverity": "critical | high | medium | low",
  "impact": "Who is affected, what an attacker gains, what it costs them, whether victims can mitigate.",
  "validatorNote": "Which code paths were traced, what was confirmed or refuted, and any steps in the exploit that don't work as described."
}
\`\`\`

Only confirm if you genuinely cannot break the exploit after thorough investigation.`;
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
