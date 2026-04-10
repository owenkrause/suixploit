import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Finding } from "../types.js";
import { FOUNDATIONAL_CONTEXT } from "../hunter/prompt.js";

const FP_CATALOG = readFileSync(
  resolve(import.meta.dirname, "../../references/false-positive-catalog.md"),
  "utf-8"
);

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

${FOUNDATIONAL_CONTEXT}

## False Positive Catalog

${FP_CATALOG}

## What Counts as a Finding

A vulnerability where an unprivileged user causes economic damage. For every finding you MUST verify:
1. What does the attacker gain, or what damage is caused?
2. What does the attack cost? (it must be net-profitable OR cause damage far exceeding its cost)
3. Why can't the victim mitigate it? (consider that victims can batch operations atomically in a single PTB)
4. Is the damage persistent or a temporary inconvenience?

Reject findings that are:
- Admin misconfiguration ("admin could set a bad parameter")
- Governance centralization or missing events
- Theoretical bugs requiring admin key compromise
- Griefing where attacker pays more than the damage caused

## Your Task

Start from the assumption the finding is WRONG. Try to prove it.

1. **Walk the exploit step by step.** Read the actual source code. For each step, track ALL state changes (both the user's local state and any global/shared state). Find the step where the exploit breaks — wrong assumptions about what a function checks, state changes that block the next step, etc.

2. **Run the false positive checks.** Apply the rationalizations table and the 5-point self-hallucination checklist from the catalog above. Does this finding fall into any known false positive pattern?

3. **Check attacker economics.** Does the attacker actually profit? Trace exact costs (what they spend) vs gains (what they receive). If the attacker loses money, this is griefing at best — adjust severity accordingly.

4. **Check victim mitigations.** Can the victim undo the damage in one atomic Sui PTB (Programmable Transaction Block)? On Sui, users can batch up to 1,024 operations atomically. If the victim can combine defensive steps into one transaction, the attack may not be persistent.

5. **Check for duplicates.** Compare against other findings in this batch — same root cause reported by different agents should be flagged.

6. **Write your verdict** to verdict-${finding.id}.json:

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
