import Anthropic from "@anthropic-ai/sdk";
import type { Finding, ModuleInfo, ValidatedFinding } from "../types.js";
import { buildValidatorAgentPrompt, buildOtherFindingsSummary } from "./prompt.js";
import { runAgent } from "../orchestrator/agent.js";
import { readVerdict } from "../orchestrator/docker.js";
import { Semaphore } from "../orchestrator/semaphore.js";

export interface ValidatorOptions {
  client: Anthropic;
  findings: Finding[];
  containerIds: string[];
  model: string;
  concurrency: number;
  maxTurns?: number;
}

interface ValidatorVerdict {
  id: string;
  validatorVerdict: "confirmed" | "adjusted" | "rejected";
  validatorNote: string;
  adjustedSeverity?: string;
  impact?: string;
  duplicateOf?: string | null;
}

export async function runValidators(options: ValidatorOptions): Promise<ValidatedFinding[]> {
  const { client, findings, containerIds, model, concurrency, maxTurns = 30 } = options;

  if (findings.length === 0) return [];

  const sem = new Semaphore(concurrency);

  // Use the first available container for all validators (they just read files)
  const containerId = containerIds[0];

  const verdicts = await Promise.all(
    findings.map(async (finding) => {
      const release = await sem.acquire();
      try {
        return await runValidatorForFinding(client, finding, findings, containerId, model, maxTurns);
      } finally {
        release();
      }
    })
  );

  return mergeVerdicts(findings, verdicts);
}

async function runValidatorForFinding(
  client: Anthropic,
  finding: Finding,
  allFindings: Finding[],
  containerId: string,
  model: string,
  maxTurns: number
): Promise<ValidatorVerdict> {
  const otherSummary = buildOtherFindingsSummary(allFindings, finding.id);
  const prompt = buildValidatorAgentPrompt(finding, otherSummary);

  const systemPrompt = `${prompt}

## Environment

You have a \`bash\` tool to run shell commands. Source code is at /workspace.
Use it to read .move files, grep for functions, trace code paths.

When you are done, write your verdict to /workspace/verdict-${finding.id}.json`;

  console.error(`[validator:${finding.id}] Starting review...`);

  const result = await runAgent(client, {
    containerId,
    systemPrompt,
    model,
    maxTurns,
    moduleName: `validator:${finding.id}`,
  });

  console.error(`[validator:${finding.id}] Finished: ${result.stopped} after ${result.turns} turns (${result.inputTokens + result.outputTokens} tokens)`);

  // Read verdict
  const verdictJson = await readVerdict(containerId, finding.id);
  try {
    return JSON.parse(verdictJson) as ValidatorVerdict;
  } catch {
    console.error(`[validator:${finding.id}] Failed to parse verdict, defaulting to confirmed`);
    return {
      id: finding.id,
      validatorVerdict: "confirmed",
      validatorNote: `Validator agent completed (${result.stopped}) but did not write a parseable verdict.`,
    };
  }
}

function mergeVerdicts(findings: Finding[], verdicts: ValidatorVerdict[]): ValidatedFinding[] {
  const verdictMap = new Map(verdicts.map((v) => [v.id, v]));
  return findings.map((f) => {
    const verdict = verdictMap.get(f.id);
    return {
      ...f,
      validatorVerdict: verdict?.validatorVerdict ?? "confirmed",
      validatorNote: verdict?.validatorNote ?? "No verdict returned",
      adjustedSeverity: verdict?.adjustedSeverity as ValidatedFinding["adjustedSeverity"],
      impact: verdict?.impact,
      duplicateOf: verdict?.duplicateOf ?? undefined,
    };
  });
}

export function filterConfirmed(findings: ValidatedFinding[]): ValidatedFinding[] {
  return findings.filter((f) => f.validatorVerdict !== "rejected");
}

export function deduplicateFindings(findings: ValidatedFinding[]): ValidatedFinding[] {
  const dominated = new Set<string>();
  for (const f of findings) {
    if (f.duplicateOf) {
      dominated.add(f.id);
    }
  }
  return findings.filter((f) => !dominated.has(f.id));
}
