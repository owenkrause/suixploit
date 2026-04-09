import Anthropic from "@anthropic-ai/sdk";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Finding, ModuleInfo, ValidatedFinding } from "../types.js";
import { buildValidatorAgentPrompt, buildOtherFindingsSummary } from "./prompt.js";
import { runAgent } from "../orchestrator/agent.js";
import type { ExecFn } from "../orchestrator/agent.js";
import { Semaphore } from "../orchestrator/semaphore.js";
import { logDetail, logResult, logStep, logWarn } from "../orchestrator/display.js";

export interface ValidatorOptions {
  client: Anthropic;
  findings: Finding[];
  exec: ExecFn;
  model: string;
  concurrency: number;
  maxTurns?: number;
  checkpointDir?: string;
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
  const { client, findings, exec, model, concurrency, maxTurns = 30, checkpointDir } = options;

  if (findings.length === 0) return [];

  const sem = new Semaphore(concurrency);

  const verdicts = await Promise.all(
    findings.map(async (finding) => {
      const release = await sem.acquire();
      try {
        const verdict = await runValidatorForFinding(client, finding, findings, exec, model, maxTurns, checkpointDir);
        if (checkpointDir) {
          const path = resolve(checkpointDir, `verdict-${finding.id}.json`);
          writeFileSync(path, JSON.stringify(verdict, null, 2));
          logDetail(`[validator:${finding.id}] verdict saved`);
        }
        return verdict;
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
  exec: ExecFn,
  model: string,
  maxTurns: number,
  checkpointDir?: string
): Promise<ValidatorVerdict> {
  const otherSummary = buildOtherFindingsSummary(allFindings, finding.id);
  const prompt = buildValidatorAgentPrompt(finding, otherSummary);

  const systemPrompt = `${prompt}

## Environment

You have a \`bash\` tool to run shell commands. Source code is in the current directory.
Use it to read .move files, grep for functions, trace code paths.

When you are done, write your verdict to verdict-${finding.id}.json in the current directory.`;

  const logFile = checkpointDir ? resolve(checkpointDir, `validator-${finding.id}.log`) : undefined;

  const result = await runAgent(client, {
    exec,
    systemPrompt,
    model,
    maxTurns,
    moduleName: `validator:${finding.id}`,
    logFile,
  });

  // Read verdict from local file
  try {
    const { stdout } = await exec(`cat verdict-${finding.id}.json`);
    return JSON.parse(stdout) as ValidatorVerdict;
  } catch {
    logWarn(`[validator:${finding.id}] failed to parse verdict, defaulting to confirmed`);
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

export async function deduplicateFindings(
  client: Anthropic,
  findings: ValidatedFinding[],
  model: string
): Promise<ValidatedFinding[]> {
  if (findings.length <= 1) return findings;

  const summaries = findings.map((f) => ({
    id: f.id,
    module: f.module,
    severity: f.adjustedSeverity ?? f.severity,
    title: f.title,
    description: f.description,
    impact: f.impact,
  }));

  const prompt = `You are deduplicating vulnerability findings. Group findings that share the same root cause.

## Findings
${JSON.stringify(summaries, null, 2)}

For each group of duplicates, pick the ONE finding with the best writeup (most detailed description + impact analysis) as the canonical entry. Mark all others as duplicates of it.

Return a JSON array of objects: { "id": "<finding id>", "duplicateOf": "<canonical id> | null" }

Every finding must appear exactly once. Set duplicateOf to null for canonical findings. Return ONLY the JSON array.`;

  logStep("Deduplicating findings...");
  const response = await client.messages.create({
    model,
    max_tokens: 4096,
    messages: [{ role: "user", content: prompt }],
  });

  const text = response.content
    .filter((b): b is Anthropic.TextBlock => b.type === "text")
    .map((b) => b.text)
    .join("");

  try {
    const dedupResults = parseJsonArray(text) as { id: string; duplicateOf: string | null }[];
    const dominated = new Set(
      dedupResults.filter((r) => r.duplicateOf).map((r) => r.id)
    );

    const deduped = findings.map((f) => {
      const result = dedupResults.find((r) => r.id === f.id);
      return { ...f, duplicateOf: result?.duplicateOf ?? undefined };
    }).filter((f) => !dominated.has(f.id));

    logDetail(`${findings.length} → ${deduped.length} unique findings`);
    return deduped;
  } catch {
    logWarn("dedup parse failed, keeping all findings");
    return findings;
  }
}

function parseJsonArray(text: string): unknown[] {
  const codeBlockMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  if (codeBlockMatch) {
    const parsed = JSON.parse(codeBlockMatch[1].trim());
    if (Array.isArray(parsed)) return parsed;
  }
  const start = text.indexOf("[");
  const end = text.lastIndexOf("]");
  if (start !== -1 && end > start) {
    const parsed = JSON.parse(text.slice(start, end + 1));
    if (Array.isArray(parsed)) return parsed;
  }
  return JSON.parse(text.trim());
}
