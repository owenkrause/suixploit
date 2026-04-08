import { readFile, readdir } from "node:fs/promises";
import { resolve, join } from "node:path";
import type {
  ModuleInfo,
  ModuleScore,
  Finding,
  ValidatedFinding,
  ScanResult,
} from "./types.js";
import { buildRankerPrompt, parseRankerResponse, filterHighPriority } from "./ranker/index.js";
import { prepareHunterPrompt } from "./hunter/index.js";

export async function resolveModules(targetPath: string): Promise<ModuleInfo[]> {
  const sourcesDir = resolve(targetPath, "sources");
  const files = await readdir(sourcesDir);
  const moveFiles = files.filter((f) => f.endsWith(".move"));

  const modules: ModuleInfo[] = [];
  for (const file of moveFiles) {
    const filePath = join(sourcesDir, file);
    const source = await readFile(filePath, "utf-8");

    // Extract module name from source
    const moduleMatch = source.match(/module\s+([\w:]+)/);
    const name = moduleMatch ? moduleMatch[1] : file.replace(".move", "");

    // Try to read protocol.md for description and invariants
    let protocolDescription: string | undefined;
    let invariants: string[] | undefined;
    try {
      const protocolPath = resolve(targetPath, "protocol.md");
      const protocol = await readFile(protocolPath, "utf-8");

      const descMatch = protocol.match(/## Description\n([\s\S]*?)(?=\n## )/);
      if (descMatch) protocolDescription = descMatch[1].trim();

      const invMatch = protocol.match(/## Invariants\n([\s\S]*?)$/);
      if (invMatch) {
        invariants = invMatch[1]
          .split("\n")
          .filter((l) => l.startsWith("- "))
          .map((l) => l.replace(/^- /, "").trim());
      }
    } catch {
      // No protocol.md — hunter will work without it
    }

    modules.push({ name, source, path: filePath, protocolDescription, invariants });
  }

  return modules;
}

export interface PipelineContext {
  target: string;
  modules: ModuleInfo[];
  rankerScores: ModuleScore[];
  hunterTargets: ModuleInfo[];
  rawFindings: Finding[];
  findings: ValidatedFinding[];
}

export function buildPipelineContext(target: string, modules: ModuleInfo[]): PipelineContext {
  return {
    target,
    modules,
    rankerScores: [],
    hunterTargets: [],
    rawFindings: [],
    findings: [],
  };
}

export function shouldSkipRanker(modules: ModuleInfo[]): boolean {
  return modules.length <= 3;
}

export function buildScanResult(ctx: PipelineContext): ScanResult {
  return {
    target: ctx.target,
    timestamp: new Date().toISOString(),
    modulesScanned: ctx.modules.length,
    modulesHunted: ctx.hunterTargets.length,
    findings: ctx.findings,
    rawFindings: ctx.rawFindings,
    rankerScores: ctx.rankerScores,
  };
}
