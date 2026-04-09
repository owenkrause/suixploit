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
  // Recursively find all .move files inside any sources/ directory, skipping tests/ and build/
  const SKIP_DIRS = new Set(["tests", "build", "node_modules", ".suixploit"]);

  async function findSourceMoveFiles(dir: string, inSources: boolean): Promise<string[]> {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return [];
    }
    const paths: string[] = [];
    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        const nowInSources = inSources || entry.name === "sources";
        paths.push(...await findSourceMoveFiles(full, nowInSources));
      } else if (inSources && entry.name.endsWith(".move")) {
        paths.push(full);
      }
    }
    return paths;
  }

  let moveFiles = await findSourceMoveFiles(resolve(targetPath), false);

  if (moveFiles.length === 0) {
    // Fallback: maybe targetPath itself is a sources/ dir
    moveFiles = await findSourceMoveFiles(resolve(targetPath), true);
  }

  // Try to read protocol.md once for all modules
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

  const modules: ModuleInfo[] = [];
  for (const filePath of moveFiles) {
    const source = await readFile(filePath, "utf-8");

    // Extract module name from declaration (not comments)
    const moduleMatch = source.match(/^module\s+([\w:]+)/m);
    const name = moduleMatch ? moduleMatch[1] : filePath.replace(/.*\//, "").replace(".move", "");

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
