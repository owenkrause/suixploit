import { resolve } from "node:path";

export interface ScanPaths {
  root: string;
  scanMeta: string;
  findingsDir: string;
  allRawFindings: string;
  validatedFindings: string;
  huntersDir: string;
  validatorsDir: string;
}

/** Generate a timestamped run directory name */
export function generateRunId(): string {
  return new Date().toISOString().replace(/:/g, "-").replace(/\.\d+Z$/, "");
}

export function buildScanPaths(runDir: string): ScanPaths {
  return {
    root: runDir,
    scanMeta: resolve(runDir, "scan.json"),
    findingsDir: resolve(runDir, "findings"),
    allRawFindings: resolve(runDir, "findings", "all-raw.json"),
    validatedFindings: resolve(runDir, "findings", "validated.json"),
    huntersDir: resolve(runDir, "hunters"),
    validatorsDir: resolve(runDir, "validators"),
  };
}

/** Convert module name to directory-safe form: deepbook_margin::oracle → deepbook_margin-oracle */
export function safeName(moduleName: string): string {
  return moduleName.replace(/::/g, "-");
}

export function hunterWorkspace(paths: ScanPaths, moduleName: string): string {
  return resolve(paths.huntersDir, safeName(moduleName));
}

export function hunterScratch(paths: ScanPaths, moduleName: string): string {
  return resolve(hunterWorkspace(paths, moduleName), "scratch");
}

/** Validator dir: validators/<module>/<findingId>/ */
export function validatorDir(paths: ScanPaths, moduleName: string, findingId: string): string {
  return resolve(paths.validatorsDir, safeName(moduleName), findingId);
}

export function validatorScratch(paths: ScanPaths, moduleName: string, findingId: string): string {
  return resolve(validatorDir(paths, moduleName, findingId), "scratch");
}

export function validatorVerdict(paths: ScanPaths, moduleName: string, findingId: string): string {
  return resolve(validatorDir(paths, moduleName, findingId), "verdict.json");
}

export function validatorLog(paths: ScanPaths, moduleName: string, findingId: string): string {
  return resolve(validatorDir(paths, moduleName, findingId), "agent.log");
}
