import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildHunterPrompt } from "./prompt.js";
import type { ModuleInfo, Finding, DevnetConfig } from "../types.js";

export interface HunterInput {
  module: ModuleInfo;
  devnetConfig: DevnetConfig;
  packageId: string;
  relatedModuleSignatures?: string;
}

export function prepareHunterPrompt(input: HunterInput): string {
  return buildHunterPrompt({
    moduleName: input.module.name,
    moduleSource: input.module.source,
    protocolDescription: input.module.protocolDescription ?? "No description provided.",
    invariants: input.module.invariants ?? [],
    attackerAddress: input.devnetConfig.attackerAddress,
    adminAddress: input.devnetConfig.adminAddress,
    userAddress: input.devnetConfig.userAddress,
    rpcUrl: input.devnetConfig.rpcUrl,
    packageId: input.packageId,
    relatedModuleSignatures: input.relatedModuleSignatures,
  });
}

export async function collectFindings(worktreePath: string): Promise<Finding[]> {
  try {
    const findingsPath = resolve(worktreePath, "findings.json");
    const content = await readFile(findingsPath, "utf-8");
    return JSON.parse(content) as Finding[];
  } catch {
    return [];
  }
}
