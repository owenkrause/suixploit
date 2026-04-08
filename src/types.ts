export type Severity = "critical" | "high" | "medium" | "low";

export type FindingCategory =
  | "capability_misuse"
  | "shared_object_race"
  | "integer_overflow"
  | "ownership_violation"
  | "hot_potato_misuse"
  | "otw_abuse"
  | "other";

export type OracleSignal = "abort" | "balance" | "ownership" | "custom";

export interface ModuleScore {
  module: string;
  score: number;
  rationale: string;
  attackSurface: string[];
}

export interface OracleResult {
  signal: OracleSignal;
  status: "EXPLOIT_CONFIRMED" | "NO_EXPLOIT";
  preTxState: Record<string, unknown>;
  postTxState: Record<string, unknown>;
}

export interface Finding {
  id: string;
  module: string;
  severity: Severity;
  category: FindingCategory;
  title: string;
  description: string;
  exploitTransaction: string;
  oracleResult: OracleResult;
  iterations: number;
}

export interface ValidatedFinding extends Finding {
  validatorVerdict: "confirmed" | "adjusted" | "rejected";
  validatorNote: string;
  adjustedSeverity?: Severity;
  impact?: string;
  duplicateOf?: string;
}

export interface ScanResult {
  target: string;
  timestamp: string;
  modulesScanned: number;
  modulesHunted: number;
  findings: ValidatedFinding[];
  rawFindings: Finding[];
  rankerScores: ModuleScore[];
}

export interface ModuleInfo {
  name: string;
  source: string;
  path: string;
  protocolDescription?: string;
  invariants?: string[];
}

export interface DevnetConfig {
  rpcUrl: string;
  faucetUrl: string;
  port: number;
  faucetPort: number;
  adminAddress: string;
  attackerAddress: string;
  userAddress: string;
  adminKeyPair: string;
  attackerKeyPair: string;
  userKeyPair: string;
}
