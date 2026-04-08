import type { OracleResult } from "../types.js";

export interface DryRunEffects {
  effects: {
    status: { status: "success" | "failure" };
  };
}

export function checkAbort(
  dryRunResult: DryRunEffects,
  expected: "should_abort"
): OracleResult {
  const txSucceeded = dryRunResult.effects.status.status === "success";

  if (expected === "should_abort" && txSucceeded) {
    return {
      signal: "abort",
      status: "EXPLOIT_CONFIRMED",
      preTxState: { expected },
      postTxState: { txStatus: dryRunResult.effects.status.status },
    };
  }

  return {
    signal: "abort",
    status: "NO_EXPLOIT",
    preTxState: { expected },
    postTxState: { txStatus: dryRunResult.effects.status.status },
  };
}
