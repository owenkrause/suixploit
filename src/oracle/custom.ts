import type { OracleResult } from "../types.js";

export interface CustomCheckOpts {
  description: string;
  preCondition: () => Promise<unknown>;
  postCondition: (pre: unknown) => Promise<boolean>;
}

export async function checkCustom(opts: CustomCheckOpts): Promise<OracleResult> {
  const preState = await opts.preCondition();
  const exploitConfirmed = await opts.postCondition(preState);

  return {
    signal: "custom",
    status: exploitConfirmed ? "EXPLOIT_CONFIRMED" : "NO_EXPLOIT",
    preTxState: { description: opts.description, preState },
    postTxState: { exploitConfirmed },
  };
}
