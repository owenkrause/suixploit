import type { OracleResult } from "../types.js";

export interface BalanceChange {
  owner: { AddressOwner: string } | { ObjectOwner: string } | Record<string, unknown>;
  coinType: string;
  amount: string;
}

export function checkBalance(
  attackerAddress: string,
  balanceChanges: BalanceChange[]
): OracleResult {
  const attackerGains = balanceChanges.filter((change) => {
    const ownerAddr =
      "AddressOwner" in change.owner
        ? (change.owner as { AddressOwner: string }).AddressOwner
        : null;
    return ownerAddr === attackerAddress && BigInt(change.amount) > 0n;
  });

  const gained = attackerGains.length > 0;

  return {
    signal: "balance",
    status: gained ? "EXPLOIT_CONFIRMED" : "NO_EXPLOIT",
    preTxState: { attackerAddress },
    postTxState: {
      balanceChanges: attackerGains.map((g) => ({
        coinType: g.coinType,
        amount: g.amount,
      })),
    },
  };
}
