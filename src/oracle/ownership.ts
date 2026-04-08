import type { OracleResult } from "../types.js";

export interface ObjectChange {
  type: "created" | "mutated" | "deleted" | "wrapped" | "published";
  objectId: string;
  owner?: { AddressOwner: string } | { Shared: unknown } | Record<string, unknown>;
  sender: string;
}

export function checkOwnership(
  attackerAddress: string,
  objectChanges: ObjectChange[]
): OracleResult {
  const stolenObjects = objectChanges.filter((change) => {
    if (change.type === "created") return false;
    if (change.type === "deleted" || change.type === "wrapped" || change.type === "published") return false;
    if (!change.owner || !("AddressOwner" in change.owner)) return false;
    const ownerAddr = (change.owner as { AddressOwner: string }).AddressOwner;
    return ownerAddr === attackerAddress;
  });

  const gained = stolenObjects.length > 0;

  return {
    signal: "ownership",
    status: gained ? "EXPLOIT_CONFIRMED" : "NO_EXPLOIT",
    preTxState: { attackerAddress },
    postTxState: {
      gainedObjects: stolenObjects.map((o) => o.objectId),
    },
  };
}
