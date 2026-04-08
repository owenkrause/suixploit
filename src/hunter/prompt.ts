export interface HunterPromptInput {
  moduleName: string;
  moduleSource: string;
  protocolDescription: string;
  invariants: string[];
  attackerAddress: string;
  adminAddress: string;
  userAddress: string;
  rpcUrl: string;
  packageId: string;
}

export function buildHunterPrompt(input: HunterPromptInput): string {
  const invariantList = input.invariants.map((inv) => `- ${inv}`).join("\n");

  return `You are auditing a Sui Move smart contract module for security vulnerabilities.

## Target
Module: ${input.moduleName}
Package ID: ${input.packageId}
Protocol description: ${input.protocolDescription}

Invariants:
${invariantList}

## Source
\`\`\`move
${input.moduleSource}
\`\`\`

## Environment
- Sui devnet RPC: ${input.rpcUrl}
- Attacker address: ${input.attackerAddress}
- Admin address: ${input.adminAddress}
- User address: ${input.userAddress}
- Sui CLI and @mysten/sui TS SDK are available
- Use \`npx tsx\` to run TypeScript files

## Oracle
To check if an exploit works, write a TS file that exports:
- \`buildTx(client, attackerAddress: string)\` — returns a Transaction
- \`attackerKeypair\` — the Ed25519Keypair for the attacker

Then run:
\`\`\`bash
npx tsx src/oracle/check.ts --signal <abort|balance|ownership> --tx <path-to-your-exploit.ts> --attacker ${input.attackerAddress} --rpc-url ${input.rpcUrl}
\`\`\`

Signals:
- \`abort\` — use when a tx SHOULD fail but succeeds (access control bypass). Add \`--expected should_abort\`
- \`balance\` — use when the attacker's balance increases (fund drain)
- \`ownership\` — use when the attacker gains objects they shouldn't own

Returns: EXPLOIT_CONFIRMED or NO_EXPLOIT

## Task
Find a vulnerability in this module and confirm it with the oracle.
Write exploit transactions as TS files, run them via dry-run, check with the oracle.
Iterate until you find something or exhaust your ideas.
When done, write your findings to findings.json in this format:
\`\`\`json
[{
  "id": "unique-id",
  "module": "${input.moduleName}",
  "severity": "critical|high|medium|low",
  "category": "capability_misuse|shared_object_race|integer_overflow|ownership_violation|hot_potato_misuse|otw_abuse|other",
  "title": "Short title",
  "description": "What the bug is and how to exploit it",
  "exploitTransaction": "// the TS exploit code",
  "oracleResult": { /* paste oracle output */ },
  "iterations": 3
}]
\`\`\``;
}
