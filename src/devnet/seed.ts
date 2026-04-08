import { execSync } from "node:child_process";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { requestSuiFromFaucetV2 } from "@mysten/sui/faucet";
import type { DevnetConfig } from "../types.js";

export interface AccountSet {
  admin: { keypair: Ed25519Keypair; address: string };
  attacker: { keypair: Ed25519Keypair; address: string };
  user: { keypair: Ed25519Keypair; address: string };
}

export function generateAccounts(): AccountSet {
  const admin = new Ed25519Keypair();
  const attacker = new Ed25519Keypair();
  const user = new Ed25519Keypair();
  return {
    admin: { keypair: admin, address: admin.toSuiAddress() },
    attacker: { keypair: attacker, address: attacker.toSuiAddress() },
    user: { keypair: user, address: user.toSuiAddress() },
  };
}

export function buildPublishCommand(contractPath: string): string {
  return `sui client publish ${contractPath} --skip-dependency-verification --gas-budget 500000000`;
}

export async function fundAccount(
  faucetUrl: string,
  address: string
): Promise<void> {
  await requestSuiFromFaucetV2({ host: faucetUrl, recipient: address });
}

export async function seedDevnet(opts: {
  rpcUrl: string;
  faucetUrl: string;
  contractPath: string;
  accounts: AccountSet;
}): Promise<{ packageId: string; devnetConfig: DevnetConfig }> {
  const { rpcUrl, faucetUrl, contractPath, accounts } = opts;

  // Fund all accounts
  await Promise.all([
    fundAccount(faucetUrl, accounts.admin.address),
    fundAccount(faucetUrl, accounts.attacker.address),
    fundAccount(faucetUrl, accounts.user.address),
  ]);

  // Publish the contract as admin
  const publishCmd = buildPublishCommand(contractPath);
  const envWithClient = {
    ...process.env,
    SUI_RPC_URL: rpcUrl,
  };

  // Export admin key and set as active address
  const adminSecret = accounts.admin.keypair.getSecretKey();
  execSync(
    `sui keytool import "${adminSecret}" ed25519 --json`,
    { env: envWithClient, encoding: "utf-8" }
  );

  execSync(
    `sui client switch --address ${accounts.admin.address}`,
    { env: envWithClient, encoding: "utf-8" }
  );

  const publishResult = execSync(publishCmd, {
    env: envWithClient,
    encoding: "utf-8",
  });

  // Parse package ID from publish output
  const packageIdMatch = publishResult.match(/"packageId":\s*"(0x[a-fA-F0-9]+)"/);
  if (!packageIdMatch) {
    throw new Error(`Failed to parse packageId from publish output:\n${publishResult}`);
  }

  const packageId = packageIdMatch[1];
  const port = parseInt(new URL(rpcUrl).port, 10);
  const faucetPort = parseInt(new URL(faucetUrl).port, 10);

  return {
    packageId,
    devnetConfig: {
      rpcUrl,
      faucetUrl,
      port,
      faucetPort,
      adminAddress: accounts.admin.address,
      attackerAddress: accounts.attacker.address,
      userAddress: accounts.user.address,
      adminKeyPair: adminSecret,
      attackerKeyPair: accounts.attacker.keypair.getSecretKey(),
      userKeyPair: accounts.user.keypair.getSecretKey(),
    },
  };
}

export async function resetState(opts: {
  rpcUrl: string;
  faucetUrl: string;
  contractPath: string;
  accounts: AccountSet;
}): Promise<{ packageId: string }> {
  const { packageId } = await seedDevnet(opts);
  return { packageId };
}
