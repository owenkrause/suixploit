import { spawn, type ChildProcess } from "node:child_process";

export interface DevnetPorts {
  port: number;
  faucetPort: number;
}

export interface DevnetProcess {
  process: ChildProcess;
  rpcUrl: string;
  faucetUrl: string;
  port: number;
  faucetPort: number;
  kill: () => void;
}

let nextPort = 9100;

export function allocatePorts(): DevnetPorts {
  const port = nextPort;
  const faucetPort = port + 23; // sui convention: faucet = rpc + 23
  nextPort += 100; // space out for safety
  return { port, faucetPort };
}

export function buildSuiStartArgs(ports: DevnetPorts): string[] {
  return [
    "start",
    "--with-faucet",
    "--force-regenesis",
    "--fullnode-rpc-port",
    String(ports.port),
    "--faucet-port",
    String(ports.faucetPort),
  ];
}

export function parsePortFromArgs(args: string[]): number {
  const idx = args.indexOf("--fullnode-rpc-port");
  if (idx === -1 || idx + 1 >= args.length) throw new Error("No port in args");
  return parseInt(args[idx + 1], 10);
}

export async function startDevnet(ports?: DevnetPorts): Promise<DevnetProcess> {
  const { port, faucetPort } = ports ?? allocatePorts();
  const args = buildSuiStartArgs({ port, faucetPort });

  const child = spawn("sui", args, {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env },
  });

  const rpcUrl = `http://127.0.0.1:${port}`;
  const faucetUrl = `http://127.0.0.1:${faucetPort}`;

  // Wait for devnet to be ready by polling the RPC endpoint
  await waitForRpc(rpcUrl);

  return {
    process: child,
    rpcUrl,
    faucetUrl,
    port,
    faucetPort,
    kill: () => {
      child.kill("SIGTERM");
    },
  };
}

async function waitForRpc(url: string, timeoutMs = 30000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "sui_getLatestCheckpointSequenceNumber",
          id: 1,
        }),
      });
      if (res.ok) return;
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`Devnet at ${url} failed to start within ${timeoutMs}ms`);
}

export function stopDevnet(devnet: DevnetProcess): void {
  devnet.kill();
}
