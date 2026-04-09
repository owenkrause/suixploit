import Anthropic from "@anthropic-ai/sdk";
import { appendFileSync, writeFileSync } from "node:fs";
import type { StatusDisplay } from "./display.js";

export type ExecFn = (command: string) => Promise<{ stdout: string; stderr: string; exitCode: number }>;

export interface AgentOptions {
  exec: ExecFn;
  systemPrompt: string;
  model: string;
  maxTurns?: number;
  moduleName: string;
  logFile?: string;
  display?: StatusDisplay;
  thinkingBudget?: number;
}

export interface AgentResult {
  moduleName: string;
  turns: number;
  inputTokens: number;
  outputTokens: number;
  stopped: "end_turn" | "max_turns" | "error";
  error?: string;
}

export function buildToolDefinition(): Anthropic.Tool {
  return {
    name: "bash",
    description:
      "Run a shell command in the container. Use this to read files, run the Sui CLI, execute TypeScript exploit scripts with `npx tsx`, and invoke the oracle with `npx tsx src/oracle/check.ts`.",
    input_schema: {
      type: "object" as const,
      properties: {
        command: {
          type: "string",
          description: "The bash command to execute",
        },
      },
      required: ["command"],
    },
  };
}

export function buildSystemPrompt(
  hunterPrompt: string,
  context: Record<string, string>
): string {
  return `${hunterPrompt}

## Environment (pre-configured — do NOT modify)

The Sui devnet is already running. The contract is already deployed. Accounts are funded. Use these values directly:

- RPC URL: ${context.rpcUrl}
- Faucet URL: ${context.faucetUrl ?? "http://127.0.0.1:9123"}
- Package ID: ${context.packageId}
- Attacker address: ${context.attackerAddress}
- Admin address: ${context.adminAddress}
- User address: ${context.userAddress}

You have a \`bash\` tool to run shell commands. The project source is at /workspace.
Working directory is /workspace. Write your exploit files there.

When you are done, write your findings to /workspace/findings.json.`;
}

export function buildMainnetSystemPrompt(
  hunterPrompt: string,
  context: Record<string, string>
): string {
  return `${hunterPrompt}

## Environment (mainnet dry-run — read-only, nothing executes on-chain)

You are analyzing a live contract on Sui mainnet. All transactions are simulated via dry-run.

- RPC URL: ${context.rpcUrl}
- Package ID: ${context.packageId}

You have a \`bash\` tool to run shell commands. The project source is in the current directory.
The @mysten/sui TypeScript SDK and Sui CLI are available.
Use \`npx tsx\` to run TypeScript files.

When you are done, write your findings to findings.json in the current directory.`;
}

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

function summarizeThinking(content: Anthropic.ContentBlock[]): string {
  for (const block of content) {
    if (block.type === "text" && block.text.length > 0) {
      // First sentence or first 80 chars of the text block
      const first = block.text.split(/[.\n]/)[0].trim();
      return first.length > 80 ? first.slice(0, 77) + "..." : first;
    }
  }
  return "";
}

export async function runAgent(
  client: Anthropic,
  options: AgentOptions
): Promise<AgentResult> {
  const { exec, systemPrompt, model, maxTurns, moduleName, logFile, display, thinkingBudget = 16000 } = options;
  const tool = buildToolDefinition();

  // Initialize log file with system prompt
  if (logFile) {
    writeFileSync(logFile, `# Agent Log: ${moduleName}\n# Model: ${model}\n# Started: ${new Date().toISOString()}\n\n`);
    appendFileSync(logFile, `## System Prompt\n${systemPrompt}\n\n---\n\n`);
  }

  function log(entry: string) {
    if (logFile) appendFileSync(logFile, entry + "\n");
  }

  function status(turn: number, tokens: number, text: string) {
    const tok = formatTokens(tokens);
    if (display) {
      display.update(moduleName, { turn, tokens: tok, status: text });
    } else {
      console.error(`[${moduleName}] turn ${turn} | ${tok} tokens | ${text}`);
    }
  }

  function emit(message: string) {
    if (display) {
      display.log(message);
    } else {
      console.error(message);
    }
  }

  let messages: Anthropic.MessageParam[] = [
    {
      role: "user",
      content:
        "Begin your security analysis. Find vulnerabilities and confirm them with the oracle.",
    },
  ];

  let turns = 0;
  let totalInputTokens = 0;
  let totalOutputTokens = 0;

  status(0, 0, "starting...");

  while (!maxTurns || turns < maxTurns) {
    turns++;
    status(turns, totalInputTokens + totalOutputTokens, "thinking...");

    let response: Anthropic.Message;
    try {
      response = await client.messages.create({
        model,
        max_tokens: 16384,
        ...(thinkingBudget > 0 ? {
          thinking: { type: "enabled" as const, budget_tokens: thinkingBudget },
        } : {}),
        system: systemPrompt,
        tools: [tool],
        messages,
      });
    } catch (err) {
      emit(`[${moduleName}] ✗ API error on turn ${turns}: ${String(err).slice(0, 120)}`);
      log(`\n## Turn ${turns} — ERROR\n${String(err)}\n`);
      if (display) display.remove(moduleName);
      return {
        moduleName,
        turns,
        inputTokens: totalInputTokens,
        outputTokens: totalOutputTokens,
        stopped: "error",
        error: String(err),
      };
    }

    totalInputTokens += response.usage.input_tokens;
    totalOutputTokens += response.usage.output_tokens;
    const totalTokens = totalInputTokens + totalOutputTokens;

    // Add assistant response to conversation
    messages.push({ role: "assistant", content: response.content });

    // Log full response
    log(`\n## Turn ${turns} (${formatTokens(totalTokens)} total)`);
    for (const block of response.content) {
      if (block.type === "thinking") log(`\n### Thinking (internal)\n${(block as unknown as { thinking: string }).thinking}\n`);
      else if (block.type === "text") log(`\n### Response\n${block.text}\n`);
      else if (block.type === "tool_use") log(`\n### Tool: ${(block.input as { command: string }).command}\n`);
    }

    if (response.stop_reason !== "tool_use") {
      const summary = summarizeThinking(response.content);
      emit(`[${moduleName}] done after ${turns} turns (${formatTokens(totalTokens)} tokens) — ${summary}`);
      if (display) display.remove(moduleName);
      return {
        moduleName,
        turns,
        inputTokens: totalInputTokens,
        outputTokens: totalOutputTokens,
        stopped: "end_turn",
      };
    }

    // Execute all tool calls
    const toolUseBlocks = response.content.filter(
      (block): block is Anthropic.ToolUseBlock => block.type === "tool_use"
    );

    // Status: show what commands are running
    const cmdSummary = toolUseBlocks.map((b) => {
      const cmd = (b.input as { command: string }).command;
      const base = cmd.split(/[|\s]/)[0];
      return base;
    }).join(", ");
    status(turns, totalTokens, cmdSummary);

    const toolResults = await Promise.all(
      toolUseBlocks.map(async (block) => {
        const input = block.input as { command: string };

        const result = await exec(input.command);
        const output = [result.stdout, result.stderr]
          .filter(Boolean)
          .join("\n")
          .slice(0, 50_000);

        // Log errors as persistent messages
        if (result.exitCode !== 0) {
          const errPreview = (result.stderr || result.stdout || "").split("\n")[0].slice(0, 120);
          emit(`[${moduleName}] ✗ exit ${result.exitCode}: ${errPreview}`);
        }

        log(`\n### Result (exit ${result.exitCode})\n\`\`\`\n${output.slice(0, 5000)}\n\`\`\`\n`);

        return {
          type: "tool_result" as const,
          tool_use_id: block.id,
          content: output || "(no output)",
        };
      })
    );

    // Warn agent on second-to-last turn to flush output
    if (maxTurns && turns === maxTurns - 1) {
      messages.push({
        role: "user",
        content: [
          ...toolResults,
          {
            type: "text" as const,
            text: `WARNING: You are about to hit your turn limit. This is your LAST turn. Write your output file NOW with whatever analysis you have so far. Note that you hit the turn limit.`,
          },
        ],
      });
    } else {
      messages.push({ role: "user", content: toolResults });
    }
  }

  emit(`[${moduleName}] hit max turns (${maxTurns}) | ${formatTokens(totalInputTokens + totalOutputTokens)} tokens`);
  log(`\n## Hit max turns (${maxTurns})\n`);
  if (display) display.remove(moduleName);

  return {
    moduleName,
    turns,
    inputTokens: totalInputTokens,
    outputTokens: totalOutputTokens,
    stopped: "max_turns",
  };
}
