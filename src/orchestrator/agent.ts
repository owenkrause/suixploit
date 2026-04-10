import Anthropic from "@anthropic-ai/sdk";
import { appendFileSync, writeFileSync } from "node:fs";
import { type StatusDisplay, c } from "./display.js";
import { listReferences, readReference } from "../references.js";
import type { EffortLevel } from "./index.js";

const MAX_RETRIES = 5;
const LOG_OUTPUT_LIMIT = 5_000;

const EFFORT_PRESETS: Record<EffortLevel, { effort: EffortLevel; maxTokens: number; toolOutputLimit: number }> = {
  low:    { effort: "low",    maxTokens: 16_000,  toolOutputLimit: 50_000 },
  medium: { effort: "medium", maxTokens: 32_000,  toolOutputLimit: 50_000 },
  high:   { effort: "high",   maxTokens: 64_000,  toolOutputLimit: 100_000 },
  max:    { effort: "max",    maxTokens: 128_000, toolOutputLimit: 150_000 },
};

export type ExecFn = (command: string) => Promise<{ stdout: string; stderr: string; exitCode: number }>;

export interface AgentOptions {
  exec: ExecFn;
  systemPrompt: string;
  model: string;
  maxTurns?: number;
  moduleName: string;
  logFile?: string;
  display?: StatusDisplay;
  effort?: EffortLevel;
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

export function buildWriteFileTool(): Anthropic.Tool {
  return {
    name: "write_file",
    description:
      "Write content to a file. Use this instead of bash heredocs/echo for writing JSON, TypeScript, or any multi-line content. Handles escaping correctly.",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "File path relative to the working directory (e.g. 'findings.json', 'exploit.mts')",
        },
        content: {
          type: "string",
          description: "The full file content to write",
        },
      },
      required: ["path", "content"],
    },
  };
}

export function buildReferenceTools(): Anthropic.Tool[] {
  return [
    {
      name: "list_references",
      description:
        "List all available security reference files with descriptions and approximate sizes. Use this to find relevant vulnerability patterns, DeFi deep-dives, or methodology guides for the module you are analyzing.",
      input_schema: {
        type: "object" as const,
        properties: {},
        required: [],
      },
    },
    {
      name: "read_reference",
      description:
        "Read a security reference file by name. Returns the full content of a specific reference (vulnerability patterns, DeFi deep-dives, false positive catalog, agent methodologies, etc.).",
      input_schema: {
        type: "object" as const,
        properties: {
          name: {
            type: "string",
            description:
              "The reference name (e.g. 'sui-patterns', 'defi-lending', 'false-positive-catalog'). Use list_references to see available names.",
          },
        },
        required: ["name"],
      },
    },
  ];
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

You have a \`bash\` tool to run shell commands and a \`write_file\` tool to write files (use this for JSON and multi-line content). The contract source is at ./target/ (symlink to /workspace).
Write your exploit scripts in the current directory.

When you are done, write your findings to findings.json in the current directory.`;
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

You have a \`bash\` tool to run shell commands and a \`write_file\` tool to write files (use this for JSON and multi-line content). The contract source is at ./target/ (symlink to the project).
The @mysten/sui v2 TypeScript SDK is available. Use \`npx tsx <file>.mts\` to run TypeScript files.
IMPORTANT: Use \`SuiJsonRpcClient\` from \`@mysten/sui/jsonRpc\` — NOT \`SuiClient\` (which does not exist in v2).
Write your exploit scripts in the current directory.

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
  const { exec, systemPrompt, model, maxTurns, moduleName, logFile, display, effort = "medium" } = options;
  const { effort: effortLevel, maxTokens, toolOutputLimit } = EFFORT_PRESETS[effort];
  const tools = [buildToolDefinition(), buildWriteFileTool(), ...buildReferenceTools()];

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
    const maxRetries = MAX_RETRIES;
    let lastErr: unknown;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        response = await client.messages.create({
          model,
          max_tokens: maxTokens,
          thinking: { type: "adaptive" as const },
          output_config: { effort: effortLevel },
          system: systemPrompt,
          tools,
          messages,
        });
        break;
      } catch (err) {
        lastErr = err;
        const isRateLimit = String(err).includes("429") || String(err).includes("rate_limit");
        const isOverloaded = String(err).includes("529") || String(err).includes("overloaded");
        if ((isRateLimit || isOverloaded) && attempt < maxRetries) {
          const delay = Math.min(2 ** attempt * 5, 60);
          status(turns, totalInputTokens + totalOutputTokens, `rate limited, retry in ${delay}s...`);
          log(`\n## Turn ${turns} — rate limited, retrying in ${delay}s (attempt ${attempt + 1}/${maxRetries})\n`);
          await new Promise((r) => setTimeout(r, delay * 1000));
          continue;
        }
        emit(`${c.red}✗${c.reset} ${c.bold}${moduleName}${c.reset} ${c.dim}API error turn ${turns}:${c.reset} ${String(err).slice(0, 120)}`);
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
    }
    // @ts-expect-error — response is assigned in the loop or we returned
    if (!response) throw lastErr;

    totalInputTokens += response.usage.input_tokens;
    totalOutputTokens += response.usage.output_tokens;
    const totalTokens = totalInputTokens + totalOutputTokens;

    // Add assistant response to conversation
    messages.push({ role: "assistant", content: response.content });

    // Log full response
    log(`\n## Turn ${turns} (${formatTokens(totalTokens)} total)`);
    for (const block of response.content) {
      if (block.type === "thinking") log(`\n### Thinking (internal)\n${(block as unknown as Record<string, unknown>).thinking ?? ""}\n`);
      else if (block.type === "text") log(`\n### Response\n${block.text}\n`);
      else if (block.type === "tool_use") {
        if (block.name === "bash") log(`\n### Tool: bash — ${(block.input as { command: string }).command}\n`);
        else if (block.name === "write_file") {
          const { path, content } = block.input as { path: string; content: string };
          log(`\n### Tool: write_file — ${path} (${content.length} bytes)\n\`\`\`\n${content.slice(0, LOG_OUTPUT_LIMIT)}\n\`\`\`\n`);
        }
        else log(`\n### Tool: ${block.name}(${JSON.stringify(block.input)})\n`);
      }
    }

    if (response.stop_reason !== "tool_use") {
      const summary = summarizeThinking(response.content);
      emit(`${c.green}✓${c.reset} ${c.bold}${moduleName}${c.reset} ${c.dim}${turns} turns │ ${formatTokens(totalTokens)} tokens${c.reset}${summary ? ` — ${summary}` : ""}`);
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
      if (b.name === "list_references") return "list_references";
      if (b.name === "read_reference") return `ref:${(b.input as { name: string }).name}`;
      if (b.name === "write_file") return `write:${(b.input as { path: string }).path}`;
      const cmd = (b.input as { command: string }).command;
      return cmd.split(/[|\s]/)[0];
    }).join(", ");
    status(turns, totalTokens, cmdSummary);

    const toolResults = await Promise.all(
      toolUseBlocks.map(async (block) => {
        let output: string;

        if (block.name === "list_references") {
          output = listReferences();
        } else if (block.name === "read_reference") {
          output = readReference((block.input as { name: string }).name);
        } else if (block.name === "write_file") {
          const { path, content } = block.input as { path: string; content: string };
          const b64 = Buffer.from(content).toString("base64");
          const result = await exec(`echo '${b64}' | base64 -d > ${path}`);
          if (result.exitCode === 0) {
            output = `Wrote ${content.length} bytes to ${path}`;
          } else {
            output = `Failed to write ${path}: ${result.stderr}`;
          }
        } else {
          // bash
          const input = block.input as { command: string };
          const result = await exec(input.command);
          output = [result.stdout, result.stderr]
            .filter(Boolean)
            .join("\n")
            .slice(0, toolOutputLimit);

          if (result.exitCode !== 0) {
            log(`\n### Command failed (exit ${result.exitCode})\n`);
          }
        }

        log(`\n### Result\n\`\`\`\n${output.slice(0, LOG_OUTPUT_LIMIT)}\n\`\`\`\n`);

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

  emit(`${c.yellow}!${c.reset} ${c.bold}${moduleName}${c.reset} ${c.dim}hit max turns (${maxTurns}) │ ${formatTokens(totalInputTokens + totalOutputTokens)} tokens${c.reset}`);
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
