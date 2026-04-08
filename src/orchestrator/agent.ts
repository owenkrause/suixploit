import Anthropic from "@anthropic-ai/sdk";
import { dockerExec } from "./docker.js";

export interface AgentOptions {
  containerId: string;
  systemPrompt: string;
  model: string;
  maxTurns: number;
  moduleName: string;
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

export async function runAgent(
  client: Anthropic,
  options: AgentOptions
): Promise<AgentResult> {
  const { containerId, systemPrompt, model, maxTurns, moduleName } = options;
  const tool = buildToolDefinition();

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

  while (turns < maxTurns) {
    turns++;

    let response: Anthropic.Message;
    try {
      response = await client.messages.create({
        model,
        max_tokens: 16384,
        system: systemPrompt,
        tools: [tool],
        messages,
      });
    } catch (err) {
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

    // Add assistant response to conversation
    messages.push({ role: "assistant", content: response.content });

    if (response.stop_reason !== "tool_use") {
      return {
        moduleName,
        turns,
        inputTokens: totalInputTokens,
        outputTokens: totalOutputTokens,
        stopped: "end_turn",
      };
    }

    // Execute all tool calls in parallel
    const toolUseBlocks = response.content.filter(
      (block): block is Anthropic.ToolUseBlock => block.type === "tool_use"
    );

    const toolResults = await Promise.all(
      toolUseBlocks.map(async (block) => {
        const input = block.input as { command: string };
        console.error(`[${moduleName}] $ ${input.command.slice(0, 100)}`);

        const result = await dockerExec(containerId, input.command);
        const output = [result.stdout, result.stderr]
          .filter(Boolean)
          .join("\n")
          .slice(0, 50_000);

        return {
          type: "tool_result" as const,
          tool_use_id: block.id,
          content: output || "(no output)",
        };
      })
    );

    messages.push({ role: "user", content: toolResults });
  }

  return {
    moduleName,
    turns,
    inputTokens: totalInputTokens,
    outputTokens: totalOutputTokens,
    stopped: "max_turns",
  };
}
