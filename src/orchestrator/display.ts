/**
 * Live-updating terminal status display for concurrent agents.
 * Styled with colors, spinners, and box-drawing characters.
 */

const ESC = "\x1b";
const CLEAR_LINE = `${ESC}[2K`;
const MOVE_UP = (n: number) => `${ESC}[${n}A`;
const HIDE_CURSOR = `${ESC}[?25l`;
const SHOW_CURSOR = `${ESC}[?25h`;

const SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

export const c = {
  reset: `${ESC}[0m`,
  bold: `${ESC}[1m`,
  dim: `${ESC}[2m`,
  red: `${ESC}[31m`,
  green: `${ESC}[32m`,
  yellow: `${ESC}[33m`,
  blue: `${ESC}[34m`,
  magenta: `${ESC}[35m`,
  cyan: `${ESC}[36m`,
  gray: `${ESC}[90m`,
};

export interface AgentStatus {
  turn: number;
  tokens: string;
  status: string;
}

export class StatusDisplay {
  private agents = new Map<string, AgentStatus>();
  private lineCount = 0;
  private enabled: boolean;
  private frame = 0;
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    this.enabled = process.stderr.isTTY ?? false;
    if (this.enabled) {
      process.stderr.write(HIDE_CURSOR);
      process.on("exit", () => process.stderr.write(SHOW_CURSOR));
      this.timer = setInterval(() => {
        if (this.agents.size > 0) {
          this.frame = (this.frame + 1) % SPINNER.length;
          this.redraw();
        }
      }, 80);
    }
  }

  update(name: string, status: AgentStatus) {
    this.agents.set(name, status);
    if (this.enabled) {
      this.redraw();
    }
  }

  /** Print a persistent message above the status block */
  log(message: string) {
    if (this.enabled) {
      this.clearBlock();
      process.stderr.write(message + "\n");
      this.lineCount = 0;
      this.redraw();
    } else {
      process.stderr.write(message + "\n");
    }
  }

  remove(name: string) {
    this.agents.delete(name);
    if (this.enabled) {
      this.clearBlock();
      this.lineCount = 0;
      this.redraw();
    }
  }

  done() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.enabled) {
      this.clearBlock();
      process.stderr.write(SHOW_CURSOR);
    }
  }

  private clearBlock() {
    if (this.lineCount > 0) {
      process.stderr.write(MOVE_UP(this.lineCount));
      for (let i = 0; i < this.lineCount; i++) {
        process.stderr.write(CLEAR_LINE + "\n");
      }
      process.stderr.write(MOVE_UP(this.lineCount));
    }
  }

  private redraw() {
    this.clearBlock();

    const lines: string[] = [];
    const maxName = Math.max(...[...this.agents.keys()].map((n) => n.length), 0);
    const spinner = SPINNER[this.frame];

    for (const [name, s] of this.agents) {
      const padded = name.padEnd(maxName);

      // Color the status text based on content
      let statusText: string;
      if (s.status.includes("rate limited") || s.status.includes("retry")) {
        statusText = `${c.yellow}${s.status}${c.reset}`;
      } else if (s.status === "thinking..." || s.status === "starting...") {
        statusText = `${c.cyan}${s.status}${c.reset}`;
      } else {
        statusText = `${c.green}${s.status}${c.reset}`;
      }

      lines.push(
        `${CLEAR_LINE}  ${c.cyan}${spinner}${c.reset} ${c.bold}${padded}${c.reset}  ${c.dim}turn ${String(s.turn).padStart(3)} │ ${s.tokens.padStart(6)}${c.reset} │ ${statusText}`
      );
    }

    if (lines.length > 0) {
      process.stderr.write(lines.join("\n") + "\n");
    }
    this.lineCount = lines.length;
  }
}

/** Styled pipeline logging helpers */
export function logStep(msg: string) {
  process.stderr.write(`${c.cyan}●${c.reset} ${msg}\n`);
}

export function logResult(msg: string) {
  process.stderr.write(`${c.green}✓${c.reset} ${msg}\n`);
}

export function logWarn(msg: string) {
  process.stderr.write(`${c.yellow}!${c.reset} ${c.dim}${msg}${c.reset}\n`);
}

export function logDetail(msg: string) {
  process.stderr.write(`  ${c.dim}${msg}${c.reset}\n`);
}
