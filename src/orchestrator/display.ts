/**
 * Live-updating terminal status display for concurrent agents.
 * Each agent gets a line that updates in-place. Persistent messages
 * (errors, completions) are printed above the status block.
 */

const ESC = "\x1b";
const CLEAR_LINE = `${ESC}[2K`;
const MOVE_UP = (n: number) => `${ESC}[${n}A`;
const HIDE_CURSOR = `${ESC}[?25l`;
const SHOW_CURSOR = `${ESC}[?25h`;

export interface AgentStatus {
  turn: number;
  tokens: string;
  status: string;
}

export class StatusDisplay {
  private agents = new Map<string, AgentStatus>();
  private lineCount = 0;
  private enabled: boolean;

  constructor() {
    // Only use live display if stderr is a TTY
    this.enabled = process.stderr.isTTY ?? false;
    if (this.enabled) {
      process.stderr.write(HIDE_CURSOR);
      process.on("exit", () => process.stderr.write(SHOW_CURSOR));
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

    for (const [name, s] of this.agents) {
      const padded = name.padEnd(maxName);
      lines.push(`${CLEAR_LINE}  ${padded}  turn ${String(s.turn).padStart(3)} | ${s.tokens.padStart(7)} | ${s.status}`);
    }

    if (lines.length > 0) {
      process.stderr.write(lines.join("\n") + "\n");
    }
    this.lineCount = lines.length;
  }
}
