export class Semaphore {
  private queue: (() => void)[] = [];
  private active = 0;

  constructor(private readonly limit: number) {}

  acquire(): Promise<() => void> {
    return new Promise<() => void>((resolve) => {
      const tryRun = () => {
        if (this.active < this.limit) {
          this.active++;
          resolve(() => {
            this.active--;
            if (this.queue.length > 0) {
              this.queue.shift()!();
            }
          });
        } else {
          this.queue.push(tryRun);
        }
      };
      tryRun();
    });
  }
}
