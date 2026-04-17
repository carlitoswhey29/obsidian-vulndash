export interface CooperativeSchedulingOptions {
  readonly itemsPerYield?: number;
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}

export class CooperativeScheduler {
  public async mapInBatches<TInput, TOutput>(
    values: readonly TInput[],
    iteratee: (value: TInput, index: number) => TOutput,
    options: CooperativeSchedulingOptions = {}
  ): Promise<TOutput[]> {
    const outputs: TOutput[] = [];
    let processedSinceYield = 0;

    for (const [index, value] of values.entries()) {
      this.throwIfAborted(options.signal);
      outputs.push(iteratee(value, index));
      processedSinceYield += 1;

      if (processedSinceYield >= (options.itemsPerYield ?? 100)) {
        processedSinceYield = 0;
        await this.yieldToHost(options);
      }
    }

    return outputs;
  }

  public async maybeYield(processedSinceYield: number, options: CooperativeSchedulingOptions = {}): Promise<void> {
    if (processedSinceYield < (options.itemsPerYield ?? 100)) {
      return;
    }

    await this.yieldToHost(options);
  }

  public async yieldToHost(options: CooperativeSchedulingOptions = {}): Promise<void> {
    this.throwIfAborted(options.signal);

    await new Promise<void>((resolve) => {
      if (typeof globalThis.requestIdleCallback === 'function') {
        globalThis.requestIdleCallback(() => resolve(), { timeout: options.timeoutMs ?? 16 });
        return;
      }

      globalThis.setTimeout(resolve, 0);
    });
  }

  public throwIfAborted(signal?: AbortSignal): void {
    if (signal?.aborted) {
      throw new Error('Async task aborted.');
    }
  }
}
