import { CooperativeScheduler } from './CooperativeScheduler';
import type {
  AsyncTaskKind,
  AsyncTaskPayloadByKind,
  AsyncTaskRequestMessage,
  AsyncTaskResponseMessage,
  AsyncTaskResultByKind,
  AsyncTaskToken
} from './AsyncTaskTypes';
import { WorkerFactory, type WorkerHandle } from './WorkerFactory';

interface PendingWorkerRequest<K extends AsyncTaskKind> {
  reject: (error: Error) => void;
  resolve: (result: AsyncTaskResultByKind[K]) => void;
}

interface AsyncTaskExecutionOptions<K extends AsyncTaskKind> {
  readonly fallback: (
    payload: AsyncTaskPayloadByKind[K],
    scheduler: CooperativeScheduler
  ) => Promise<AsyncTaskResultByKind[K]>;
  readonly preferWorker?: boolean;
}

class WorkerClient<K extends AsyncTaskKind> {
  private nextRequestId = 1;
  private readonly pending = new Map<number, PendingWorkerRequest<K>>();

  public constructor(
    private readonly taskKind: K,
    private readonly handle: WorkerHandle
  ) {
    this.handle.worker.addEventListener('error', (event: ErrorEvent) => {
      const error = event.error instanceof Error
        ? event.error
        : new Error(event.message || `Worker task "${this.taskKind}" failed.`);
      this.rejectAll(error);
    });
    this.handle.worker.addEventListener('message', (event: MessageEvent<AsyncTaskResponseMessage<K>>) => {
      this.handleMessage(event.data);
    });
  }

  public dispose(): void {
    this.rejectAll(new Error(`Worker task "${this.taskKind}" was disposed.`));
    this.handle.dispose();
  }

  public post(payload: AsyncTaskPayloadByKind[K]): Promise<AsyncTaskResultByKind[K]> {
    const requestId = this.nextRequestId++;
    const message: AsyncTaskRequestMessage<K> = {
      payload,
      requestId,
      taskKind: this.taskKind
    };

    return new Promise<AsyncTaskResultByKind[K]>((resolve, reject) => {
      this.pending.set(requestId, {
        reject,
        resolve
      });
      this.handle.worker.postMessage(message);
    });
  }

  private handleMessage(message: AsyncTaskResponseMessage<K>): void {
    if (message.taskKind !== this.taskKind) {
      return;
    }

    const pending = this.pending.get(message.requestId);
    if (!pending) {
      return;
    }

    this.pending.delete(message.requestId);
    if (message.success) {
      pending.resolve(message.result);
      return;
    }

    pending.reject(new Error(message.error));
  }

  private rejectAll(error: Error): void {
    const pendingRequests = Array.from(this.pending.values());
    this.pending.clear();

    for (const pending of pendingRequests) {
      pending.reject(error);
    }
  }
}

export class AsyncTaskCoordinator {
  private readonly scheduler: CooperativeScheduler;
  private readonly tokens = new Map<string, number>();
  private readonly workerClients = new Map<AsyncTaskKind, WorkerClient<AsyncTaskKind>>();
  private readonly workerFactory: WorkerFactory;

  public constructor(
    workerFactory = new WorkerFactory(),
    scheduler = new CooperativeScheduler()
  ) {
    this.workerFactory = workerFactory;
    this.scheduler = scheduler;
  }

  public beginToken(key: string): AsyncTaskToken {
    const generation = (this.tokens.get(key) ?? 0) + 1;
    this.tokens.set(key, generation);
    return {
      generation,
      key
    };
  }

  public dispose(): void {
    for (const client of this.workerClients.values()) {
      client.dispose();
    }

    this.workerClients.clear();
  }

  public async execute<K extends AsyncTaskKind>(
    taskKind: K,
    payload: AsyncTaskPayloadByKind[K],
    options: AsyncTaskExecutionOptions<K>
  ): Promise<AsyncTaskResultByKind[K]> {
    if (options.preferWorker !== false) {
      const workerClient = await this.getWorkerClient(taskKind);
      if (workerClient) {
        try {
          return await workerClient.post(payload);
        } catch (error) {
          this.disposeWorkerClient(taskKind);
          console.warn('[vulndash.async.worker_fallback]', {
            error: error instanceof Error ? error.message : 'unknown_worker_error',
            taskKind
          });
        }
      }
    }

    return options.fallback(payload, this.scheduler);
  }

  public isCurrent(token: AsyncTaskToken): boolean {
    return this.tokens.get(token.key) === token.generation;
  }

  public releaseToken(token: AsyncTaskToken): void {
    if (this.isCurrent(token)) {
      this.tokens.delete(token.key);
    }
  }

  private disposeWorkerClient(taskKind: AsyncTaskKind): void {
    const client = this.workerClients.get(taskKind);
    if (!client) {
      return;
    }

    client.dispose();
    this.workerClients.delete(taskKind);
  }

  private async getWorkerClient<K extends AsyncTaskKind>(taskKind: K): Promise<WorkerClient<K> | null> {
    const existingClient = this.workerClients.get(taskKind) as WorkerClient<K> | undefined;
    if (existingClient) {
      return existingClient;
    }

    const workerHandle = await this.workerFactory.create(taskKind);
    if (!workerHandle) {
      return null;
    }

    const client = new WorkerClient(taskKind, workerHandle);
    this.workerClients.set(taskKind, client as unknown as WorkerClient<AsyncTaskKind>);
    return client;
  }
}
