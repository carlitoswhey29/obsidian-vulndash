import type { AsyncTaskKind } from './AsyncTaskTypes';
import { WORKER_BUNDLE_LOADERS } from './WorkerBundleRegistry';

export interface WorkerHandle {
  readonly worker: Worker;
  dispose(): void;
}

export class WorkerFactory {
  private readonly unavailableKinds = new Set<AsyncTaskKind>();

  public async create(taskKind: AsyncTaskKind): Promise<WorkerHandle | null> {
    if (
      this.unavailableKinds.has(taskKind)
      || typeof Worker !== 'function'
      || typeof Blob === 'undefined'
      || typeof URL.createObjectURL !== 'function'
    ) {
      return null;
    }

    try {
      const workerCode = await WORKER_BUNDLE_LOADERS[taskKind]();
      const blobUrl = URL.createObjectURL(new Blob([workerCode], {
        type: 'text/javascript'
      }));
      const worker = new Worker(blobUrl, {
        name: `vulndash-${taskKind}`
      });

      return {
        dispose: () => {
          worker.terminate();
          URL.revokeObjectURL(blobUrl);
        },
        worker
      };
    } catch (error) {
      this.unavailableKinds.add(taskKind);
      console.warn('[vulndash.async.worker_unavailable]', {
        error: error instanceof Error ? error.message : 'unknown_worker_error',
        taskKind
      });
      return null;
    }
  }
}
