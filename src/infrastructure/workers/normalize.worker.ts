import { normalizeVulnerabilityBatch } from '../../application/pipeline/VulnerabilityBatchNormalizer';
import type { AsyncTaskRequestMessage, AsyncTaskResponseMessage } from '../async/AsyncTaskTypes';

const toErrorMessage = (error: unknown): string => {
  if (error instanceof Error && error.message.trim()) {
    return error.message.trim();
  }

  return 'Worker vulnerability normalization failed.';
};

self.onmessage = (event: MessageEvent<AsyncTaskRequestMessage<'normalize-vulnerabilities'>>) => {
  const request = event.data;

  try {
    const message: AsyncTaskResponseMessage<'normalize-vulnerabilities'> = {
      requestId: request.requestId,
      result: {
        batch: normalizeVulnerabilityBatch(request.payload.input)
      },
      success: true,
      taskKind: 'normalize-vulnerabilities'
    };
    self.postMessage(message);
  } catch (error) {
    const message: AsyncTaskResponseMessage<'normalize-vulnerabilities'> = {
      error: toErrorMessage(error),
      requestId: request.requestId,
      success: false,
      taskKind: 'normalize-vulnerabilities'
    };
    self.postMessage(message);
  }
};

export {};
