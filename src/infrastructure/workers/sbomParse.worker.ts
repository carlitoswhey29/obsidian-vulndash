import { parseSbomJson } from '../parsers';
import type { AsyncTaskRequestMessage, AsyncTaskResponseMessage, ParseSbomTaskRequest } from '../async/AsyncTaskTypes';

const toErrorMessage = (error: unknown): string => {
  if (error instanceof Error && error.message.trim()) {
    return error.message.trim();
  }

  return 'Worker SBOM parse failed.';
};

const parseSbom = (payload: ParseSbomTaskRequest): AsyncTaskResponseMessage<'parse-sbom'> => {
  const parsed = JSON.parse(payload.raw) as unknown;
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('SBOM file is not a valid JSON object.');
  }

  return {
    requestId: -1,
    result: {
      document: parseSbomJson(parsed, { source: payload.source })
    },
    success: true,
    taskKind: 'parse-sbom'
  };
};

self.onmessage = (event: MessageEvent<AsyncTaskRequestMessage<'parse-sbom'>>) => {
  const request = event.data;

  try {
    const response = parseSbom(request.payload);
    const message: AsyncTaskResponseMessage<'parse-sbom'> = {
      ...response,
      requestId: request.requestId
    };
    self.postMessage(message);
  } catch (error) {
    const message: AsyncTaskResponseMessage<'parse-sbom'> = {
      error: toErrorMessage(error),
      requestId: request.requestId,
      success: false,
      taskKind: 'parse-sbom'
    };
    self.postMessage(message);
  }
};

export {};
