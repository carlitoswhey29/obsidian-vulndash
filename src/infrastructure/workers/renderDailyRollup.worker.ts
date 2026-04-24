import { RollupMarkdownRenderer } from '../../application/rollup/RollupMarkdownRenderer';
import type {
  AsyncTaskRequestMessage,
  AsyncTaskResponseMessage,
  RenderDailyRollupTaskRequest
} from '../async/AsyncTaskTypes';

const renderer = new RollupMarkdownRenderer();

const toErrorMessage = (error: unknown): string => {
  if (error instanceof Error && error.message.trim()) {
    return error.message.trim();
  }

  return 'Worker daily rollup render failed.';
};

const renderDailyRollup = (
  payload: RenderDailyRollupTaskRequest
): AsyncTaskResponseMessage<'render-daily-rollup'> => ({
  requestId: -1,
  result: {
    document: renderer.render(payload)
  },
  success: true,
  taskKind: 'render-daily-rollup'
});

self.onmessage = (event: MessageEvent<AsyncTaskRequestMessage<'render-daily-rollup'>>) => {
  const request = event.data;

  try {
    const response = renderDailyRollup(request.payload);
    const message: AsyncTaskResponseMessage<'render-daily-rollup'> = {
      ...response,
      requestId: request.requestId
    };
    self.postMessage(message);
  } catch (error) {
    const message: AsyncTaskResponseMessage<'render-daily-rollup'> = {
      error: toErrorMessage(error),
      requestId: request.requestId,
      success: false,
      taskKind: 'render-daily-rollup'
    };
    self.postMessage(message);
  }
};

export {};
