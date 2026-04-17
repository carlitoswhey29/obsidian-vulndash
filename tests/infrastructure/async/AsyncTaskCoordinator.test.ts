import assert from 'node:assert/strict';
import test from 'node:test';
import { AsyncTaskCoordinator } from '../../../src/infrastructure/async/AsyncTaskCoordinator';
import { WorkerFactory } from '../../../src/infrastructure/async/WorkerFactory';

class NullWorkerFactory extends WorkerFactory {
  public override async create() {
    return null;
  }
}

test('coordinator falls back when a worker is unavailable and tracks current tokens', async () => {
  const coordinator = new AsyncTaskCoordinator(new NullWorkerFactory());
  const first = coordinator.beginToken('sbom:primary');
  const second = coordinator.beginToken('sbom:primary');

  assert.equal(coordinator.isCurrent(first), false);
  assert.equal(coordinator.isCurrent(second), true);

  let fallbackCalls = 0;
  const result = await coordinator.execute('parse-sbom', {
    raw: '{}',
    source: {
      basename: 'sbom',
      path: 'reports/sbom.json'
    }
  }, {
    fallback: async () => {
      fallbackCalls += 1;
      return {
        document: {
          components: [],
          format: 'spdx',
          name: 'fallback',
          sourcePath: 'reports/sbom.json'
        }
      };
    }
  });

  assert.equal(fallbackCalls, 1);
  assert.equal(result.document.name, 'fallback');

  coordinator.releaseToken(second);
  assert.equal(coordinator.isCurrent(second), false);
});
