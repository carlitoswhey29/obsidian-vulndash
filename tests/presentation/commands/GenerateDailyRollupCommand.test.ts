import assert from 'node:assert/strict';
import test from 'node:test';
import { GenerateDailyRollupCommand } from '../../../src/presentation/commands/GenerateDailyRollupCommand';

test('GenerateDailyRollupCommand registers the manual briefing command and invokes the generator callback', async () => {
  const registrations: Array<{ readonly callback: () => void; readonly id: string; readonly name: string; }> = [];
  let invocations = 0;
  const registrar = {
    addCommand(command: { readonly callback: () => void; readonly id: string; readonly name: string; }) {
      registrations.push(command);
    }
  };

  new GenerateDailyRollupCommand(async () => {
    invocations += 1;
  }).register(registrar);

  const registered = registrations[0];
  assert.ok(registered);
  assert.equal(registered.id, 'vulndash-generate-daily-rollup');
  assert.equal(registered.name, 'Generate daily threat briefing');
  registered.callback();
  await Promise.resolve();
  assert.equal(invocations, 1);
});
