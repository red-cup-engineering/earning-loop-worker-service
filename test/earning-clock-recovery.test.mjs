import test from 'node:test';
import assert from 'node:assert/strict';
import { EarningClock, CRONS } from '../worker/earning-loops.mjs';
import { HASHN_STATE } from '../src/hashn-acquisition.mjs';
import { RESEARCH_STATE } from '../src/ln-church-research.mjs';

for (const failingKey of [HASHN_STATE, 'hashn/next-pulse-at', 'earning-clock/core-next-at', RESEARCH_STATE,
  'earning-clock/observed-release-id', 'earning-clock/armed-release']) {
  test(`original alarm rearms after planning read failure at ${failingKey}`, async (t) => {
    const now = Date.parse('2026-11-10T19:22:30Z');
    t.mock.method(Date, 'now', () => now);
    const error = new Error(`read unavailable: ${failingKey}`), alarms = [];
    let effects = 0, writes = 0;
    const storage = {
      async get(key) { if (key === failingKey) throw error; },
      async put() { writes++; },
      async setAlarm(at) { alarms.push(at); },
    };
    const clock = new EarningClock({ storage }, { RELEASE_METADATA: { id: 'release-fixture' } }, {
      configuration: { commercial: { enabled: true }, hashAcquisition: { enabled: true },
        researchProcurement: { enabled: true }, crons: CRONS },
      commercialPass: async () => { effects++; },
      researchPass: async () => { effects++; },
      acquisitionPass: async () => { effects++; },
    });
    await assert.rejects(clock.alarm(), value => value === error);
    assert.deepEqual(alarms, [Date.parse('2026-11-10T19:30:00Z')]);
    assert.equal(effects, 0);
    assert.equal(writes, 0);
  });
}

test('original alarm rearms when final research read fails and its queue remains usable', async (t) => {
  let now = Date.parse('2026-11-10T19:22:30Z'), reads = 0, effects = 0;
  t.mock.method(Date, 'now', () => now);
  const error = new Error('final research read unavailable'), alarms = [];
  const storage = {
    async get(key) {
      if (key === RESEARCH_STATE && ++reads === 2) throw error;
      return { terminal: true };
    },
    async put() {},
    async setAlarm(at) { alarms.push(at); },
  };
  const clock = new EarningClock({ storage }, {}, {
    configuration: { commercial: { enabled: true }, researchProcurement: { enabled: true }, crons: CRONS },
    commercialPass: async () => { effects++; return { stage: 'fixture-received', requests: 0 }; },
  });
  await assert.rejects(clock.alarm(), value => value === error);
  assert.deepEqual(alarms, [Date.parse('2026-11-10T19:30:00Z')]);
  assert.equal(effects, 1);
  now = Date.parse('2026-11-10T19:37:30Z');
  await clock.alarm();
  assert.equal(effects, 2);
  assert.deepEqual(alarms, [Date.parse('2026-11-10T19:30:00Z'), Date.parse('2026-11-10T19:45:00Z')]);
});
