import test from 'node:test';
import assert from 'node:assert/strict';
import { EarningClock, CRONS } from '../worker/earning-loops.mjs';
import { bucket } from './memory.mjs';

test('commercial alarms serialize private effects and occupy their own invocation between maintenance ticks', async () => {
  const originalNow = Date.now;
  Date.now = () => Date.parse('2026-10-24T20:07:30Z');
  let active = 0, maximum = 0, calls = 0, release;
  const waiting = new Promise(resolve => { release = resolve; });
  const values = new Map();
  const state = { storage: { async put(k,v) { values.set(k,v); }, async setAlarm(at) { assert.equal(at, Date.parse('2026-10-24T20:15:00Z')); } } };
  const env = { STATE: { async put() { assert.fail('commercial pulse must not use metered R2'); } } };
  const clock = new EarningClock(state, env, { configuration: { commercial: { enabled: true }, crons: CRONS },
    commercialPass: async ({ storage }) => {
      assert.equal(storage, state.storage); active++; maximum = Math.max(maximum, active); calls++;
      if (calls === 1) await waiting;
      active--; return { stage: 'awaiting-hire', requests: 1, newCashExpenseUsd: 0 };
    } });
  try {
    const first = clock.alarm(), second = clock.alarm();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(calls, 1); release(); await Promise.all([first, second]);
    assert.equal(calls, 2); assert.equal(maximum, 1);
    const reading = values.get('opentask/public-summary');
    assert.deepEqual(reading, { stage: 'awaiting-hire', requests: 1, newCashExpenseUsd: 0, at: '2026-10-24T20:07:30.000Z' });
  } finally { Date.now = originalNow; }
});
