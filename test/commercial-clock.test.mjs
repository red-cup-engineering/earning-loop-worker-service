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

test('native release metadata arms one prompt private verification, retains the prior alarm and cannot replay via clock', async () => {
  const originalNow = Date.now(); let time = Date.parse('2026-10-24T20:01:00Z');
  const realNow = Date.now; Date.now = () => time;
  let alarm = Date.parse('2026-10-24T20:03:00Z'), calls = 0;
  const auth = { pendingRefresh: true, refreshToken: 'private-held-runtime' };
  const values = new Map([['opentask/auth', auth]]);
  const state = { storage: { async get(k) { return values.get(k); }, async put(k,v) { values.set(k,v); },
    async getAlarm() { return alarm; }, async setAlarm(at) { alarm = at; } } };
  const env = { RELEASE_METADATA: { id: 'release-a' }, STATE: { put() { assert.fail('no commercial R2'); } } };
  const configuration = { commercial: { enabled: true }, crons: { pass: '59 23 * * *', directives: '58 23 * * *', scorecard: '57 23 * * *' } };
  const clock = new EarningClock(state, env, { configuration, commercialPass: async () => {
    assert.equal(values.get('earning-clock/observed-release-id'), env.RELEASE_METADATA.id);
    calls++; return { stage: 'awaiting-hire', requests: 3, newCashExpenseUsd: 0, privateToken: 'excluded' };
  } });
  try {
    await clock.fetch(new Request('https://worker.example/clock'));
    assert.equal(alarm, time + 1000);
    time += 200; await clock.fetch(new Request('https://worker.example/clock'));
    assert.equal(alarm, Date.parse('2026-10-24T20:01:01Z'));
    time = alarm; await clock.alarm(); assert.equal(calls, 1);
    assert.equal(alarm, Date.parse('2026-10-24T20:03:00Z'));
    await clock.fetch(new Request('https://worker.example/clock')); assert.equal(alarm, Date.parse('2026-10-24T20:03:00Z'));
    const summary = await (await clock.fetch(new Request('https://worker.example/commercial.json'))).json();
    assert.equal(JSON.stringify(summary).includes('private'), false);
    time = alarm; await clock.alarm(); assert.equal(calls, 1, 'seen release at noncommercial slot does not bootstrap twice');
    env.RELEASE_METADATA.id = 'release-b'; await clock.fetch(new Request('https://worker.example/clock'));
    assert.equal(alarm, time + 1000); time = alarm; await clock.alarm(); assert.equal(calls, 2);
    assert.equal(values.get('opentask/auth'), auth, 'existing runtime auth and pending marker are untouched');
  } finally { Date.now = realNow; }
});
