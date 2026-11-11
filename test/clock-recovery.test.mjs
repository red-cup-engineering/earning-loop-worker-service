import test from 'node:test';
import assert from 'node:assert/strict';
import { nextTick, withAlarmRecovery } from '../src/clock.mjs';

test('failed planning reads rearm without another read and retain the original error', async (t) => {
  const now = Date.parse('2026-11-10T19:22:30Z');
  t.mock.method(Date, 'now', () => now);
  const error = new Error('rows_read limit exceeded');
  let reads = 0;
  const alarms = [];
  const storage = {
    async get() { reads++; throw error; },
    async setAlarm(at) { alarms.push(at); },
  };
  await assert.rejects(withAlarmRecovery(storage, () => storage.get('private-state')), value => value === error);
  assert.equal(reads, 1);
  assert.deepEqual(alarms, [Date.parse('2026-11-10T19:30:00Z')]);
});

test('a successfully selected deadline is neither overwritten nor written twice on failure', async () => {
  const error = new Error('work failed');
  const alarms = [];
  await assert.rejects(withAlarmRecovery({ async setAlarm(at) { alarms.push(at); } }, async setAlarm => {
    try { throw error; } finally { await setAlarm(123456789); }
  }), value => value === error);
  assert.deepEqual(alarms, [123456789]);
});

test('healthy work preserves its result and performs only its original alarm write', async () => {
  const alarms = [];
  const result = await withAlarmRecovery({ async setAlarm(at) { alarms.push(at); } }, async setAlarm => {
    await setAlarm(123456789);
    return 'received';
  });
  assert.equal(result, 'received');
  assert.deepEqual(alarms, [123456789]);
});

test('fallback uses failure-time clock even when the turn crosses UTC midnight', async (t) => {
  let now = Date.parse('2026-11-10T23:59:59Z');
  t.mock.method(Date, 'now', () => now);
  const alarms = [];
  await assert.rejects(withAlarmRecovery({ async setAlarm(at) { alarms.push(at); } }, async () => {
    now = Date.parse('2026-11-11T00:00:01Z');
    throw new Error('late failure');
  }), /late failure/);
  assert.deepEqual(alarms, [Date.parse('2026-11-11T00:15:00Z')]);
  assert.ok(alarms[0] > now);
});

test('failed selected alarm write receives one bounded fallback attempt', async (t) => {
  const now = Date.parse('2026-11-10T19:22:30Z');
  t.mock.method(Date, 'now', () => now);
  const error = new Error('selected alarm unavailable');
  const alarms = [];
  await assert.rejects(withAlarmRecovery({ async setAlarm(at) {
    alarms.push(at);
    if (alarms.length === 1) throw error;
  } }, async setAlarm => setAlarm(now + 1000)), value => value === error);
  assert.deepEqual(alarms, [now + 1000, nextTick(now)]);
});

test('failed fallback preserves both errors and cannot report a restored alarm', async () => {
  const original = new Error('rows_read limit exceeded');
  const fallback = new Error('alarm write refused');
  let writes = 0;
  await assert.rejects(withAlarmRecovery({ async setAlarm() { writes++; throw fallback; } }, async () => {
    throw original;
  }), error => error instanceof AggregateError && error.errors[0] === original && error.errors[1] === fallback);
  assert.equal(writes, 1);
});
