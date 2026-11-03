// Authored for later independent qualification; not run during source-only work.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runOnchainHook, onchainPublicReading, FINANCIAL_RESOURCE_PROVIDER } from '../src/onchain-hook.mjs';
import { scorecard } from '../src/scorecard.mjs';
import { bucket } from './memory.mjs';
import { read, register } from '../src/registers.mjs';

const now = new Date('2026-10-24T20:00:00Z'), cron = '*/15 * * * *';
const original = { effect: 'original-clock-occurrence', request: 'original-request-ni', input: { run: 'original-principal:policy' } };
const reply = (stage = 'publish') => ({ event: { id: 'original-admitted-event', content: {
  type: 'FinancialArenaEvent', version: 1, run: original.input.run, cycle: 1, stage, status: 'complete',
  at: now.toISOString(), execute: { effect: 'intent-only', offers: [] }, knowledge: { prior: 'original-predecessor' },
} }, status: { type: 'FinancialArenaStatus', version: 1, run: original.input.run, cycle: stage === 'learn' ? 2 : 1,
  lastRun: now.toISOString(), backlog: 1, next: stage === 'learn' ? 'monitor' : ['monitor', 'analyze', 'plan', 'publish', 'learn'][['monitor', 'analyze', 'plan', 'publish', 'learn'].indexOf(stage) + 1],
  stages: ['monitor', 'analyze', 'plan', 'publish', 'learn'].map((name, index, stages) => ({ stage: name,
    status: stage === 'learn' ? 'pending' : index <= stages.indexOf(stage) ? 'complete' : 'pending' })), blockers: [], interventions: { total: 0 },
} });
const port = overrides => ({ identify: async () => original, checkpoint: async () => {},
  provider: async () => reply(), reconcile: async () => { throw Error('unexpected reconcile'); }, ...overrides });

test('original pending reference precedes provider call and intent never counts as earnings', async () => {
  const env = { STATE: bucket() };
  const onchain = port({ provider: async (provider, request) => {
    assert.equal(provider, FINANCIAL_RESOURCE_PROVIDER); assert.deepEqual(request, original);
    const pending = await read(env.STATE, register('onchain'));
    assert.equal(pending.status, 'resource-pending'); assert.deepEqual(pending.original, original);
    assert.deepEqual(pending.occurrence, { at: now.toISOString(), cron }); return reply();
  } });
  const received = await runOnchainHook(env, { now, cron, onchain });
  assert.equal(received.status, 'resource-received');
  const reading = await read(env.STATE, register('onchain'));
  assert.deepEqual(reading.answer, reply());
  const card = scorecard({ onchain: reading }, { now });
  assert.equal(card.onchain.usefulWork, 'intent-only');
  assert.equal(card.onchain.accountedEarnings, 'not-established');
  assert.equal(card.outsideRevenueUSD.week, 0);
});

test('lost provider result retains original occurrence; later pulse observes only original request', async () => {
  const env = { STATE: bucket() }; let calls = 0, reconciles = 0;
  const onchain = port({ provider: async () => { calls++; throw Error('send may have completed'); } });
  assert.equal((await runOnchainHook(env, { now, cron, onchain })).status, 'resource-uncertain');
  const later = new Date(now.getTime() + 900000);
  const restored = port({ identify: async () => { throw Error('must not choose a new identity'); },
    provider: async () => { throw Error('must not resubmit'); }, reconcile: async held => {
      reconciles++; assert.deepEqual(held, { provider: FINANCIAL_RESOURCE_PROVIDER, ...original }); return reply();
    } });
  assert.equal((await runOnchainHook(env, { now: later, cron, onchain: restored, url: 'https://unused.invalid' })).status, 'resource-received');
  assert.equal(calls, 1); assert.equal(reconciles, 1);
  assert.equal((await read(env.STATE, register('onchain'))).occurrence.at, now.toISOString());
});

test('malformed original result stays uncertain and missing port cannot overwrite or use HTTP', async () => {
  const env = { STATE: bucket() };
  await runOnchainHook(env, { now, cron, onchain: port({ provider: async () => ({ status: 200, fills: [] }) }) });
  const before = await read(env.STATE, register('onchain'));
  assert.equal(before.status, 'resource-uncertain');
  await runOnchainHook(env, { now, cron, url: 'https://unused.invalid', fetchImpl: () => { throw Error('fallback forbidden'); } });
  assert.deepEqual(await read(env.STATE, register('onchain')), before);
});

test('lost fence cannot receive uncertainty into a different restored state', async () => {
  const env = { STATE: bucket() }; let lost = false;
  await assert.rejects(runOnchainHook(env, { now, cron, onchain: port({
    checkpoint: async () => { if (lost) throw Error('original pending reservation lost'); },
    provider: async () => { lost = true; return reply(); },
  }) }), /reservation lost/);
  assert.equal((await read(env.STATE, register('onchain'))).status, 'resource-pending');
});

test('duplicate received original effect cannot advance another financial stage', async () => {
  const env = { STATE: bucket() }; let calls = 0;
  const onchain = port({ provider: async () => { calls++; return reply(); } });
  await runOnchainHook(env, { now, cron, onchain });
  await runOnchainHook(env, { now, cron, onchain });
  assert.equal(calls, 1);
  await assert.rejects(runOnchainHook(env, { now, cron, onchain: port({
    identify: async () => ({ ...original, request: 'substituted-request' }),
  }) }), /substituted/);
});

test('legacy POST uncertainty preserves response authority and blocks every later automatic attempt', async () => {
  const env = { STATE: bucket() }; let calls = 0;
  const fetchImpl = async () => { calls++; assert.equal((await read(env.STATE, register('onchain'))).status, 'legacy-pending'); throw Error('connection lost'); };
  await runOnchainHook(env, { now, cron, url: 'https://original.invalid', fetchImpl });
  const before = await read(env.STATE, register('onchain'));
  await runOnchainHook(env, { now: new Date(now.getTime() + 900000), cron, onchain: port(), url: 'https://alternate.invalid', fetchImpl });
  assert.equal(calls, 1); assert.deepEqual(await read(env.STATE, register('onchain')), before);
});

test('legacy 200 retains transport evidence without financial receiving or earning', async () => {
  const env = { STATE: bucket() };
  await runOnchainHook(env, { now, cron, url: 'https://original.invalid', fetchImpl: async () => Response.json({ fills: [{ netAtomic: '1000000' }] }) });
  const reading = await read(env.STATE, register('onchain'));
  assert.equal(reading.status, 'legacy-response-received'); assert.equal(reading.accountedEarnings, 'not-established');
  assert.equal(scorecard({ onchain: reading }, { now }).outsideRevenueUSD.week, 0);
});

test('dated original readings keep current state bounded and retain every original response', async () => {
  const env = { STATE: bucket() };
  for (let n = 0; n < 4; n++) await runOnchainHook(env, { now: new Date(now.getTime() + n * 900000), cron,
    url: 'https://original.invalid', fetchImpl: async () => Response.json({ originalReceipt: n }) });
  const current = await read(env.STATE, register('onchain'));
  assert.equal(current.legacy, undefined); assert.equal(current.answer.originalReceipt, 3);
  const previous = await read(env.STATE, current.previousReading);
  assert.equal(previous.answer.originalReceipt, 2); assert.equal(previous.legacy, undefined);
  assert.equal((await read(env.STATE, previous.previousReading)).answer.originalReceipt, 1);
  const publicReading = onchainPublicReading({ ...current, error: 'private-state-path', answer: { token: 'private-token' } });
  const publicBytes = JSON.stringify(publicReading);
  assert.equal(publicBytes.includes('original.invalid'), false); assert.equal(publicBytes.includes('private-'), false);
  assert.equal(publicBytes.includes('previousReading'), false);
});

test('inconsistent original status cannot establish a received financial stage', async () => {
  const env = { STATE: bucket() }; const wrong = reply(); wrong.status.next = 'monitor';
  assert.equal((await runOnchainHook(env, { now, cron, onchain: port({ provider: async () => wrong }) })).status, 'resource-uncertain');
});

test('pre-upgrade unknown HTTP reading cannot silently move to a new resource identity', async () => {
  const previous = { at: now.toISOString(), status: 'unreachable', error: 'original retained diagnostic' };
  const env = { STATE: bucket({ [register('onchain')]: previous }) };
  const result = await runOnchainHook(env, { now, cron, onchain: port({
    identify: async () => { throw Error('original legacy request is unresolved'); },
  }) });
  assert.equal(result.reconciliation, 'original-receiving-required');
  assert.deepEqual(await read(env.STATE, register('onchain')), previous);
});
