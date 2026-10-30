import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { EarningClock, CRONS } from '../worker/earning-loops.mjs';
import { bucket } from './memory.mjs';
import { RESEARCH_STATE, RESEARCH_SUMMARY } from '../src/ln-church-research.mjs';

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

test('pending paid research takes one isolated pulse, rearms its status deadline and preserves CSV custody',async()=>{
  const realNow=Date.now;let time=Date.parse('2026-10-24T22:01:00Z');Date.now=()=>time;
  const auth={privateKey:'held-not-used'},values=new Map([['opentask/auth',auth],['opentask/public-summary',{stage:'awaiting-hire'}]]);
  let alarm=time+450000,research=0,csv=0;
  const storage={async get(k){return values.get(k);},async put(k,v){values.set(k,v);},async getAlarm(){return alarm;},async setAlarm(v){alarm=v;}};
  const clock=new EarningClock({storage},{STATE:{put(){assert.fail('no research R2');}}},{
    configuration:{commercial:{enabled:true},researchProcurement:{enabled:true},crons:CRONS},
    researchPass:async()=>{research++;await storage.put(RESEARCH_STATE,{terminal:research===2,nextAttemptAt:time+30000});await storage.put(RESEARCH_SUMMARY,{stage:'research-evaluation-pending',secret:'excluded'});},
    commercialPass:async()=>{csv++;return {stage:'awaiting-hire',requests:1};}
  });
  try{
    await clock.alarm();assert.equal(research,1);assert.equal(csv,0);assert.equal(alarm,time+30000);
    assert.equal(values.get('opentask/auth'),auth);assert.deepEqual(values.get('opentask/public-summary'),{stage:'awaiting-hire'});
    const summary=await(await clock.fetch(new Request('https://example.test/research.json'))).json();assert.equal(summary.secret,undefined);
    time=alarm;await clock.alarm();assert.equal(research,2);
    time=Date.parse('2026-10-24T22:07:30Z');await clock.alarm();assert.equal(csv,1);assert.equal(research,2);
  }finally{Date.now=realNow;}
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


test('commercial status projects every selected original journal without exposing private custody',async()=>{
  const values=new Map([
    ['opentask/public-summary',{stage:'bid-created',requests:3,at:'2026-10-26T15:52:30Z',taskId:'new',productId:'csv'}],
    ['opentask/commercial',{stage:'awaiting-hire',observedAt:'2026-10-26T15:22:30Z',agreement:{private:'hidden'}}],
    ['opentask/commercial/new',{stage:'bid-created',observedAt:'2026-10-26T15:52:30Z',bidId:'private-bid',bidPending:{body:'hidden'}}],
    ['opentask/auth',{accessToken:'hidden'}]
  ]);
  const clock=new EarningClock({storage:{get:async key=>values.get(key),getAlarm:async()=>null}}, {},
    {configuration:{commercial:{enabled:true,taskId:'old',productId:'original',offers:[{taskId:'new',bidId:null,productId:'csv'}]}}});
  const response=await clock.fetch(new Request('https://worker.test/commercial.json'));
  const body=await response.json();
  assert.deepEqual(body.offers.map(x=>[x.taskId,x.stage]),[['new','bid-created'],['old','awaiting-hire']]);
  assert.equal(JSON.stringify(body).includes('hidden'),false);
  assert.equal(JSON.stringify(body).includes('private-bid'),false);
  assert.equal(values.size,4);
});

test('commercial entrypoint relative import graph resolves, with missing-module negative control', () => {
  // The ordinary node --check does not resolve imports; the entrypoint graph must.
  const importsOf = source => [...source.matchAll(/(?:^|\n)\s*(?:import|export)\s+(?:[^;]*?\s+from\s*)?['"](\.[^'"]+)['"]/g)].map(match => match[1]);
  const entry = new URL('../worker/earning-loops.mjs', import.meta.url);
  const pending = [entry], seen = new Set(), missing = [];
  while (pending.length) {
    const file = pending.pop(), name = fileURLToPath(file);
    if (seen.has(name)) continue;
    seen.add(name);
    if (!existsSync(name)) { missing.push(name); continue; }
    for (const specifier of importsOf(readFileSync(name, 'utf8'))) {
      const target = new URL(specifier, file);
      if (!existsSync(fileURLToPath(target))) missing.push(name + ' -> ' + specifier);
      else pending.push(target);
    }
  }
  assert.deepEqual(missing, [], 'all relative imports in the actual Worker graph must resolve');
  const sentinel = './intentionally-absent-observer-fixture.mjs';
  assert.deepEqual(importsOf("import { missing } from './intentionally-absent-observer-fixture.mjs';"), [sentinel]);
  assert.equal(existsSync(fileURLToPath(new URL(sentinel, entry))), false,
    'negative control must remain an absent relative module');
});
