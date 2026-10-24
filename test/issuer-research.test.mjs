import test from 'node:test';
import assert from 'node:assert/strict';
import { bucket } from './memory.mjs';
import { refreshIssuerResearch, retryDelayMs } from '../src/issuer-research.mjs';
import { projectOperation, deploymentMetadata } from '../src/deployment.mjs';
import { receiveSettlements } from '../src/settlements.mjs';
const at = new Date('2026-10-24T20:00:00Z');
const config = { cacheKey: 'issuer/cohort.json', issuers: [{ cik: '320193' }, { cik: '789019' }], userAgent: 'test contact@example.test' };

test('optional issuer configuration causes no reads, writes or producer calls', async () => {
  assert.deepEqual(await refreshIssuerResearch({}, undefined, { now: at, prepare: () => assert.fail() }), { status: 'not-configured' });
});
test('complete producer result replaces the old cohort once, only after resolution', async () => {
  const state = bucket({ [config.cacheKey]: { old: true } });
  let complete; const waiting = new Promise(resolve => { complete = resolve; });
  const work = refreshIssuerResearch({ STATE: state }, config, { now: at, prepare: async supplied => { assert.equal(supplied, config); return waiting; } });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(await (await state.get(config.cacheKey)).json(), { old: true });
  const full = { type: 'IssuerRevenuePreparedCohort', results: { annual: { complete: true }, quarter: { complete: true } } };
  complete(full); await work;
  assert.deepEqual(await (await state.get(config.cacheKey)).json(), full);
});
test('a failed source preserves the prior cohort and durable Retry-After suppresses the next tick', async () => {
  const state = bucket({ [config.cacheKey]: { old: true } }); let calls = 0;
  const prepare = async () => { calls++; throw Object.assign(new Error('SEC busy'), { code: 'issuer-revenue-source-unavailable', reason: 'http-429', retryable: true, retryAfter: '3600' }); };
  const failed = await refreshIssuerResearch({ STATE: state }, config, { now: at, prepare, clock: () => at });
  assert.equal(failed.retryAfter, '3600'); assert.equal(failed.nextAttemptAt, '2026-10-24T21:00:00.000Z');
  assert.deepEqual(await (await state.get(config.cacheKey)).json(), { old: true });
  const deferred = await refreshIssuerResearch({ STATE: state }, config, { now: new Date(at.getTime() + 900000), prepare });
  assert.equal(deferred.status, 'deferred'); assert.equal(calls, 1);
});
test('Retry-After honors delays beyond24hours and blocks unrepresentable positive instructions', () => {
  assert.equal(retryDelayMs('120', at), 120000);
  assert.equal(retryDelayMs('Sat, 24 Oct 2026 20:30:00 GMT', at), 1800000);
  assert.equal(retryDelayMs('172800', at), 172800000);
  assert.equal(retryDelayMs('Mon, 26 Oct 2026 20:00:00 GMT', at), 172800000);
  assert.equal(retryDelayMs('999999999999999999999999', at), Infinity);
  for (const value of ['bad', '-1', '0.5', 'Fri, 23 Oct 2026 20:30:00 GMT', null]) assert.equal(retryDelayMs(value, at), 0);
});
test('long Retry-After is never shortened; unrepresentable delay remains durably held', async () => {
  for (const retryAfter of ['172800','Mon, 26 Oct 2026 20:00:00 GMT','999999999999999999999999']) {
    const state=bucket({[config.cacheKey]:{old:true}});let calls=0;
    const prepare=async()=>{calls++;throw Object.assign(new Error('SEC busy'),{retryAfter});};
    const failed=await refreshIssuerResearch({STATE:state},config,{now:at,prepare,clock:()=>at});
    const deferred=await refreshIssuerResearch({STATE:state},config,{now:new Date(at.getTime()+86400000),prepare});
    assert.equal(deferred.status,'deferred');assert.equal(calls,1);
    if(retryAfter.startsWith('999'))assert.equal(failed.retryBlocked,true);
    else assert.equal(failed.nextAttemptAt,'2026-10-26T20:00:00.000Z');
  }
});
test('Retry-After seconds starts at the observed refusal, after a slow source attempt', async()=>{
  const state=bucket();
  const refusedAt=new Date(at.getTime()+60000);
  const prepare=async()=>{throw Object.assign(new Error('SEC busy'),{retryAfter:'172800'});};
  const result=await refreshIssuerResearch({STATE:state},config,{now:at,prepare,clock:()=>refusedAt});
  assert.equal(result.nextAttemptAt,'2026-10-26T20:01:00.000Z');
});
test('deployment projection activates only explicitly admitted issuer configuration and refuses over-budget acquisition', () => {
  const admitted = { ...config, enabled: true, resourceAdmission: { status: 'received' } };
  const record = { worker: 'test', merchantPayTo: '0x'+'b'.repeat(40), limits: { settlementsPerPass: 4, routeProbesPerPass: 3 }, repair: { repository: null }, issuerResearch: admitted };
  assert.equal(projectOperation({ ...record, issuerResearch: config }).issuerResearch, undefined);
  assert.equal(projectOperation({ ...record, issuerResearch: { ...admitted, resourceAdmission: { status: 'unreceived' } } }).issuerResearch, undefined);
  assert.deepEqual(projectOperation(record).issuerResearch, admitted);
  assert.throws(() => projectOperation({ ...record, limits: { ...record.limits, routeProbesPerPass: 4 } }), /subrequest/);
  assert.throws(() => projectOperation({ ...record, onchainScanUrl: 'https://example.test' }), /subrequest/);
  const existing = { compatibility_date: '2026-10-01', compatibility_flags: ['some_existing_flag'], bindings: [{ type: 'plain_text', name: 'UNKNOWN', text: 'retained' }, { type: 'r2_bucket', name: 'OTHER', bucket_name: 'other' }, { type: 'secret_text', name: 'TOKEN' }] };
  const metadata = deploymentMetadata({ ...record, buckets: { state: 'state', settlementWitnesses: 'witnesses' } }, existing);
  assert.deepEqual(metadata.bindings.find(b => b.name === 'RELEASE_METADATA'), { type: 'version_metadata', name: 'RELEASE_METADATA' });
  assert.equal(metadata.bindings.find(b => b.name === 'UNKNOWN').text, 'retained');
  assert.equal(metadata.bindings.find(b => b.name === 'OTHER').bucket_name, 'other');
  assert.ok(metadata.keep_bindings.includes('secret_text'));
  assert.ok(metadata.compatibility_flags.includes('nodejs_compat'));
  assert.ok(metadata.compatibility_flags.includes('some_existing_flag'));
});
test('one bounded settlement page continues past already-seen witnesses without losing later arrivals', async () => {
  const env = { STATE: bucket(), MARKET_SETTLEMENTS: bucket(Object.fromEntries(Array.from({length: 10}, (_, i) => ['settlements/eip155:8453/'+i, {}]))) };
  let lists = 0; const original = env.MARKET_SETTLEMENTS.list;
  env.MARKET_SETTLEMENTS.list = async args => { lists++; assert.equal(args.limit, 4); return original(args); };
  for (let i=0; i<3; i++) { const result = await receiveSettlements(env, { limit: 4, fetchImpl: () => assert.fail('invalid witness causes no RPC') }); assert.equal(lists, i+1); assert.equal(result.refused, Math.min(10, (i+1)*4)); }
  const reading = await (await env.STATE.get('registers/earning-loops/settlements.json')).json();
  assert.equal(reading.scanCursor, null);
});

async function measuredPass({ routeProbes = 3, alarm = false, date = at } = {}) {
  const { run, CRONS, EarningClock } = await import('../worker/earning-loops.mjs');
  const { BASE_USDC } = await import('../src/settlements.mjs');
  let calls=0;
  const measured = initial => { const b=bucket(initial); for(const name of ['get','put','list']) { const f=b[name]; b[name]=async(...args)=>{calls++;return f(...args);}; } return b; };
  const payer='0x'+'a'.repeat(40), payTo='0x'+'b'.repeat(40), block='0x'+'d'.repeat(64);
  const topic = a => '0x'+'0'.repeat(24)+a.slice(2);
  const witnesses = Object.fromEntries(Array.from({length:4},(_,i)=>{
    const transaction='0x'+String(i+1).repeat(64);
    return ['settlements/eip155:8453/'+i,{network:'eip155:8453',transaction,payer,payTo,asset:BASE_USDC,amount:'50000'}];
  }));
  const env={STATE:measured(),MARKET_SETTLEMENTS:measured(witnesses)};
  const configuration={crons:CRONS,merchantPayTo:payTo,limits:{settlementsPerPass:4,routeProbesPerPass:routeProbes},repair:{repository:null},catalogUrl:'https://market.test/v1/catalog',economics:{burnUsdPerMonth:600,floorUsdPerDay:20,goalUsdPerDay:200},issuerResearch:config};
  let rpc=0;
  const original=globalThis.fetch;
  globalThis.fetch=async(url,init={})=>{
    calls++;
    if(init.body?.includes('eth_getTransactionReceipt')){
      rpc++;
      if(rpc%4===1||rpc%4===2)return Response.json({result:null});
      const transaction=JSON.parse(init.body).params[0];
      return Response.json({result:{status:'0x1',transactionHash:transaction,blockHash:block,blockNumber:'0x10',logs:[{address:BASE_USDC,topics:['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',topic(payer),topic(payTo)],data:'0x'+(50000).toString(16).padStart(64,'0'),logIndex:'0x2'}]}});
    }
    if(url===configuration.catalogUrl)return Response.json({offers:Array.from({length:routeProbes},(_,i)=>({listed:true,method:'GET',route:'/offer'+i,url:'https://market.test/offer'+i,amountAtomic:'50000'}))});
    return new Response('{}',{status:402});
  };
  try {
    const options={configuration,prepareIssuerRevenueCohort:async()=>{await fetch('https://data.sec.gov/a');await fetch('https://data.sec.gov/b');return {type:'IssuerRevenuePreparedCohort',observedAt:date.toISOString()};}};
    if(alarm){
      const originalNow=Date.now;Date.now=()=>date.getTime();
      try{await new EarningClock({storage:{async setAlarm(){calls++;}}},env,options).alarm();}
      finally{Date.now=originalNow;}
    }else await run(env,CRONS.pass,date,options);
    const result=JSON.parse(env.STATE.store.get('registers/earning-loops/last-run.json'));
    assert.equal(result.settlements.received.length,4);assert.equal(result.routes.probed,routeProbes);assert.equal(result.issuerResearch.status,'prepared');
    assert.equal(rpc,16);return calls;
  } finally {globalThis.fetch=original;}
}
test('actual qualified pass uses41 subrequests for four witnesses/four provider attempts, three routes and two SEC reads',async()=>{assert.equal(await measuredPass(),41);});
test('the coincident weekly alarm includes the scorecard branch and clock rearm within48 measured calls',async()=>{assert.equal(await measuredPass({alarm:true,date:new Date('2026-10-26T14:00:00Z')}),48);});
test('the coincident daily alarm includes price directives and clock rearm within47 measured calls',async()=>{assert.equal(await measuredPass({alarm:true,date:new Date('2026-10-27T13:30:00Z')}),47);});
