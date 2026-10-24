import test from 'node:test';
import assert from 'node:assert/strict';
import { withIssuerSqliteStore, issuerSqliteResponse, issuerSqliteStoragePlan } from '../src/issuer-sqlite-cache.mjs';
import { refreshIssuerResearch } from '../src/issuer-research.mjs';
const cfg={enabled:true,resourceAdmission:{status:'received'},cacheKey:'issuer-research/current.json',maximumCohortBytes:524288};
const at=new Date('2026-10-24T20:00:00.000Z');
const status={status:'prepared',at:at.toISOString(),cacheKey:cfg.cacheKey,observedAt:at.toISOString(),nextAttemptAt:'2026-10-24T20:15:00.000Z'};
function state(initial={}) {
  const values=new Map(Object.entries(initial));const calls=[];
  return {values,calls,failCommit:false,
    async get(key){calls.push(['get',key]);return structuredClone(values.get(key));},
    async transaction(work){calls.push(['transaction']);const next=new Map(values);
      await work({async put(key,value){calls.push(['put',key]);next.set(key,structuredClone(value));}});
      if(this.failCommit)throw new Error('storage unavailable');
      values.clear();for(const [key,value]of next)values.set(key,value);
    }};
}
const wrapper=body=>({cacheKey:cfg.cacheKey,body:JSON.stringify(body)});
const request=(key=cfg.cacheKey,method='GET')=>new Request('https://private.invalid/issuer-evidence?'+new URLSearchParams({key}),{method});
test('disabled and unreceived issuer configuration grants no storage or work',async()=>{
  for(const configuration of [undefined,{...cfg,enabled:false},{...cfg,resourceAdmission:{status:'pending'}}]){
    const storage=state();assert.deepEqual(await withIssuerSqliteStore(storage,configuration,()=>assert.fail()),{status:'not-configured'});
    assert.equal((await issuerSqliteResponse(request(),storage,configuration)).status,404);assert.deepEqual(storage.calls,[]);
  }
  assert.throws(()=>issuerSqliteStoragePlan({...cfg,cacheKey:'registers/earning-loops/issuer-research.json'}),TypeError);
});
test('full return precedes atomic cohort and status publication, preserving unrelated custody',async()=>{
  const storage=state({'opentask/auth':{secret:'untouched'},'earning-clock/observed-release-id':'existing','issuer-evidence/cohort':wrapper({old:true})});
  let release;const pending=new Promise(resolve=>release=resolve);
  const work=withIssuerSqliteStore(storage,cfg,async store=>{await store.put(cfg.cacheKey,JSON.stringify({new:true}));await pending;await store.put('registers/earning-loops/issuer-research.json',JSON.stringify(status));return 'prepared';});
  await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(storage.values.get('issuer-evidence/cohort'),wrapper({old:true}));
  release();assert.equal(await work,'prepared');assert.deepEqual(storage.values.get('issuer-evidence/cohort'),wrapper({new:true}));
  assert.deepEqual(storage.values.get('opentask/auth'),{secret:'untouched'});assert.equal(storage.values.get('earning-clock/observed-release-id'),'existing');
  assert.equal(storage.calls.filter(([name])=>name==='transaction').length,1);
  assert.deepEqual(storage.calls.filter(([name])=>name==='put').map(([,key])=>key).sort(),['issuer-evidence/cohort','issuer-evidence/status']);
});
test('failed callback and failed atomic transaction retain both prior values',async()=>{
  for(const commitFailure of [false,true]){
    const storage=state({'issuer-evidence/cohort':wrapper({old:true}),'issuer-evidence/status':wrapper(status)});storage.failCommit=commitFailure;
    const before=structuredClone([...storage.values]);
    await assert.rejects(withIssuerSqliteStore(storage,cfg,async store=>{await store.put(cfg.cacheKey,'{"new":true}');await store.put('registers/earning-loops/issuer-research.json',JSON.stringify(status));if(!commitFailure)throw new Error('producer incomplete');}));
    assert.deepEqual([...storage.values],before);
  }
});
test('scoped store refuses arbitrary keys before touching OpenTask or control storage',async()=>{
  const storage=state();
  await withIssuerSqliteStore(storage,cfg,async store=>{
    for(const key of ['opentask/auth','earning-clock/armed-release','other']){
      await assert.rejects(store.get(key),TypeError);await assert.rejects(store.put(key,'{}'),TypeError);
    }
  });assert.deepEqual(storage.calls,[['get','issuer-evidence/cohort'],['get','issuer-evidence/status']]);
});
test('corrupt persisted status cannot authorize source acquisition',async()=>{
  for(const value of [null,[],42,{...status,retryBlocked:'true'},{...status,nextAttemptAt:'bad'},{...status,nextAttemptAt:'2026-10-23T20:00:00.000Z'}]){
    const storage=state({'issuer-evidence/status':wrapper(value)});let acquisitions=0;
    await assert.rejects(withIssuerSqliteStore(storage,cfg,store=>refreshIssuerResearch(store,cfg,{now:at,prepare:async()=>{acquisitions++;return{};}})));
    assert.equal(acquisitions,0);
  }
});
test('literal long Retry-After survives SQLite reentry and prior cohort remains served',async()=>{
  const storage=state({'issuer-evidence/cohort':wrapper({old:true})});let acquisitions=0;
  const options={now:at,clock:()=>at,prepare:async()=>{acquisitions++;throw Object.assign(new Error('SEC busy'),{retryAfter:'172800'});}};
  await withIssuerSqliteStore(storage,cfg,store=>refreshIssuerResearch(store,cfg,options));
  const second=await withIssuerSqliteStore(storage,cfg,store=>refreshIssuerResearch(store,cfg,{...options,now:new Date(at.getTime()+86400000)}));
  assert.equal(second.status,'deferred');assert.equal(acquisitions,1);
  const retained=JSON.parse(storage.values.get('issuer-evidence/status').body);assert.equal(retained.retryAfter,'172800');assert.equal(retained.nextAttemptAt,'2026-10-26T20:00:00.000Z');
  assert.equal(await(await issuerSqliteResponse(request(),storage,cfg)).text(),'{"old":true}');
});
test('oversized status commits a durable hold and never publishes a staged new cohort',async()=>{
  const storage=state({'issuer-evidence/cohort':wrapper({old:true})});
  const result=await withIssuerSqliteStore(storage,cfg,async store=>{
    await store.put(cfg.cacheKey,'{"new":true}');
    await store.put('registers/earning-loops/issuer-research.json',JSON.stringify({...status,error:'x'.repeat(524288)}));
    return {status:'prepared'};
  });
  assert.deepEqual(result,{status:'unavailable',cacheKey:cfg.cacheKey,retryBlocked:true,reason:'status-overflow',nextAttemptAt:null});
  assert.deepEqual(storage.values.get('issuer-evidence/cohort'),wrapper({old:true}));
  let acquisitions=0;
  const reentry=await withIssuerSqliteStore(storage,cfg,store=>refreshIssuerResearch(store,cfg,{now:at,prepare:async()=>{acquisitions++;return{};}}));
  assert.equal(reentry.status,'deferred');assert.equal(acquisitions,0);
});
test('private read preserves exact Unicode bytes and never changes alarm or status',async()=>{
  const body=JSON.stringify({value:'é🙂'}),storage=state({'issuer-evidence/cohort':{cacheKey:cfg.cacheKey,body}});
  const response=await issuerSqliteResponse(request(),storage,cfg);
  assert.equal(response.status,200);assert.equal(response.headers.get('content-length'),String(new TextEncoder().encode(body).length));
  assert.equal(await response.text(),body);assert.deepEqual(storage.calls,[['get','issuer-evidence/cohort']]);
});
test('private read rejects other methods/keys/query shapes without storage and cannot arm a clock',async()=>{
  const storage=state();
  assert.equal(await issuerSqliteResponse(new Request('https://private.invalid/clock'),storage,cfg),null);
  assert.equal((await issuerSqliteResponse(request(cfg.cacheKey,'POST'),storage,cfg)).status,405);
  for(const url of ['https://private.invalid/issuer-evidence','https://private.invalid/issuer-evidence?key=opentask%2Fauth','https://private.invalid/issuer-evidence?'+new URLSearchParams({key:cfg.cacheKey,extra:'x'}),'https://private.invalid/issuer-evidence?key='+encodeURIComponent(cfg.cacheKey)+'&key='+encodeURIComponent(cfg.cacheKey)])
    assert.equal((await issuerSqliteResponse(new Request(url),storage,cfg)).status,404);
  assert.deepEqual(storage.calls,[]);
});
test('missing, mismatched, corrupt or oversized cohort never becomes a successful read',async()=>{
  for(const [value,expected]of [[undefined,404],[{cacheKey:'other',body:'{}'},404],[wrapper(null),200],[{cacheKey:cfg.cacheKey,body:'bad'},503],[{cacheKey:cfg.cacheKey,body:JSON.stringify('x'.repeat(524288))},503]]){
    const storage=state(value===undefined?{}:{'issuer-evidence/cohort':value});
    assert.equal((await issuerSqliteResponse(request(),storage,cfg)).status,expected);
  }
});

 

test('actual clock private cache read bypasses alarm arming and public Worker exposes neither cache nor private status',async()=>{
  const {EarningClock,default:worker}=await import('../worker/earning-loops.mjs');
  const storage=state({'issuer-evidence/cohort':wrapper({old:true})});
  storage.getAlarm=()=>assert.fail('private read must not inspect or arm alarm');
  storage.setAlarm=()=>assert.fail('private read must not change alarm');
  const clock=new EarningClock({storage},{},{configuration:{issuerResearch:cfg}});
  assert.equal(await(await clock.fetch(request())).text(),'{"old":true}');
  for(const path of ['/issuer-evidence?key='+encodeURIComponent(cfg.cacheKey),'/issuer-research.json']){
    assert.equal((await worker.fetch(new Request('https://public.invalid'+path),{STATE:{get(){assert.fail('public issuer read must not reach R2');}},CLOCK:{get(){assert.fail('public issuer read must not reach private DO');}}})).status,404);
  }
});
test('ordinary run publishes issuer data and retry state only in SQLite, excluding private result from R2 last-run',async()=>{
  const {run,CRONS}=await import('../worker/earning-loops.mjs');
  const {bucket}=await import('./memory.mjs');
  const STATE=bucket(),issuerStorage=state();
  const configuration={crons:CRONS,limits:{settlementsPerPass:0,routeProbesPerPass:0},repair:{repository:null},issuerResearch:cfg};
  const previousFetch=globalThis.fetch;globalThis.fetch=()=>assert.fail('no external network in integration receiving');
  try{
    const result=await run({STATE},CRONS.pass,at,{configuration,issuerStorage,prepareIssuerRevenueCohort:async()=>({type:'IssuerRevenuePreparedCohort',observedAt:at.toISOString()})});
    assert.equal(result.issuerResearch.status,'prepared');
    assert.ok(issuerStorage.values.has('issuer-evidence/cohort'));
    assert.ok(issuerStorage.values.has('issuer-evidence/status'));
    assert.equal(STATE.store.has(cfg.cacheKey),false);
    assert.equal(STATE.store.has('registers/earning-loops/issuer-research.json'),false);
    assert.equal(Object.hasOwn(JSON.parse(STATE.store.get('registers/earning-loops/last-run.json')),'issuerResearch'),false);
  }finally{globalThis.fetch=previousFetch;}
});

 

test('semantically invalid staged status rolls back the entire publication even when work catches the rejection',async()=>{
  const storage=state({'issuer-evidence/cohort':wrapper({old:true}),'issuer-evidence/status':wrapper(status)});
  const before=structuredClone([...storage.values]);
  await assert.rejects(withIssuerSqliteStore(storage,cfg,async store=>{
    await store.put(cfg.cacheKey,'{"new":true}');
    await assert.rejects(store.put('registers/earning-loops/issuer-research.json','{"status":"prepared"}'));
    return 'ignored-invalid-status';
  }));
  assert.deepEqual([...storage.values],before);
});
test('serialized transaction ceiling discards staged cohort and durably holds instead of shortening retry authority',async()=>{
  const storage=state({'issuer-evidence/cohort':wrapper({old:true})});
  const cohort=JSON.stringify('\\'.repeat(260000));
  const unavailable={status:'unavailable',at:at.toISOString(),cacheKey:cfg.cacheKey,error:'\\'.repeat(250000),code:null,reason:null,retryable:true,retryAfter:'172800',retryBlocked:false,nextAttemptAt:'2026-10-26T20:00:00.000Z'};
  assert.ok(new TextEncoder().encode(cohort).length<=cfg.maximumCohortBytes);
  assert.ok(new TextEncoder().encode(JSON.stringify(unavailable)).length<=524288);
  const result=await withIssuerSqliteStore(storage,cfg,async store=>{
    await store.put(cfg.cacheKey,cohort);
    await store.put('registers/earning-loops/issuer-research.json',JSON.stringify(unavailable));
    return {status:'prepared'};
  });
  assert.equal(result.reason,'status-overflow');assert.equal(result.retryBlocked,true);
  assert.deepEqual(storage.values.get('issuer-evidence/cohort'),wrapper({old:true}));
});

