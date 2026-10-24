import test from 'node:test';
import assert from 'node:assert/strict';
import { EarningClock, CRONS } from '../worker/earning-loops.mjs';
import { runHashnAcquisition, HASHN_STATE, HASHN_SUMMARY } from '../src/hashn-acquisition.mjs';
import { projectOperation } from '../src/deployment.mjs';
import { bucket } from './memory.mjs';

const instance={enabled:true,workspaceId:'11111111-1111-4111-8111-111111111111',buyerAgentId:'22222222-2222-4222-8222-222222222222',
  offerId:'private-proposal',note:'private acquisition scope',maximumNewCashExpenseUsd:0,maximumProviderRequestsPerPass:3,pollIntervalMs:21600000};
test('acquisition has an isolated invocation and never displaces CSV or maintenance deadlines',async()=>{
  const realNow=Date.now,realFetch=globalThis.fetch;let time=Date.parse('2026-10-24T23:07:30Z');Date.now=()=>time;
  globalThis.fetch=async()=>Response.json({offers:[]});
  const auth={refreshToken:'held'},values=new Map([['opentask/auth',auth]]);let alarm=null,csv=0,acq=0;
  const storage={async get(k){return values.get(k);},async put(k,v){values.set(k,v);},async getAlarm(){return alarm;},async setAlarm(v){alarm=v;}};
  const env={STATE:bucket(),MARKET_SETTLEMENTS:bucket()};
  const clock=new EarningClock({storage},env,{configuration:{commercial:{enabled:true},hashAcquisition:instance,crons:CRONS,
    limits:{settlementsPerPass:1,routeProbesPerPass:0},repair:{},catalogUrl:'https://fixture.example/catalog'},
    commercialPass:async()=>{csv++;return{stage:'awaiting-hire',requests:1};},
    acquisitionPass:async()=>{acq++;assert.ok(values.get('hashn/next-pulse-at')>time);await storage.put(HASHN_STATE,{stage:'hashn-pending',nextAttemptAt:time+21600000});}
  });
  try{
    await clock.alarm();assert.equal(csv,1);assert.equal(acq,0);assert.equal(alarm,time+1000);
    time=alarm;await clock.alarm();assert.equal(csv,1);assert.equal(acq,1);assert.equal(alarm,Date.parse('2026-10-24T23:15:00Z'));
    assert.equal(env.STATE.store.size,0,'isolated acquisition and CSV do not touch R2');assert.equal(values.get('opentask/auth'),auth);
    time=alarm;await clock.alarm();assert.equal(acq,1);assert.ok(env.STATE.store.has('registers/earning-loops/last-run.json'),'maintenance ran on time');
    time=Date.parse('2026-10-24T23:22:30Z');await clock.alarm();assert.equal(csv,2);assert.equal(acq,1);
  }finally{Date.now=realNow;globalThis.fetch=realFetch;}
});
test('a failed acquisition cannot create a tight alarm loop or overwrite commercial custody',async()=>{
  const realNow=Date.now;let time=Date.parse('2026-10-24T23:08:00Z');Date.now=()=>time;
  const values=new Map([['earning-clock/core-next-at',time+420000]]);let alarm;
  const storage={async get(k){return values.get(k);},async put(k,v){values.set(k,v);},async setAlarm(v){alarm=v;}};
  const clock=new EarningClock({storage},{},{configuration:{hashAcquisition:instance,crons:CRONS},acquisitionPass:async()=>{throw new Error('test failure');}});
  try{await assert.rejects(clock.alarm(),/test failure/);assert.equal(alarm,time+420000);assert.equal(values.get('hashn/next-pulse-at'),time+21600000);}
  finally{Date.now=realNow;}
});
test('release receiving schedules one schema read despite both six-hour timers, retaining the knock and core reservation',async()=>{
  const realNow=Date.now,realFetch=globalThis.fetch;let time=Date.parse('2026-10-24T23:08:00Z');Date.now=()=>time;
  const credential={agentId:'33333333-3333-4333-8333-333333333333',apiToken:'aw_private_fixture_only'};
  const values=new Map();let alarm=time+420000,posts=0,reads=0,csv=0,outgoing=[];
  const storage={async get(k){return structuredClone(values.get(k));},async put(k,v){values.set(k,structuredClone(v));},async getAlarm(){return alarm;},async setAlarm(v){alarm=v;}};
  globalThis.fetch=async(url,init)=>{
    if(url.endsWith('/agents/me'))return Response.json({agent_id:credential.agentId});
    if(url.endsWith('/knocks')){reads++;if(posts)assert.equal(values.get(HASHN_STATE).knocksSchemaRevision,2);return Response.json({incoming_pending:[],outgoing});}
    posts++;outgoing=[{knock_id:'77777777-7777-4777-8777-777777777777',knocked_workspace_id:instance.workspaceId,
      from_agent_id:credential.agentId,to_agent_id:instance.buyerAgentId,note:instance.note,status:'pending',reply:null,result_workspace_id:null}];
    return Response.json({knock_id:outgoing[0].knock_id},{status:201});
  };
  const clock=new EarningClock({storage},{HASHN_CREDENTIAL_JSON:JSON.stringify(credential),RELEASE_METADATA:{id:'schema-receiving-release'}},
    {configuration:{commercial:{enabled:true},hashAcquisition:instance,crons:CRONS},commercialPass:async()=>{csv++;return{stage:'awaiting-hire',requests:0};}});
  try{
    await runHashnAcquisition({storage,instance,initialCredential:credential,now:()=>time});
    const prior=values.get(HASHN_STATE);delete prior.knocksSchemaRevision;prior.stage='hashn-knocks-shape-held';prior.nextAttemptAt=time+21600000;
    await storage.put(HASHN_STATE,prior);await storage.put('hashn/next-pulse-at',time+21600000);
    reads=0;await clock.alarm();assert.equal(csv,1);assert.equal(reads,0);assert.equal(alarm,time+1000);
    const core=values.get('earning-clock/core-next-at');time=alarm;await clock.alarm();
    assert.equal(reads,1);assert.equal(posts,1);assert.equal(values.get(HASHN_STATE).stage,'hashn-pending');
    assert.equal(values.get(HASHN_STATE).knocksSchemaRevision,2);assert.equal(alarm,core);
    time+=1000;await clock.alarm();assert.equal(reads,1);assert.equal(posts,1);
  }finally{Date.now=realNow;globalThis.fetch=realFetch;}
});
test('acquisition public reading is a strict projection and cannot trigger an effect',async()=>{
  const secret='aw_should_never_appear';let calls=0;
  const values=new Map([[HASHN_SUMMARY,{stage:'hashn-pending',requests:1,at:'2026-10-24T23:00:00Z',newCashExpenseUsd:0,
    apiToken:secret,note:'private',providerReceipt:{body:'private'},resultWorkspaceId:'private',offerId:'public-offer',agreementReceived:false}]]);
  const clock=new EarningClock({storage:{async get(k){return values.get(k);}}},{},{acquisitionPass:async()=>{calls++;}});
  const r=await(await clock.fetch(new Request('https://fixture.example/acquisition.json'))).json();
  assert.equal(calls,0);for(const k of ['apiToken','note','providerReceipt','resultWorkspaceId'])assert.equal(r[k],undefined);
  assert.equal(r.agreementReceived,false);
});
test('source projection rejects non-private clocks and altered cash/request/poll admission',()=>{
  const base={merchantPayTo:'0x'+'1'.repeat(40),clock:'durable-object-alarm',repair:{},hashAcquisition:instance};
  assert.deepEqual(projectOperation(base).hashAcquisition,instance);
  for(const hashAcquisition of [{...instance,maximumNewCashExpenseUsd:1},{...instance,maximumProviderRequestsPerPass:99},{...instance,pollIntervalMs:1}])
    assert.throws(()=>projectOperation({...base,hashAcquisition}));
  assert.throws(()=>projectOperation({...base,clock:'cron-triggers'}));
});
