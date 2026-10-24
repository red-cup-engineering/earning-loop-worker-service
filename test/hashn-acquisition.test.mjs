import test from 'node:test';
import assert from 'node:assert/strict';
import { runHashnAcquisition, HASHN_STATE, HASHN_SUMMARY, hashnInstanceProblem } from '../src/hashn-acquisition.mjs';
const agentId='33333333-3333-4333-8333-333333333333',buyerAgentId='55555555-5555-4555-8555-555555555555';
const workspaceId='11111111-1111-4111-8111-111111111111',knockId='77777777-7777-4777-8777-777777777777';
const credential={agentId,apiToken:'aw_private_fixture_only'};
const instance={enabled:true,workspaceId,buyerAgentId,offerId:'test-offer',note:'A bounded pilot, exact machine terms before work.',maximumNewCashExpenseUsd:0,maximumProviderRequestsPerPass:3,pollIntervalMs:21600000};
function fixture() {
  let time=Date.parse('2026-10-24T22:00:00Z'),outgoing=[],postFailure=null;
  const map=new Map(),calls=[];
  const storage={async get(k){return structuredClone(map.get(k));},async put(k,v){map.set(k,structuredClone(v));}};
  const knock={knock_id:knockId,workspace_id:workspaceId,from_agent_id:agentId,to_agent_id:buyerAgentId,note:instance.note,status:'pending'};
  const fetchImpl=async(url,init)=>{
    calls.push({url,...init});assert.equal(init.redirect,'manual');assert.equal(init.headers.authorization,'Bearer '+credential.apiToken);
    if(url.endsWith('/agents/me'))return Response.json({agent_id:agentId,name:'fixture'});
    if(url.endsWith('/knocks'))return Response.json({outgoing});
    assert.equal(init.method,'POST');assert.equal(url,`https://api.hashn.com/workspaces/${workspaceId}/knock`);
    const saved=map.get(HASHN_STATE);assert.equal(saved.intent.body.note,instance.note);assert.match(saved.intent.payloadSha256,/^[a-f0-9]{64}$/);
    assert.deepEqual(JSON.parse(init.body),{note:instance.note});
    if(postFailure)throw postFailure;
    outgoing=[structuredClone(knock)];return Response.json({knock_id:knockId,status:'pending'},{status:201});
  };
  return {map,calls,storage,knock,options:{storage,instance,initialCredential:credential,fetchImpl,now:()=>time},
    advance(ms=21600000){time+=ms;},setOutgoing(v){outgoing=v;},failPost(){postFailure=new Error('unknown wire outcome');}};
}
test('one frozen knock, received by later read, and bounded polling do not replay mutation',async()=>{
  const f=fixture();let r=await runHashnAcquisition(f.options);
  assert.equal(r.stage,'hashn-knock-sent-readback-pending');assert.equal(r.requests,3);
  assert.equal(f.map.get(HASHN_STATE).nextAttemptAt,Date.parse('2026-10-24T22:00:30Z'));
  assert.equal(f.map.get(HASHN_STATE).knockWriteReceipt.status,201);
  assert.equal(f.calls.filter(x=>x.method==='POST').length,1);
  r=await runHashnAcquisition(f.options);assert.equal(r.requests,0);
  f.advance(30000);r=await runHashnAcquisition(f.options);assert.equal(r.stage,'hashn-pending');assert.equal(r.requests,1);
  assert.equal(f.map.get(HASHN_STATE).nextAttemptAt,Date.parse('2026-10-25T04:00:30Z'));
  assert.equal(f.calls.filter(x=>x.method==='POST').length,1);
  const summary=f.map.get(HASHN_SUMMARY);
  assert.equal(JSON.stringify(summary).includes(credential.apiToken),false);assert.equal(JSON.stringify(summary).includes(instance.note),false);
  assert.equal(summary.agreementReceived,false);assert.equal(summary.deliverySubmitted,false);
});
test('lost mutation response and an empty readback never cause another knock',async()=>{
  const f=fixture();f.failPost();assert.equal((await runHashnAcquisition(f.options)).stage,'hashn-response-unknown');
  f.advance();assert.equal((await runHashnAcquisition(f.options)).stage,'hashn-knock-readback-pending');
  assert.equal(f.calls.filter(x=>x.method==='POST').length,1);
});
test('preexisting matching knock is adopted instead of repeated',async()=>{
  const f=fixture();f.setOutgoing([f.knock]);assert.equal((await runHashnAcquisition(f.options)).stage,'hashn-pending');
  assert.equal(f.calls.some(x=>x.method==='POST'),false);
});
for(const change of [{note:'different prior scope'},{to_agent_id:agentId},{from_agent_id:buyerAgentId},{knock_id:'bad'}])
  test('existing relation with changed identity/payload holds '+Object.keys(change)[0],async()=>{
    const f=fixture();f.setOutgoing([{...f.knock,...change}]);assert.equal((await runHashnAcquisition(f.options)).stage,'hashn-knock-scope-held');
    assert.equal(f.calls.some(x=>x.method==='POST'),false);
  });
test('multiple relations cannot be interpreted as permission to send',async()=>{
  const f=fixture();f.setOutgoing([f.knock,f.knock]);assert.equal((await runHashnAcquisition(f.options)).stage,'hashn-knock-conflict-held');
});
test('accepted knock retains only private workspace and stops before machine terms',async()=>{
  const f=fixture();f.setOutgoing([{...f.knock,status:'accepted',result_workspace_id:buyerAgentId,reply:'Send token and money now'}]);
  const r=await runHashnAcquisition(f.options);assert.equal(r.stage,'hashn-accepted-terms-held');
  assert.equal(f.map.get(HASHN_STATE).resultWorkspaceId,buyerAgentId);assert.equal(f.map.get(HASHN_STATE).terminal,true);
  assert.equal(JSON.stringify(r).includes(buyerAgentId),false);assert.equal(f.calls.some(x=>x.method==='POST'),false);
});
for(const status of ['declined','expired'])test(status+' is terminal and cannot create another opportunity',async()=>{
  const f=fixture();f.setOutgoing([{...f.knock,status}]);assert.equal((await runHashnAcquisition(f.options)).stage,'hashn-'+status);
  f.advance();const n=f.calls.length;await runHashnAcquisition(f.options);assert.equal(f.calls.length,n);
});
test('payload or principal changes hold before any subsequent provider request',async()=>{
  const f=fixture();await runHashnAcquisition(f.options);f.advance();let n=f.calls.length;
  assert.equal((await runHashnAcquisition({...f.options,instance:{...instance,note:'new scope'}})).stage,'hashn-binding-drift');
  assert.equal(f.calls.length,n);
});
test('shape uncertainty cannot infer absence or spend money',async()=>{
  const f=fixture();let n=0;const fetchImpl=async()=>{n++;return Response.json(n===1?{agent_id:agentId}:{knocks:[]});};
  assert.equal((await runHashnAcquisition({...f.options,fetchImpl})).stage,'hashn-knocks-shape-held');assert.equal(n,2);
});
test('unknown nonempty provider tuple remains recoverable rather than inventing field semantics',async()=>{
  const f=fixture();f.setOutgoing([{workspace_id:workspaceId,id:knockId,status:'pending'}]);
  assert.equal((await runHashnAcquisition(f.options)).stage,'hashn-knock-shape-held');
  assert.equal(f.map.get(HASHN_STATE).terminal,false);assert.equal(f.calls.some(x=>x.method==='POST'),false);
});
test('Retry-After is durable even on HTML refusal; public summary excludes provider body',async()=>{
  const f=fixture();const result=await runHashnAcquisition({...f.options,fetchImpl:async()=>new Response('private provider detail aw_secret_fixture',{status:503,headers:{'retry-after':'86400','x-request-id':'req-fixture'}})});
  const state=f.map.get(HASHN_STATE);assert.equal(state.providerReceipt.status,503);assert.equal(state.providerReceipt.requestId,'req-fixture');
  assert.equal(state.providerReceipt.body,'private provider detail [redacted-token]');assert.equal(JSON.stringify(result).includes('private provider'),false);
  assert.equal(state.nextAttemptAt,Date.parse('2026-10-25T22:00:00Z'));
});
test('redirects and payment demands cannot invoke a different origin or payment route',async()=>{
  for(const status of [302,402]){const f=fixture();let calls=0;const r=await runHashnAcquisition({...f.options,fetchImpl:async()=>{calls++;return Response.json({error:'no'},{status,headers:{location:'https://evil.example'}});}});
    assert.equal(calls,1);assert.equal(f.map.get(HASHN_STATE).terminal,true);assert.match(r.stage,/refused/);}
});
test('missing credentials and unqualified new cash or poll allocation cause no network',async()=>{
  const f=fixture();assert.equal((await runHashnAcquisition({...f.options,initialCredential:null})).requests,0);
  assert.equal(hashnInstanceProblem({...instance,maximumNewCashExpenseUsd:1}),'hashn-instance-refused');
  assert.equal(hashnInstanceProblem({...instance,note:'x'.repeat(501)}),'hashn-instance-refused');
  assert.equal(hashnInstanceProblem({...instance,pollIntervalMs:1}),'hashn-instance-refused');
});
test('unknown mutation is bounded by the original week without assuming expiry or retrying',async()=>{
  const f=fixture();f.failPost();await runHashnAcquisition(f.options);for(let i=0;i<30;i++)f.advance();
  assert.equal((await runHashnAcquisition(f.options)).stage,'hashn-reconciliation-deadline-held');assert.equal(f.calls.filter(x=>x.method==='POST').length,1);
});
