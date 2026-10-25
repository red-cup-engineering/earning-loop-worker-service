import assert from 'node:assert/strict';
import { runHashnAcquisition, HASHN_STATE } from '../src/hashn-acquisition.mjs';
export const testNativeHashn = { async test() {
  const agentId='33333333-3333-4333-8333-333333333333',buyerAgentId='55555555-5555-4555-8555-555555555555';
  const workspaceId='11111111-1111-4111-8111-111111111111',knockId='77777777-7777-4777-8777-777777777777';
  const instance={enabled:true,workspaceId,buyerAgentId,offerId:'fixture',note:'Exact terms before work.',maximumNewCashExpenseUsd:0,maximumProviderRequestsPerPass:3,pollIntervalMs:21600000};
  let time=Date.parse('2026-10-24T22:00:00Z'),posts=0,outgoing=[];
  const values=new Map(),storage={async get(k){return structuredClone(values.get(k));},async put(k,v){values.set(k,structuredClone(v));}};
  const options={storage,instance,initialCredential:{agentId,apiToken:'aw_runtime_fixture_only'},now:()=>time,fetchImpl:async(url,init)=>{
    if(url.endsWith('/agents/me'))return Response.json({agent_id:agentId});
    if(url.endsWith('/knocks'))return Response.json({outgoing});
    assert.equal(values.get(HASHN_STATE).intent.body.note,instance.note);assert.equal(init.method,'POST');posts++;
    outgoing=[{knock_id:knockId,knocked_workspace_id:workspaceId,from_agent_id:agentId,to_agent_id:buyerAgentId,note:instance.note,status:'pending'}];
    return Response.json({knock_id:knockId},{status:201});
  }};
  const first=await runHashnAcquisition(options);assert.equal(first.requests,3);assert.equal(first.stage,'hashn-knock-sent-readback-pending');
  time+=30000;const next=await runHashnAcquisition(options);assert.equal(next.requests,1);assert.equal(next.stage,'hashn-pending');assert.equal(posts,1);
} };
