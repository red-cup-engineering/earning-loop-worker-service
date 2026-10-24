import test from 'node:test';
import assert from 'node:assert/strict';
import { publishHashnOffer } from '../src/hashn-offer-publication.mjs';
const agentId='33333333-3333-4333-8333-333333333333';
const credential={agentId,apiToken:'aw_publication_fixture_only'};
const listing={name:'reconciliation-pilot',path:'listings/reconciliation-pilot.md',convention:'agent-services',can:'One bounded reconciliation pilot after exact agreement.',
  contact_method:'hashn knock',contact_info:`POST https://api.hashn.com/agents/${agentId}/knock`,fields:{project:'fixture-project'}};
const descriptor={provider:'https://api.hashn.com',agentId,price:{amount:10,currency:'USDC'},listing};
function fixture(price=10){let state,posts=0;const custody={async getAttempt(){return structuredClone(state);},async putAttempt(v){state=structuredClone(v);}};
  const fetchImpl=async(url,init)=>{
    if(url.endsWith('/agents/me'))return Response.json({agent_id:agentId});
    if(url.endsWith('/listings/check'))return Response.json({ok:true,in_forest:true,path:listing.path,header:{can:listing.can,project:'fixture-project','payment.amount':price,'payment.currency':'USDC'}});
    assert.equal(url,'https://api.hashn.com/listings');assert.equal(state.stage,'publication-intent');assert.deepEqual(state.intent.body,listing);posts++;
    throw new Error('response lost after provider may have committed');
  };return{custody,fetchImpl,state:()=>state,posts:()=>posts};}
test('unknown public listing write keeps exact intent and cannot be repeated',async()=>{
  const f=fixture();assert.equal((await publishHashnOffer({...f,descriptor,credential})).stage,'publication-outcome-held');
  const prior=f.state();assert.equal(prior.intent.path,'/listings');assert.equal(f.posts(),1);
  assert.equal((await publishHashnOffer({...f,descriptor,credential})).stage,'publication-outcome-held');assert.equal(f.posts(),1);
});
test('provider price-unit mismatch holds before any public listing mutation',async()=>{
  const f=fixture(10000000);const result=await publishHashnOffer({...f,descriptor,credential});
  assert.equal(result.stage,'publication-check-held');assert.equal(f.posts(),0);assert.equal(f.state().intent,undefined);
});
