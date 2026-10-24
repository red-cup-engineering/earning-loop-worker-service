import test from 'node:test';
import assert from 'node:assert/strict';
import { provisionHashnAgent, HASHN_CREDENTIAL_ID } from '../src/hashn-provisioning.mjs';
const agentId = '33333333-3333-4333-8333-333333333333';
const credential = { agentId, apiToken: 'aw_private_fixture_only' };
function fixture(fetchImpl) {
  let attempt, secret;
  const custody = { async getAttempt() { return structuredClone(attempt); }, async putAttempt(v) { attempt = structuredClone(v); },
    async getCredential() { return secret; }, async putCredential(id,v) { assert.equal(id,HASHN_CREDENTIAL_ID); secret = v; } };
  return { custody, fetchImpl, attempt: () => attempt, secret: () => secret };
}
test('signup intent precedes the single effect; credential is sealed and never returned', async () => {
  let calls = 0;
  const f = fixture(async (url, init) => {
    calls++; assert.equal(f.attempt().stage,'signup-intent'); assert.equal(url,'https://api.hashn.com/agents');
    assert.deepEqual(JSON.parse(init.body),{name:'561-group earning-loops'});
    return Response.json({agent_id:agentId,api_token:credential.apiToken},{status:201});
  });
  const result = await provisionHashnAgent(f);
  assert.equal(calls,1); assert.equal(result.created,true); assert.deepEqual(f.secret(),credential);
  assert.equal(JSON.stringify([result,f.attempt()]).includes(credential.apiToken),false);
});
test('uncertain signup cannot create a second principal',async()=>{
  let calls=0; const f=fixture(async()=>{calls++;throw new Error('response lost');});
  assert.equal((await provisionHashnAgent(f)).stage,'signup-outcome-held');
  assert.equal((await provisionHashnAgent(f)).stage,'signup-outcome-held');assert.equal(calls,1);
});
test('stored credential is reused and checked against original identity without signup',async()=>{
  let calls=0;const f=fixture(async(url,init)=>{calls++;assert.equal(url,'https://api.hashn.com/agents/me');assert.equal(init.headers.authorization,'Bearer '+credential.apiToken);return Response.json({agent_id:agentId,name:'561-group earning-loops'});});
  await f.custody.putCredential(HASHN_CREDENTIAL_ID,credential);
  assert.equal((await provisionHashnAgent(f)).created,false);assert.equal(calls,1);
});
test('seal failure retains signup uncertainty and cannot replay signup',async()=>{
  let calls=0;const f=fixture(async()=>{calls++;return Response.json({agent_id:agentId,api_token:credential.apiToken},{status:201});});
  f.custody.putCredential=async()=>{throw new Error('sealing refused');};
  assert.equal((await provisionHashnAgent(f)).stage,'signup-outcome-held');await provisionHashnAgent(f);assert.equal(calls,1);
});
test('provider refusal retains causal status/id/body privately with token fields removed',async()=>{
  const f=fixture(async()=>Response.json({error:'reserved_name',message:'provider explains refusal',api_token:'aw_provider_secret'},
    {status:400,headers:{'x-request-id':'request-fixture'}}));
  const result=await provisionHashnAgent(f),receipt=f.attempt().providerReceipt;
  assert.equal(receipt.status,400);assert.equal(receipt.requestId,'request-fixture');
  assert.equal(receipt.body.error,'reserved_name');assert.equal(receipt.body.message,'provider explains refusal');
  assert.equal(receipt.body.api_token,'[redacted]');assert.equal(JSON.stringify(result).includes('reserved_name'),false);
});
