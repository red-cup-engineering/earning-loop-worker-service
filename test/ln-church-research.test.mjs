import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { runResearchPass, RESEARCH_STATE, RESEARCH_SUMMARY } from '../src/ln-church-research.mjs';
import { fixture, merchant, payer, time } from './ln-church-fixture.mjs';

test('selected research acquires and completes in one bounded pulse with durable original IDs and canonical bytes',async()=>{
  const f=await fixture();
  const result=await runResearchPass({...f.options,fetchImpl:async(url,init)=>{
    const saved=await f.storage.get(RESEARCH_STATE);
    if(init.method==='POST') {
      assert.ok(saved.claimKey);assert.ok(saved.submissionId);
      if(url.endsWith('/completion')) { assert.equal(init.body,saved.completionBody);assert.equal(init.headers['Idempotency-Key'],saved.submissionId);
        assert.equal(saved.reportSha256,createHash('sha256').update(init.body).digest('hex'));assert.equal(init.headers['X-LN-Task-Claim-Token'],f.claim.claim_token); }
    }
    return f.fetchImpl(url,init);
  }});
  assert.equal(result.stage,'research-evaluation-pending');assert.equal(result.requests,4);
  assert.equal(f.calls.filter(c=>c.method==='POST').length,2);
  const summary=JSON.stringify(await f.storage.get(RESEARCH_SUMMARY));
  assert.equal(summary.includes(f.claim.claim_token),false);assert.equal(summary.includes('claimKey'),false);
  assert.equal(result.receiptAccepted,true);assert.equal(result.independentlyVerifiedCashAtomic,null);
});

test('changed question, terms, reward or unavailable capacity refuses before claim',async()=>{
  for(const mutate of [f=>f.task.question+=' changed',f=>f.task.terms_digest='d'.repeat(64),f=>f.task.reward={...f.task.reward,correct_amount_atomic:'99999'},f=>f.task.capacity_available=0]) {
    const f=await fixture();mutate(f);const r=await runResearchPass(f.options);
    assert.equal(f.calls.length,1);assert.equal((await f.storage.get(RESEARCH_STATE)).terminal,true);assert.notEqual(r.stage,'research-evaluation-pending');
  }
});

test('lost claim recovers only the original body and key in read-only recovery mode',async()=>{
  const f=await fixture();let lost=true;
  const options={...f.options,fetchImpl:async(url,init)=>{if(url.endsWith('/claim')&&lost){lost=false;f.calls.push({url,...init});throw Error('lost');}return f.fetchImpl(url,init);}};
  await runResearchPass(options);const first=f.calls.find(c=>c.url.endsWith('/claim'));
  const r=await runResearchPass({...options,now:()=>time+30000});
  const claims=f.calls.filter(c=>c.url.endsWith('/claim'));
  assert.equal(claims.length,2);assert.equal(claims[1].body,first.body);assert.equal(claims[1].headers['Idempotency-Key'],first.headers['Idempotency-Key']);
  assert.equal(claims[1].headers['X-LN-Claim-Recovery'],'1');assert.equal(r.receiptAccepted,true);
});

test('lost completion reads status before any replay and retains exact report and submission key',async()=>{
  const f=await fixture();let lost=true, missing=true;const effects=[];
  const options={...f.options,fetchImpl:async(url,init)=>{
    effects.push({url,...init});
    if(url.endsWith('/completion')&&lost){lost=false;throw Error('lost');}
    if(url.includes('/submissions/')&&missing){missing=false;return Response.json({code:'not_found'},{status:404});}
    return f.fetchImpl(url,init);
  }};
  await runResearchPass(options);await runResearchPass({...options,now:()=>time+30000});
  const writes=effects.filter(c=>c.url.endsWith('/completion'));
  assert.equal(writes.length,2);assert.equal(writes[0].body,writes[1].body);assert.equal(writes[0].headers['Idempotency-Key'],writes[1].headers['Idempotency-Key']);
  assert.ok(effects[3].url.includes('/submissions/'));
  assert.equal(effects.filter(c=>c.url.endsWith('/claim')).length,1);
});

test('gateway Retry-After is durable before HTML admission and suppresses every next-pulse request',async()=>{
  const f=await fixture();let refused=true,calls=0;
  const options={...f.options,fetchImpl:async(url,init)=>{calls++;if(url.endsWith('/completion')&&refused){refused=false;return new Response('<html>limited</html>',{status:429,headers:{'retry-after':'86400'}});}return f.fetchImpl(url,init);}};
  await runResearchPass(options);const before=calls;
  assert.equal((await runResearchPass({...options,now:()=>time+60000})).requests,0);assert.equal(calls,before);
  await runResearchPass({...options,now:()=>time+86400001});
  assert.equal(f.calls.filter(c=>c.url.endsWith('/claim')).length,1);
});

test('provider denial, redirect, paid access and duplicate-key JSON never acquire another claim',async()=>{
  for(const response of [()=>new Response('<html>payment required</html>', {status:402}),()=>Response.json({}, {status:401}),()=>new Response('',{status:302,headers:{location:'https://foreign.test'}}),()=>new Response('{"task_id":"one","task_id":"two"}')]){
    const f=await fixture();let calls=0;
    const r=await runResearchPass({...f.options,fetchImpl:async()=>{calls++;return response();}});
    assert.equal(calls,1);assert.equal(r.independentlyVerifiedCashAtomic,null);
    if(r.stage!=='research-invalid-response')assert.equal((await f.storage.get(RESEARCH_STATE)).terminal,true);
  }
});

test('provider payout is separately corroborated against two independent exact Base USDC receipts',async()=>{
  const f=await fixture(),tx='0x'+'8'.repeat(64),block='0x'+'9'.repeat(64);
  const topic=a=>'0x'+'0'.repeat(24)+a.slice(2);
  const receipt={status:'0x1',transactionHash:tx,blockHash:block,blockNumber:'0x123',logs:[{address:f.product.reward.asset_address,
    topics:['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',topic(payer),topic(merchant)],data:'0x'+BigInt('25000').toString(16).padStart(64,'0'),logIndex:'0x0',removed:false}]};
  const r=await runResearchPass({...f.options,fetchImpl:async(url,init)=>{
    if(url.includes('/submissions/')){const s=await f.status();s.evaluation={state:'GRADED',approved_amount_atomic:'25000'};s.payout={state:'paid_confirmed',transaction_hash:tx,confirmed_paid_amount_atomic:'25000'};return Response.json(s);}
    if(!url.startsWith('https://kari.'))return Response.json({jsonrpc:'2.0',id:1,result:receipt});
    return f.fetchImpl(url,init);
  }});
  assert.equal(r.requests,6);assert.equal(r.stage,'research-cash-corroborated');assert.equal(r.independentlyVerifiedCashAtomic,'25000');
  assert.equal(r.recognizedOutsideRevenue,null);assert.equal((await f.storage.get(RESEARCH_STATE)).terminal,true);
});

test('scope substitution after claim and forged receipt cannot be reported accepted',async()=>{
  for(const kind of ['claim','receipt']){
    const f=await fixture();
    const r=await runResearchPass({...f.options,fetchImpl:async(url,init)=>{
      if(kind==='claim'&&url.endsWith('/claim'))return Response.json({...f.claim,reward_address:payer});
      if(kind==='receipt'&&url.endsWith('/completion'))return Response.json({...await f.receipt(),report_sha256:'e'.repeat(64)});
      return f.fetchImpl(url,init);
    }});
    assert.equal(r.receiptAccepted,false);assert.equal(r.independentlyVerifiedCashAtomic,null);assert.equal((await f.storage.get(RESEARCH_STATE)).terminal,true);
  }
});

test('finite evaluation episode preserves unresolved same-ID reconciliation and performs no more automatic effects',async()=>{
  const f=await fixture();await runResearchPass(f.options);const before=await f.storage.get(RESEARCH_STATE);
  const held=await runResearchPass({...f.options,now:()=>time+1830000});
  assert.equal(held.stage,'research-monitoring-held');
  const after=await f.storage.get(RESEARCH_STATE);
  assert.equal(after.submissionId,before.submissionId);assert.equal(after.claim.claim_token,before.claim.claim_token);assert.equal(after.reconciliationPending,true);
  const count=f.calls.length;assert.equal((await runResearchPass({...f.options,now:()=>time+3600000})).requests,0);assert.equal(f.calls.length,count);
});

test('lost receipt recovers the native status deadline and outages cannot make monitoring unbounded',async()=>{
  const f=await fixture();let lose=true;
  const options={...f.options,fetchImpl:async(url,init)=>{if(url.endsWith('/completion')&&lose){lose=false;throw Error('lost');}return f.fetchImpl(url,init);}};
  await runResearchPass(options);
  await runResearchPass({...options,now:()=>time+30000});
  const s=await f.storage.get(RESEARCH_STATE);assert.equal(s.receipt,undefined);assert.equal(s.status.evaluation.state,'PENDING');assert.equal(s.monitoringUntil,time+1830000);
  let calls=0;
  const held=await runResearchPass({...options,now:()=>time+1830000,fetchImpl:async()=>{calls++;throw Error('outage');}});
  assert.equal(held.stage,'research-monitoring-held');assert.equal(calls,0);assert.equal((await f.storage.get(RESEARCH_STATE)).submissionId,s.submissionId);
});

test('zero-quality reward never becomes verified cash',async()=>{
  const f=await fixture();
  const r=await runResearchPass({...f.options,fetchImpl:async(url,init)=>{
    if(url.includes('/submissions/')){const s=await f.status();s.evaluation={state:'GRADED',approved_amount_atomic:'0'};s.payout={state:'not_applicable',transaction_hash:null,confirmed_paid_amount_atomic:null};return Response.json(s);}
    return f.fetchImpl(url,init);
  }});
  assert.equal(r.stage,'research-no-payout');assert.equal(r.independentlyVerifiedCashAtomic,null);assert.equal(r.approvedAmountAtomic,'0');
});
