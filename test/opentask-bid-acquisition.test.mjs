import test from 'node:test';
import assert from 'node:assert/strict';
import { acquirePreparedBid, commercialOffers } from '../src/opentask-bid-acquisition.mjs';

const instance = { taskId:'task-a', buyerId:'buyer-a', profileId:'seller-a', maximumNewCashExpenseUsd:0,
  taskDescription:'Convert supplied CSV to JSON', expectedTaskUpdatedAt:'2026-10-26T00:00:00.000Z',
  priceText:'100 USDC', bidApproach:'Frozen conversion with agent acceptance and buyer-funded settlement.' };
const context = () => ({ task:{id:instance.taskId, owner:{id:instance.buyerId,kind:'agent'}, status:'open',
  executionMode:'pitch', updatedAt:instance.expectedTaskUpdatedAt, description:instance.taskDescription, capabilityRequirements:[]},
  availableActions:[{schemaVersion:'opentask-available-actions-v1',action:'create_bid',state:'available',entity:{id:instance.taskId},
    actor:{role:'worker',eligibleProfileId:instance.profileId,requiredScopeMode:'all',requiredScopes:['bids:write']},
    invocation:{method:'POST',endpoint:`/api/agent/tasks/${instance.taskId}/bids`,bodyTemplate:{expectedTaskUpdatedAt:instance.expectedTaskUpdatedAt}},
    confirmation:{required:false},payment:null}] });
const now = new Date('2026-10-26T15:00:00Z');

test('seller records intent before its single conditional bid',async()=>{
  const state={},calls=[];
  const client={request:async(path,options)=>{
    calls.push({path,options});
    if(path.startsWith('/api/agent/bids?'))return {bids:[],nextCursor:null};
    if(!options)return context();
    assert.ok(state.bidPending);assert.equal(options.body.priceText,'100 USDC');return {bid:{id:'bid-a'}};
  }};
  assert.equal(await acquirePreparedBid({client,instance,state,save:async()=>{},now}),'bid-created');
  assert.equal(state.bidId,'bid-a');assert.equal(calls.filter(x=>x.options?.method==='POST').length,1);
});

test('lost creation reconciles to one existing bid without another write',async()=>{
  const state={bidPending:{path:'retained'}},calls=[];
  const client={request:async(path,options)=>{calls.push(options);return {bids:[{id:'bid-a',task:{id:instance.taskId},status:'active',priceText:instance.priceText,approach:instance.bidApproach}],nextCursor:null};}};
  assert.equal(await acquirePreparedBid({client,instance,state,save:async()=>{},now}),'bid-received');
  assert.equal(state.bidId,'bid-a');assert.equal(calls.length,1);assert.equal(calls[0],undefined);
});

test('absence after an uncertain effect does not repeat creation',async()=>{
  const state={bidPending:{path:'retained'}};
  const client={request:async()=>({bids:[],nextCursor:null})};
  assert.equal(await acquirePreparedBid({client,instance,state,save:async()=>{},now}),'bid-effect-readback-pending');
});

test('changed scope and human buyers cannot receive an automatic bid',async()=>{
  for(const change of [v=>v.task.owner.kind='human',v=>v.task.updatedAt='2026-10-27T00:00:00Z']){
    const value=context();change(value);
    const client={request:async(path,options)=>{assert.equal(options,undefined);return path.includes('/bids?')?{bids:[],nextCursor:null}:value;}};
    assert.equal(await acquirePreparedBid({client,instance,state:{},save:async()=>{},now}),'buyer-scope-held');
  }
});

test('offer selection preserves original custody and limits work',()=>{
  const base={...instance,taskId:'old',bidId:'old-bid',offers:[{taskId:'new',bidId:null,profileId:'another',maximumNewCashExpenseUsd:9}]};
  const offers=commercialOffers(base);
  assert.equal(offers.length,2);assert.equal(offers[0].profileId,instance.profileId);
  assert.equal(offers[0].maximumNewCashExpenseUsd,0);assert.equal(offers[1].bidId,'old-bid');
  assert.throws(()=>commercialOffers({...base,offers:[{taskId:'old'}]}));
});
