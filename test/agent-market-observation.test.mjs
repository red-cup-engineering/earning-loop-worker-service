import assert from "node:assert/strict";
import test from "node:test";
import { observeAgentMarketIndex, AGENT_MARKET_INDEX } from "../src/agent-market-observation.mjs";
import { projectOperation } from "../src/deployment.mjs";
import { run } from "../worker/earning-loops.mjs";
import { bucket } from "./memory.mjs";

const date = "2026-10-24T13:30:00.000Z";
const plan = { enabled:true, ownHost:"market.561.group", limit:12,
  queries:["check an npm dependency vulnerability","verify a Base network transaction"] };
const fakeService = {
 id:123,protocol:"x402",name:"Original CVE triage",description:"Reads relevant advisories",
 url:"https://market.561.group/v1/orphan-patch/score",http_method:"POST",
 price_usd:"0.02",payment_network:"eip155:8453",health_status:"healthy",
 domain_verified:1,x402_payment_valid:true
};
const response = services => Response.json({ services,total:services.length });
const configured = {
 worker:"earning-loops-561-group", merchantPayTo:"0x"+"1".repeat(40),
 clock:"durable-object-alarm",
 crons:{pass:"*/15 * * * *",directives:"30 13 * * *",scorecard:"0 14 * * 1"},
 limits:{routeProbesPerPass:1,settlementsPerPass:1},
 repair:{brokenStreakBeforeRepair:3,repository:null},
 buckets:{state:"test-bucket",settlementWitnesses:"test-settlements"},
 catalogUrl:"https://market.561.group/v1/catalog",economics:{burnUsdPerMonth:600},
 onchainScanUrl:null,
 agentMarketIntelligence:plan,
};

test("a source-selected independent market query uses one free bounded external GET per buyer job", async () => {
 const seen=[];
 const value=await observeAgentMarketIndex({
  ...plan,observedAt:date,
  fetchImpl:async (url,opts)=>{
   seen.push({url,opts});
   return response([fakeService,{
    id:"other",protocol:"x402",name:"Competitor",description:"Another option",
    url:"https://rival.example.org/triage",price_usd:0.01
   }]);
  }
 });
 assert.equal(seen.length,2);
 for(let i=0;i<seen.length;i++){
  const u=new URL(seen[i].url);
  assert.equal(u.origin+u.pathname,AGENT_MARKET_INDEX);
  assert.equal(u.searchParams.get("protocol"),"x402");
  assert.equal(u.searchParams.get("q"),plan.queries[i]);
  assert.equal(u.searchParams.get("limit"),"12");
  assert.equal(seen[i].opts.method,"GET");
  assert.equal(seen[i].opts.headers.accept,"application/json");
 }
 assert.equal(value.searchReadings.length,2);
 assert.equal(value.listings.length,4);
 assert.deepEqual(value.searchReadings.map(r=>r.ownSellerRanks),[[1],[1]]);
 assert.equal(value.listings[0].advertisedUsdPerCall,"0.02");
 assert.equal(value.listings[0].reportedPaymentValid,true);
 assert.equal(value.listings[1].ownSeller,false);
 assert.equal(value.buyerConversionObserved,false);
 assert.equal(value.realMoneyOrAcceptedWorkObserved,false);
 assert.equal(value.completeMarketCoverage,false);
});

test("external market failures stay unavailable, not empty supply, and one surviving page stays available",async()=>{
 const v=await observeAgentMarketIndex({
  ...plan,observedAt:date,
  fetchImpl:async(url)=>new URL(url).searchParams.get("q")===plan.queries[0]
    ? response([fakeService]) : Response.json({error:"rate limited"},{status:429})
 });
 assert.equal(v.searchReadings[0].state,"observed-first-page");
 assert.equal(v.searchReadings[1].state,"unavailable");
 assert.equal(v.searchReadings[1].ownSellerRanks,null);
 assert.equal(v.listings.length,1);
});

test("oversized streams and non-x402 or private HTTP endpoints never qualify",async()=>{
 const invalid=await observeAgentMarketIndex({
  queries:[plan.queries[0]],ownHost:plan.ownHost,limit:12,observedAt:date,
  fetchImpl:async()=>response([{...fakeService,protocol:"l402"},
   {...fakeService,url:"http://127.0.0.1/admin"},
   {...fakeService,url:"https://user:secret@private.example.com/"}])
 });
 assert.equal(invalid.listings.length,0);
 const gigantic=await observeAgentMarketIndex({
  queries:[plan.queries[0]],ownHost:plan.ownHost,limit:12,observedAt:date,
  fetchImpl:async()=>new Response(" ".repeat(193000),{status:200})
 });
 assert.equal(gigantic.searchReadings[0].state,"unavailable");
});

test("the existing deployment alone selects source-bounded watch without permitting another scheduler",()=>{
 const selected=projectOperation(configured);
 assert.deepEqual(selected.agentMarketIntelligence,plan);
 for(const override of [
  {clock:"cron-triggers"},
  {agentMarketIntelligence:{...plan,ownHost:"another-merchant.example.com"}},
  {agentMarketIntelligence:{...plan,queries:["n",""]}},
  {agentMarketIntelligence:{...plan,limit:100}},
  {agentMarketIntelligence:{...plan,queries:[plan.queries[0],plan.queries[0]]}},
 ]){
  assert.throws(()=>projectOperation({...configured,...override}),/agent market scan/u);
 }
 const without=projectOperation({...configured,agentMarketIntelligence:undefined});
 assert.equal(without.agentMarketIntelligence,undefined);
});

test("the existing daily directives tick saves an independent observation with no new chat task",async()=>{
 const state=bucket();
 let calls=0;
 const value=await run({STATE:state},"30 13 * * *",new Date(date),{
  configuration:projectOperation(configured),
  marketObserver:async args=>{calls++;assert.deepEqual(args.queries,plan.queries);
   return {kind:"561-group.agent-market-index-observation.v1",observedAt:date,
    searchReadings:[{state:"observed-first-page"}],listings:[fakeService],
    buyerConversionObserved:false,realMoneyOrAcceptedWorkObserved:false};
  }
 });
 assert.equal(calls,1);
 assert.equal(value.agentMarketIntelligence.observed,1);
 const saved=await state.get("registers/earning-loops/agent-market-observation.json");
 assert.ok(saved);
 assert.equal((await saved.json()).listings.length,1);
});

test("a directory outage never overwrites the last qualified R2 market reading",async()=>{
 const state=bucket({"registers/earning-loops/agent-market-observation.json":{observedAt:"previous-qualified-receipt",listings:[]}});
 const value=await run({STATE:state},"30 13 * * *",new Date(date),{
  configuration:projectOperation(configured),
  marketObserver:async()=>({
   searchReadings:[{state:"unavailable"}],listings:[],observedAt:date
  })
 });
 assert.match(value.agentMarketIntelligence.error,/no source-confirmed/u);
 assert.equal((await (await state.get("registers/earning-loops/agent-market-observation.json")).json()).observedAt,"previous-qualified-receipt");
});
