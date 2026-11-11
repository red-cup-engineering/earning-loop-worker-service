import test from 'node:test';
import assert from 'node:assert/strict';
import {issuerSettlementCustodyPlan,issuerSettlementResponse,receiveIssuerSettlements} from '../src/issuer-settlement-custody.mjs';
import {createIssuerSettlementStore} from '../src/issuer-settlement-store.mjs';
import {witnessProblem,corroborate,usdc,BASE_PROVIDERS,BASE_USDC} from '../src/settlements.mjs';
const cfg={enabled:true,resourceAdmission:{status:'received'},network:'eip155:8453',asset:BASE_USDC,payTo:'0x'+'b'.repeat(40),operation:'issuer-revenue-comparison',method:'POST',route:'/v1/issuer-revenue-comparison',sku:'fixture-issuer-sku',gateway:'fixture-issuer-gateway',ledgerAccount:'Income:Sales:X402:IssuerResearch',amount:'50000'};
const at=Date.parse('2026-10-24T20:07:30.000Z'),payer='0x'+'a'.repeat(40);
const tx=n=>'0x'+n.toString(16).padStart(64,'0');
const logical=n=>'settlements/eip155:8453/'+tx(n)+'.json';
const rawKey=n=>'issuer-settlements/witness/'+tx(n),pendingKey=n=>'issuer-settlements/pending/'+tx(n),receiptKey=n=>'issuer-settlements/receipt/'+tx(n);
const witness=(n,over={})=>({network:cfg.network,asset:cfg.asset,payTo:cfg.payTo,operation:cfg.operation,method:cfg.method,route:cfg.route,sku:cfg.sku,gateway:cfg.gateway,ledgerAccount:cfg.ledgerAccount,amount:cfg.amount,payer,transaction:tx(n),recordedAt:'2026-10-24T20:00:00.000Z',...over});
function storage(){
 const values=new Map(),calls=[];let queue=Promise.resolve();
 const api={values,calls,failCommit:false,
 async get(k){calls.push(['get',k]);return structuredClone(values.get(k));},
 async put(k,v){calls.push(['put',k]);values.set(k,structuredClone(v));},
 async list({prefix='',startAfter,limit=4}={}){calls.push(['list',prefix,startAfter,limit]);return new Map([...values].filter(([k])=>k.startsWith(prefix)&&(!startAfter||k>startAfter)).sort(([a],[b])=>a.localeCompare(b)).slice(0,limit).map(([k,v])=>[k,structuredClone(v)]));},
 async transaction(work){const task=queue.then(async()=>{const next=new Map(structuredClone([...values]));const result=await work({get:async k=>structuredClone(next.get(k)),put:async(k,v)=>next.set(k,structuredClone(v)),delete:async k=>next.delete(k),list:async({prefix='',startAfter,limit=4}={})=>new Map([...next].filter(([k])=>k.startsWith(prefix)&&(!startAfter||k>startAfter)).sort(([a],[b])=>a.localeCompare(b)).slice(0,limit).map(([k,v])=>[k,structuredClone(v)]))});if(api.failCommit)throw new Error('SQLITE_FULL');values.clear();for(const[k,v]of next)values.set(k,v);return result;});queue=task.catch(()=>{});return task;}};return api;
}
const request=(n,{method='POST',text=JSON.stringify(witness(n)),key=logical(n),headers={'content-type':'application/json','if-none-match':'*'}}={})=>new Request('https://private.invalid/issuer-settlement-witness?'+new URLSearchParams({key}),{method,headers,body:method==='POST'?text:undefined});
const append=(s,n,over={})=>issuerSettlementResponse(request(n,over),s,cfg);
const receipt=(n,status='0x1')=>({status,transactionHash:tx(n),blockHash:'0x'+'d'.repeat(64),blockNumber:'0x10',logs:[{address:BASE_USDC,topics:['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef','0x'+'0'.repeat(24)+payer.slice(2),'0x'+'0'.repeat(24)+cfg.payTo.slice(2)],data:'0x'+(50000).toString(16).padStart(64,'0'),logIndex:'0x2'}]});
const adapters=fetch=>({witnessProblem,corroborate,usdc,BASE_PROVIDERS,fetch,now:()=>at,groupPayers:new Set()});
const rpcResult=fn=>async(url,init)=>{assert.ok(BASE_PROVIDERS.includes(url));assert.equal(init.redirect,'manual');const payload=JSON.parse(init.body);assert.equal(payload.method,'eth_getTransactionReceipt');return Response.json({result:fn(payload.params[0])});};
test('disabled financial custody grants no storage namespace work or RPC',async()=>{
 for(const c of[undefined,{...cfg,enabled:false},{...cfg,resourceAdmission:{status:'pending'}}]){
  const s=storage();assert.equal(issuerSettlementCustodyPlan(c),null);
  assert.equal((await issuerSettlementResponse(request(1),s,c)).status,404);
  assert.deepEqual(await receiveIssuerSettlements(s,c,{}),{status:'not-configured'});
  assert.equal(createIssuerSettlementStore(null,c),undefined);assert.deepEqual(s.calls,[]);
 }
});
test('invalid fixed commercial identity is refused before effects',()=>{
 for(const change of[{network:'other'},{asset:payer},{operation:'other'},{route:'/other'},{method:'GET'},{amount:'50001'},{sku:''},{payTo:'bad'}])assert.throws(()=>issuerSettlementCustodyPlan({...cfg,...change}),TypeError);
});
test('private route refuses methods and unconfigured arbitrary keys without storage',async()=>{
 const s=storage();
 assert.equal(await issuerSettlementResponse(new Request('https://private.invalid/clock'),s,cfg),null);
 assert.equal((await issuerSettlementResponse(new Request('https://private.invalid/issuer-settlement-witness',{method:'DELETE'}),s,cfg)).status,405);
 for(const key of['opentask/auth','issuer-evidence/cohort','settlements/eip155:1/'+tx(1)+'.json'])assert.equal((await issuerSettlementResponse(request(1,{method:'GET',key}),s,cfg)).status,404);
 assert.deepEqual(s.calls,[]);
});
test('first writer preserves exact original text and adds only bounded issuer custody rows',async()=>{
 const s=storage();s.values.set('opentask/auth',{private:'untouched'});const text=JSON.stringify(witness(1,{note:'é🙂'}),null,1);
 assert.equal((await append(s,1,{text})).status,201);assert.equal(s.values.get(rawKey(1)),text);assert.deepEqual(s.values.get(pendingKey(1)),{transaction:tx(1)});
 const response=await issuerSettlementResponse(request(1,{method:'GET'}),s,cfg);assert.equal(response.status,200);assert.equal(Number(response.headers.get('content-length')),Buffer.byteLength(text));assert.equal(await response.text(),text);
 assert.deepEqual(s.values.get('opentask/auth'),{private:'untouched'});
 assert.equal(s.values.get('issuer-settlements/capacity').recordCount,3);
});
test('duplicate and concurrent first writers cannot replace the original or duplicate pending',async()=>{
 const s=storage();const first=JSON.stringify(witness(1,{note:'first'}));assert.equal((await append(s,1,{text:first})).status,201);
 assert.equal((await append(s,1,{text:JSON.stringify(witness(1,{note:'later'}))})).status,412);assert.equal(s.values.get(rawKey(1)),first);
 const results=await Promise.all([append(s,2),append(s,2)]);assert.deepEqual(results.map(r=>r.status).sort(),[201,412]);assert.equal(s.values.get('issuer-settlements/capacity').recordCount,5);
});
test('failed atomic transaction and earlier platform full preserve all prior custody',async()=>{
 const s=storage();await append(s,1);const prior=structuredClone([...s.values]);s.failCommit=true;assert.equal((await append(s,2)).status,503);assert.deepEqual([...s.values],prior);
});
test('new testimony must match the exact price recipient and original offer identity',async()=>{
 for(const change of[{amount:'50001'},{payTo:payer},{asset:payer},{sku:'wrong'},{operation:'other'},{transaction:tx(2)},{payer:'bad'}]){const s=storage();assert.notEqual((await append(s,1,{text:JSON.stringify(witness(1,change))})).status,201);assert.equal(s.values.size,0);}
});
test('actual raw byte overflow and malformed representation cannot create custody',async()=>{
 for(const text of['{','[]','null',JSON.stringify(witness(1,{note:'x'.repeat(32768)}))]){const s=storage();assert.notEqual((await append(s,1,{text})).status,201);assert.equal(s.values.size,0);}
});
test('metadata binds immutable commercial configuration and drift holds accepted pending',async()=>{
 const s=storage();await append(s,1);const prior=structuredClone([...s.values]),changed={...cfg,sku:'new-sku'};let calls=0;
 assert.deepEqual(await receiveIssuerSettlements(s,changed,adapters(()=>{calls++;assert.fail();})),{status:'held',reason:'configuration-identity-changed'});
 assert.equal((await issuerSettlementResponse(request(2,{text:JSON.stringify(witness(2,{sku:'new-sku'}))}),s,changed)).status,503);
 assert.equal(calls,0);assert.deepEqual([...s.values],prior);
});
test('corrupt metadata and opaque cursor never authorize acquisition or counter reset',async()=>{
 for(const mutate of[m=>({...m,recordCount:-1}),m=>({...m,cursor:'opentask/auth'}),()=>null,m=>({...m,chargedBytes:'4096'})]){
  const s=storage();await append(s,1);s.values.set('issuer-settlements/capacity',mutate(s.values.get('issuer-settlements/capacity')));const prior=structuredClone([...s.values]);let fetched=0;
  try{await receiveIssuerSettlements(s,cfg,adapters(()=>{fetched++;assert.fail();}));}catch{}
  assert.equal(fetched,0);assert.deepEqual([...s.values],prior);assert.notEqual((await append(s,2)).status,201);
 }
});
test('quota refusal never evicts original testimony',async()=>{
 for(const field of['recordCount','chargedBytes']){const s=storage();await append(s,1);const m=s.values.get('issuer-settlements/capacity');m[field]=field==='recordCount'?50000:268435456;const prior=structuredClone([...s.values]);assert.equal((await append(s,2)).status,503);assert.deepEqual([...s.values],prior);}
});
test('original corroboration produces one immutable USDC cash receipt without outside revenue',async()=>{
 const s=storage();await append(s,1);const result=await receiveIssuerSettlements(s,cfg,adapters(rpcResult(hash=>receipt(Number(BigInt(hash))))));
 const got=s.values.get(receiptKey(1));assert.equal(result.corroborated,1);assert.equal(got.sourceId,'evm:eip155:8453:'+BASE_USDC+':'+cfg.payTo+':'+tx(1)+':2');
 assert.equal(got.currency,'USDC');assert.equal(got.usdValuation,null);assert.equal(got.payerClass,'unclassified');assert.equal(got.usd,.05);assert.equal(got.classificationBasis,'absence from Group register does not establish outside ownership');
 assert.ok(s.values.has(rawKey(1)));assert.equal(s.values.has(pendingKey(1)),false);
 const before=structuredClone([...s.values]);await receiveIssuerSettlements(s,cfg,adapters(()=>assert.fail('terminal witness must not be fetched again')));assert.deepEqual([...s.values],before);
});
test('four witnesses exhaust at most sixteen provider requests in the original order',async()=>{
 const s=storage();for(let n=1;n<=4;n++)await append(s,n);const seen=new Map();let calls=0;
 const fetch=rpcResult(hash=>{calls++;const n=(seen.get(hash)||0)+1;seen.set(hash,n);return n<=2?null:receipt(Number(BigInt(hash)));});
 const result=await receiveIssuerSettlements(s,cfg,adapters(fetch));assert.equal(result.considered,4);assert.equal(result.providerRequests,16);assert.equal(calls,16);assert.equal(result.corroborated,4);
});
test('retrying provider observations stay pending and round robin cannot starve later witnesses',async()=>{
 const s=storage();for(let n=1;n<=6;n++)await append(s,n);const visited=[];
 const missing=async(url,init)=>{visited.push(JSON.parse(init.body).params[0]);return Response.json({result:null});};
 await receiveIssuerSettlements(s,cfg,adapters(missing));assert.equal(new Set(visited).size,4);assert.equal(visited.length,16);visited.length=0;
 await receiveIssuerSettlements(s,cfg,adapters(missing));assert.ok(visited.includes(tx(5))&&visited.includes(tx(6)));assert.equal(new Set(visited).size,4);
 assert.ok([...Array(6)].every((_,i)=>s.values.has(pendingKey(i+1))));
});
test('permanent failed transaction is terminal without inventing cash or deleting raw',async()=>{
 const s=storage();await append(s,1);await receiveIssuerSettlements(s,cfg,adapters(rpcResult(hash=>receipt(Number(BigInt(hash)),'0x0'))));
 const got=s.values.get(receiptKey(1));assert.equal(got.status,'refused');assert.equal(got.reason,'failed-transaction');assert.equal(Object.hasOwn(got,'sourceId'),false);assert.equal(s.values.has(pendingKey(1)),false);assert.ok(s.values.has(rawKey(1)));
});
test('provider disagreement remains retryable testimony and does not become payment',async()=>{
 const s=storage();await append(s,1);let n=0;const fetch=rpcResult(hash=>({...receipt(Number(BigInt(hash))),blockHash:'0x'+(++n%2?'c':'d').repeat(64)}));
 await receiveIssuerSettlements(s,cfg,adapters(fetch));assert.ok(s.values.has(pendingKey(1)));assert.equal(s.values.has(receiptKey(1)),false);
});
test('missing metadata over existing owned rows cannot reset capacity',async()=>{
 const s=storage();s.values.set(rawKey(1),JSON.stringify(witness(1)));const prior=structuredClone([...s.values]);assert.equal((await append(s,2)).status,503);assert.deepEqual([...s.values],prior);
});
test('client exposes only original conditional journal shape and fixed singleton transport',async()=>{
 const s=storage(),calls=[];const namespace={idFromName(name){calls.push(['id',name]);assert.equal(name,'earning-loops');return name;},get(id){calls.push(['stub',id]);return{fetch:async request=>{assert.equal(request.redirect,'manual');return issuerSettlementResponse(request,s,cfg);}};}};
 const store=createIssuerSettlementStore(namespace,cfg);await assert.rejects(store.get('opentask/auth'),TypeError);assert.deepEqual(calls,[]);
 const options={onlyIf:{etagDoesNotMatch:'*'},httpMetadata:{contentType:'application/json'}};
 assert.equal(await store.get(logical(1)),null);assert.ok(await store.put(logical(1),JSON.stringify(witness(1)),options));
 assert.deepEqual(await(await store.get(logical(1))).json(),witness(1));assert.equal(await store.put(logical(1),JSON.stringify(witness(1)),options),null);
 await assert.rejects(store.put(logical(2),JSON.stringify(witness(2)),{}),TypeError);
});
test('client never follows private transport redirects or discloses source errors',async()=>{
 for(const status of[301,302,307,308,500]){let calls=0;const namespace={idFromName:()=>1,get:()=>({fetch:async request=>{calls++;assert.equal(request.redirect,'manual');return new Response('private-secret',{status,headers:{location:'https://untrusted.invalid/refresh'}});}})};
  await assert.rejects(createIssuerSettlementStore(namespace,cfg).get(logical(1)),e=>!e.message.includes('private-secret'));assert.equal(calls,1);
 }
});


test('RPC redirects and oversized representations cannot become cash or discard pending originals',async()=>{
 for(const kind of ['redirect','oversize']){
  const s=storage();await append(s,1);const original=s.values.get(rawKey(1));let calls=0;
  const fetch=async(url,init)=>{calls++;assert.equal(init.redirect,'manual');return kind==='redirect'?new Response('private-provider-body',{status:302,headers:{location:'https://untrusted.invalid/receipt'}}):new Response('x'.repeat(262145),{status:200});};
  const result=await receiveIssuerSettlements(s,cfg,adapters(fetch));assert.equal(calls,4);assert.equal(result.retryPending,1);assert.ok(s.values.has(pendingKey(1)));assert.equal(s.values.get(rawKey(1)),original);assert.equal(s.values.has(receiptKey(1)),false);
 }
});
