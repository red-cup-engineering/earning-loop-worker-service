/* issuer-private-settlement-custody; specification ni:///sha-256;NfoPd76YNGyNO9CtP5HGaF5Ue3QZSYhQQKKFdR6LtFE.
 * Source: earning-loop-worker-service/specifications/issuer-private-settlement-custody.work-order.md, lines 1–42, sha256:87851b65650e3326e34ce6fd7acb5ea27055f4467d282f0e03dbf913e5ae90d8.
 * Receiving obligations remain external: pure-receiving qualifies only admission and plan metadata; io-receiving requires independent native I/O, SQLite workerd, composed-pulse, original-owner integration, resource and customer/payment receiving before promotion.
 * Authority/applicability: EVM receipt custody, Original earning-loop settlement receiver, ../src/settlements.mjs (payment-evidence); IETF RFC9110, https://www.rfc-editor.org/rfc/rfc9110 (representation); 561 Group root received direction 2026-10-24, ./issuer-private-settlement-custody.work-order.md (operation); Cloudflare SQLite limits received 2026-10-24, https://developers.cloudflare.com/durable-objects/platform/limits/ (platform).
 * Red Cup Engineering: native deriveJsnodeModules, fabricate-jsnode-closure.mjs (source-free); approved private custody direction (physical); original journal identity, market.561.group/src/edge-settlement.mjs (witness-admission); private binding consumer (server); unchanged native edge journal provider (client); original corroboration kernel, ../src/settlements.mjs (receiver); original received event identity, ../src/settlements.mjs (cash-record); approved existing EarningClock wiring (composition); inspected original settlements.mjs interface 2026-10-24 (original-adapter-contracts). All apply as scoped by the supplied work order.
 * Trace: admission -> pure-receiving; plans/no-expansion -> io-receiving, under cash-record/client/composition/operation/payment-evidence/physical/platform/receiver/representation/server/source-free/witness-admission. pulse-budget -> composition/operation/platform -> io-receiving.
 * Caller obligations: original earning-loops enqueue exclusively owns mutations and receiving; private handler precedes catchall and is never publicly forwarded. Receive only after bounded commercial/research work on the existing between-maintenance 7.5-minute pulse, never maintenance/public refresh. Preserve original cache/OpenTask/R2/alarms; no new schedule, namespace, credentials, payment execution, deployment, aggregate or raw deletion. APP owner scopes its separate provider to the original issuer declaration and prunes the namespace before compute.
 * Limits are ceilings, not reserved capacity, actual Free quota, execution authority, demand or income forecasts. 50 requests is the root business allocation (worker-subrequest-ceiling), not vendor quota evidence. 16 issuer RPC plus bounded 12 commercial and actual clock calls require independent whole-pulse receiving. USDC observation is separate from USD valuation, outside ownership, delivery and buyer acceptance; no USD200/day claim.
 */
const E = new TextEncoder();
const ASSET = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const TX = /^0x[0-9a-f]{64}$/;
const PREFIX = 'issuer-settlements/';
const META = PREFIX + 'capacity';
const RAW = PREFIX + 'witness/';
const PENDING = PREFIX + 'pending/';
const RECEIPT = PREFIX + 'receipt/';
const PATH = '/issuer-settlement-witness';
const FIELDS = ['network','asset','payTo','operation','method','route','amount','sku','gateway','ledgerAccount'];
const PROVIDERS = ['https://base-rpc.publicnode.com','https://base.drpc.org','https://base-mainnet.public.blastapi.io','https://mainnet.base.org'];
const bytes = s => E.encode(s).byteLength;
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const fail = () => { throw new Error('issuer-settlement-unavailable'); };
const exactKeys = (v, keys) => object(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v,k));
const charge = (k,v) => bytes(k) + bytes(JSON.stringify(v));
const identity = p => Object.fromEntries(FIELDS.map(k => [k,p[k]]));
const same = (a,b) => exactKeys(a,FIELDS) && FIELDS.every(k => a[k] === b[k]);
const pendingKey = k => typeof k === 'string' && k.startsWith(PENDING) && TX.test(k.slice(PENDING.length));

/** Admit trusted source configuration and return immutable receiving-ceiling metadata only.
 * @param {*} configuration Original Public declaration plus received merchant/Group projection.
 * @returns {object|null} Fixed normalized custody plan, or null before admission.
 */
export function issuerSettlementCustodyPlan(configuration) {
 const c = configuration;
 if (!c || c.enabled !== true || c.resourceAdmission?.status !== 'received') return null;
 const text = k => typeof c[k] === 'string' && c[k].length > 0 && bytes(c[k]) <= 512 && !/[\r\n]/.test(c[k]);
 if (c.network !== 'eip155:8453' || typeof c.asset !== 'string' || c.asset.toLowerCase() !== ASSET || typeof c.payTo !== 'string' || !ADDRESS.test(c.payTo) || c.operation !== 'issuer-revenue-comparison' || c.method !== 'POST' || c.route !== '/v1/issuer-revenue-comparison' || c.amount !== '50000' || !['sku','gateway','ledgerAccount'].every(text)) throw new TypeError('Invalid issuer settlement configuration');
 return Object.freeze({prefix:PREFIX,metadataKey:META,witnessPrefix:RAW,pendingPrefix:PENDING,receiptPrefix:RECEIPT,objectName:'earning-loops',path:PATH,maximumRecords:50000,maximumCustodyBytes:268435456,maximumRawWitnessBytes:32768,maximumTransactionBytes:1900000,maximumWitnessesPerPulse:4,maximumProviderAttemptsPerWitness:4,maximumRpcBytes:262144,network:c.network,asset:c.asset.toLowerCase(),payTo:c.payTo.toLowerCase(),operation:c.operation,method:c.method,route:c.route,sku:c.sku,gateway:c.gateway,ledgerAccount:c.ledgerAccount,amount:c.amount,maximumWorkerCallsPerPulse:50});
}
function logical(tx) { return 'settlements/eip155:8453/' + tx + '.json'; }
function parseKey(key) {
 const m = typeof key === 'string' && /^settlements\/eip155:8453\/(0x[0-9a-f]{64})\.json$/.exec(key);
 return m ? m[1] : null;
}
function witness(text,tx,p) {
 if (typeof text !== 'string' || bytes(text) > 32768) fail();
 const w = JSON.parse(text);
 if (!object(w) || w.transaction !== tx || w.network !== p.network || typeof w.payer !== 'string' || !ADDRESS.test(w.payer)) fail();
 for (const k of FIELDS) {
  if (k === 'asset' || k === 'payTo') { if (typeof w[k] !== 'string' || w[k].toLowerCase() !== p[k]) fail(); }
  else if (w[k] !== p[k]) fail();
 }
 return w;
}
function validateMeta(m) {
 if (!exactKeys(m,['version','identity','recordCount','chargedBytes','cursor']) || m.version !== 1 || !exactKeys(m.identity,FIELDS) || !Number.isSafeInteger(m.recordCount) || m.recordCount < 1 || m.recordCount > 50000 || !Number.isSafeInteger(m.chargedBytes) || m.chargedBytes < 4096 || m.chargedBytes > 268435456 || (m.cursor !== null && !pendingKey(m.cursor)) || charge(META,m) > 4096) fail();
 const ip = issuerSettlementCustodyPlan({...m.identity,enabled:true,resourceAdmission:{status:'received'}});
 if (!same(m.identity,identity(ip))) fail();
 if (m.recordCount === 1 && m.chargedBytes !== 4096) fail();
 return m;
}
async function metadata(s,p) {
 const m = await s.get(META);
 if (m !== undefined) return validateMeta(m);
 const rows = await s.list({prefix:PREFIX,limit:1});
 if (!(rows instanceof Map) || rows.size) fail();
 return {version:1,identity:identity(p),recordCount:1,chargedBytes:4096,cursor:null};
}
function pending(v,tx) { if (!exactKeys(v,['transaction']) || v.transaction !== tx) fail(); }
function boundedRecord(v) {
 if (!object(v)) fail();
 const text = JSON.stringify(v);
 if (typeof text !== 'string' || bytes(text) > 65536) fail();
 const parsed = JSON.parse(text);
 if (JSON.stringify(parsed) !== text) fail();
 return text;
}
function capacity(m) { validateMeta(m); return m; }
function mutations(entries,deletions=[]) {
 const n = entries.reduce((n,[k,v]) => n + charge(k,v),0) + deletions.reduce((n,k) => n + bytes(k),0);
 if (n > 1900000 || entries.some(([k,v]) => charge(k,v) > 1900000)) fail();
}
function response(status,text='') {
 return new Response(text,{status,headers:{'Content-Type':'application/json','Content-Length':String(bytes(text)),'Cache-Control':'no-store'}});
}
async function readText(body,limit) {
 if (!body) return '';
 const reader = body.getReader();
 const decoder = new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});
 let n=0, result='';
 try {
  for (;;) { const {done,value}=await reader.read(); if(done) break; n+=value.byteLength; if(n>limit) fail(); result+=decoder.decode(value,{stream:true}); }
  return result+decoder.decode();
 } catch(e) { try { await reader.cancel(); } catch {} throw e; }
 finally { reader.releaseLock(); }
}

/** Serve the private immutable first-writer witness route through the original serialized owner.
 * @param {Request} request Private binding request.
 * @param {object} storage Existing EarningClock transactional SQLite storage.
 * @param {*} configuration Trusted issuer configuration.
 * @returns {Promise<Response|null>} Explicit private response, or null for another pathname.
 */
export async function issuerSettlementResponse(request,storage,configuration) {
 const url = new URL(request.url);
 if (url.pathname !== PATH) return null;
 const p = issuerSettlementCustodyPlan(configuration);
 if (!p) return response(404);
 if (request.method !== 'GET' && request.method !== 'POST') return new Response('',{status:405,headers:{Allow:'GET, POST','Content-Type':'application/json','Content-Length':'0','Cache-Control':'no-store'}});
 const entries = [...url.searchParams];
 const tx = entries.length === 1 && entries[0][0] === 'key' ? parseKey(entries[0][1]) : null;
 if (!tx) return response(404);
 if (request.method === 'GET') {
  try { const raw=await storage.get(RAW+tx); if(raw===undefined) return response(404); witness(raw,tx,p); return response(200,raw); } catch { return response(503); }
 }
 if (request.headers.get('If-None-Match') !== '*') return response(428);
 if (!/^application\/json(?:\s*;.*)?$/i.test(request.headers.get('Content-Type') || '')) return response(415);
 let raw;
 try { raw=await readText(request.body,32768); witness(raw,tx,p); } catch { return response(400); }
 try {
  const status=await storage.transaction(async s => {
   const m=await metadata(s,p);
   if (!same(m.identity,identity(p))) return 503;
   const old=await s.get(RAW+tx);
   if(old!==undefined) { witness(old,tx,p); return 412; }
   if(await s.get(PENDING+tx)!==undefined || await s.get(RECEIPT+tx)!==undefined) fail();
   const pv={transaction:tx};
   const next=capacity({...m,recordCount:m.recordCount+2,chargedBytes:m.chargedBytes+charge(RAW+tx,raw)+charge(PENDING+tx,pv)});
   const writes=[[RAW+tx,raw],[PENDING+tx,pv],[META,next]];
   mutations(writes);
   for(const [k,v] of writes) await s.put(k,v);
   return 201;
  });
  return response(status);
 } catch { return response(503); }
}
function adaptersFor(a) {
 if (!object(a) || !['witnessProblem','corroborate','usdc'].every(k=>typeof a[k]==='function') || !Array.isArray(a.BASE_PROVIDERS) || a.BASE_PROVIDERS.length!==4 || !PROVIDERS.every((v,i)=>a.BASE_PROVIDERS[i]===v) || !(a.groupPayers instanceof Set)) throw new TypeError('Invalid issuer settlement adapters');
 for(const payer of a.groupPayers) if(typeof payer!=='string' || !/^0x[0-9a-f]{40}$/.test(payer)) throw new TypeError('Invalid issuer settlement adapters');
 const fetch=a.fetch===undefined?globalThis.fetch:a.fetch;
 const now=a.now===undefined?Date.now:a.now;
 if(typeof fetch!=='function' || typeof now!=='function') throw new TypeError('Invalid issuer settlement adapters');
 return {...a,fetch,now};
}
function instant(a) { const n=a.now(); if(typeof n!=='number' || !Number.isFinite(n)) fail(); return new Date(n).toISOString(); }
async function rpc(a,url,tx) {
 const controller=new AbortController();
 let timer, res;
 const timeout=new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new Error('timeout'));},10000);});
 const task=(async()=>{
  try {
   res=await a.fetch(url,{method:'POST',redirect:'manual',signal:controller.signal,headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_getTransactionReceipt',params:[tx]})});
   if(res.status!==200) { try {await res.body?.cancel();} catch {} return null; }
   const parsed=JSON.parse(await readText(res.body,262144));
   return object(parsed) && !parsed.error && object(parsed.result) ? parsed.result : null;
  } catch { return null; }
 })();
 try {return await Promise.race([task,timeout]);} catch { controller.abort(); try {const cancellation=res?.body?.cancel(); cancellation?.catch(()=>{});} catch {} return null;} finally {clearTimeout(timer);}
}
function cash(w,tx,checked,a,at) {
 const group=a.groupPayers.has(w.payer.toLowerCase());
 const result={evidenceVersion:2,sourceId:`evm:eip155:8453:${ASSET}:${w.payTo.toLowerCase()}:${tx}:${BigInt(checked.transfer.logIndex).toString()}`,witnessKey:logical(tx),transactionHash:w.transaction,payer:w.payer,receiver:w.payTo,amount:w.amount,currency:'USDC',usdValuation:null,usd:a.usdc(w.amount),payerClass:group?'group':'unclassified',classificationBasis:group?'current Group payer register':'absence from Group register does not establish outside ownership',blockNumber:Number(BigInt(checked.receipt.blockNumber)),corroboratedAt:at};
 for(const k of ['paymentObservation','deliveryObservation','responsePreparation','witnessId','route','method','gateway','sku','ledgerAccount','recordedAt']) result[k]=w[k]??null;
 if(typeof result.usd!=='number' || !Number.isFinite(result.usd) || !Number.isSafeInteger(result.blockNumber) || result.blockNumber<0) fail();
 boundedRecord(result);
 return result;
}
async function advance(storage,p,key) {
 await storage.transaction(async s=>{
  const m=await metadata(s,p); if(!same(m.identity,identity(p))) fail();
  const next=capacity({...m,cursor:key}); mutations([[META,next]]); await s.put(META,next);
 });
}
async function terminal(storage,p,key,raw,record) {
 boundedRecord(record);
 return storage.transaction(async s=>{
  const m=await metadata(s,p); if(!same(m.identity,identity(p))) fail();
  const tx=key.slice(PENDING.length), pv=await s.get(key); pending(pv,tx);
  if(await s.get(RAW+tx)!==raw || await s.get(RECEIPT+tx)!==undefined) fail();
  const next=capacity({...m,chargedBytes:m.chargedBytes-charge(key,pv)+charge(RECEIPT+tx,record),cursor:key});
  const writes=[[RECEIPT+tx,record],[META,next]]; mutations(writes,[key]);
  for(const [k,v] of writes) await s.put(k,v);
  if(!await s.delete(key)) fail();
  return true;
 });
}

/** Receive at most four distinct pending originals using the injected original settlement kernel.
 * @param {object} storage Existing EarningClock SQLite storage under its original enqueue.
 * @param {*} configuration Trusted immutable issuer identity and resource admission.
 * @param {object} adapters Original witnessProblem/corroborate/usdc, BASE_PROVIDERS, groupPayers and optional fetch/now.
 * @returns {Promise<object>} Not-configured, configuration hold, or committed per-pulse observation counters; corrupt/source/clock failures reject without inventing receiving.
 */
export async function receiveIssuerSettlements(storage,configuration,adapters) {
 const p=issuerSettlementCustodyPlan(configuration);
 if(!p) return {status:'not-configured'};
 const a=adaptersFor(adapters);
 instant(a);
 const m=await metadata(storage,p);
 if(!same(m.identity,identity(p))) return {status:'held',reason:'configuration-identity-changed'};
 const selected=new Map();
 const page=async options=>{
  const rows=await storage.list(options);
  if(!(rows instanceof Map) || rows.size>4) fail();
  for(const [k,v] of rows) {
   if(!pendingKey(k)) fail();
   if(options.startAfter!==undefined && k<=options.startAfter) fail();
   pending(v,k.slice(PENDING.length));
   if(selected.size<4 && !selected.has(k)) selected.set(k,v);
  }
 };
 await page({prefix:PENDING,limit:4,...(m.cursor===null?{}:{startAfter:m.cursor})});
 if(m.cursor!==null && selected.size<4) await page({prefix:PENDING,limit:4});
 const result={status:'observed',considered:0,providerRequests:0,corroborated:0,refused:0,retryPending:0};
 for(const [key] of selected) {
  const tx=key.slice(PENDING.length);
  const raw=await storage.get(RAW+tx);
  const w=witness(raw,tx,p);
  if(await storage.get(RECEIPT+tx)!==undefined) fail();
  result.considered++;
  let checked;
  const problem=a.witnessProblem(w);
  if(problem!==null) { if(typeof problem!=='string' || !problem) fail(); checked={ok:false,reason:problem}; }
  else {
   const receipts=[];
   for(const provider of a.BASE_PROVIDERS) {
    instant(a);
    result.providerRequests++;
    const receipt=await rpc(a,provider,w.transaction);
    if(receipt!==null) receipts.push(receipt);
    if(receipts.length===2) break;
   }
   checked=a.corroborate(w,receipts);
  }
  if(!object(checked) || (checked.ok!==true && checked.ok!==false)) fail();
  const at=instant(a);
  if(checked.ok===false && checked.retry===true) {
   result.retryPending++; await advance(storage,p,key); continue;
  }
  let record;
  if(checked.ok===true) record=cash(w,tx,checked,a,at);
  else {
   if(typeof checked.reason!=='string' || !checked.reason) fail();
   record={status:'refused',transaction:tx,witnessKey:logical(tx),reason:checked.reason,at};
  }
  try {
   await terminal(storage,p,key,raw,record);
   if(checked.ok) result.corroborated++; else result.refused++;
  } catch {
   result.retryPending++;
   await advance(storage,p,key);
  }
 }
 return result;
}
