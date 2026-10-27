/**
 * Self-hosted external agent-service directory acquisition for the ORIGINAL
 * earning loop. Coesite controls buyer-task inputs; 402 Index is a public,
 * free and source-identified outside directory. Opportunity Engineering owns
 * interpretation/market strategy; this adapter only observes bounded facts.
 * No crawler, registration, payment, wallet, price change or customer claim.
 */
export const AGENT_MARKET_INDEX = "https://402index.io/api/v1/services";
const MAX_BYTES = 192_000;
const HTTP = /^https:\/\//u;
const trimmed = (value, max) => typeof value === "string" ? value.replace(/[\u0000-\u001f\u007f]/gu," ").trim().slice(0,max) : "";
const price = value => {
  if ((typeof value !== "string" && typeof value !== "number") ||
      (typeof value === "number" && !Number.isFinite(value))) return null;
  const text = String(value);
  return /^(?:0|[1-9]\d{0,9})(?:\.\d{1,8})?$/u.test(text) ? text : null;
};
const endpoint = value => {
  if (typeof value !== "string" || value.length > 2048 || !HTTP.test(value)) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password ||
        url.hash || !url.hostname.includes(".") ||
        url.hostname.endsWith(".local") || /^\d+\.\d+\.\d+\.\d+$/u.test(url.hostname))
      return null;
    return url;
  } catch { return null; }
};
const configOf = ({ queries, ownHost, limit } = {}) => {
  if (!Array.isArray(queries) || queries.length < 1 || queries.length > 6 ||
      queries.some(q => typeof q !== "string" || q.length < 5 || q.length > 160 || q.trim() !== q) ||
      new Set(queries).size !== queries.length ||
      typeof ownHost !== "string" || !/^[a-z0-9.-]{4,253}$/u.test(ownHost) ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 30)
    throw new TypeError("bounded original agent-market buyer jobs and seller hostname required");
  return { queries, ownHost, limit };
};
async function readJson(response) {
  if (!response?.ok) throw new Error("external directory unavailable or rate limited");
  const stated = Number(response.headers?.get?.("content-length"));
  if (Number.isFinite(stated) && stated > MAX_BYTES) throw new RangeError("oversized external directory page");
  const stream = response.body;
  if (stream && typeof stream.getReader === "function") {
    const reader = stream.getReader();
    let total = 0;
    const chunks = [];
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!(value instanceof Uint8Array)) throw new TypeError("unexpected directory response chunk");
        total += value.length;
        if (total > MAX_BYTES) throw new RangeError("oversized external directory page");
        chunks.push(value);
      }
    } catch (error) { await reader.cancel().catch(() => {}); throw error; }
    const all = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { all.set(chunk,offset); offset += chunk.length; }
    return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(all));
  }
  const text = await response.text();
  if (new TextEncoder().encode(text).length > MAX_BYTES) throw new RangeError("oversized external directory page");
  return JSON.parse(text);
}
function observation(row, query, rank, observedAt, sourceUrl, ownHost) {
  if (!row || typeof row !== "object" || Array.isArray(row) ||
      String(row.protocol ?? "").toLowerCase() !== "x402") return null;
  const url = endpoint(row.url);
  if (!url || !trimmed(row.name,256)) return null;
  const sellerHost = url.hostname.toLowerCase();
  return Object.freeze({
    directoryId: ["string","number"].includes(typeof row.id) ? String(row.id).slice(0,100) : null,
    sourceUrl, observedAt, buyerJob:query, position:rank,
    name:trimmed(row.name,256), description:trimmed(row.description,600),
    endpoint:url.href, sellerHost, ownSeller:sellerHost===ownHost,
    method:trimmed(row.http_method,12) || null,
    category:trimmed(row.category,80) || null,
    advertisedUsdPerCall:price(row.price_usd),
    paymentAsset:trimmed(row.payment_asset,40) || null,
    paymentNetwork:trimmed(row.payment_network,60) || null,
    reportedHealth:trimmed(row.health_status,40) || "unknown",
    reportedDomainVerified:row.domain_verified===1 || row.domain_verified===true,
    reportedPaymentValid:row.x402_payment_valid===1 || row.x402_payment_valid===true ?
      true : row.x402_payment_valid===0 || row.x402_payment_valid===false ? false : null,
    independentlyPaidBuyerObserved:false,
    liveSellerChallengeObserved:false,
    usefulCustomerDeliveryObserved:false,
    listingOnly:true
  });
}
/**
 * Source-qualified acquisition of 1-6 real buyer-task searches: one page per
 * job, no directory mutation, no paid requests, no external offer probing.
 * Errors preserve coverage as unknown and do not invent an absent market.
 */
export async function observeAgentMarketIndex({
  queries, ownHost = "market.561.group", limit = 12,
  observedAt, fetchImpl = fetch, timeoutMs = 8000
} = {}) {
  const cfg = configOf({ queries, ownHost, limit });
  if (typeof observedAt !== "string" || !Number.isFinite(Date.parse(observedAt)) ||
      typeof fetchImpl !== "function" || !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 1000 || timeoutMs > 15000)
    throw new TypeError("dated bounded directory acquisition required");
  const readings = [], entries = [];
  for (const query of cfg.queries) {
    const url = new URL(AGENT_MARKET_INDEX);
    url.searchParams.set("protocol","x402");
    url.searchParams.set("q",query);
    url.searchParams.set("limit",String(cfg.limit));
    url.searchParams.set("offset","0");
    try {
      const response = await fetchImpl(url.href, {
        method:"GET",headers:{accept:"application/json"},
        signal:AbortSignal.timeout(timeoutMs)
      });
      const body = await readJson(response);
      if (!body || !Array.isArray(body.services) || body.services.length > cfg.limit)
        throw new TypeError("external directory page has no bounded service list");
      const rows = body.services.map((row,i)=>observation(row,query,i+1,observedAt,url.href,cfg.ownHost)).filter(Boolean);
      entries.push(...rows);
      readings.push(Object.freeze({
        buyerJob:query, sourceUrl:url.href, state:"observed-first-page",
        returned:body.services.length, admitted:rows.length,
        ownSellerRanks:rows.filter(r=>r.ownSeller).map(r=>r.position),
        searchDegraded:trimmed(response.headers?.get?.("X-402index-Search-Degraded"),100)||null,
        anotherPageKnown:typeof body.total==="number" ? body.total > cfg.limit : null
      }));
    } catch (error) {
      readings.push(Object.freeze({
        buyerJob:query, sourceUrl:url.href, state:"unavailable",
        returned:null, admitted:null, ownSellerRanks:null,
        error:trimmed(error?.message ?? String(error),180)||"directory-read-failed",
        searchDegraded:null, anotherPageKnown:null
      }));
    }
  }
  return Object.freeze({
    kind:"561-group.agent-market-index-observation.v1",
    observedAt, directory:AGENT_MARKET_INDEX,
    market:"x402", ownHost:cfg.ownHost,
    searchReadings:Object.freeze(readings),
    listings:Object.freeze(entries),
    completeMarketCoverage:false,
    buyerConversionObserved:false,
    realMoneyOrAcceptedWorkObserved:false,
    authorizedActions:[],
    independentlyReceived:false
  });
}
