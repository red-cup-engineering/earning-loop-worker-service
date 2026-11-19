// ../../apps/market.561.group/src/issuer-settlement-store.mjs
var ASSET = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
var ADDRESS = /^0x[0-9a-fA-F]{40}$/;
var KEY = /^settlements\/eip155:8453\/(0x[0-9a-f]{64})\.json$/;
var encoder = new TextEncoder();
var unavailable = () => new Error("issuer-settlement-unavailable");
var isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
var byteLength = (value) => encoder.encode(value).byteLength;
function issuerSettlementStorePlan(configuration2) {
  if (!configuration2 || configuration2.enabled !== true || configuration2.resourceAdmission?.status !== "received") return null;
  const c = configuration2;
  const shortText = (value) => typeof value === "string" && value.length > 0 && !/[\r\n]/.test(value) && byteLength(value) <= 512;
  if (c.network !== "eip155:8453" || typeof c.asset !== "string" || c.asset.toLowerCase() !== ASSET || typeof c.payTo !== "string" || !ADDRESS.test(c.payTo) || c.operation !== "issuer-revenue-comparison" || c.method !== "POST" || c.route !== "/v1/issuer-revenue-comparison" || c.amount !== "50000" || !shortText(c.sku) || !shortText(c.gateway) || !shortText(c.ledgerAccount)) {
    throw new TypeError("Invalid issuer settlement configuration");
  }
  return Object.freeze({
    prefix: "issuer-settlements/",
    metadataKey: "issuer-settlements/capacity",
    witnessPrefix: "issuer-settlements/witness/",
    pendingPrefix: "issuer-settlements/pending/",
    receiptPrefix: "issuer-settlements/receipt/",
    objectName: "earning-loops",
    path: "/issuer-settlement-witness",
    maximumRecords: 5e4,
    maximumCustodyBytes: 268435456,
    maximumRawWitnessBytes: 32768,
    maximumTransactionBytes: 19e5,
    maximumWitnessesPerPulse: 4,
    maximumProviderAttemptsPerWitness: 4,
    maximumRpcBytes: 262144,
    network: c.network,
    asset: c.asset.toLowerCase(),
    payTo: c.payTo.toLowerCase(),
    operation: c.operation,
    method: c.method,
    route: c.route,
    sku: c.sku,
    gateway: c.gateway,
    ledgerAccount: c.ledgerAccount,
    amount: c.amount,
    maximumWorkerCallsPerPulse: 50
  });
}
function transactionFor(key) {
  if (typeof key !== "string") throw unavailable();
  const match = KEY.exec(key);
  if (!match) throw unavailable();
  return match[1];
}
function witnessFrom(text, transaction, plan) {
  if (typeof text !== "string" || byteLength(text) > plan.maximumRawWitnessBytes) throw unavailable();
  const witness = JSON.parse(text);
  if (!isObject(witness) || witness.network !== plan.network || witness.transaction !== transaction || typeof witness.payer !== "string" || !ADDRESS.test(witness.payer) || typeof witness.payTo !== "string" || witness.payTo.toLowerCase() !== plan.payTo || typeof witness.asset !== "string" || witness.asset.toLowerCase() !== plan.asset) throw unavailable();
  for (const field of ["operation", "method", "route", "sku", "gateway", "ledgerAccount", "amount"]) {
    if (witness[field] !== plan[field]) throw unavailable();
  }
  return witness;
}
function exactKeys(value, keys) {
  if (!isObject(value)) return false;
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
function validOptions(options2) {
  return exactKeys(options2, ["onlyIf", "httpMetadata"]) && exactKeys(options2.onlyIf, ["etagDoesNotMatch"]) && options2.onlyIf.etagDoesNotMatch === "*" && exactKeys(options2.httpMetadata, ["contentType"]) && options2.httpMetadata.contentType === "application/json";
}
async function cancelBody(response) {
  if (response?.body) await response.body.cancel();
}
async function readWitness(response, transaction, plan) {
  let reader;
  let finished = false;
  try {
    const lengthText = response.headers.get("Content-Length");
    if (typeof lengthText !== "string" || !/^(0|[1-9][0-9]*)$/.test(lengthText)) throw unavailable();
    const expected = Number(lengthText);
    if (!Number.isSafeInteger(expected) || expected > plan.maximumRawWitnessBytes) throw unavailable();
    const media = response.headers.get("Content-Type");
    if (typeof media !== "string" || media.split(";", 1)[0].trim().toLowerCase() !== "application/json") throw unavailable();
    if (!response.body || typeof response.body.getReader !== "function") throw unavailable();
    reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
      const part = await reader.read();
      if (part.done) {
        finished = true;
        break;
      }
      if (!(part.value instanceof Uint8Array)) throw unavailable();
      total += part.value.byteLength;
      if (total > plan.maximumRawWitnessBytes || total > expected) throw unavailable();
      chunks.push(part.value.slice());
    }
    if (total !== expected) throw unavailable();
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    return witnessFrom(text, transaction, plan);
  } finally {
    if (reader) {
      try {
        if (!finished) await reader.cancel();
      } finally {
        reader.releaseLock();
      }
    } else {
      await cancelBody(response);
    }
  }
}
function createIssuerSettlementStore(namespace, configuration2) {
  const plan = issuerSettlementStorePlan(configuration2);
  if (plan === null) return void 0;
  if (!namespace || typeof namespace.idFromName !== "function" || typeof namespace.get !== "function") {
    throw new TypeError("Invalid issuer settlement namespace");
  }
  async function request(key, method, text) {
    const id = namespace.idFromName(plan.objectName);
    const stub = namespace.get(id);
    if (!stub || typeof stub.fetch !== "function") throw unavailable();
    const url = new URL(plan.path, "https://issuer-settlement.internal");
    url.searchParams.set("key", key);
    const init = { method, redirect: "manual" };
    if (method === "POST") {
      init.headers = { "If-None-Match": "*", "Content-Type": "application/json" };
      init.body = text;
    }
    return await stub.fetch(url.toString(), init);
  }
  return Object.freeze({
    async get(key) {
      let response;
      let handled = false;
      try {
        const transaction = transactionFor(key);
        response = await request(key, "GET");
        if (response.status === 404) {
          handled = true;
          await cancelBody(response);
          return null;
        }
        if (response.status !== 200) throw unavailable();
        handled = true;
        const witness = await readWitness(response, transaction, plan);
        return { json: async () => witness };
      } catch {
        throw unavailable();
      } finally {
        if (response && !handled) {
          try {
            await cancelBody(response);
          } catch {
          }
        }
      }
    },
    async put(key, text, options2) {
      let response;
      try {
        const transaction = transactionFor(key);
        if (!validOptions(options2)) throw unavailable();
        witnessFrom(text, transaction, plan);
        response = await request(key, "POST", text);
        const status = response.status;
        await cancelBody(response);
        response = void 0;
        if (status === 201) return { stored: true };
        if (status === 412) return null;
        throw unavailable();
      } catch {
        throw unavailable();
      } finally {
        if (response) {
          try {
            await cancelBody(response);
          } catch {
          }
        }
      }
    }
  });
}

// data/records/fabrication-run-records/2026-10-24-issuer-private-settlement-custody/clarification/adapter-contracts/receiving-fixtures/market.mjs
var configuration = { enabled: true, resourceAdmission: { status: "received" }, network: "eip155:8453", asset: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", payTo: "0x" + "b".repeat(40), operation: "issuer-revenue-comparison", method: "POST", route: "/v1/issuer-revenue-comparison", sku: "fixture-issuer-sku", gateway: "fixture-issuer-gateway", ledgerAccount: "Income:Sales:X402:IssuerResearch", amount: "50000" };
var options = { onlyIf: { etagDoesNotMatch: "*" }, httpMetadata: { contentType: "application/json" } };
var market_default = { async fetch(request, env) {
  const store = createIssuerSettlementStore(env.CLOCK, configuration), key = new URL(request.url).searchParams.get("key");
  try {
    if (request.method === "POST") {
      const result = await store.put(key, await request.text(), options);
      return new Response(result ? "stored" : "prior", { status: result ? 201 : 412 });
    }
    const item = await store.get(key);
    return item ? Response.json(await item.json()) : new Response("missing", { status: 404 });
  } catch {
    return new Response("held", { status: 503 });
  }
} };
export {
  market_default as default
};
