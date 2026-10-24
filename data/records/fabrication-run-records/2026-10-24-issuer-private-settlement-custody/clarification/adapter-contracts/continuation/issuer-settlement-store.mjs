/**
 * issuer-private-settlement-custody, specification v2.
 * Source: earning-loop-worker-service/specifications/issuer-private-settlement-custody.work-order.md
 * SHA256: 87851b65650e3326e34ce6fd7acb5ea27055f4467d282f0e03dbf913e5ae90d8; lines 1–42.
 * Specification digest: ni:///sha-256;NfoPd76YNGyNO9CtP5HGaF5Ue3QZSYhQQKKFdR6LtFE.
 * Requirements admission/plans/pulse-budget and prohibition no-expansion apply.
 * client/witness-admission: Red Cup Engineering, unchanged native edge journal
 * provider/original journal identity, work-order lines 16/18 and
 * market.561.group/src/edge-settlement.mjs. This provider preserves the original
 * journal's conditional contract, original text, and duplicate ownership.
 * representation: IETF RFC9110, https://www.rfc-editor.org/rfc/rfc9110;
 * explicit status/media/length and no followed redirects (line 10).
 * operation/composition: 561 Group root received direction 2026-10-24 and
 * Red Cup Engineering approved existing EarningClock wiring, work-order lines
 * 12/21. Caller selects this provider only for the source-owned issuer offer,
 * prunes the raw namespace before compute, and preserves other providers.
 * platform: Cloudflare SQLite limits received 2026-10-24,
 * https://developers.cloudflare.com/durable-objects/platform/limits/ (line 13).
 * Physical quota, first writer, atomic accounting and receiving belong to the
 * custody owner; this transport neither reserves capacity nor bypasses refusal.
 * payment-evidence/cash-record/original-adapter-contracts: original settlements.mjs
 * receiver and inspected interface 2026-10-24, ../src/settlements.mjs, lines 9/20/22.
 * This client does not corroborate, settle, classify revenue or infer acceptance.
 * physical/server/receiver: Red Cup Engineering approved private custody
 * direction/private binding consumer/original corroboration kernel, work-order
 * lines 15/17/19, remain server obligations, including immutable originals,
 * capacity identity guards, pending-only receiving and atomic terminal writes.
 * source-free: Red Cup Engineering native deriveJsnodeModules,
 * computer-code-development-engine/scripts/fabricate-jsnode-closure.mjs, line 14.
 * Trace: admission -> pure-receiving; plans/no-expansion -> io-receiving;
 * pulse-budget -> composition/operation/platform -> io-receiving. Projection:
 * jsnode-modules. Pure examples establish admission/metadata only. Independent
 * native I/O, SQLite workerd and composed-pulse receiving, whole source-owned
 * build, independent review, resource admission and actual customer/payment
 * receiving remain mandatory before promotion (lines 33–35). The 50-request
 * ceiling is the root business allocation, not observed runtime/vendor capacity;
 * 16 RPC plus bounded 12 commercial plus actual clock calls require separate
 * whole-pulse receiving. No USD200/day, reserved-free-capacity or income claim.
 * No R2, env.STATE, credentials, arbitrary keys/objects, new alarms/schedules,
 * public routes, raw deletion, payment signing/purchase or deployment.
 */

const ASSET = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const KEY = /^settlements\/eip155:8453\/(0x[0-9a-f]{64})\.json$/;
const encoder = new TextEncoder();
const unavailable = () => new Error('issuer-settlement-unavailable');
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const byteLength = value => encoder.encode(value).byteLength;

/**
 * Admit trusted source-owned issuer configuration and return fixed transport
 * coordinates and immutable ceilings. No effects or runtime budget are granted.
 * @param {*} configuration Original trusted configuration, unchanged in shape.
 * @returns {object|null} Normalized plan, or null before admission.
 */
export function issuerSettlementStorePlan(configuration) {
  if (!configuration || configuration.enabled !== true || configuration.resourceAdmission?.status !== 'received') return null;
  const c = configuration;
  const shortText = value => typeof value === 'string' && value.length > 0 && !/[\r\n]/.test(value) && byteLength(value) <= 512;
  if (c.network !== 'eip155:8453' || typeof c.asset !== 'string' || c.asset.toLowerCase() !== ASSET ||
      typeof c.payTo !== 'string' || !ADDRESS.test(c.payTo) || c.operation !== 'issuer-revenue-comparison' ||
      c.method !== 'POST' || c.route !== '/v1/issuer-revenue-comparison' || c.amount !== '50000' ||
      !shortText(c.sku) || !shortText(c.gateway) || !shortText(c.ledgerAccount)) {
    throw new TypeError('Invalid issuer settlement configuration');
  }
  return Object.freeze({
    prefix: 'issuer-settlements/', metadataKey: 'issuer-settlements/capacity',
    witnessPrefix: 'issuer-settlements/witness/', pendingPrefix: 'issuer-settlements/pending/',
    receiptPrefix: 'issuer-settlements/receipt/', objectName: 'earning-loops',
    path: '/issuer-settlement-witness', maximumRecords: 50000, maximumCustodyBytes: 268435456,
    maximumRawWitnessBytes: 32768, maximumTransactionBytes: 1900000,
    maximumWitnessesPerPulse: 4, maximumProviderAttemptsPerWitness: 4, maximumRpcBytes: 262144,
    network: c.network, asset: c.asset.toLowerCase(), payTo: c.payTo.toLowerCase(),
    operation: c.operation, method: c.method, route: c.route, sku: c.sku, gateway: c.gateway,
    ledgerAccount: c.ledgerAccount, amount: c.amount, maximumWorkerCallsPerPulse: 50
  });
}

function transactionFor(key) {
  if (typeof key !== 'string') throw unavailable();
  const match = KEY.exec(key);
  if (!match) throw unavailable();
  return match[1];
}

function witnessFrom(text, transaction, plan) {
  if (typeof text !== 'string' || byteLength(text) > plan.maximumRawWitnessBytes) throw unavailable();
  const witness = JSON.parse(text);
  if (!isObject(witness) || witness.network !== plan.network || witness.transaction !== transaction ||
      typeof witness.payer !== 'string' || !ADDRESS.test(witness.payer) ||
      typeof witness.payTo !== 'string' || witness.payTo.toLowerCase() !== plan.payTo ||
      typeof witness.asset !== 'string' || witness.asset.toLowerCase() !== plan.asset) throw unavailable();
  for (const field of ['operation', 'method', 'route', 'sku', 'gateway', 'ledgerAccount', 'amount']) {
    if (witness[field] !== plan[field]) throw unavailable();
  }
  return witness;
}

function exactKeys(value, keys) {
  if (!isObject(value)) return false;
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

function validOptions(options) {
  return exactKeys(options, ['onlyIf', 'httpMetadata']) &&
    exactKeys(options.onlyIf, ['etagDoesNotMatch']) && options.onlyIf.etagDoesNotMatch === '*' &&
    exactKeys(options.httpMetadata, ['contentType']) && options.httpMetadata.contentType === 'application/json';
}

async function cancelBody(response) {
  if (response?.body) await response.body.cancel();
}

async function readWitness(response, transaction, plan) {
  let reader;
  let finished = false;
  try {
    const lengthText = response.headers.get('Content-Length');
    if (typeof lengthText !== 'string' || !/^(0|[1-9][0-9]*)$/.test(lengthText)) throw unavailable();
    const expected = Number(lengthText);
    if (!Number.isSafeInteger(expected) || expected > plan.maximumRawWitnessBytes) throw unavailable();
    const media = response.headers.get('Content-Type');
    if (typeof media !== 'string' || media.split(';', 1)[0].trim().toLowerCase() !== 'application/json') throw unavailable();
    if (!response.body || typeof response.body.getReader !== 'function') throw unavailable();
    reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
      const part = await reader.read();
      if (part.done) { finished = true; break; }
      if (!(part.value instanceof Uint8Array)) throw unavailable();
      total += part.value.byteLength;
      if (total > plan.maximumRawWitnessBytes || total > expected) throw unavailable();
      chunks.push(part.value.slice());
    }
    if (total !== expected) throw unavailable();
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    // Preserve a BOM as text rather than silently stripping witness bytes.
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    return witnessFrom(text, transaction, plan);
  } finally {
    if (reader) {
      try { if (!finished) await reader.cancel(); } finally { reader.releaseLock(); }
    } else {
      await cancelBody(response);
    }
  }
}

/**
 * Construct the scoped original-journal conditional provider. No namespace
 * method is called before admission or before each operation's input validation.
 * Custody failure never undoes settlement or establishes received custody.
 * @param {object} namespace Existing trusted EarningClock namespace binding.
 * @param {*} configuration Original trusted source-owned issuer configuration.
 * @returns {{get:function,put:function}|undefined} Only async get/put, or undefined.
 */
export function createIssuerSettlementStore(namespace, configuration) {
  const plan = issuerSettlementStorePlan(configuration);
  if (plan === null) return undefined;
  if (!namespace || typeof namespace.idFromName !== 'function' || typeof namespace.get !== 'function') {
    throw new TypeError('Invalid issuer settlement namespace');
  }

  async function request(key, method, text) {
    const id = namespace.idFromName(plan.objectName);
    const stub = namespace.get(id);
    if (!stub || typeof stub.fetch !== 'function') throw unavailable();
    const url = new URL(plan.path, 'https://issuer-settlement.internal');
    url.searchParams.set('key', key);
    const init = { method, redirect: 'manual' };
    if (method === 'POST') {
      init.headers = { 'If-None-Match': '*', 'Content-Type': 'application/json' };
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
        response = await request(key, 'GET');
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
        if (response && !handled) { try { await cancelBody(response); } catch {} }
      }
    },
    async put(key, text, options) {
      let response;
      try {
        const transaction = transactionFor(key);
        if (!validOptions(options)) throw unavailable();
        // Validation never reserializes or replaces the original witness text.
        witnessFrom(text, transaction, plan);
        response = await request(key, 'POST', text);
        const status = response.status;
        await cancelBody(response);
        response = undefined;
        if (status === 201) return { stored: true };
        if (status === 412) return null;
        throw unavailable();
      } catch {
        throw unavailable();
      } finally {
        if (response) { try { await cancelBody(response); } catch {} }
      }
    }
  });
}
