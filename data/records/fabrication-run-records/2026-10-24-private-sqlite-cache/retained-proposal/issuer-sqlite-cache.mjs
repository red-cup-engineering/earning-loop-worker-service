/**
 * issuer-private-sqlite-cache — selected module src/issuer-sqlite-cache.mjs.
 * Source: earning-loop-worker-service/specifications/issuer-private-sqlite-cache.work-order.md
 * (lines 1–36), sha256:cd22c3850fe531977e567aba633bee94d08b07330001bc2025e82b1ab640070e.
 * Specification: ni:///sha-256;xqZBnu3XnJj6OIUarAaerOfphyiKDpBCJ8pFBehZEc4.
 * Requirements admission (line 3), coordinates (line 4), prohibition
 * no-authority-expansion (line 6), claim bounded-cache (line 24).
 *
 * Normative authority/revision/locator/applicability:
 * byte-custody: IETF, RFC9110, https://www.rfc-editor.org/rfc/rfc9110;
 * private GET preserves representation bytes and length, without refresh.
 * house-operation: 561 Group, original paid issuer operation 2026-10-24;
 * /home/emsenn/info/lib/emsenn/services/561-group/services/561-group-services-section/services/561-group-opportunity-services-section/data/records/opportunity-records/2026-10-24-issuer-period-reconciliation.json;
 * annual AAPL/MSFT comparison uses one trusted completed cache, no request-driven
 * acquisition or unadmitted cash; supplier retains reconciliation/provenance/selection.
 * sqlite-platform: Cloudflare, docs observed 2026-10-24,
 * https://developers.cloudflare.com/durable-objects/platform/limits/;
 * SQLite 2MB row limit, existing cross-script binding, conservative 1900000-byte
 * serialized transaction ceiling; no billable headroom claim.
 * async-contract: Red Cup Engineering, accepted issuer caller contract at
 * c425608745ace8e864ba8e1df2fcd12058240f72, ./issuer-research-integration.md;
 * preserve Retry-After and full-only publication, no data writes through R2.
 * source-free: Red Cup Engineering, native deriveJsnodeModules;
 * /home/emsenn/info/lib/emsenn/services/561-group/services/engineering-services-section/services/computer-engineering-services-section/services/computer-systems-engineering-services-section/services/computer-code-development-system-services-section/apps/computer-code-development-engine/scripts/fabricate-jsnode-closure.mjs;
 * whole-unit source-free proposal must be received unchanged by consumer owners.
 * async-custody, async-atomic, async-overflow, async-server, async-client and
 * async-integration: Red Cup Engineering, approved private cache contract
 * 2026-10-24, ./issuer-private-sqlite-cache.work-order.md, lines 14–19;
 * mandatory complete async contracts require independent I/O qualification.
 * async-status: Red Cup Engineering, independent receiving correction 2026-10-24,
 * same locator, line 20; validate existing coordinator records without inventing
 * retry policy, changing Retry-After or acquiring new authority.
 *
 * This module implements server custody, atomic staging, durable overflow hold,
 * private GET and status validation. The separate market module implements the
 * streaming client; no cross-module import or private worker dependency.
 * Final owner: earning-loop-worker-service/src/issuer-sqlite-cache.mjs.
 * Receiving integration must inject issuerStore into existing refreshIssuerResearch,
 * remove issuer STATE fallbacks, wrap refresh on the existing serialized queue,
 * and call the private handler before the alarm-arming catch-all. Market receives
 * src/issuer-evidence-store.mjs at market.561.group, binds the existing external
 * namespace/class/script and earning-loops singleton, and injects readStore only.
 * Existing run/tick, OpenTask custody, alarms, public routes and maintenance remain.
 * No public cache/refresh route, source acquisition, credential/OpenTask read,
 * arbitrary key, alarm mutation, namespace, migration, schedule or deployment.
 *
 * Traceability: admission, coordinates and no-authority-expansion each trace to
 * async-atomic/client/contract/custody/integration/overflow/server/status,
 * byte-custody, house-operation, source-free and sqlite-platform, through
 * projection jsnode-modules. coordinates requires pure-receiving; admission and
 * no-authority-expansion require io-receiving (lines 30–32).
 * Pure examples qualify plans only. Independent memory and actual workerd
 * receiving across two services on the original singleton must cover deferred
 * producers, atomic publication/rollback, source and serialization failure, long
 * literal Retry-After reentry, durable overflow/no acquisition, two-key custody,
 * arbitrary-key rejection, method/query/disabled/public routing, original Unicode
 * bytes and limits, malformed transport, missing/stale consumer 503, native
 * prepared producer/read supplier path, retained OpenTask commercial tests and
 * current alarm. No deployment, paid-success or cost qualification is claimed.
 */

const encoder = new TextEncoder();
const COHORT = 'issuer-evidence/cohort';
const STATUS = 'issuer-evidence/status';
const LOGICAL_STATUS = 'registers/earning-loops/issuer-research.json';
const STATUS_LIMIT = 524288;
const TRANSACTION_LIMIT = 1900000;
const bytes = text => encoder.encode(text).byteLength;
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

/**
 * Admit host configuration and return the exact bounded SQLite coordinates.
 * Admission does not grant resource or source authority.
 * @param {*} configuration Trusted host configuration.
 * @returns {object|null} Storage plan, or null when not admitted.
 */
export function issuerSqliteStoragePlan(configuration) {
  if (configuration == null || configuration.enabled !== true ||
      configuration.resourceAdmission?.status !== 'received') return null;
  const { cacheKey, maximumCohortBytes } = configuration;
  if (typeof cacheKey !== 'string' || cacheKey.length === 0 ||
      bytes(cacheKey) > 256 || cacheKey === LOGICAL_STATUS ||
      !Number.isSafeInteger(maximumCohortBytes) || maximumCohortBytes <= 0 ||
      maximumCohortBytes > STATUS_LIMIT) {
    throw new TypeError('Invalid issuer cache configuration');
  }
  return {
    cohortKey: COHORT, statusKey: STATUS, logicalStatusKey: LOGICAL_STATUS,
    cacheKey, maximumCohortBytes, maximumStatusBytes: STATUS_LIMIT,
    maximumTransactionBytes: TRANSACTION_LIMIT
  };
}

function sentinel(cacheKey) {
  return { status: 'unavailable', cacheKey, retryBlocked: true,
    reason: 'status-overflow', nextAttemptAt: null };
}

function instant(value) {
  if (typeof value !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
}

function validateStatus(value, cacheKey) {
  if (!object(value) || value.cacheKey !== cacheKey)
    throw new TypeError('Invalid issuer status');
  const expected = sentinel(cacheKey);
  const keys = Object.keys(expected);
  if (Object.keys(value).length === keys.length &&
      keys.every(key => own(value, key) && value[key] === expected[key])) return;
  if (!instant(value.at)) throw new TypeError('Invalid issuer status instant');
  const deadline = () => instant(value.nextAttemptAt) &&
    Date.parse(value.nextAttemptAt) >= Date.parse(value.at);
  if (value.status === 'prepared') {
    if (!(value.observedAt === null || instant(value.observedAt)) ||
        !deadline() || (own(value, 'retryBlocked') && value.retryBlocked !== false))
      throw new TypeError('Invalid prepared issuer status');
    return;
  }
  const nullableString = item => item === null || typeof item === 'string';
  if (value.status !== 'unavailable' || typeof value.error !== 'string' ||
      !nullableString(value.code) || !nullableString(value.reason) ||
      typeof value.retryable !== 'boolean' || !nullableString(value.retryAfter) ||
      typeof value.retryBlocked !== 'boolean' ||
      (value.retryBlocked ? value.nextAttemptAt !== null : !deadline()))
    throw new TypeError('Invalid unavailable issuer status');
}

function recordSize(key, record) {
  return bytes(key) + bytes(JSON.stringify(record));
}

function readRecord(record, key, plan) {
  if (record === undefined || record === null) return null;
  if (!object(record) || Object.keys(record).length !== 2 ||
      !own(record, 'cacheKey') || !own(record, 'body') ||
      typeof record.cacheKey !== 'string' || typeof record.body !== 'string')
    throw new TypeError('Invalid issuer physical record');
  const limit = key === COHORT ? plan.maximumCohortBytes : plan.maximumStatusBytes;
  if (bytes(record.body) > limit || recordSize(key, record) > plan.maximumTransactionBytes)
    throw new TypeError('Oversized issuer physical record');
  const parsed = JSON.parse(record.body);
  if (record.cacheKey !== plan.cacheKey) return null;
  if (key === STATUS) validateStatus(parsed, plan.cacheKey);
  return record.body;
}

/**
 * Run work once outside a transaction using a private two-key staging store,
 * then atomically publish staged values. Corrupt persisted state fails before work.
 * @param {object} storage Existing DurableObjectStorage get/transaction capabilities.
 * @param {*} configuration Trusted host configuration.
 * @param {Function} work Coordinator receiving the scoped bucket-compatible store.
 * @returns {Promise<*>} Resolved work result after publication, overflow sentinel,
 * or the not-configured result.
 */
export async function withIssuerSqliteStore(storage, configuration, work) {
  const plan = issuerSqliteStoragePlan(configuration);
  if (!plan) return { status: 'not-configured' };
  if (!storage || typeof storage.get !== 'function' ||
      typeof storage.transaction !== 'function' || typeof work !== 'function')
    throw new TypeError('Issuer storage and work capabilities required');

  // Validate both persisted records before the coordinator can acquire sources.
  const initial = new Map();
  initial.set(COHORT, readRecord(await storage.get(COHORT), COHORT, plan));
  initial.set(STATUS, readRecord(await storage.get(STATUS), STATUS, plan));
  const staged = new Map();
  let overflow = false;
  let invalidStatus = null;
  let active = true;
  const held = sentinel(plan.cacheKey);
  const physicalKey = key => {
    if (key === plan.cacheKey) return COHORT;
    if (key === plan.logicalStatusKey) return STATUS;
    throw new TypeError('Issuer logical key is not admitted');
  };
  const hold = () => {
    overflow = true;
    staged.clear();
    staged.set(STATUS, { cacheKey: plan.cacheKey, body: JSON.stringify(held) });
  };
  const checkBudget = () => {
    let total = 0;
    for (const [key, record] of staged) {
      const size = recordSize(key, record);
      if (size > plan.maximumTransactionBytes) { hold(); return; }
      total += size;
    }
    if (total > plan.maximumTransactionBytes) hold();
  };
  const store = Object.freeze({
    async get(key) {
      const physical = physicalKey(key);
      if (!active) throw new TypeError('Issuer store scope has ended');
      const body = staged.has(physical) ? staged.get(physical).body : initial.get(physical);
      return body === null ? null : { json: async () => JSON.parse(body) };
    },
    async put(key, text) {
      const physical = physicalKey(key);
      if (!active) throw new TypeError('Issuer store scope has ended');
      let parsed;
      try {
        if (typeof text !== 'string') throw new TypeError('JSON text required');
        parsed = JSON.parse(text);
      } catch (error) {
        if (physical === STATUS) { hold(); return; }
        throw error;
      }
      const limit = physical === COHORT ? plan.maximumCohortBytes : plan.maximumStatusBytes;
      if (bytes(text) > limit) {
        if (physical === STATUS) { hold(); return; }
        throw new TypeError('Issuer cohort exceeds byte limit');
      }
      if (physical === STATUS) {
        try { validateStatus(parsed, plan.cacheKey); }
        catch (error) { invalidStatus = error; throw error; }
      }
      if (overflow) return;
      staged.set(physical, { cacheKey: plan.cacheKey, body: text });
      checkBudget();
    }
  });
  let result;
  try { result = await work(store); }
  finally { active = false; }
  if (invalidStatus) throw invalidStatus;
  if (staged.size) {
    const writes = Array.from(staged, ([key, record]) => [key, { ...record }]);
    await storage.transaction(async transaction => {
      if (!transaction || typeof transaction.put !== 'function')
        throw new TypeError('Issuer transaction put capability required');
      for (const [key, record] of writes) await transaction.put(key, { ...record });
    });
  }
  return overflow ? held : result;
}

function emptyResponse(status, headers = {}) {
  return new Response(null, { status, headers: { 'Cache-Control': 'no-store', ...headers } });
}

/**
 * Serve only the admitted private GET using one cohort read and original JSON
 * bytes; callers must invoke this before existing alarm-arming fallback logic.
 * @param {Request} request Existing EarningClock fetch request.
 * @param {object} storage Existing DurableObjectStorage get capability.
 * @param {*} configuration Trusted host configuration.
 * @returns {Promise<Response|null>} Private response or null for another pathname.
 */
export async function issuerSqliteResponse(request, storage, configuration) {
  const url = new URL(request.url);
  if (url.pathname !== '/issuer-evidence') return null;
  const plan = issuerSqliteStoragePlan(configuration);
  if (!plan) return emptyResponse(404);
  if (request.method !== 'GET') return emptyResponse(405, { Allow: 'GET' });
  const entries = Array.from(url.searchParams);
  if (entries.length !== 1 || entries[0][0] !== 'key' || entries[0][1] !== plan.cacheKey)
    return emptyResponse(404);
  try {
    const body = readRecord(await storage.get(plan.cohortKey), plan.cohortKey, plan);
    if (body === null) return emptyResponse(404);
    const encoded = encoder.encode(body);
    return new Response(encoded, {
      status: 200,
      headers: { 'Content-Type': 'application/json',
        'Content-Length': String(encoded.byteLength), 'Cache-Control': 'no-store' }
    });
  } catch {
    return emptyResponse(503);
  }
}
