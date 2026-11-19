/*
 * issuer-private-sqlite-cache / src/issuer-sqlite-cache.mjs
 * ArtifactFabricationSpecification v2; projection jsnode-modules.
 * Source: earning-loop-worker-service/specifications/issuer-private-sqlite-cache-edge.work-order.md, lines 1–37.
 * Source digest: sha256:e7974b3d619a4293d95f501e5273739caad95942989c8fce212dfc0fdb6ef28a.
 * Specification: ni:///sha-256;QqZcGyMOQUowWQ9OPhouLllz12w33a4Vg8t_Hmo1Jr8.
 * Normative authority register (locators relative to the supplied carrier remain relative):
 * byte-custody: IETF, RFC9110, https://www.rfc-editor.org/rfc/rfc9110; actual private GET bytes, length, media semantics and no refresh.
 * edge-transport: Cloudflare, actual workerd1.20261024.1 native receiving 2026-10-24; earning-loop-worker-service/data/records/worker-runtime-test-records/61bfd8ff392d5904ccc9b1a088e8af5ca7871a632bb90f608f82903d27d54898/config.capnp; client manual redirects and status refusal belong to the other module.
 * house-operation: 561 Group, original paid issuer operation 2026-10-24; 561-group-opportunity-services-section/data/records/opportunity-records/2026-10-24-issuer-period-reconciliation.json; fixed singleton and two keys, supplier owns reconciliation/provenance/freshness, no request-driven acquisition or incremental cash authority.
 * sqlite-platform: Cloudflare, docs observed 2026-10-24, https://developers.cloudflare.com/durable-objects/platform/limits/; conservative 1900000-byte serialized transaction ceiling below SQLite 2MB, no billable headroom inference.
 * async-contract: Red Cup Engineering, accepted issuer caller contract at c425608745ace8e864ba8e1df2fcd12058240f72, ./issuer-research-integration.md; preserve Retry-After and full-only publication, no R2 writes.
 * source-free: Red Cup Engineering, native deriveJsnodeModules; computer-code-development-engine/scripts/fabricate-jsnode-closure.mjs; unchanged whole-unit proposal requires independent receiving before wiring.
 * async-custody, async-atomic, async-overflow, async-server, async-client, async-integration: Red Cup Engineering, approved private cache contract 2026-10-24, ./issuer-private-sqlite-cache.work-order.md; complete mandatory async contracts, independently qualified I/O.
 * async-status: Red Cup Engineering, independent receiving correction 2026-10-24, same locator; validate existing coordinator records without inventing retry policy.
 * Trace: admission and no-authority-expansion -> all thirteen constraints -> jsnode-modules -> io-receiving; coordinates -> same constraints/projection -> pure-receiving.
 * Receiving obligations remain outstanding: pure admission/disabled/unreceived/invalid assays do not qualify I/O. Independent memory and actual workerd two-service/private-binding receiving must verify deferred and atomic publication, rollback, failures, durable Retry-After and overflow reentry, exact keys, no OpenTask/alarm effects, HTTP/query/admission rules, bytes/Unicode/bounds/malformed transport, stale/missing consumer refusal, native supplier producer/read path, retained commercial tests and alarms. No deployment, paid success or cost claim.
 * Integration owner: earning-loop-worker-service/src/issuer-sqlite-cache.mjs. Existing serialized EarningClock queue wraps refresh; private handler precedes alarm catch-all. Supplier consumes issuerStore with no issuer STATE fallback. Existing run/tick, public routes, OpenTask custody and maintenance remain intact. The market module is separately received at market.561.group/src/issuer-evidence-store.mjs using the existing external namespace/singleton and readStore only.
 * No public cache/refresh route, source acquisition, credentials, arbitrary keys, alarm mutation, namespace, migration, schedule, external dependency, private worker import or deployment is authorized.
 */
const COHORT = 'issuer-evidence/cohort';
const STATUS = 'issuer-evidence/status';
const LOGICAL_STATUS = 'registers/earning-loops/issuer-research.json';
const STATUS_LIMIT = 524288;
const TRANSACTION_LIMIT = 1900000;
const encoder = new TextEncoder();
const bytes = value => encoder.encode(value).byteLength;
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function invalid() { return new TypeError('Invalid issuer cache record'); }

/**
 * Admit host configuration and return the exact bounded SQLite coordinates, without effects.
 * @param {*} configuration Host resource admission and cache configuration.
 * @returns {object|null} The storage plan, or null when not admitted.
 */
export function issuerSqliteStoragePlan(configuration) {
  if (configuration == null || configuration.enabled !== true || configuration.resourceAdmission?.status !== 'received') return null;
  const { cacheKey, maximumCohortBytes } = configuration;
  if (typeof cacheKey !== 'string' || cacheKey.length === 0 || bytes(cacheKey) > 256 || cacheKey === LOGICAL_STATUS || !Number.isSafeInteger(maximumCohortBytes) || maximumCohortBytes <= 0 || maximumCohortBytes > STATUS_LIMIT) throw new TypeError('Invalid issuer cache configuration');
  return { cohortKey: COHORT, statusKey: STATUS, logicalStatusKey: LOGICAL_STATUS, cacheKey, maximumCohortBytes, maximumStatusBytes: STATUS_LIMIT, maximumTransactionBytes: TRANSACTION_LIMIT };
}
function instant(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
}
function sentinel(cacheKey) {
  return { status: 'unavailable', cacheKey, retryBlocked: true, reason: 'status-overflow', nextAttemptAt: null };
}
function validateStatus(value, cacheKey) {
  if (!object(value) || value.cacheKey !== cacheKey) throw invalid();
  const special = sentinel(cacheKey);
  if (Object.keys(value).length === Object.keys(special).length && Object.keys(special).every(key => own(value, key) && value[key] === special[key])) return;
  if (!instant(value.at)) throw invalid();
  const deadline = () => instant(value.nextAttemptAt) && Date.parse(value.nextAttemptAt) >= Date.parse(value.at);
  if (value.status === 'prepared') {
    if (!(value.observedAt === null || instant(value.observedAt)) || (own(value, 'retryBlocked') && value.retryBlocked !== false) || !deadline()) throw invalid();
  } else if (value.status === 'unavailable') {
    const nullableString = v => v === null || typeof v === 'string';
    if (typeof value.error !== 'string' || !nullableString(value.code) || !nullableString(value.reason) || typeof value.retryable !== 'boolean' || !nullableString(value.retryAfter) || typeof value.retryBlocked !== 'boolean' || (value.retryBlocked ? value.nextAttemptAt !== null : !deadline())) throw invalid();
  } else throw invalid();
}
function physicalSize(key, record) { return bytes(key) + bytes(JSON.stringify(record)); }
function readRecord(record, key, plan) {
  if (record === undefined) return null;
  if (!object(record) || Object.keys(record).length !== 2 || !own(record, 'cacheKey') || !own(record, 'body') || typeof record.cacheKey !== 'string' || typeof record.body !== 'string') throw invalid();
  const limit = key === COHORT ? plan.maximumCohortBytes : STATUS_LIMIT;
  if (bytes(record.body) > limit || physicalSize(key, record) > TRANSACTION_LIMIT) throw invalid();
  const parsed = JSON.parse(record.body);
  if (record.cacheKey !== plan.cacheKey) return null;
  if (key === STATUS) validateStatus(parsed, plan.cacheKey);
  return record.body;
}

/**
 * Run work once outside a transaction using a scoped bucket adapter, then atomically publish staged JSON.
 * Stored records are validated before work; overflow durably blocks retry while preserving the prior cohort.
 * @param {object} storage Existing DurableObjectStorage get and transaction capabilities.
 * @param {*} configuration Host resource admission and cache configuration.
 * @param {function(object): *} work Existing coordinator receiving async get and put methods.
 * @returns {Promise<*>} The resolved work result after publication, an overflow sentinel, or not-configured status.
 */
export async function withIssuerSqliteStore(storage, configuration, work) {
  const plan = issuerSqliteStoragePlan(configuration);
  if (plan === null) return { status: 'not-configured' };
  if (!storage || typeof storage.get !== 'function' || typeof storage.transaction !== 'function' || typeof work !== 'function') throw new TypeError('Invalid issuer storage capabilities');
  const initial = new Map();
  initial.set(COHORT, readRecord(await storage.get(COHORT), COHORT, plan));
  initial.set(STATUS, readRecord(await storage.get(STATUS), STATUS, plan));
  const staged = new Map();
  let closed = false;
  let overflow = false;
  let fatal = null;
  const hold = sentinel(plan.cacheKey);
  function resolve(key) {
    if (closed) throw new TypeError('Issuer store scope closed');
    if (key === plan.cacheKey) return COHORT;
    if (key === LOGICAL_STATUS) return STATUS;
    throw new TypeError('Unadmitted issuer cache key');
  }
  function failClosed() {
    overflow = true;
    staged.clear();
    staged.set(STATUS, { cacheKey: plan.cacheKey, body: JSON.stringify(hold) });
  }
  function boundTransaction() {
    let total = 0;
    for (const [key, record] of staged) {
      const size = physicalSize(key, record);
      if (size > TRANSACTION_LIMIT) { failClosed(); return; }
      total += size;
    }
    if (total > TRANSACTION_LIMIT) failClosed();
  }
  const store = {
    async get(key) {
      const physical = resolve(key);
      const body = staged.has(physical) ? staged.get(physical).body : initial.get(physical);
      return body === null ? null : { json: async () => JSON.parse(body) };
    },
    async put(key, text) {
      const physical = resolve(key);
      let parsed;
      if (physical === STATUS) {
        try {
          if (typeof text !== 'string' || bytes(text) > STATUS_LIMIT) { failClosed(); return; }
          parsed = JSON.parse(text);
        } catch { failClosed(); return; }
        try { validateStatus(parsed, plan.cacheKey); } catch (error) { fatal = error; throw error; }
      } else {
        if (typeof text !== 'string' || bytes(text) > plan.maximumCohortBytes) throw invalid();
        JSON.parse(text);
      }
      if (overflow) return;
      staged.set(physical, { cacheKey: plan.cacheKey, body: text });
      boundTransaction();
    }
  };
  let result;
  try { result = await work(store); } finally { closed = true; }
  if (fatal !== null) throw fatal;
  if (staged.size !== 0) {
    await storage.transaction(async transaction => {
      for (const [key, record] of staged) await transaction.put(key, record);
    });
  }
  return overflow ? hold : result;
}
function response(status, headers = {}) {
  return new Response(null, { status, headers: { 'Cache-Control': 'no-store', ...headers } });
}

/**
 * Serve only the private admitted GET endpoint using one cohort read and its unchanged JSON bytes.
 * Invoke before the existing alarm-arming catch-all; freshness remains the supplier selector's responsibility.
 * @param {Request} request The existing EarningClock fetch request.
 * @param {object} storage Existing DurableObjectStorage get capability.
 * @param {*} configuration Host resource admission and cache configuration.
 * @returns {Promise<Response|null>} A private HTTP response, or null for another pathname.
 */
export async function issuerSqliteResponse(request, storage, configuration) {
  const url = new URL(request.url);
  if (url.pathname !== '/issuer-evidence') return null;
  const plan = issuerSqliteStoragePlan(configuration);
  if (plan === null) return response(404);
  if (request.method !== 'GET') return response(405, { Allow: 'GET' });
  const entries = [...url.searchParams];
  if (entries.length !== 1 || entries[0][0] !== 'key' || entries[0][1] !== plan.cacheKey) return response(404);
  try {
    const body = readRecord(await storage.get(COHORT), COHORT, plan);
    if (body === null) return response(404);
    const data = encoder.encode(body);
    return new Response(data, { status: 200, headers: { 'Content-Type': 'application/json', 'Content-Length': String(data.byteLength), 'Cache-Control': 'no-store' } });
  } catch { return response(503); }
}
