/**
 * Private issuer evidence reader; selected module src/issuer-evidence-store.mjs.
 * Source: issuer-private-sqlite-cache-edge.work-order.md, lines 1–37,
 * sha256:e7974b3d619a4293d95f501e5273739caad95942989c8fce212dfc0fdb6ef28a.
 * Specification: ni:///sha-256;QqZcGyMOQUowWQ9OPhouLllz12w33a4Vg8t_Hmo1Jr8.
 * Implements admission, coordinates and no-authority-expansion through the
 * jsnode-modules projection. Guards confer no resource or source authority.
 * IETF RFC9110 (https://www.rfc-editor.org/rfc/rfc9110): preserve body bytes
 * and length; GET authorizes no refresh or hidden mutation.
 * Cloudflare, actual workerd1.20261024.1 native receiving 2026-10-24:
 * edge-transport requires redirect manual, with rejection of redirect status;
 * receiving locator is earning-loop-worker-service/data/records/
 * worker-runtime-test-records/61bfd8ff392d5904ccc9b1a088e8af5ca7871a632bb90f608f82903d27d54898/config.capnp.
 * 561 Group, original paid issuer operation 2026-10-24, opportunity record
 * 2026-10-24-issuer-period-reconciliation.json: existing singleton only;
 * supplier owns reconciliation, provenance, selector and freshness semantics.
 * Cloudflare limits, docs observed 2026-10-24:
 * https://developers.cloudflare.com/durable-objects/platform/limits/;
 * existing cross-script binding only, no billable-capacity inference.
 * Red Cup Engineering async-contract, accepted caller contract at
 * c425608745ace8e864ba8e1df2fcd12058240f72, ./issuer-research-integration.md:
 * retain supplier Retry-After and full-only publication; no R2 writes.
 * Red Cup Engineering source-free, native deriveJsnodeModules,
 * fabricate-jsnode-closure.mjs: unchanged proposal requires independent
 * receiving at market.561.group/src/issuer-evidence-store.mjs.
 * Red Cup Engineering approved private cache contract 2026-10-24,
 * ./issuer-private-sqlite-cache.work-order.md, async-custody/atomic/overflow/
 * server/client/integration, and independent receiving correction 2026-10-24
 * async-status: server storage, atomic publication, durable overflow hold and
 * status validation remain server obligations; this module supplies readStore
 * only and never refreshes or changes retry policy. No private worker import,
 * external package, filesystem, process, environment, source acquisition,
 * OpenTask/credential access, arbitrary-key access, alarms, schedule, new
 * namespace, public route, migration or deployment.
 * Traceability: admission -> io-receiving; coordinates -> pure-receiving;
 * no-authority-expansion -> io-receiving, with all work-order constraints.
 * Pure examples qualify plans only. Independent memory and actual workerd
 * receiving across both services on the original singleton must separately
 * qualify async I/O, atomicity/rollback, durable retry and overflow reentry,
 * custody, routing, exact bytes, Unicode/limits/malformed transport, missing
 * and stale consumer behavior, native supplier path, existing commercial
 * tests and retained alarms. This source asserts no receiving success,
 * deployment, paid success or cost claim.
 */

/**
 * Derive the admitted private existing-singleton read coordinates without I/O.
 * @param {*} configuration Host configuration; extra trusted metadata is ignored.
 * @returns {null|{objectName:string,path:string,cacheKey:string,maximumCohortBytes:number}} The admitted plan, or null.
 */
export function issuerEvidenceReadPlan(configuration) {
  if (configuration == null || configuration.enabled !== true ||
      configuration.resourceAdmission?.status !== 'received') return null;
  const { cacheKey, maximumCohortBytes } = configuration;
  if (typeof cacheKey !== 'string' || cacheKey.length === 0 ||
      new TextEncoder().encode(cacheKey).byteLength > 256 ||
      cacheKey === 'registers/earning-loops/issuer-research.json' ||
      !Number.isSafeInteger(maximumCohortBytes) ||
      maximumCohortBytes <= 0 || maximumCohortBytes > 524288) {
    throw new TypeError('Invalid issuer cache configuration');
  }
  return { objectName: 'earning-loops', path: '/issuer-evidence', cacheKey, maximumCohortBytes };
}

function unavailable() {
  const error = new Error('Issuer revenue unavailable');
  error.code = 'issuer-revenue-unavailable';
  error.status = 503;
  error.retryable = true;
  return error;
}

async function cancelBody(body) {
  try {
    if (body != null && typeof body.cancel === 'function') await body.cancel();
  } catch {
    // Cancellation failure must not disclose transport errors.
  }
}

/**
 * Create the private streaming reader using the existing Durable Object binding.
 * The returned get rejects arbitrary keys before binding calls, never follows
 * redirects, and returns the original unconsumed stream with its bounded size.
 * @param {*} namespace Existing namespace exposing idFromName and get functions.
 * @param {*} configuration Host configuration admitted by issuerEvidenceReadPlan.
 * @returns {undefined|{get:(key:string)=>Promise<null|{body:ReadableStream,size:number}>}} A scoped read store, or undefined when not admitted.
 */
export function createIssuerEvidenceReadStore(namespace, configuration) {
  const plan = issuerEvidenceReadPlan(configuration);
  if (plan === null) return undefined;
  if (namespace == null || typeof namespace.idFromName !== 'function' ||
      typeof namespace.get !== 'function') {
    throw new TypeError('Invalid issuer namespace');
  }
  return {
    async get(key) {
      if (key !== plan.cacheKey) throw new TypeError('Invalid issuer cache key');
      try {
        const id = namespace.idFromName(plan.objectName);
        const stub = namespace.get(id);
        const url = new URL(plan.path, 'https://issuer-cache.invalid');
        url.search = new URLSearchParams({ key: plan.cacheKey }).toString();
        const response = await stub.fetch(new Request(url, {
          method: 'GET',
          redirect: 'manual'
        }));
        if (response.status === 404) {
          await cancelBody(response.body);
          return null;
        }
        if (response.status !== 200) {
          await cancelBody(response.body);
          throw unavailable();
        }
        const body = response.body;
        let length;
        let valid = false;
        try {
          const text = response.headers.get('Content-Length');
          length = Number(text);
          valid = body instanceof ReadableStream &&
            typeof text === 'string' && /^(0|[1-9][0-9]*)$/.test(text) &&
            Number.isSafeInteger(length) && length >= 0 &&
            String(length) === text && length <= plan.maximumCohortBytes;
        } catch {
          valid = false;
        }
        if (!valid) {
          await cancelBody(body);
          throw unavailable();
        }
        return { body, size: length };
      } catch {
        throw unavailable();
      }
    }
  };
}
