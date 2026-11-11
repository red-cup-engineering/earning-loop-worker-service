/**
 * issuer-private-sqlite-cache / src/issuer-evidence-store.mjs
 * ArtifactFabricationSpecification v2; projection jsnode-modules.
 * Source: earning-loop-worker-service/specifications/issuer-private-sqlite-cache.work-order.md,
 * lines 1–36; sha256:cd22c3850fe531977e567aba633bee94d08b07330001bc2025e82b1ab640070e.
 * Specification: ni:///sha-256;xqZBnu3XnJj6OIUarAaerOfphyiKDpBCJ8pFBehZEc4.
 *
 * Normative scope and traceability:
 * admission (line 3), coordinates (line 4), and no-authority-expansion
 * (line 6) apply to this module under all declared constraint IDs:
 * async-atomic, async-client, async-contract, async-custody, async-integration,
 * async-overflow, async-server, async-status, byte-custody, house-operation,
 * source-free, sqlite-platform. Server storage, publication, overflow and
 * status validation obligations belong to src/issuer-sqlite-cache.mjs; this
 * module neither implements nor bypasses them.
 *
 * byte-custody: IETF, RFC9110, https://www.rfc-editor.org/rfc/rfc9110;
 * private GET preserves representation bytes and length, with no refresh.
 * house-operation: 561 Group, original paid issuer operation 2026-10-24,
 * opportunity-records/2026-10-24-issuer-period-reconciliation.json; the
 * approved singleton serves a trusted complete annual AAPL/MSFT cohort.
 * Supplier owns reconciliation, provenance, selection and freshness. No
 * request-driven SEC acquisition or unadmitted incremental cash is granted.
 * sqlite-platform: Cloudflare, docs observed 2026-10-24,
 * https://developers.cloudflare.com/durable-objects/platform/limits/;
 * existing EarningClock namespace and singleton only. The server's 1900000
 * serialized-byte ceiling is below the SQLite 2MB row limit and implies no
 * billable headroom.
 * async-contract: Red Cup Engineering, accepted issuer caller contract at
 * c425608745ace8e864ba8e1df2fcd12058240f72, ./issuer-research-integration.md;
 * preserve Retry-After and full-only publication; no R2 writes.
 * source-free: Red Cup Engineering, native deriveJsnodeModules,
 * computer-code-development-engine/scripts/fabricate-jsnode-closure.mjs;
 * unchanged native proposal requires independent receiving before wiring.
 * async-custody/atomic/overflow/server/client/integration: Red Cup Engineering,
 * approved private cache contract 2026-10-24,
 * ./issuer-private-sqlite-cache.work-order.md, lines 14–19; mandatory full
 * async interfaces require independent I/O qualification. This module
 * implements async-client using real admitted transport coordinates only.
 * async-status: Red Cup Engineering, independent receiving correction
 * 2026-10-24, same locator, line 20; coordinator retry policy and durable
 * fail-closed status remain server/supplier responsibilities.
 *
 * Final owner: market.561.group/src/issuer-evidence-store.mjs, received as
 * the exact proposal without a new package or private worker dependency.
 * Existing external namespace/class/script and earning-loops singleton
 * must be bound by the host; inject this readStore only, never refresh.
 * No public cache/refresh route, acquisition, OpenTask/credential access,
 * arbitrary key, alarm mutation, namespace, migration, schedule, external
 * dependency or deployment. Existing run/tick, public routes, OpenTask
 * custody and maintenance remain intact.
 *
 * Receiving obligations (lines 30–32): pure-receiving checks admitted,
 * disabled, unreceived and invalid plans without effects; it qualifies
 * plans only. io-receiving separately requires independent memory and real
 * workerd tests across the two services on the original singleton: deferred
 * producer/prior value, atomic publication/rollback, failed source and
 * serialization, literal long Retry-After reentry, overflow sentinel reentry
 * without acquisition, only two server physical keys, no OpenTask/alarm
 * mutation, exact logical key, GET405/wrong-query/public404/disabled404,
 * original bytes/length, Unicode/limits/overflow/malformed transport,
 * missing/stale consumer503, native prepared producer/read supplier path,
 * and retained commercial tests/current alarm. No deployment, paid success
 * or cost claim follows from this proposal. Admission and prohibition trace
 * to io-receiving; coordinates trace to pure-receiving.
 */

/**
 * Admit host configuration and return the exact private singleton read plan.
 * Additional trusted metadata is ignored; admission grants no source authority.
 * @param {*} configuration Host configuration, without reshaping its input.
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
    throw new TypeError('Invalid issuer evidence configuration');
  }
  return { objectName: 'earning-loops', path: '/issuer-evidence',
    cacheKey, maximumCohortBytes };
}

function unavailable() {
  return Object.assign(new Error('Issuer evidence unavailable'), {
    code: 'issuer-revenue-unavailable', status: 503, retryable: true
  });
}

async function cancelBody(body) {
  try {
    if (body != null && typeof body.cancel === 'function') await body.cancel();
  } catch { /* Cancellation cannot disclose or replace the transport error. */ }
}

/**
 * Create a private stream-only reader using the existing admitted namespace.
 * Reads accept only the configured key and never consume or cache the stream.
 * @param {*} namespace Existing Durable Object namespace with idFromName/get.
 * @param {*} configuration Trusted host admission configuration.
 * @returns {undefined|{get:(key:*)=>Promise<null|{body:ReadableStream,size:number}>}} A scoped read store, or undefined when unadmitted.
 */
export function createIssuerEvidenceReadStore(namespace, configuration) {
  const plan = issuerEvidenceReadPlan(configuration);
  if (plan === null) return undefined;
  if (namespace == null || typeof namespace.idFromName !== 'function' ||
      typeof namespace.get !== 'function') {
    throw new TypeError('Invalid issuer evidence namespace');
  }
  return {
    async get(key) {
      if (key !== plan.cacheKey) {
        throw new TypeError('Issuer evidence key is not admitted');
      }
      let body;
      try {
        const id = namespace.idFromName(plan.objectName);
        const stub = namespace.get(id);
        const url = new URL(plan.path, 'https://issuer-cache.invalid');
        url.search = new URLSearchParams({ key: plan.cacheKey }).toString();
        const response = await stub.fetch(new Request(url, {
          method: 'GET', redirect: 'error'
        }));
        if (response.status === 404) return null;
        if (response.status !== 200) throw unavailable();
        body = response.body;
        const rawLength = response.headers.get('Content-Length');
        if (!(body instanceof ReadableStream) ||
            typeof rawLength !== 'string' ||
            !/^(0|[1-9][0-9]*)$/.test(rawLength)) {
          throw unavailable();
        }
        const size = Number(rawLength);
        if (!Number.isSafeInteger(size) || size < 0 ||
            size > plan.maximumCohortBytes) throw unavailable();
        return { body, size };
      } catch {
        await cancelBody(body);
        throw unavailable();
      }
    }
  };
}
