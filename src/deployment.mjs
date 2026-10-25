import { hashnInstanceProblem } from './hashn-acquisition.mjs';
import { issuerSettlementCustodyPlan } from './issuer-settlement-custody.mjs';

export function projectOperation(record, { excludeIssuerResearch = false } = {}) {
  if (typeof excludeIssuerResearch !== 'boolean') throw new TypeError('issuer release selection must be boolean');
  if (typeof record.merchantPayTo !== 'string' || !/^0x[\da-f]{40}$/i.test(record.merchantPayTo))
    throw new TypeError('operation.merchantPayTo must name the independently authorized merchant recipient');
  const operation = { worker: record.worker, crons: record.crons, limits: record.limits, buckets: record.buckets, catalogUrl: record.catalogUrl,
    economics: record.economics, merchantPayTo: record.merchantPayTo, clock: record.clock ?? 'cron-triggers',
    repair: { brokenStreakBeforeRepair: record.repair.brokenStreakBeforeRepair, repository: record.repair.repository }, onchainScanUrl: record.onchainScanUrl };
  if (!excludeIssuerResearch && record.issuerResearch?.enabled === true && record.issuerResearch.resourceAdmission?.status === 'received') {
    if (operation.clock !== 'durable-object-alarm')
      throw new TypeError('issuer operation requires serialized private Durable Object custody');
    const n = record.issuerResearch.issuers?.length;
    const routes = record.limits?.routeProbesPerPass, witnesses = record.limits?.settlementsPerPass;
    if (!Number.isInteger(n) || n < 2 || n > 5 || !Number.isInteger(routes) || routes < 0 || routes + n > 5
      || !Number.isInteger(witnesses) || witnesses < 0 || witnesses > 4 || record.repair.repository || record.onchainScanUrl)
      throw new TypeError('issuer operation exceeds its qualified subrequest allocation (47 per coincident tick, plus clock)');
    operation.issuerResearch = record.issuerResearch;
  }
  if (record.issuerSettlements?.enabled === true && record.issuerSettlements.resourceAdmission?.status === 'received') {
    const custody = issuerSettlementCustodyPlan(record.issuerSettlements);
    if (operation.clock !== 'durable-object-alarm' || custody.payTo !== record.merchantPayTo.toLowerCase())
      throw new TypeError('issuer financial custody requires the original private clock and merchant recipient');
    operation.issuerSettlements = record.issuerSettlements;
  }
  if (record.commercial) {
    if (record.commercial.enabled && operation.clock !== 'durable-object-alarm')
      throw new TypeError('commercial operation requires serialized private Durable Object custody');
    operation.commercial = record.commercial;
  }
  if (record.researchProcurement) {
    if (record.researchProcurement.enabled && operation.clock !== 'durable-object-alarm')
      throw new TypeError('research procurement requires serialized private Durable Object custody');
    operation.researchProcurement = record.researchProcurement;
  }
  if (record.hashAcquisition) {
    if (record.hashAcquisition.enabled && (operation.clock !== 'durable-object-alarm' || hashnInstanceProblem(record.hashAcquisition)))
      throw new TypeError('Hashn acquisition requires private singleton custody and a qualified zero-cash bounded instance');
    operation.hashAcquisition = record.hashAcquisition;
  }
  // An Operations-defined, source-limited public market observation rides
  // this SAME self-arming clock. No fresh timer, merchant, signer or provider
  // credentials; the directory reader only performs bounded public GETs.
  if (record.agentMarketIntelligence !== undefined) {
    const plan = record.agentMarketIntelligence;
    if (plan === null || typeof plan !== "object" || Array.isArray(plan) ||
        typeof plan.enabled !== "boolean")
      throw new TypeError("agent market intelligence requires a typed enablement choice");
    if (plan.enabled === true) {
      const queries = plan.queries;
      if (operation.clock !== "durable-object-alarm" ||
          typeof record.crons?.directives !== "string" || !record.crons.directives.trim() ||
          plan.ownHost !== "market.561.group" ||
          !Array.isArray(queries) || queries.length < 1 || queries.length > 6 ||
          queries.some(q => typeof q !== "string" || q.length < 5 || q.length > 160 ||
            q.trim() !== q || /[\\r\\n\\0]/u.test(q)) ||
          new Set(queries).size !== queries.length ||
          !Number.isSafeInteger(plan.limit) || plan.limit < 1 || plan.limit > 30)
        throw new TypeError("agent market scan requires original alarm, bounded buyer tasks and this seller");
      operation.agentMarketIntelligence = {
        enabled: true, ownHost: plan.ownHost, queries: [...queries], limit: plan.limit
      };
    }
  }
  return operation;
}

export function deploymentMetadata(operation, existing = {}) {
  const bindings = new Map((existing.bindings ?? []).filter(b => b.type !== 'secret_text').map(b => [b.name, b]));
  bindings.set('STATE', { type: 'r2_bucket', name: 'STATE', bucket_name: operation.buckets.state });
  bindings.set('MARKET_SETTLEMENTS', { type: 'r2_bucket', name: 'MARKET_SETTLEMENTS', bucket_name: operation.buckets.settlementWitnesses });
  bindings.set('RELEASE_METADATA', { type: 'version_metadata', name: 'RELEASE_METADATA' });
  const metadata = { main_module: 'worker.mjs', compatibility_date: existing.compatibility_date ?? '2026-09-01',
    compatibility_flags: [...new Set([...(existing.compatibility_flags ?? []), 'nodejs_compat'])],
    bindings: [...bindings.values()], keep_bindings: ['secret_text'] };
  if (operation.clock === 'durable-object-alarm' && !bindings.has('CLOCK')) {
    metadata.bindings.push({ type: 'durable_object_namespace', name: 'CLOCK', class_name: 'EarningClock' });
    metadata.migrations = { new_tag: 'v1', new_sqlite_classes: ['EarningClock'] };
  }
  return metadata;
}
