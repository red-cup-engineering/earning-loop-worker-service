// Earning loops as one Cloudflare Worker: crons no house machine has to keep alive. The operating parameters
// (crons, limits, catalog, economics, repair target) come from the Operations record the deploy compiles into
// data/operation.mjs; the committed default mirrors Coesite's earning-loops operation.
//   pass        receive and corroborate seller settlements, check that listed offers are buyable, and run the
//               on-chain engine's scan hook;
//   directives  propose price directives from what buyers revealed (the self-adjusting loop);
//   scorecard   write the weekly earnings scorecard.
// GET / answers 503 while any listed offer is unbuyable, so an uptime checker alerts on a lost sale.
import operation from "../data/operation.mjs";
import groupPayerList from "../data/group-payers.mjs";
import products from "../data/products.mjs";
import researchProducts from '../data/research-products.mjs';
import { runResearchPass, RESEARCH_STATE, RESEARCH_SUMMARY } from '../src/ln-church-research.mjs';
import { runCommercialPass } from "../src/opentask-commercial-pass.mjs";
import { runHashnAcquisition, hashnSchemaReadbackDue, HASHN_STATE, HASHN_SUMMARY } from '../src/hashn-acquisition.mjs';
import { receiveSettlements, witnessProblem, corroborate, usdc, BASE_PROVIDERS } from "../src/settlements.mjs";
import { checkRoutes } from "../src/route-health.mjs";
import { writeScorecard } from "../src/scorecard.mjs";
import { writeDirectives } from "../src/price-directives.mjs";
import { runOnchainHook, onchainPublicReading } from "../src/onchain-hook.mjs";
import { register, read, put } from "../src/registers.mjs";
import { dueCrons, nextTick } from "../src/clock.mjs";
import { refreshIssuerResearch } from "../src/issuer-research.mjs";
import { withIssuerSqliteStore, issuerSqliteResponse } from "../src/issuer-sqlite-cache.mjs";
import { receiveIssuerSettlements, issuerSettlementResponse } from '../src/issuer-settlement-custody.mjs';

const groupPayers = new Set(groupPayerList);
const issuerSettlementAdapters = Object.freeze({ witnessProblem, corroborate, usdc,
  BASE_PROVIDERS: Object.freeze([...BASE_PROVIDERS]), groupPayers });
export const CRONS = operation.crons;

export async function run(env, cron, now = new Date(), { configuration = operation, prepareIssuerRevenueCohort, issuerStorage, withOnchain } = {}) {
  if (withOnchain !== undefined && typeof withOnchain !== 'function') throw new TypeError('Original resource selection is a private host function');
  if (configuration.issuerResearch && (withOnchain || env.ONCHAIN_SCAN_URL || configuration.onchainScanUrl))
    throw new TypeError('issuer operation has no subrequest allocation for an onchain hook');
  const outcome = { cron, at: now.toISOString() };
  const step = async (name, work) => {
    try { outcome[name] = await work(); } catch (error) {
      outcome[name] = { error: name === 'onchain' ? 'original-onchain-custody-unconfirmed' : error.message };
    }
  };
  if (cron === configuration.crons.directives) await step("directives", () => writeDirectives(env, { now, groupPayers }));
  else if (cron === configuration.crons.scorecard) await step("scorecard", async () => (await writeScorecard(env, { now, groupPayers, economics: configuration.economics })).outsideRevenueUSD);
  else {
    await step("settlements", () => receiveSettlements(env, { now, groupPayers, limit: configuration.limits.settlementsPerPass }));
    await step("routes", () => checkRoutes(env, { now, catalogUrl: configuration.catalogUrl, limit: configuration.limits.routeProbesPerPass,
      brokenStreak: configuration.repair.brokenStreakBeforeRepair, repository: configuration.repair.repository, payTo: configuration.merchantPayTo }));
    await step("scorecard", async () => (await writeScorecard(env, { now, groupPayers, economics: configuration.economics })).outsideRevenueUSD);
    await step("onchain", () => {
      const receive = onchain => runOnchainHook(env, { now, cron, onchain, url: env.ONCHAIN_SCAN_URL ?? configuration.onchainScanUrl });
      return withOnchain ? withOnchain(Object.freeze({ at: now.toISOString(), cron }), receive) : receive();
    });
    if (configuration.issuerResearch) await step("issuerResearch", () => withIssuerSqliteStore(issuerStorage, configuration.issuerResearch,
      store => refreshIssuerResearch(store, configuration.issuerResearch, { now, prepare: prepareIssuerRevenueCohort })));
  }
  const { issuerResearch, ...publicOutcome } = outcome;
  await put(env.STATE, register("last-run"), publicOutcome);
  return outcome;
}

const READINGS = { "/settlements.json": "settlements", "/route-health.json": "route-health", "/scorecard.json": "scorecard",
  "/price-directives.json": "price-directives", "/onchain.json": "onchain", "/last-run.json": "last-run" };

// Run every loop whose operation cron matches this quarter-hour tick, the most frequent last so the daily and
// weekly readings come from the previous pass's settled state.
export async function tick(env, date, options = {}) {
  const crons = (options.configuration ?? operation).crons;
  const due = dueCrons(crons, date).sort((a, b) => (a === crons.pass) - (b === crons.pass));
  const outcomes = [];
  for (const cron of due) outcomes.push(await run(env, cron, date, options));
  return outcomes;
}

export class EarningClock {
  constructor(state, env, options = {}) { this.state = state; this.env = env; this.options = options; this.queue = Promise.resolve(); }
  enqueue(work) {
    const task = this.queue.then(work);
    this.queue = task.catch(() => {});
    return task;
  }
  releaseId() { const id = this.env.RELEASE_METADATA?.id; return typeof id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(id) ? id : null; }
  async alarm() {
    return this.enqueue(async () => {
      const configuration = this.options.configuration ?? operation;
      const acquisition = configuration.hashAcquisition?.enabled === true;
      const financial = configuration.issuerSettlements?.enabled === true && configuration.issuerSettlements.resourceAdmission?.status === 'received';
      const at = Date.now(), commercial = configuration.commercial?.enabled === true || configuration.researchProcurement?.enabled === true || acquisition || financial;
      const acquisitionState = acquisition ? await this.state.storage.get(HASHN_STATE) : null;
      const acquisitionPulseAt = acquisition ? await this.state.storage.get('hashn/next-pulse-at') : null;
      const acquisitionDue = acquisition && !acquisitionState?.terminal && !acquisitionState?.retryBlocked && !(acquisitionState?.retryAt > at) &&
        (hashnSchemaReadbackDue(acquisitionState,at) || !(acquisitionState?.nextAttemptAt > at) && !(acquisitionPulseAt > at));
      const coreNextAt = acquisition ? await this.state.storage.get('earning-clock/core-next-at') : null;
      const researchState = configuration.researchProcurement?.enabled ? await this.state.storage.get(RESEARCH_STATE) : null;
      const researchPending = configuration.researchProcurement?.enabled === true && !researchState?.terminal;
      const researchDue = researchPending && !researchState?.retryBlocked && !(researchState?.nextAttemptAt > at);
      const slot = commercial ? Math.round(at / 450000) * 450000 : Math.round(at / 60000) * 60000;
      const releaseId = commercial ? this.releaseId() : null;
      const bootstrap = releaseId && await this.state.storage.get('earning-clock/observed-release-id') !== releaseId;
      const armed = bootstrap ? await this.state.storage.get('earning-clock/armed-release') : null;
      // Acquisition gets a separate invocation only AFTER a core invocation has
      // reserved its next alarm. A due knock can never displace CSV/maintenance.
      const acquisitionOnly = acquisitionDue && !bootstrap && !researchDue && Number.isFinite(coreNextAt) && at < coreNextAt;
      // Admission is durable before work: public clock arming cannot replay it.
      if (bootstrap) await this.state.storage.put('earning-clock/observed-release-id', releaseId);
      try {
        if (acquisitionOnly) {
          // A storage/transport failure must not turn a one-off acquisition
          // into a one-second retry loop. Reserve the six-hour pulse first.
          await this.state.storage.put('hashn/next-pulse-at',at+21600000);
          await (this.options.acquisitionPass ?? runHashnAcquisition)({ storage: this.state.storage,
            instance: configuration.hashAcquisition, initialCredential: this.env.HASHN_CREDENTIAL_JSON, now: () => at });
          const received = await this.state.storage.get(HASHN_STATE);
          if (Number.isFinite(received?.nextAttemptAt) && received.nextAttemptAt > at)
            await this.state.storage.put('hashn/next-pulse-at',received.nextAttemptAt);
        } else if (bootstrap || researchDue || commercial && slot % 900000 !== 0) {
          if (researchDue || bootstrap && researchPending) {
            await (this.options.researchPass ?? runResearchPass)({ storage: this.state.storage, instance: configuration.researchProcurement,
              products: this.options.researchProducts ?? researchProducts, merchant: configuration.merchantPayTo, groupPayers });
          } else if (configuration.commercial?.enabled) {
            const result = await (this.options.commercialPass ?? runCommercialPass)({ storage: this.state.storage, initialCredential: this.env.OPENTASK_CREDENTIAL_JSON,
            instance: configuration.commercial, products: this.options.products ?? products, merchant: configuration.merchantPayTo, now: new Date(at) });
            await this.state.storage.put('opentask/public-summary', { stage: result.stage, requests: result.requests,
            newCashExpenseUsd: 0, at: new Date(at).toISOString(), ...(result.taskId ? { taskId: result.taskId, productId: result.productId } : {}) });
          }
          if (financial && !bootstrap && !researchDue && slot % 900000 !== 0)
            await (this.options.issuerSettlementPass ?? receiveIssuerSettlements)(this.state.storage,
              configuration.issuerSettlements, issuerSettlementAdapters);
        } else await tick(this.env, new Date(slot), { ...this.options, issuerStorage: this.state.storage });
      } finally {
        let alarm = acquisitionOnly ? coreNextAt : commercial ? (Math.floor(at / 450000) + 1) * 450000 : nextTick(at);
        if (bootstrap && armed?.id === releaseId && Number.isFinite(armed.previousAlarm))
          alarm = Math.min(alarm, armed.previousAlarm > Date.now() ? armed.previousAlarm : Date.now() + 1000);
        if (acquisition && !acquisitionOnly) await this.state.storage.put('earning-clock/core-next-at',alarm);
        if (configuration.researchProcurement?.enabled) {
          const pending = await this.state.storage.get(RESEARCH_STATE);
          if (!pending?.terminal && !pending?.retryBlocked && Number.isFinite(pending?.nextAttemptAt))
            alarm = Math.min(alarm, Math.max(Date.now() + 1000,pending.nextAttemptAt));
        }
        if (acquisition) {
          const pending = await this.state.storage.get(HASHN_STATE);
          const pulseAt = await this.state.storage.get('hashn/next-pulse-at');
          if (!pending?.terminal && !pending?.retryBlocked)
            alarm = Math.min(alarm,hashnSchemaReadbackDue(pending,Date.now()) ? Date.now()+1000 :
              Math.max(Date.now()+1000,pending?.nextAttemptAt ?? 0,pulseAt ?? 0,pending?.retryAt ?? 0));
        }
        await this.state.storage.setAlarm(alarm);
      }
    });
  }
  async fetch(request) {
    if (request && new URL(request.url).pathname === '/issuer-settlement-witness')
      return this.enqueue(() => issuerSettlementResponse(request, this.state.storage,
        (this.options.configuration ?? operation).issuerSettlements));
    if (request && new URL(request.url).pathname === '/acquisition.json') {
      const summary = await this.state.storage.get(HASHN_SUMMARY);
      if (!summary) return new Response('not yet observed\n',{status:404});
      const fields = ['stage','requests','newCashExpenseUsd','at','offerId','knockStatus','agreementReceived','deliverySubmitted','recognizedOutsideRevenue'];
      return Response.json(Object.fromEntries(fields.filter(key => Object.hasOwn(summary,key)).map(key => [key,summary[key]])),{headers:{'cache-control':'no-store'}});
    }
    if (request) {
      const response = await issuerSqliteResponse(request, this.state.storage, (this.options.configuration ?? operation).issuerResearch);
      if (response) return response;
    }
    if (request && new URL(request.url).pathname === '/research.json') {
      const summary = await this.state.storage.get(RESEARCH_SUMMARY);
      if (!summary) return new Response('not yet observed\n',{status:404});
      const fields = ['stage','requests','newCashExpenseUsd','at','taskId','productId','receiptAccepted','evaluationState','approvedAmountAtomic','providerPayoutState','payoutTx','independentlyVerifiedCashAtomic','recognizedOutsideRevenue'];
      const alarm = await this.state.storage.getAlarm();
      return Response.json({ ...Object.fromEntries(fields.filter(key => Object.hasOwn(summary,key)).map(key => [key,summary[key]])),nextTick:alarm ? new Date(alarm).toISOString() : null },{headers:{'cache-control':'no-store'}});
    }
    if (request && new URL(request.url).pathname === '/commercial.json') {
      const summary = await this.state.storage.get('opentask/public-summary');
      if (!summary) return new Response('not yet observed\n', { status: 404 });
      const alarm = await this.state.storage.getAlarm();
      return Response.json({ stage: summary.stage, requests: summary.requests, newCashExpenseUsd: 0,
        at: summary.at, taskId: summary.taskId, productId: summary.productId, nextTick: alarm ? new Date(alarm).toISOString() : null }, { headers: { 'cache-control': 'no-store' } });
    }
    return this.enqueue(async () => {
      let alarm = await this.state.storage.getAlarm();
      const configuration = this.options.configuration ?? operation;
      const at = Date.now(), commercial = configuration.commercial?.enabled || configuration.researchProcurement?.enabled || configuration.hashAcquisition?.enabled
        || configuration.issuerSettlements?.enabled === true && configuration.issuerSettlements.resourceAdmission?.status === 'received';
      const releaseId = commercial ? this.releaseId() : null;
      if (releaseId && await this.state.storage.get('earning-clock/observed-release-id') !== releaseId) {
        const armed = await this.state.storage.get('earning-clock/armed-release');
        if (armed?.id !== releaseId) {
          await this.state.storage.put('earning-clock/armed-release', { id: releaseId, previousAlarm: alarm ?? null });
          alarm = at + 1000;
          await this.state.storage.setAlarm(alarm);
        }
      }
      if (!alarm) { alarm = commercial ? (Math.floor(at / 450000) + 1) * 450000 : nextTick(at); await this.state.storage.setAlarm(alarm); }
      return Response.json({ nextTick: new Date(alarm).toISOString() });
    });
  }
}

export function createEarningWorker({ withOnchain } = {}) { return {
  async scheduled(event, env, context) {
    if (!Number.isFinite(event.scheduledTime)) throw new TypeError('Original scheduled occurrence is required');
    context.waitUntil(run(env, event.cron, new Date(event.scheduledTime), { withOnchain }));
  },
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (path === "/products.json") return Response.json(products, { headers: { "cache-control": "public, max-age=300" } });
    if (path === '/research-products.json') return Response.json(researchProducts,{headers:{'cache-control':'public, max-age=300'}});
    if (path === '/research.json' && env.CLOCK) return env.CLOCK.get(env.CLOCK.idFromName('earning-loops')).fetch(request);
    if (path === '/commercial.json' && env.CLOCK) return env.CLOCK.get(env.CLOCK.idFromName('earning-loops')).fetch(request);
    if (path === '/acquisition.json' && env.CLOCK) return env.CLOCK.get(env.CLOCK.idFromName('earning-loops')).fetch(request);
    if (path === "/clock" && env.CLOCK) return env.CLOCK.get(env.CLOCK.idFromName("earning-loops")).fetch(request);
    if (READINGS[path]) {
      const value = await read(env.STATE, register(READINGS[path]));
      return value ? Response.json(path === '/onchain.json' ? onchainPublicReading(value) : value, { headers: { "cache-control": "no-store" } }) : new Response("not yet observed\n", { status: 404 });
    }
    if (path !== "/") return new Response("not found\n", { status: 404 });
    const [health, card, last] = await Promise.all(["route-health", "scorecard", "last-run"].map((name) => read(env.STATE, register(name))));
    if (!health) return new Response("no observations yet\n", { status: 503 });
    const broken = Object.entries(health.routes).filter(([, r]) => r.held === false && !r.delistedAt);
    const lines = [
      `${health.held} buyable, ${health.broken} unbuyable listed offers, as of ${health.at}`,
      card ? `outside revenue: USD ${card.outsideRevenueUSD.week} this week, USD ${card.outsideRevenueUSD.trailing30} trailing 30 days (goal USD ${card.targetsUSDPerDay.goal}/day); mode ${card.mode}` : "no scorecard yet",
      last ? `last pass ${last.at} (${last.cron})` : "",
      "", ...broken.map(([route, r]) => `UNBUYABLE  ${route}: ${r.finding}`),
    ];
    return new Response(`${lines.join("\n")}\n`, { status: broken.length ? 503 : 200, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
  },
}; }
export default createEarningWorker();
