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
import { runCommercialPass } from "../src/opentask-commercial-pass.mjs";
import { receiveSettlements } from "../src/settlements.mjs";
import { checkRoutes } from "../src/route-health.mjs";
import { writeScorecard } from "../src/scorecard.mjs";
import { writeDirectives } from "../src/price-directives.mjs";
import { runOnchainHook } from "../src/onchain-hook.mjs";
import { register, read, put } from "../src/registers.mjs";
import { dueCrons, nextTick } from "../src/clock.mjs";
import { refreshIssuerResearch } from "../src/issuer-research.mjs";

const groupPayers = new Set(groupPayerList);
export const CRONS = operation.crons;

export async function run(env, cron, now = new Date(), { configuration = operation, prepareIssuerRevenueCohort } = {}) {
  if (configuration.issuerResearch && (env.ONCHAIN_SCAN_URL || configuration.onchainScanUrl))
    throw new TypeError('issuer operation has no subrequest allocation for an onchain hook');
  const outcome = { cron, at: now.toISOString() };
  const step = async (name, work) => {
    try { outcome[name] = await work(); } catch (error) { outcome[name] = { error: error.message }; }
  };
  if (cron === configuration.crons.directives) await step("directives", () => writeDirectives(env, { now, groupPayers }));
  else if (cron === configuration.crons.scorecard) await step("scorecard", async () => (await writeScorecard(env, { now, groupPayers, economics: configuration.economics })).outsideRevenueUSD);
  else {
    await step("settlements", () => receiveSettlements(env, { now, groupPayers, limit: configuration.limits.settlementsPerPass }));
    await step("routes", () => checkRoutes(env, { now, catalogUrl: configuration.catalogUrl, limit: configuration.limits.routeProbesPerPass,
      brokenStreak: configuration.repair.brokenStreakBeforeRepair, repository: configuration.repair.repository, payTo: configuration.merchantPayTo }));
    await step("scorecard", async () => (await writeScorecard(env, { now, groupPayers, economics: configuration.economics })).outsideRevenueUSD);
    await step("onchain", () => runOnchainHook(env, { now, cron, url: env.ONCHAIN_SCAN_URL ?? configuration.onchainScanUrl }));
    if (configuration.issuerResearch) await step("issuerResearch", () => refreshIssuerResearch(env, configuration.issuerResearch, { now, prepare: prepareIssuerRevenueCohort }));
  }
  await put(env.STATE, register("last-run"), outcome);
  return outcome;
}

const READINGS = { "/settlements.json": "settlements", "/route-health.json": "route-health", "/scorecard.json": "scorecard",
  "/price-directives.json": "price-directives", "/onchain.json": "onchain", "/last-run.json": "last-run", "/issuer-research.json": "issuer-research" };

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
      const at = Date.now(), commercial = configuration.commercial?.enabled === true;
      const slot = commercial ? Math.round(at / 450000) * 450000 : Math.round(at / 60000) * 60000;
      const releaseId = commercial ? this.releaseId() : null;
      const bootstrap = releaseId && await this.state.storage.get('earning-clock/observed-release-id') !== releaseId;
      const armed = bootstrap ? await this.state.storage.get('earning-clock/armed-release') : null;
      // Admission is durable before work: public clock arming cannot replay it.
      if (bootstrap) await this.state.storage.put('earning-clock/observed-release-id', releaseId);
      try {
        if (bootstrap || commercial && slot % 900000 !== 0) {
          const result = await (this.options.commercialPass ?? runCommercialPass)({ storage: this.state.storage, initialCredential: this.env.OPENTASK_CREDENTIAL_JSON,
            instance: configuration.commercial, products: this.options.products ?? products, merchant: configuration.merchantPayTo, now: new Date(at) });
          await this.state.storage.put('opentask/public-summary', { stage: result.stage, requests: result.requests,
            newCashExpenseUsd: 0, at: new Date(at).toISOString() });
        } else await tick(this.env, new Date(slot), this.options);
      } finally {
        let alarm = commercial ? (Math.floor(at / 450000) + 1) * 450000 : nextTick(at);
        if (bootstrap && armed?.id === releaseId && Number.isFinite(armed.previousAlarm))
          alarm = Math.min(alarm, armed.previousAlarm > Date.now() ? armed.previousAlarm : Date.now() + 1000);
        await this.state.storage.setAlarm(alarm);
      }
    });
  }
  async fetch(request) {
    if (request && new URL(request.url).pathname === '/commercial.json') {
      const summary = await this.state.storage.get('opentask/public-summary');
      if (!summary) return new Response('not yet observed\n', { status: 404 });
      const alarm = await this.state.storage.getAlarm();
      return Response.json({ stage: summary.stage, requests: summary.requests, newCashExpenseUsd: 0,
        at: summary.at, nextTick: alarm ? new Date(alarm).toISOString() : null }, { headers: { 'cache-control': 'no-store' } });
    }
    return this.enqueue(async () => {
      let alarm = await this.state.storage.getAlarm();
      const at = Date.now(), commercial = (this.options.configuration ?? operation).commercial?.enabled;
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

export default {
  async scheduled(event, env, context) { context.waitUntil(run(env, event.cron)); },
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (path === "/products.json") return Response.json(products, { headers: { "cache-control": "public, max-age=300" } });
    if (path === '/commercial.json' && env.CLOCK) return env.CLOCK.get(env.CLOCK.idFromName('earning-loops')).fetch(request);
    if (path === "/clock" && env.CLOCK) return env.CLOCK.get(env.CLOCK.idFromName("earning-loops")).fetch(request);
    if (READINGS[path]) {
      const value = await read(env.STATE, register(READINGS[path]));
      return value ? Response.json(value, { headers: { "cache-control": "no-store" } }) : new Response("not yet observed\n", { status: 404 });
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
};
