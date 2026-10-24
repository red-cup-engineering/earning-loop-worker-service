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
import { receiveSettlements } from "../src/settlements.mjs";
import { checkRoutes } from "../src/route-health.mjs";
import { writeScorecard } from "../src/scorecard.mjs";
import { writeDirectives } from "../src/price-directives.mjs";
import { runOnchainHook } from "../src/onchain-hook.mjs";
import { register, read, put } from "../src/registers.mjs";
import { dueCrons, nextTick } from "../src/clock.mjs";

const groupPayers = new Set(groupPayerList);
export const CRONS = operation.crons;

export async function run(env, cron, now = new Date()) {
  const outcome = { cron, at: now.toISOString() };
  const step = async (name, work) => {
    try { outcome[name] = await work(); } catch (error) { outcome[name] = { error: error.message }; }
  };
  if (cron === CRONS.directives) await step("directives", () => writeDirectives(env, { now, groupPayers }));
  else if (cron === CRONS.scorecard) await step("scorecard", async () => (await writeScorecard(env, { now, groupPayers, economics: operation.economics })).outsideRevenueUSD);
  else {
    await step("settlements", () => receiveSettlements(env, { now, groupPayers, limit: operation.limits.settlementsPerPass }));
    await step("routes", () => checkRoutes(env, { now, catalogUrl: operation.catalogUrl, limit: operation.limits.routeProbesPerPass,
      brokenStreak: operation.repair.brokenStreakBeforeRepair, repository: operation.repair.repository }));
    await step("onchain", () => runOnchainHook(env, { now, cron, url: env.ONCHAIN_SCAN_URL ?? operation.onchainScanUrl }));
  }
  await put(env.STATE, register("last-run"), outcome);
  return outcome;
}

const READINGS = { "/settlements.json": "settlements", "/route-health.json": "route-health", "/scorecard.json": "scorecard",
  "/price-directives.json": "price-directives", "/onchain.json": "onchain", "/last-run.json": "last-run" };

// Run every loop whose operation cron matches this quarter-hour tick, the most frequent last so the daily and
// weekly readings come from the previous pass's settled state.
export async function tick(env, date) {
  const due = dueCrons(CRONS, date).sort((a, b) => (a === CRONS.pass) - (b === CRONS.pass));
  const outcomes = [];
  for (const cron of due) outcomes.push(await run(env, cron, date));
  return outcomes;
}

export class EarningClock {
  constructor(state, env) { this.state = state; this.env = env; }
  async alarm() {
    const at = Date.now(), slot = new Date(Math.round(at / 60_000) * 60_000);
    try { await tick(this.env, slot); } finally { await this.state.storage.setAlarm(nextTick(at)); }
  }
  async fetch() {
    let alarm = await this.state.storage.getAlarm();
    if (!alarm) { alarm = nextTick(Date.now()); await this.state.storage.setAlarm(alarm); }
    return Response.json({ nextTick: new Date(alarm).toISOString() });
  }
}

export default {
  async scheduled(event, env, context) { context.waitUntil(run(env, event.cron)); },
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
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
