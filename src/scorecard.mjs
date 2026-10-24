// The weekly earnings scorecard, computed from corroborated chain receipts rather than from a ledger a house
// machine has to update. Payers are classified with the current Group payer list at read time, so a wallet
// later found to be the Group's stops counting as revenue everywhere at once.
import { register, record, read, put } from "./registers.mjs";

export const BURN_USD_PER_MONTH = 600, FLOOR_USD_PER_DAY = 20, GOAL_USD_PER_DAY = 200;
const DAY = 86_400_000;

export function mode(ratio, retainedSurplus = 0) {
  if (ratio >= 1) return retainedSurplus > 0 ? "building-runway" : "self-funding";
  return ratio >= 0.1 ? "climbing" : "starving";
}

export const DEFAULT_ECONOMICS = { burnUsdPerMonth: BURN_USD_PER_MONTH, floorUsdPerDay: FLOOR_USD_PER_DAY, goalUsdPerDay: GOAL_USD_PER_DAY, burnBasis: "leader-estimate" };

export function scorecard({ settlements = {}, routes = {}, onchain = null }, { now = new Date(), groupPayers = new Set(), economics = DEFAULT_ECONOMICS } = {}) {
  const at = now.getTime(), list = Object.values(settlements);
  const since = (days) => list.filter((s) => at - Date.parse(s.recordedAt ?? s.corroboratedAt) <= days * DAY);
  const outside = (rows) => rows.filter((s) => !groupPayers.has(s.payer));
  const sum = (rows) => Number(rows.reduce((total, s) => total + s.usd, 0).toFixed(6));
  const week = since(7), month = since(30);
  const trailing30 = sum(outside(month));
  const byRoute = {};
  for (const s of outside(month)) byRoute[s.route ?? "unknown"] = Number(((byRoute[s.route ?? "unknown"] ?? 0) + s.usd).toFixed(6));
  const live = Object.values(routes).filter((r) => !r.delistedAt);
  const ratio = Number((trailing30 / economics.burnUsdPerMonth).toFixed(4));
  return {
    type: "EarningsScorecard", at: now.toISOString(),
    outsideRevenueUSD: { week: sum(outside(week)), trailing30, perDayTrailing30: Number((trailing30 / 30).toFixed(4)) },
    groupPayerRevenueUSD: { week: sum(week.filter((s) => groupPayers.has(s.payer))), trailing30: sum(month.filter((s) => groupPayers.has(s.payer))) },
    outsideBuyers: new Set(outside(month).map((s) => s.payer)).size,
    outsideRevenueByRoute: byRoute,
    burnUSD: { monthly: economics.burnUsdPerMonth, basis: economics.burnBasis ?? "leader-estimate" },
    targetsUSDPerDay: { floor: economics.floorUsdPerDay, goal: economics.goalUsdPerDay },
    selfFundingRatio: ratio, mode: mode(ratio),
    offers: { listed: live.length, buyable: live.filter((r) => r.held).length, broken: live.filter((r) => r.held === false).length },
    onchain: onchain ? { lastRunAt: onchain.at, status: onchain.status ?? null } : null,
    source: "corroborated Base receipts of the seller's settlement witnesses (earning loops)",
  };
}

export async function writeScorecard(env, { now = new Date(), groupPayers, economics } = {}) {
  const card = scorecard({
    settlements: (await read(env.STATE, register("settlements")))?.settlements,
    routes: (await read(env.STATE, register("route-health")))?.routes,
    onchain: await read(env.STATE, register("onchain")),
  }, { now, groupPayers, economics });
  await put(env.STATE, register("scorecard"), card);
  await put(env.STATE, record("scorecards", card.at.slice(0, 10)), card);
  return card;
}
