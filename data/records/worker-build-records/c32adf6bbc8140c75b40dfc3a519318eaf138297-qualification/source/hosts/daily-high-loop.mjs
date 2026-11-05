#!/usr/bin/env node
// The daily-high forecast loop, run once a day on a holding host after the 01Z NBM (about 02Z UTC). For each
// Kalshi daily-high series in the Operations record it:
//   1. issues Lenticule Science's calibrated distribution (scripts/forecast-daily-high.mjs, unchanged, from a pinned
//      checkout) and stores the document, so it is served from cache instead of recomputed per request;
//   2. records yesterday's settled NWS CLI high with Science's own parser, for the model's refit and station switch;
//   3. prices every open Kalshi bracket for the target date from the same distribution, next to Kalshi's public
//      bid, ask and last price, so edge over the market itself is measured day by day;
//   4. records the series' settlement source and flags brackets Kalshi settles on a source other than the NWS CLI
//      the forecast is fitted to.
// Documents go to an R2 bucket through the Cloudflare API: forecasts/<date>/<station>.json,
// settled/<date>/<station>.json, edge-log/<date>/<series>.json and edge-log/<date>/summary.json.
//
//   CLOUDFLARE_ACCOUNT_ID=… R2_API_TOKEN=… node hosts/daily-high-loop.mjs --operation <daily-high-operation.json> [--date YYYY-MM-DD] [--dry-run]
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
const arg = (name, fallback) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : fallback; };
const operation = JSON.parse(readFileSync(arg("operation"), "utf8"));
const date = arg("date", new Date().toISOString().slice(0, 10));
const dryRun = process.argv.includes("--dry-run");
const KALSHI = "https://external-api.kalshi.com/trade-api/v2"; // as @red-cup-engineering/kalshi-public-market-data-service
const IEM = "https://mesonet.agron.iastate.edu";
const MONTHS = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];
const day = (d, k) => new Date(Date.parse(`${d}T00:00:00Z`) + k * 864e5).toISOString().slice(0, 10);
const eventCode = (d) => `${d.slice(2, 4)}${MONTHS[Number(d.slice(5, 7)) - 1]}${d.slice(8, 10)}`;
const { parseCliJson } = await import(join(operation.science.checkout, "src/daily-high-distribution/iem.mjs"));

// Standard normal CDF (Abramowitz-Stegun 7.1.26), enough for bracket probabilities to 1e-7.
const phi = (z) => { const t = 1 / (1 + 0.3275911 * Math.abs(z) / Math.SQRT2), y = 1 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.exp(-z * z / 2); return 0.5 * (1 + Math.sign(z) * y); };
// A bracket [lo, hi] in whole degrees holds the integer reading y when lo <= y <= hi; integer readings come from
// the continuous distribution by rounding, so the bracket covers (lo - 0.5, hi + 0.5).
export function bracketProbability({ mean, sd }, lo, hi) {
  const below = hi == null ? 1 : phi((hi + 0.5 - mean) / sd), atLeast = lo == null ? 0 : phi((lo - 0.5 - mean) / sd);
  return Math.max(0, below - atLeast);
}
// Kalshi bracket bounds from a market's strike fields: "between" floor..cap, "greater" above floor, "less" below cap.
export function bracketBounds(market) {
  if (market.strike_type === "between") return [market.floor_strike, market.cap_strike];
  if (market.strike_type === "greater") return [market.floor_strike + 1, null];
  if (market.strike_type === "less") return [null, market.cap_strike - 1];
  return null;
}

// Kalshi quotes in dollar strings (yes_ask_dollars); older responses carried integer cents (yes_ask).
export function dollars(market, field) {
  if (market[`${field}_dollars`] != null) return Number(market[`${field}_dollars`]);
  return market[field] == null ? null : market[field] / 100;
}

async function json(url) {
  const response = await fetch(url, { headers: { accept: "application/json", "user-agent": "red-cup earning-loop daily-high-loop" } });
  if (!response.ok) throw new Error(`${response.status} from ${url}`);
  return response.json();
}

async function put(key, value) {
  if (dryRun) return console.log(`would write ${operation.bucket}/${key}`);
  const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID}/r2/buckets/${operation.bucket}/objects/${key}`, {
    method: "PUT", headers: { authorization: `Bearer ${process.env.R2_API_TOKEN}`, "content-type": "application/json" }, body: JSON.stringify(value, null, 2),
  });
  if (!response.ok) throw new Error(`R2 refused ${key}: ${response.status} ${await response.text()}`);
}

const summary = { date, issuedAt: new Date().toISOString(), science: operation.science, series: [] };
for (const { series, station } of operation.stations) {
  const entry = { series, station };
  try {
    const { stdout } = await run(process.execPath, [join(operation.science.checkout, "scripts/forecast-daily-high.mjs"), "--station", station, "--date", date], { timeout: 240_000 });
    const forecast = JSON.parse(stdout);
    await put(`forecasts/${date}/${station}.json`, forecast);
    entry.forecast = { mean: forecast.distribution.mean, sd: forecast.distribution.sd, model: forecast.model.name };

    const cli = new Map(parseCliJson(await (await fetch(`${IEM}/json/cli.py?station=${station}&year=${day(date, -1).slice(0, 4)}`)).text()));
    if (cli.has(day(date, -1))) await put(`settled/${day(date, -1)}/${station}.json`, { station, localDate: day(date, -1), source: "NWS Daily Climate Report (CLI) via IEM", maximumTemperatureF: cli.get(day(date, -1)) });

    const seriesInfo = (await json(`${KALSHI}/series/${series}`)).series ?? {};
    const sources = seriesInfo.settlement_sources ?? [];
    const cliSettled = sources.some((s) => /weather\.gov|National Weather Service|CLI/i.test(`${s.name} ${s.url}`));
    const markets = ((await json(`${KALSHI}/markets?series_ticker=${series}&status=open&limit=200`)).markets ?? [])
      .filter((m) => m.event_ticker?.endsWith(eventCode(date)));
    const brackets = markets.map((m) => {
      const bounds = bracketBounds(m);
      if (!bounds) return { ticker: m.ticker, unpriced: `strike_type ${m.strike_type}` };
      const p = bracketProbability(forecast.distribution, ...bounds);
      const ask = dollars(m, "yes_ask"), bid = dollars(m, "yes_bid");
      return { ticker: m.ticker, lo: bounds[0], hi: bounds[1], forecastProbability: +p.toFixed(6), yesBid: bid, yesAsk: ask, lastPrice: dollars(m, "last_price"),
        volume: m.volume ?? null, edgeBuyYes: ask == null ? null : +(p - ask).toFixed(4), edgeSellYes: bid == null ? null : +(bid - p).toFixed(4) };
    });
    const log = { series, station, date, observedAt: new Date().toISOString(), settlementSources: sources, settlementSourceMatchesForecast: cliSettled,
      forecast: { distribution: forecast.distribution, model: forecast.model, issuedAt: forecast.issuedAt }, brackets };
    await put(`edge-log/${date}/${series}.json`, log);
    Object.assign(entry, { brackets: brackets.length, settlementSourceMatchesForecast: cliSettled,
      bestEdge: Math.max(...brackets.flatMap((b) => [b.edgeBuyYes ?? -1, b.edgeSellYes ?? -1]), -1) });
  } catch (error) { entry.error = error.message; }
  summary.series.push(entry);
}
await put(`edge-log/${date}/summary.json`, summary);
console.log(JSON.stringify(summary, null, 2));
