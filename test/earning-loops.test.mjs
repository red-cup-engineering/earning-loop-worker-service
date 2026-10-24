import test from "node:test";
import assert from "node:assert/strict";
import { bucket } from "./memory.mjs";
import { corroborate, receiveSettlements, BASE_USDC } from "../src/settlements.mjs";
import { judge, probeRequest, checkRoutes } from "../src/route-health.mjs";
import { scorecard, mode } from "../src/scorecard.mjs";
import { proposeDirectives, stepUp, markApplied, FLOOR_ATOMIC } from "../src/price-directives.mjs";
import { revealedBorder } from "../src/border-price.mjs";
import { applyDirectives } from "../scripts/apply-price-directives.mjs";
import { run, CRONS } from "../worker/earning-loops.mjs";

const payer = "0x" + "a".repeat(40), payTo = "0x" + "b".repeat(40), tx = "0x" + "c".repeat(64), block = "0x" + "d".repeat(64);
const topic = (a) => "0x" + "0".repeat(24) + a.slice(2);
const witness = { network: "eip155:8453", transaction: tx, payer, payTo, asset: BASE_USDC, amount: "50000", route: "/v1/pacing/analysis", method: "POST", recordedAt: "2026-10-20T00:00:00Z" };
const receipt = { status: "0x1", transactionHash: tx, blockHash: block, blockNumber: "0x10",
  logs: [{ address: BASE_USDC, topics: ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", topic(payer), topic(payTo)], data: "0x" + (50000).toString(16).padStart(64, "0"), logIndex: "0x2" }] };
const delivery = { basis: "server-response-prepared", status: 200, bodyBytes: 100, requesterAccepted: true };
const outside = { payerClass: "outside-confirmed", deliveryObservation: delivery };
const challenge = (amount, url = "https://m/x", override = {}) => btoa(JSON.stringify({ x402Version: 2, resource: { url }, accepts: [{ scheme: "exact", network: "eip155:8453", asset: BASE_USDC, amount, payTo, ...override }] }));

test("a settlement corroborates only when two providers agree on one matching USDC transfer", () => {
  assert.equal(corroborate(witness, [receipt, receipt]).ok, true);
  assert.equal(corroborate(witness, [receipt]).reason, "two-provider-receipts-required");
  assert.equal(corroborate(witness, [receipt, { ...receipt, blockHash: "0x" + "e".repeat(64) }]).reason, "provider-disagreement");
  assert.equal(corroborate({ ...witness, amount: "1" }, [receipt, receipt]).reason, "exactly-one-matching-usdc-transfer-required");
  assert.equal(corroborate(witness, [{ ...receipt, status: "0x0" }, receipt]).reason, "failed-transaction");
});

test("an offer is buyable only when its documented example meets a 402 for the catalog's exact price", () => {
  const offer = { method: "POST", url: "https://m/x", price: "$0.05", amountAtomic: "50000", request: { example: { body: { a: 1 } } } };
  assert.equal(JSON.parse(probeRequest(offer)[1].body).a, 1);
  assert.equal(judge(offer, 402, challenge("50000"), { payTo, resourceUrl: offer.url }).held, true);
  assert.match(judge(offer, 400, null).finding, /400/);
  assert.match(judge(offer, 402, challenge("1200"), { payTo }).finding, /asks 1200/);
  assert.match(judge(offer, 402, "not-base64!").finding, /decode/);
});

test("the border relation never reads an unobserved or unsold offer as a reason to cut", () => {
  assert.equal(revealedBorder({ healthyDays: 3, listedDays: 3, outsideSales: 0 }), "unobserved");
  assert.equal(revealedBorder({ healthyDays: 20, listedDays: 20, outsideSales: 0 }), "open-gap");
  assert.equal(revealedBorder({ healthyDays: 20, listedDays: 20, outsideSales: 25 }), "crossed-range");
});

test("price directives raise on crossed range, lift sub-cent toys to a cent, and revert a raise that lost buyers", () => {
  const now = new Date("2026-11-30T00:00:00Z"), old = "2026-10-01T00:00:00Z";
  const routes = { "POST /hot": { firstListedAt: old, heldSince: old, held: true, amountAtomic: "50000" },
    "POST /toy": { firstListedAt: old, heldSince: old, held: true, amountAtomic: "1200" },
    "POST /quiet": { firstListedAt: old, heldSince: old, held: true, amountAtomic: "250000" },
    "POST /broken": { firstListedAt: old, heldSince: null, held: false, amountAtomic: "1000" } };
  const settlements = Object.fromEntries(Array.from({ length: 21 }, (_, i) => [i, { ...outside, route: "/hot", payer, usd: 0.05, recordedAt: "2026-11-25T00:00:00Z" }]));
  const out = proposeDirectives({ routes, settlements }, { now });
  const by = Object.fromEntries(out.map((d) => [d.route, d]));
  assert.equal(by["POST /hot"].to, String(stepUp(50000n)));
  assert.equal(by["POST /toy"].to, String(FLOOR_ATOMIC));
  assert.equal(by["POST /quiet"].kind, "change-one-thing");
  assert.equal(by["POST /broken"], undefined);
  const raised = { id: "r", route: "POST /hot", kind: "raise", from: "50000", to: "80000", status: "applied", appliedAt: "2026-11-01T00:00:00Z" };
  const lost = Object.fromEntries(Array.from({ length: 10 }, (_, i) => [i, { ...outside, route: "/hot", payer, usd: 0.05, recordedAt: "2026-10-25T00:00:00Z" }]));
  const revert = proposeDirectives({ routes: { "POST /hot": { ...routes["POST /hot"], amountAtomic: "80000" } }, settlements: lost, previous: [raised] }, { now });
  assert.equal(revert[0].kind, "revert");
  assert.equal(revert[0].to, "50000");
  const pending = [{ route: "POST /toy", kind: "raise", from: "1200", to: "10000", status: "proposed" }];
  assert.equal(markApplied(pending, { "POST /toy": { amountAtomic: "10000" } })[0].status, "applied");
});

test("applying directives rewrites only the matching catalog prices it still finds at their old amount", () => {
  const catalog = [{ method: "POST", route: "/toy", price: "$0.0012" }, { method: "GET", route: "/other", price: "$0.01" }];
  const directives = [{ route: "POST /toy", kind: "raise", from: "1200", to: "10000", status: "proposed" },
    { route: "GET /other", kind: "raise", from: "999", to: "20000", status: "proposed" },
    { route: "POST /toy", kind: "change-one-thing", from: "1200", to: "1200", status: "proposed" }];
  const changes = applyDirectives(catalog, directives);
  assert.deepEqual(changes.map((c) => [c.route, c.to]), [["POST /toy", "$0.01"]]);
  assert.equal(catalog[0].price, "$0.01");
  assert.equal(catalog[1].price, "$0.01");
});

test("the scorecard counts only outside payers and reads the mode from the burn", () => {
  const now = new Date("2026-10-26T14:00:00Z");
  const group = "0x" + "f".repeat(40);
  const card = scorecard({ settlements: { a: { ...outside, payer, usd: 3, route: "/x", recordedAt: "2026-10-25T00:00:00Z" }, b: { payer: group, usd: 9, route: "/x", recordedAt: "2026-10-25T00:00:00Z" } } }, { now, groupPayers: new Set([group]) });
  assert.equal(card.outsideRevenueUSD.week, 3);
  assert.equal(card.groupPayerCashReceivedUSD.week, 9);
  assert.equal(card.mode, "starving");
  assert.equal(card.targetsUSDPerDay.goal, 200);
  assert.equal(mode(1.2), "self-funding");
});

test("one pass receives a settlement, checks a route and records the absent engine, all in R2", async () => {
  const env = { STATE: bucket(), MARKET_SETTLEMENTS: bucket({ [`settlements/eip155:8453/${tx}.json`]: witness }) };
  const fetchImpl = async (url, init = {}) => {
    if (url.endsWith("/v1/catalog")) return Response.json({ offers: [{ listed: true, method: "POST", route: "/v1/pacing/analysis", url: "https://m/v1/pacing/analysis", price: "$0.05", amountAtomic: "50000", request: { example: { body: {} } } }] });
    if (init.body?.includes("eth_getTransactionReceipt")) return Response.json({ result: receipt });
    return new Response("{}", { status: 402, headers: { "payment-required": challenge("50000", "https://m/v1/pacing/analysis", { payTo: "0x32886F6F361C1d570255c2762967A2e41D0E9B1a" }) } });
  };
  const original = globalThis.fetch; globalThis.fetch = fetchImpl;
  try {
    const outcome = await run(env, CRONS.pass, new Date("2026-10-24T20:00:00Z"));
    assert.equal(outcome.settlements.received.length, 1);
    assert.equal(outcome.settlements.received[0].payerClass, "unclassified");
    assert.equal(outcome.routes.held, 1);
    assert.equal(outcome.onchain.status, "no-engine-attached");
    const again = await run(env, CRONS.pass, new Date("2026-10-24T20:15:00Z"));
    assert.equal(again.settlements.received.length, 0);
    const card = await run(env, CRONS.scorecard, new Date("2026-10-26T14:00:00Z"));
    assert.equal(card.scorecard.week, 0);
  } finally { globalThis.fetch = original; }
});

test("the clock runs the pass every quarter hour, directives daily at 13:30 and the scorecard on Monday 14:00 UTC", async () => {
  const { dueCrons, nextTick, matches } = await import("../src/clock.mjs");
  assert.deepEqual(dueCrons(CRONS, new Date("2026-10-27T10:15:00Z")), [CRONS.pass]);
  assert.deepEqual(dueCrons(CRONS, new Date("2026-10-27T13:30:00Z")).sort(), [CRONS.pass, CRONS.directives].sort());
  assert.ok(dueCrons(CRONS, new Date("2026-10-26T14:00:00Z")).includes(CRONS.scorecard));
  assert.ok(!matches(CRONS.scorecard, new Date("2026-10-27T14:00:00Z")));
  assert.equal(new Date(nextTick(Date.parse("2026-10-24T20:07:00Z"))).toISOString(), "2026-10-24T20:15:00.000Z");
});

test("buyability refuses wrong merchant, wrong scheme, missing merchant authority and resource substitution", () => {
  const offer = { amountAtomic: "50000" };
  assert.equal(judge(offer, 402, challenge("50000"), {}).held, false);
  assert.equal(judge(offer, 402, challenge("50000", "https://m/x", { payTo: payer }), { payTo }).held, false);
  assert.equal(judge(offer, 402, challenge("50000", "https://m/x", { scheme: "upto" }), { payTo }).held, false);
  assert.equal(judge(offer, 402, challenge("50000", "https://m/other"), { payTo, resourceUrl: "https://m/x" }).held, false);
});

test("corroboration refuses a failed second receipt, substituted transaction, different log index or removed log", () => {
  for (const other of [
    { ...receipt, status: "0x0" },
    { ...receipt, transactionHash: "0x" + "e".repeat(64) },
    { ...receipt, logs: [{ ...receipt.logs[0], logIndex: "0x3" }] },
    { ...receipt, logs: [{ ...receipt.logs[0], removed: true }] },
  ]) assert.equal(corroborate(witness, [receipt, other]).ok, false);
});

test("cash from unknown wallets, prepared responses without acceptance, house payments and future dates cannot inflate revenue", () => {
  const now = new Date("2026-10-26T14:00:00Z");
  const sample = { payer, usd: 1, route: "/x", recordedAt: "2026-10-25T00:00:00Z" };
  const card = scorecard({ settlements: {
    unknown: { ...sample, ...outside, payerClass: "outside" }, // legacy absence-based label
    prepared: { ...sample, ...outside, deliveryObservation: { ...delivery, requesterAccepted: null } },
    future: { ...sample, ...outside, recordedAt: "2026-10-27T00:00:00Z" },
  } }, { now });
  assert.equal(card.outsideRevenueUSD.week, 0);
  assert.equal(card.unclassifiedCashReceivedUSD.week, 1);
  assert.equal(card.outsidePaidDeliveriesUSD.week, 1);
  assert.equal(card.outsideCashReceivedUSD.week, 1);
  const directives = proposeDirectives({ routes: {}, settlements: {} }, { now });
  assert.deepEqual(directives, []);
});

test("invalid witnesses never reach a provider and repaired broken routes are checked before old healthy routes", async () => {
  const env = { STATE: bucket(), MARKET_SETTLEMENTS: bucket({ [`settlements/eip155:8453/${tx}.json`]: { ...witness, payer: "bad" } }) };
  let calls = 0;
  await receiveSettlements(env, { fetchImpl: () => { calls++; throw Error("invalid witness reached provider"); } });
  assert.equal(calls, 0);
  await env.STATE.put("registers/earning-loops/route-health.json", JSON.stringify({ routes: {
    "GET /healthy": { held: true, observedAt: "2026-10-23T00:00:00Z" },
    "GET /repaired": { held: false, observedAt: "2026-10-24T00:00:00Z", brokenStreak: 3 },
  } }));
  const requested = [];
  const out = await checkRoutes(env, { limit: 1, payTo, fetchImpl: async (url) => {
    if (url.endsWith("/v1/catalog")) return Response.json({ offers: ["healthy", "repaired"].map(name => ({ listed: true, method: "GET", route: "/" + name, url: "https://m/" + name, amountAtomic: "50000" })) });
    requested.push(url);
    return new Response("{}", { status: 402, headers: { "payment-required": challenge("50000", url) } });
  } });
  assert.deepEqual(requested, ["https://m/repaired"]);
  assert.equal(out.broken, 0);
});
