// data/records/fabrication-run-records/2026-10-24-issuer-private-settlement-custody/clarification/adapter-contracts/receiving-fixtures/driver.mjs
import assert from "node:assert/strict";
var tx = (n) => "0x" + n.toString(16).padStart(64, "0");
var key = (n) => "settlements/eip155:8453/" + tx(n) + ".json";
var witness = (n) => ({ network: "eip155:8453", asset: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", payTo: "0x" + "b".repeat(40), payer: "0x" + "a".repeat(40), transaction: tx(n), operation: "issuer-revenue-comparison", method: "POST", route: "/v1/issuer-revenue-comparison", amount: "50000", sku: "fixture-issuer-sku", gateway: "fixture-issuer-gateway", ledgerAccount: "Income:Sales:X402:IssuerResearch", recordedAt: "2026-10-24T20:00:00.000Z", note: "\xE9\u{1F642}" });
var testFinancialSqliteCustody = { async test(controller, env) {
  const clock = env.CLOCK.get(env.CLOCK.idFromName("earning-loops")), seed = await (await clock.fetch("https://fixture.invalid/fixture/seed")).json();
  const text = JSON.stringify(witness(1), null, 1), url = "https://fixture.invalid/read?" + new URLSearchParams({ key: key(1) });
  assert.equal((await env.MARKET.fetch(url)).status, 404);
  assert.equal((await env.MARKET.fetch(url, { method: "POST", body: text })).status, 201);
  assert.equal((await env.MARKET.fetch(url, { method: "POST", body: JSON.stringify({ ...witness(1), note: "replacement" }) })).status, 412);
  assert.deepEqual(await (await env.MARKET.fetch(url)).json(), witness(1));
  const drift = await (await clock.fetch("https://fixture.invalid/fixture/identity-drift")).json();
  assert.deepEqual(drift, { status: "held", reason: "configuration-identity-changed" });
  const received = await (await clock.fetch("https://fixture.invalid/fixture/receive")).json();
  assert.equal(received.result.corroborated, 1);
  assert.equal(received.calls, 2);
  const before = await (await clock.fetch("https://fixture.invalid/fixture/inspect")).json();
  assert.equal(before.raw, text);
  assert.equal(before.pending, void 0);
  assert.equal(before.receipt.currency, "USDC");
  assert.equal(before.receipt.usdValuation, null);
  assert.equal(before.receipt.payerClass, "unclassified");
  assert.equal(before.receipt.sourceId, "evm:eip155:8453:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913:0x" + "b".repeat(40) + ":" + tx(1) + ":2");
  await clock.fetch("https://fixture.invalid/fixture/quota");
  assert.equal((await env.MARKET.fetch("https://fixture.invalid/read?" + new URLSearchParams({ key: key(2) }), { method: "POST", body: JSON.stringify(witness(2)) })).status, 503);
  const after = await (await clock.fetch("https://fixture.invalid/fixture/inspect")).json();
  assert.equal(after.raw, text);
  assert.deepEqual(after.receipt, before.receipt);
  assert.deepEqual(after.auth, { marker: "PRIVATE-FIXTURE-ONLY" });
  assert.equal(after.alarm, seed.alarm);
  assert.equal((await clock.fetch("https://fixture.invalid/issuer-settlement-witness?key=opentask%2Fauth")).status, 404);
} };
export {
  testFinancialSqliteCustody
};
