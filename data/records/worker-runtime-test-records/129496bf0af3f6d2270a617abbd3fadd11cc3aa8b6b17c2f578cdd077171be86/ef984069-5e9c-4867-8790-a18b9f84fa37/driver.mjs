// test/workerd-issuer-financial-driver.mjs
import assert from "node:assert/strict";

// test/issuer-financial-fixture.mjs
var configuration = Object.freeze({
  enabled: true,
  resourceAdmission: { status: "received" },
  network: "eip155:8453",
  asset: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
  payTo: "0x" + "b".repeat(40),
  operation: "issuer-revenue-comparison",
  method: "POST",
  route: "/v1/issuer-revenue-comparison",
  amount: "50000",
  sku: "fixture-issuer-sku",
  gateway: "fixture-issuer-gateway",
  ledgerAccount: "Income:Sales:X402:IssuerResearch"
});
var transaction = (n) => "0x" + n.toString(16).padStart(64, "0");
var logicalKey = (n) => "settlements/eip155:8453/" + transaction(n) + ".json";
var witnessText = (n) => JSON.stringify({
  ...configuration,
  payer: "0x" + "a".repeat(40),
  transaction: transaction(n),
  recordedAt: "2026-10-24T20:00:00.000Z",
  marker: "original \xE9\u{1F642}"
}, null, 2);

// test/workerd-issuer-financial-driver.mjs
var testPrivateFinancialSqlite = { async test(controller, env) {
  const object = env.CLOCK.get(env.CLOCK.idFromName("earning-loops"));
  const inspect = async () => (await object.fetch("https://private.invalid/fixture/inspect")).json();
  const put = (n, text = witnessText(n)) => env.MARKET.fetch("https://market.invalid/put", {
    method: "POST",
    body: JSON.stringify({ key: logicalKey(n), text })
  });
  const seed = await (await object.fetch("https://private.invalid/fixture/seed")).json();
  assert.equal((await env.MARKET.fetch("https://market.invalid/read?" + new URLSearchParams({ key: logicalKey(1) }))).status, 404);
  assert.deepEqual((await Promise.all([put(1), put(1)])).map((r) => r.status).sort(), [201, 412]);
  for (let n = 2; n <= 4; n++) assert.equal((await put(n)).status, 201);
  const direct = await object.fetch("https://private.invalid/issuer-settlement-witness?" + new URLSearchParams({ key: logicalKey(1) }));
  assert.equal(direct.status, 200);
  assert.equal(direct.headers.get("content-length"), String(new TextEncoder().encode(witnessText(1)).byteLength));
  assert.equal(await direct.text(), witnessText(1));
  const read = await env.MARKET.fetch("https://market.invalid/read?" + new URLSearchParams({ key: logicalKey(1) }));
  assert.deepEqual(await read.json(), JSON.parse(witnessText(1)));
  const first = await inspect();
  const firstRows = new Map(first.rows);
  const metadata = firstRows.get("issuer-settlements/capacity");
  assert.equal(metadata.recordCount, 9);
  const encoded = (s) => new TextEncoder().encode(s).byteLength;
  const charged = 4096 + first.rows.filter(([key]) => key.startsWith("issuer-settlements/") && key !== "issuer-settlements/capacity").reduce((total, [key, value]) => total + encoded(key) + encoded(JSON.stringify(value)), 0);
  assert.equal(metadata.chargedBytes, charged);
  assert.equal((await object.fetch("https://private.invalid/fixture/failed-commit")).status, 503);
  assert.deepEqual(await inspect(), first);
  assert.equal((await put(5, witnessText(5).replace('"50000"', '"50001"'))).status, 503);
  assert.equal((await put(6, JSON.stringify({ ...JSON.parse(witnessText(6)), marker: "x".repeat(32768) }))).status, 503);
  assert.deepEqual(await inspect(), first);
  assert.equal((await object.fetch("https://private.invalid/issuer-settlement-witness?key=opentask%2Fauth")).status, 404);
  const observed = await (await object.fetch("https://private.invalid/fixture/receive")).json();
  assert.deepEqual(observed, { result: {
    status: "observed",
    considered: 4,
    providerRequests: 16,
    corroborated: 4,
    refused: 0,
    retryPending: 0
  }, requests: 16 });
  const completed = await inspect();
  const rows = new Map(completed.rows);
  assert.equal(completed.alarm, seed.alarm);
  assert.deepEqual(rows.get("opentask/auth"), { marker: "PRIVATE-TEST-CUSTODY" });
  assert.deepEqual(rows.get("issuer-evidence/cohort"), { marker: "EXISTING-CACHE" });
  for (let n = 1; n <= 4; n++) {
    assert.equal(rows.get("issuer-settlements/witness/" + transaction(n)), witnessText(n));
    assert.equal(rows.has("issuer-settlements/pending/" + transaction(n)), false);
    const receipt = rows.get("issuer-settlements/receipt/" + transaction(n));
    assert.equal(receipt.sourceId, `evm:eip155:8453:${configuration.asset}:${configuration.payTo}:${transaction(n)}:2`);
    assert.equal(receipt.currency, "USDC");
    assert.equal(receipt.usdValuation, null);
    assert.equal(receipt.payerClass, "unclassified");
  }
  assert.equal(rows.get("issuer-settlements/capacity").recordCount, 9);
  assert.deepEqual(await (await object.fetch("https://private.invalid/fixture/receive")).json(), {
    result: { status: "observed", considered: 0, providerRequests: 0, corroborated: 0, refused: 0, retryPending: 0 },
    requests: 0
  });
  assert.deepEqual(await inspect(), completed);
  for (const method of ["GET", "POST"]) assert.equal((await env.PUBLIC_LOOP.fetch(
    "https://public.invalid/issuer-settlement-witness?" + new URLSearchParams({ key: logicalKey(1) }),
    { method }
  )).status, 404);
} };
export {
  testPrivateFinancialSqlite
};
