import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { AGENT_MARKET_INDEX, observeAgentMarketIndex } from '../src/agent-market-observation.mjs';

const at = '2026-10-27T14:00:00.000Z';
const queries = ['verify a Base transfer', 'check a package vulnerability'];
const owner = 'market.561.group';
const listing = (url, extra = {}) => ({
  id: 'source-a', name: 'A source-listed operation', protocol: 'x402',
  url, price_usd: '0.001', x402_payment_valid: true,
  health_status: 'healthy', ...extra,
});

test('source-owned independent directory search is a finite read without purchase or inferred demand', async () => {
  const requests = [];
  const observed = await observeAgentMarketIndex({
    queries, ownHost: owner, limit: 3, observedAt: at,
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return Response.json({ services: [
        listing('https://market.561.group/v1/base-chain/balance'),
        listing('https://rival.example.org/check', { id: 'other', price_usd: '0.05' }),
      ], total: 8 });
    },
  });
  assert.equal(requests.length, 2);
  for (let index = 0; index < 2; index++) {
    const url = new URL(requests[index].url);
    assert.equal(url.origin + url.pathname, AGENT_MARKET_INDEX);
    assert.equal(url.searchParams.get('q'), queries[index]);
    assert.equal(url.searchParams.get('protocol'), 'x402');
    assert.equal(requests[index].options.method, 'GET');
  }
  assert.deepEqual(observed.searchReadings.map(row => row.ownSellerRanks), [[1], [1]]);
  assert.equal(observed.searchReadings[0].anotherPageKnown, true);
  assert.equal(observed.listings.length, 4);
  assert.equal(observed.listings[0].advertisedUsdPerCall, '0.001');
  assert.equal(observed.listings[0].independentlyPaidBuyerObserved, false);
  assert.equal(observed.buyerConversionObserved, false);
  assert.equal(observed.realMoneyOrAcceptedWorkObserved, false);
  assert.equal(observed.independentlyReceived, false);
  assert.deepEqual(observed.authorizedActions, []);
});

test('one unavailable source page remains an unknown, not evidence of absent competitors', async () => {
  const observed = await observeAgentMarketIndex({
    queries, ownHost: owner, limit: 3, observedAt: at,
    fetchImpl: async url => new URL(url).searchParams.get('q') === queries[0]
      ? Response.json({ services: [listing('https://market.561.group/api')], total: 1 })
      : Response.json({ error: 'rate limit' }, { status: 429 }),
  });
  assert.deepEqual(observed.searchReadings.map(row => row.state),
    ['observed-first-page', 'unavailable']);
  assert.equal(observed.searchReadings[1].admitted, null);
  assert.equal(observed.searchReadings[1].ownSellerRanks, null);
  assert.equal(observed.completeMarketCoverage, false);
  assert.equal(observed.listings.length, 1);
});

test('malformed or non-x402 source advertisements are neither offers nor sales', async () => {
  const observed = await observeAgentMarketIndex({
    queries: [queries[0]], ownHost: owner, limit: 3, observedAt: at,
    fetchImpl: async () => Response.json({ services: [
      listing('https://market.561.group/api', { protocol: 'l402' }),
      listing('http://localhost/private'),
      listing('https://name:password@private.example.org/api'),
    ], total: 3 }),
  });
  assert.equal(observed.listings.length, 0);
  assert.equal(observed.searchReadings[0].returned, 3);
  assert.equal(observed.searchReadings[0].admitted, 0);
  assert.equal(observed.realMoneyOrAcceptedWorkObserved, false);
});

test('oversized independent source reads fail closed under the original byte ceiling', async () => {
  const observed = await observeAgentMarketIndex({
    queries: [queries[0]], ownHost: owner, limit: 1, observedAt: at,
    fetchImpl: async () => new Response(' '.repeat(193000), { status: 200 }),
  });
  assert.equal(observed.searchReadings[0].state, 'unavailable');
  assert.match(observed.searchReadings[0].error, /oversized/i);
  assert.deepEqual(observed.listings, []);
});

test('the autonomous Worker does not buy the unconsumed Web Platform and branding closure', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(Object.hasOwn(pkg.dependencies, '@red-cup-engineering/computer-web-platform'), false);
  assert.equal(Object.hasOwn(pkg.dependencies, '@coesite-operations/enterprise-branding-services-section'), false);
  assert.equal(pkg.name, '@red-cup-engineering/earning-loop-worker-service');
});
