import test from 'node:test';
import assert from 'node:assert/strict';
import { runCommercialPass, fingerprint, buyerConfirmation, criterionClaims } from '../src/opentask-commercial-pass.mjs';

const merchant = '0x' + 'a'.repeat(40);
const instance = { enabled: true, productId: 'prepared-csv', profileId: 'seller-1', taskId: 'task-1', bidId: 'bid-1', buyerId: 'buyer-1',
  priceText: '50 USDC', priceAmountAtomic: '50000000', priceCurrency: 'USDC', network: 'BASE', maximumNewCashExpenseUsd: 0, maximumInputBytes: 1048576 };
const product = { name: 'Prepared CSV', artifactUrl: 'https://example.org/source-v1.tgz', artifactSha256: 'b'.repeat(64),
  sourceCommit: 'c'.repeat(40), sourceUrl: 'https://example.org/source/commit', verificationInstructions: 'Run the packaged pytest tests.',
  maximumInputBytes: 1048576, criteriaEvidence: { README: 'Packaged usage instructions.', pytest: 'Packaged reproducible tests.' } };
function harness() {
  const held = new Map(), requests = [];
  const storage = { async get(k) { return structuredClone(held.get(k)); }, async put(k,v) { held.set(k,structuredClone(v)); } };
  const contract = { id: 'contract-1', source: 'bid', task: { id: instance.taskId }, bid: { id: instance.bidId, priceText: instance.priceText },
    seller: { id: instance.profileId }, buyer: { id: instance.buyerId }, status: 'in_progress', termsSnapshot: { exact: 'accepted provider terms' } };
  const provider = { hired: false, messages: [], deliveries: [], dropCreate: false, writes: true, payee: merchant, time: Date.parse('2026-10-24T20:00:00Z') };
  const context = () => ({ contract: { ...contract, nativeDeliveryAvailability: contract.nativeDeliveryAvailability ?? { globallyEnabled: true, eligible: true, enabled: provider.writes, unavailableReason: null } },
    availableActions: [{ schemaVersion: 'opentask-available-actions-v1', action: 'prepare_delivery', state: 'available',
      entity: { type: 'contract', id: contract.id }, actor: { eligibleProfileId: instance.profileId, role: 'worker', requiredScopes: ['deliveries:read','deliveries:write'], requiredScopeMode: 'all' },
      invocation: { method: 'GET', endpoint: `/api/agent/contracts/${contract.id}/deliveries` }, payment: null }] });
  const base = '/api/agent/contracts/contract-1';
  const clientFactory = () => {
    let calls = 0;
    return { get calls() { return calls; }, async request(path, options = {}) {
      calls++; if (calls > 12) throw Error('budget exceeded');
      requests.push({ path, ...structuredClone(options) });
      const method = options.method ?? 'GET';
      if (path.startsWith('/api/agent/contracts?')) return { contracts: provider.hired ? [contract] : [], nextCursor: null };
      if (path === base) return context();
      if (path === base + '/payout-destination') return { contractId: contract.id, role: 'seller', currentDestinationActive: true,
        blockedReason: null, currentDestination: { address: provider.payee, token: 'USDC', network: 'BASE', memo: null } };
      if (path.startsWith(base + '/messages?')) return { messages: provider.messages, nextCursor: null };
      if (path === base + '/messages' && method === 'POST') {
        provider.messages.push({ id: 'offer-1', author: { id: instance.profileId, kind: 'agent' }, body: options.body.body });
        return { ok: true, id: 'offer-1' };
      }
      if (path === base + '/deliveries' && method === 'GET') return { deliveries: provider.deliveries, nextCursor: null };
      if (path === base + '/deliveries' && method === 'POST') {
        if (provider.refuseCreate) { const e = Object.assign(new Error('refused'), provider.refuseCreate); provider.refuseCreate = null; throw e; }
        const p = { id: 'package-1', contractId: contract.id, ...options.body, status: 'draft', version: 1, milestoneId: null,
          availableActions: { edit: true, submit: true }, artifacts: [], criteria: [
            { id: 'c1', text: 'README', artifactIds: [] }, { id: 'c2', text: 'pytest', artifactIds: [] }] };
        provider.deliveries.push(p);
        if (provider.dropCreate) { provider.dropCreate = false; const e = Error('unknown'); e.code = 'response-unknown'; throw e; }
        return { delivery: p };
      }
      const p = provider.deliveries[0];
      if (path === base + '/deliveries/package-1' && method === 'GET') return { delivery: p, comparison: null };
      if (path.endsWith('/external-artifacts') && method === 'POST') {
        assert.equal(options.body.expectedVersion, p.version);
        p.artifacts.push({ id: 'a1', externalUrl: options.body.url, description: options.body.description }); p.version++;
        return { delivery: p };
      }
      if (path === base + '/deliveries/package-1' && method === 'PATCH') {
        assert.equal(options.body.expectedVersion, p.version);
        for (const claim of options.body.criteria) Object.assign(p.criteria.find(c => c.id === claim.criterionId),
          { sellerClaim: claim.claim, sellerNote: claim.note, artifactIds: claim.artifactIds });
        p.version++; return { delivery: p };
      }
      if (path.endsWith('/submit') && method === 'POST') {
        assert.equal(options.body.expectedVersion, p.version); assert.equal(options.body.confirmed, true);
        p.status = 'submitted'; p.revision = 1; p.manifestDigest = 'd'.repeat(64); contract.status = 'submitted';
        return { delivery: p };
      }
      if (path.includes('/crypto-payment-requests/')) return { paymentRequest: provider.payment };
      throw Error('unexpected provider request ' + path);
    } };
  };
  const pulse = () => runCommercialPass({ storage, instance, products: { [instance.productId]: product }, merchant,
    clientFactory, now: new Date(provider.time) });
  const confirm = () => {
    const sent = provider.messages.find(m => m.id === 'offer-1');
    const expected = JSON.parse(sent.body.slice(sent.body.indexOf('\n') + 1));
    provider.messages.push({ id: 'buyer-confirmation', author: { id: instance.buyerId, kind: 'agent' }, body: JSON.stringify(expected) });
    return expected;
  };
  return { storage, held, requests, contract, provider, pulse, confirm };
}

async function agreed(h) {
  h.provider.hired = true;
  assert.equal((await h.pulse()).stage, 'hire-discovered');
  assert.equal((await h.pulse()).stage, 'agreement-requested');
  h.confirm();
  assert.equal((await h.pulse()).stage, 'buyer-agreement-received');
}

test('no hire makes one bounded read, spends no cash, and never calls a delivery effect', async () => {
  const h = harness(), result = await h.pulse();
  assert.deepEqual(result, { stage: 'awaiting-hire', requests: 1, newCashExpenseUsd: 0 });
  assert.equal(h.requests.some(r => r.method), false);
  assert.equal(JSON.stringify(result).includes('buyer-1'), false);
});

test('real matching hire negotiates one strict buyer confirmation then advances immutable delivery', async () => {
  const h = harness(); await agreed(h);
  for (const stage of ['create-received','attach-received','claim-received','submit-received','submitted-awaiting-buyer']) {
    const result = await h.pulse(); assert.equal(result.stage, stage); assert.ok(result.requests <= 12);
    assert.equal(JSON.stringify(result).includes('contract-1'), false);
  }
  const mutations = h.requests.filter(r => r.method);
  assert.deepEqual(mutations.map(r => r.method), ['POST','POST','POST','PATCH','POST']);
  assert.ok(mutations.every(r => r.key));
  assert.equal(h.held.get('opentask/commercial').observations.delivery.manifestDigest, 'd'.repeat(64));
  assert.equal(h.held.get('opentask/commercial').observations.settlement, undefined);
});

test('seller-authored, human-authored, changed-product and command-bearing JSON cannot confirm buyer authority', async () => {
  const h = harness(); h.provider.hired = true; await h.pulse(); await h.pulse();
  const expected = h.confirm(); h.provider.messages.pop();
  for (const message of [
    { author: { id: instance.profileId, kind: 'agent' }, body: JSON.stringify(expected) },
    { author: { id: instance.buyerId, kind: 'human' }, body: JSON.stringify(expected) },
    { author: { id: instance.buyerId, kind: 'agent' }, body: JSON.stringify({ ...expected, artifactSha256: 'e'.repeat(64) }) },
    { author: { id: instance.buyerId, kind: 'agent' }, body: JSON.stringify({ ...expected, command: 'execute arbitrary text' }) },
  ]) assert.equal(buyerConfirmation(message, expected, instance.buyerId), null);
  assert.equal((await h.pulse()).stage, 'agreement-pending');
  assert.equal(h.requests.filter(r => r.method === 'POST').length, 1, 'does not repeat confirmed outbound request');
});

test('wrong payee and task/bid substitutions refuse without messages or delivery writes', async () => {
  for (const change of [h => h.provider.payee = '0x'+'f'.repeat(40), h => h.contract.bid.id = 'other-bid', h => h.contract.task.id = 'other-task']) {
    const h = harness(); h.provider.hired = true; await h.pulse(); change(h);
    assert.match((await h.pulse()).stage, /held|mismatch/);
    assert.equal(h.requests.some(r => r.method), false);
  }
});

test('lost create response is read back as the same draft, rather than creating a second delivery', async () => {
  const h = harness(); await agreed(h); h.provider.dropCreate = true;
  assert.equal((await h.pulse()).stage, 'effect-readback-pending');
  assert.equal((await h.pulse()).stage, 'attach-received');
  assert.equal(h.provider.deliveries.length, 1);
  assert.equal(h.requests.filter(r => r.method === 'POST' && r.path.endsWith('/deliveries')).length, 1);
});

test('unknown criteria and disabled seller writes remain pending without invented claims', async () => {
  const h = harness(); await agreed(h); await h.pulse(); await h.pulse();
  h.provider.deliveries[0].criteria.push({ id: 'c3', text: '100 tests using pytest', artifactIds: [] });
  assert.equal((await h.pulse()).stage, 'criterion-evidence-held');
  assert.equal(h.requests.some(r => r.method === 'PATCH'), false);
  h.provider.writes = false;
  assert.equal((await h.pulse()).stage, 'delivery-action-held');
  assert.equal(criterionClaims({ criteria: [{ id: 'x', text: '100 tests using pytest' }] }, product, 'a1'), null);
});

test('changed frozen terms stop operation; paid-looking labels alone cannot count as settlement', async () => {
  const h = harness(); await agreed(h);
  h.contract.termsSnapshot.extra = 'changed terms';
  assert.equal((await h.pulse()).stage, 'terms-drift-held');
  delete h.contract.termsSnapshot.extra;
  h.contract.status = 'accepted';
  assert.equal((await h.pulse()).stage, 'acceptance-observed-awaiting-proof');
  assert.equal(h.held.get('opentask/commercial').observations.settlement, undefined);
});

test('settlement observation requires exact provider request amount, payee and router proof fields', async () => {
  const h = harness(); await agreed(h);
  h.contract.status = 'accepted'; h.contract.hasRouterVerifiedPayment = true;
  h.contract.verifiedCryptoPaymentRequest = { id: 'payment-1' };
  h.provider.payment = { id: 'payment-1', contractId: 'contract-1', status: 'verified', sellerAddress: merchant,
    chainId: 8453, tokenSymbol: 'USDC', tokenDecimals: 6, tokenAddress: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913', sellerAmountAtomic: '50000000', paidTxHash: '0x'+'f'.repeat(64),
    paidBlockNumber: '100', paidLogIndex: 2, verifiedAt: '2026-10-24T20:00:00Z' };
  assert.equal((await h.pulse()).stage, 'settlement-reported-delivery-unreceived');
  h.provider.payment.sellerAmountAtomic = '1';
  assert.equal((await h.pulse()).stage, 'payment-proof-held');
  assert.equal(h.requests.some(r => /\/decision$|\/pay$|\/verify$/.test(r.path)), false);
});

test('canonical snapshot digest is stable across object key order', async () => {
  assert.equal(await fingerprint({ b: 2, a: { y: 1, x: 2 } }), await fingerprint({ a: { x: 2, y: 1 }, b: 2 }));
});

test('documented REST context without hosted-MCP operational fields permits exact actor action', async () => {
  const h = harness(); await agreed(h);
  h.contract.nativeDeliveryAvailability = { globallyEnabled: true, eligible: true, enabled: true, unavailableReason: null };
  assert.equal((await h.pulse()).stage, 'create-received');
});

test('false, unknown or globally disabled REST eligibility refuses delivery writes', async () => {
  for (const feature of [
    { globallyEnabled: true, eligible: false, enabled: false },
    { globallyEnabled: true, eligible: null, enabled: false },
    { globallyEnabled: false, eligible: true, enabled: true },
  ]) {
    const h = harness(); await agreed(h); h.contract.nativeDeliveryAvailability = feature;
    assert.equal((await h.pulse()).stage, 'delivery-action-held');
    assert.equal(h.requests.some(r => r.path.endsWith('/deliveries') && r.method === 'POST'), false);
  }
});

test('429 retains one pending mutation, honors Retry-After through next day, then resumes the same intent', async () => {
  const h = harness(); await agreed(h);
  h.provider.refuseCreate = { status: 429, code: 'rate_limited', retryAt: h.provider.time + 86400000, retryAfter: '86400' };
  assert.equal((await h.pulse()).stage, 'effect-readback-pending');
  const before = h.requests.length;
  assert.equal((await h.pulse()).stage, 'provider-retry-deferred'); assert.equal(h.requests.length, before);
  h.provider.time += 86400000;
  assert.equal((await h.pulse()).stage, 'create-received');
  const creates = h.requests.filter(r => r.method === 'POST' && r.path.endsWith('/deliveries'));
  assert.equal(creates.length, 2); assert.equal(creates[0].key, creates[1].key); assert.equal(h.provider.deliveries.length, 1);
});

test('unchanged provider denial retains exact intent without replaying a refused mutation', async () => {
  const h = harness(); await agreed(h);
  h.provider.refuseCreate = { status: 403, code: 'native_delivery_not_eligible' };
  await h.pulse();
  assert.equal((await h.pulse()).stage, 'provider-write-refused');
  assert.equal(h.requests.filter(r => r.method === 'POST' && r.path.endsWith('/deliveries')).length, 1);
  assert.ok(h.held.get('opentask/commercial').pending);
});

test('unfabricated two-bid observer refuses before private storage or provider access', async () => {
  let touched = 0;
  const refuseStorage = { async get() { touched++; throw new Error('storage accessed'); },
    async put() { touched++; throw new Error('storage changed'); } };
  const refuseClient = () => { touched++; throw new Error('provider accessed'); };
  await assert.rejects(runCommercialPass({
    instance: { ...instance, bidObservation: { enabled: true } },
    storage: refuseStorage, clientFactory: refuseClient
  }), /commercial-bid-observation-source-not-admitted/);
  await assert.rejects(runCommercialPass({
    observation: { enabled: true }, storage: refuseStorage, clientFactory: refuseClient
  }), /commercial-bid-observation-source-not-admitted/);
  assert.equal(touched, 0);
});
