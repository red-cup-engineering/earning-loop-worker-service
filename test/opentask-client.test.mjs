import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createPublicKey, createHash, verify } from 'node:crypto';
import { Buffer as NativeBuffer } from 'node:buffer';
import { allowedRequest, createOpenTaskClient } from '../src/opentask-client.mjs';

const seed = { accessToken: 'initial-access', refreshToken: 'initial-refresh', credentialId: 'credential-1',
  expiresAt: 2000000, privateJwk: { kty: 'EC', crv: 'P-256', d: 'test-key' } };
function storage(initial = {}) {
  const values = new Map(Object.entries(initial));
  return { values, async get(k) { return structuredClone(values.get(k)); }, async put(k, v) { values.set(k, structuredClone(v)); } };
}
const tokens = { access_token: 'rotated-access', refresh_token: 'rotated-refresh', expires_in: 86400 };

test('finite allowlist refuses buyer, payment, foreign, encoded path and arbitrary query effects', () => {
  for (const [method, path] of [['POST','/api/agent/contracts/x/decision'], ['POST','/api/agent/contracts/x/pay'],
    ['POST','/api/agent/contracts/x/crypto-payment-requests'], ['GET','https://evil.invalid/api/agent/contracts'],
    ['GET','/api/agent/contracts/%2fdecision'], ['GET','/api/agent/contracts?evil=1'], ['GET','//evil.invalid/api/agent/contracts']])
    assert.equal(allowedRequest(method, path), false, path);
  assert.equal(allowedRequest('GET','/api/agent/contracts?role=seller&limit=20'), true);
  assert.equal(allowedRequest('GET','/api/agent/bids/b1/messages?limit=20'), true);
  assert.equal(allowedRequest('POST','/api/agent/bids/b1/messages'), false);
  assert.equal(allowedRequest('POST','/api/agent/contracts/x/deliveries/y/submit'), true);
});

test('fresh DPoP for each request, nonce retry, no redirect following or private seed expansion', async () => {
  const state = storage({ 'opentask/auth': seed }), proofs = [], sent = [];
  const client = createOpenTaskClient({ storage: state, initialCredential: seed, now: () => 1000000,
    proof: async x => { proofs.push(x); return `proof-${proofs.length}`; }, fetchImpl: async (url, init) => {
      sent.push(init); return sent.length === 1 ? Response.json({ error: 'use_dpop_nonce' }, { status: 401, headers: { 'dpop-nonce': 'nonce-1' } }) : Response.json({ contracts: [] });
    } });
  await client.request('/api/agent/contracts?role=seller');
  assert.equal(proofs.length, 2); assert.equal(proofs[1].nonce, 'nonce-1');
  assert.equal(sent[0].headers.authorization, 'DPoP initial-access');
  assert.equal(sent[1].headers.dpop, 'proof-2'); assert.equal(sent[0].redirect, 'manual');
  assert.equal((await state.get('opentask/auth')).recoveryPrivateKey, undefined);
  const redirected = createOpenTaskClient({ storage: state, now: () => 1000000, proof: async () => 'p',
    fetchImpl: async () => new Response('', { status: 302, headers: { location: 'https://evil.invalid' } }) });
  await assert.rejects(redirected.request('/api/agent/contracts'), { code: 'redirect-refused' });
});

test('refresh marker precedes exchange and rotated pair is durable before protected use', async () => {
  const state = storage({ 'opentask/auth': { ...seed, expiresAt: 1000001 } }), paths = [];
  const client = createOpenTaskClient({ storage: state, initialCredential: { ...seed, expiresAt: 1000001 }, now: () => 1000000,
    proof: async () => 'proof', fetchImpl: async (url, init) => {
      paths.push(new URL(url).pathname);
      const held = await state.get('opentask/auth');
      if (url.endsWith('/auth/token')) {
        assert.equal(held.pendingRefresh, true);
        assert.equal(init.headers.authorization, undefined);
        assert.equal(new URLSearchParams(init.body).get('grant_type'), 'refresh_token');
        return Response.json(tokens);
      }
      assert.equal(held.accessToken, tokens.access_token); assert.equal(held.pendingRefresh, undefined);
      assert.equal(init.headers.authorization, 'DPoP rotated-access');
      return Response.json({ contracts: [] });
    } });
  await client.request('/api/agent/contracts');
  assert.deepEqual(paths, ['/api/agent/auth/token','/api/agent/contracts']);
});

test('lost refresh response uses assertion, never replays refresh; restart resumes pending assertion', async () => {
  for (const resume of [false, true]) {
    const state = storage({ 'opentask/auth': { ...seed, expiresAt: 1, ...(resume ? { pendingRefresh: true } : {}) } }), paths = [];
    const client = createOpenTaskClient({ storage: state, initialCredential: { ...seed, expiresAt: 1 }, now: () => 1000000,
      proof: async () => 'p', signCanonical: async (_, text) => { assert.equal(text, 'exact canonical bytes'); return 'signature'; },
      fetchImpl: async (url, init) => {
        paths.push(new URL(url).pathname);
        if (url.endsWith('/auth/token')) throw Error('lost response');
        if (url.endsWith('/assert/challenge')) return Response.json({ assertion_id: 'a1', canonical_payload: 'exact canonical bytes' });
        if (url.endsWith('/assert/complete')) { assert.equal(JSON.parse(init.body).signature, 'signature'); return Response.json(tokens); }
        return Response.json({ contracts: [] });
      } });
    await client.request('/api/agent/contracts');
    assert.equal(paths.filter(p => p.endsWith('/auth/token')).length, resume ? 0 : 1);
    assert.equal(paths.filter(p => p.endsWith('/assert/challenge')).length, 1);
    assert.equal((await state.get('opentask/auth')).refreshToken, tokens.refresh_token);
  }
});

test('explicit replay revocation is terminal and does not trigger assertion or repeated polling', async () => {
  const state = storage({ 'opentask/auth': { ...seed, expiresAt: 1 } }); let calls = 0;
  const client = createOpenTaskClient({ storage: state, initialCredential: { ...seed, expiresAt: 1 }, now: () => 1000000,
    proof: async () => 'p', fetchImpl: async () => { calls++; return Response.json({ error: 'refresh_reuse' }, { status: 400 }); } });
  await assert.rejects(client.request('/api/agent/contracts'), { code: 'refresh_reuse' });
  await assert.rejects(client.request('/api/agent/contracts'), { code: 'credential-terminal' });
  assert.equal(calls, 1);
});

test('invalid grant tries one assertion; its rejection is terminal', async () => {
  const state = storage({ 'opentask/auth': { ...seed, expiresAt: 1 } }); let calls = 0;
  const client = createOpenTaskClient({ storage: state, initialCredential: { ...seed, expiresAt: 1 }, now: () => 1000000,
    proof: async () => 'p', fetchImpl: async () => { calls++; return Response.json({ error: 'invalid_grant' }, { status: 400 }); } });
  await assert.rejects(client.request('/api/agent/contracts'), { code: 'invalid_grant' });
  assert.equal(calls, 2); assert.equal((await state.get('opentask/auth')).authFailure, 'invalid_grant');
});

test('request budget refuses the thirteenth fetch and mutating calls require stable keys', async () => {
  const state = storage({ 'opentask/auth': seed }); let fetched = 0;
  const client = createOpenTaskClient({ storage: state, initialCredential: seed, now: () => 1000000, proof: async () => 'p',
    fetchImpl: async () => { fetched++; return Response.json({}); } });
  for (let i = 0; i < 12; i++) await client.request('/api/agent/contracts');
  await assert.rejects(client.request('/api/agent/contracts'), { code: 'commercial-request-budget' });
  await assert.rejects(client.request('/api/agent/contracts/x/deliveries', { method: 'POST', body: {} }), { code: 'idempotency-required' });
  assert.equal(fetched, 12); assert.equal(client.calls, 12);
});

test('empty or restored DO asserts operational key and never consumes a stale deployment seed refresh', async () => {
  const state = storage(), paths = [];
  const client = createOpenTaskClient({ storage: state, initialCredential: { ...seed, recoveryPrivateKey: 'excluded' },
    now: () => 1000000, proof: async () => 'p', signCanonical: async () => 'assertion-signature',
    fetchImpl: async url => {
      paths.push(new URL(url).pathname);
      assert.equal((await state.get('opentask/auth')).recoveryPrivateKey, undefined);
      if (url.endsWith('/assert/challenge')) return Response.json({ assertion_id: 'a1', canonical_payload: 'canonical' });
      if (url.endsWith('/assert/complete')) return Response.json(tokens);
      return Response.json({ contracts: [] });
    } });
  await client.request('/api/agent/contracts');
  assert.deepEqual(paths, ['/api/agent/auth/assert/challenge', '/api/agent/auth/assert/complete', '/api/agent/contracts']);
});

test('nested explicit reuse reason overrides invalid_grant and never asserts', async () => {
  const state = storage({ 'opentask/auth': { ...seed, expiresAt: 1 } }); let calls = 0;
  const client = createOpenTaskClient({ storage: state, now: () => 1000000, proof: async () => 'p',
    fetchImpl: async () => { calls++; return Response.json({ error: { code: 'invalid_grant' }, reason: 'refresh_token_reuse_detected' }, { status: 400 }); } });
  await assert.rejects(client.request('/api/agent/contracts'), { code: 'refresh_token_reuse_detected' });
  assert.equal(calls, 1); assert.equal((await state.get('opentask/auth')).authFailure, 'refresh_token_reuse_detected');
});

test('actual registry OAuth proof and operational assertion interoperate with native P-256 verification', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const state = storage();
  const client = createOpenTaskClient({ storage: state, initialCredential: { ...seed, privateJwk: privateKey.export({ format: 'jwk' }) },
    now: () => 1000000, fetchImpl: async (url, init) => {
      if (url.endsWith('/assert/challenge')) return Response.json({ assertion_id: 'a1', canonical_payload: 'exact provider canonical payload' });
      if (url.endsWith('/assert/complete')) {
        const signature = JSON.parse(init.body).signature;
        assert.equal(verify('sha256', Buffer.from('exact provider canonical payload'), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url')), true);
        return Response.json(tokens);
      }
      const parts = init.headers.dpop.split('.');
      const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url'));
      assert.equal(header.typ, 'dpop+jwt'); assert.equal(header.alg, 'ES256'); assert.equal(header.jwk.d, undefined);
      assert.equal(payload.htm, 'GET'); assert.equal(payload.htu, 'https://opentask.ai/api/agent/contracts');
      assert.equal(verify('sha256', Buffer.from(parts.slice(0, 2).join('.')), {
        key: createPublicKey({ key: header.jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363',
      }, Buffer.from(parts[2], 'base64url')), true);
      return Response.json({ contracts: [] });
    } });
  await client.request('/api/agent/contracts?role=seller');
  assert.equal(client.calls, 3);
});

test('Retry-After is durable before auth and ordinary requests, including unrepresentable valid seconds', async () => {
  for (const retry of ['86400','999999999999999999999999']) {
    let time = 1000000, calls = 0;
    const state = storage({ 'opentask/auth': { ...seed, expiresAt: 1e12 } });
    const client = createOpenTaskClient({ storage: state, now: () => time, proof: async () => 'p', fetchImpl: async () => {
      calls++; return calls === 1 ? Response.json({ error: 'rate_limited' }, { status: 429, headers: { 'retry-after': retry } }) : Response.json({ contracts: [] });
    } });
    await assert.rejects(client.request('/api/agent/contracts'), { code: 'rate_limited' });
    time += 900000;
    await assert.rejects(client.request('/api/agent/contracts'), { code: 'provider-retry-deferred' }); assert.equal(calls, 1);
    if (retry === '86400') { time = 1000000 + 86400000; await client.request('/api/agent/contracts'); assert.equal(calls, 2); }
    else assert.equal((await state.get('opentask/provider-backoff')).retryBlocked, true);
  }
});

test('ordinary authorization refusals become private terminal custody with no repeated polling', async () => {
  for (const code of ['invalid_access_token','access_denied','insufficient_scope','reauthentication_required']) {
    let calls = 0;
    const state = storage({ 'opentask/auth': seed });
    const client = createOpenTaskClient({ storage: state, now: () => 1000000, proof: async () => 'p',
      fetchImpl: async () => { calls++; return Response.json({ error: code }, { status: 403 }); } });
    await assert.rejects(client.request('/api/agent/contracts'), { code });
    await assert.rejects(client.request('/api/agent/contracts'), { code: 'credential-terminal' }); assert.equal(calls, 1);
  }
});

test('gateway HTML and oversized responses retain Retry-After before body parsing or size refusal', async () => {
  for (const status of [429, 503]) for (const oversized of [false, true]) {
    let calls = 0, time = 1000000;
    const state = storage({ 'opentask/auth': { ...seed, expiresAt: 1e12 } });
    const client = createOpenTaskClient({ storage: state, now: () => time, proof: async () => 'p', fetchImpl: async () => {
      calls++; return new Response('<html>gateway unavailable</html>', { status, headers: {
        'content-type': 'text/html', 'retry-after': '86400', ...(oversized ? { 'content-length': '300000' } : {}),
      } });
    } });
    await assert.rejects(client.request('/api/agent/contracts'), { code: oversized ? 'response-too-large' : 'invalid-response', retryAt: 87400000 });
    time += 900000;
    await assert.rejects(client.request('/api/agent/contracts'), { code: 'provider-retry-deferred' });
    assert.equal(calls, 1);
    assert.equal((await state.get('opentask/provider-backoff')).retryAfter, '86400');
  }
});

test('actual registry assertion and DPoP access-token proof work without global Buffer', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const state = storage(), original = globalThis.Buffer;
  const challenge = Response.json({ assertion_id: 'local-only', canonical_payload: 'ephemeral fake challenge' });
  const replacement = Response.json(tokens), contracts = Response.json({ contracts: [] });
  const client = createOpenTaskClient({ storage: state, initialCredential: { ...seed, privateJwk: privateKey.export({ format: 'jwk' }) },
    now: () => 1000000, fetchImpl: async (url, init) => {
      if (url.endsWith('/assert/challenge')) return challenge;
      if (url.endsWith('/assert/complete')) {
        assert.equal((await state.get('opentask/auth')).pendingRefresh, true);
        assert.equal(verify('sha256', NativeBuffer.from('ephemeral fake challenge'), { key: publicKey, dsaEncoding: 'ieee-p1363' },
          NativeBuffer.from(JSON.parse(init.body).signature, 'base64url')), true);
        return replacement;
      }
      const parts = init.headers.dpop.split('.');
      const header = JSON.parse(NativeBuffer.from(parts[0], 'base64url'));
      const payload = JSON.parse(NativeBuffer.from(parts[1], 'base64url'));
      assert.equal(header.typ, 'dpop+jwt'); assert.equal(header.jwk.d, undefined);
      assert.equal(payload.htm, 'GET'); assert.equal(payload.htu, 'https://opentask.ai/api/agent/contracts');
      assert.equal(payload.ath, createHash('sha256').update(tokens.access_token).digest('base64url'));
      assert.equal(verify('sha256', NativeBuffer.from(parts.slice(0, 2).join('.')), { key: publicKey, dsaEncoding: 'ieee-p1363' }, NativeBuffer.from(parts[2], 'base64url')), true);
      return contracts;
    } });
  try { delete globalThis.Buffer; await client.request('/api/agent/contracts'); }
  finally { globalThis.Buffer = original; }
  assert.equal(client.calls, 3); assert.equal((await state.get('opentask/auth')).accessToken, tokens.access_token);
});

test('signing, proof and stream failures expose static phases without private error text', async () => {
  const secret = 'private fake challenge/key/body';
  const seeded = storage({ 'opentask/auth': seed });
  const proof = createOpenTaskClient({ storage: seeded, now: () => 1000000, proof: async () => { throw Error(secret); }, fetchImpl: () => assert.fail() });
  await assert.rejects(proof.request('/api/agent/contracts'), { code: 'proof-generation-failed', message: 'proof-generation-failed' });
  const assertion = createOpenTaskClient({ storage: storage(), initialCredential: seed, now: () => 1000000,
    signCanonical: async () => { throw Error(secret); }, fetchImpl: async () => Response.json({ assertion_id: 'a1', canonical_payload: secret }) });
  await assert.rejects(assertion.request('/api/agent/contracts'), { code: 'challenge-sign-failed', message: 'challenge-sign-failed' });
  const stream = createOpenTaskClient({ storage: seeded, now: () => 1000000, proof: async () => 'p',
    fetchImpl: async () => new Response(new ReadableStream({ start(controller) { controller.error(Error(secret)); } })) });
  await assert.rejects(stream.request('/api/agent/contracts'), { code: 'response-read-failed', message: 'response-read-failed' });
});
