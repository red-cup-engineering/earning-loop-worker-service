import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { createOpenTaskClient, defaultCanonical } from '../src/opentask-client.mjs';
import { signDpopProof } from '@red-cup-engineering/oauth-services-section/dpop';
export { testNativeResearch } from './workerd-research-worker.mjs';

export const testNativeAuthentication = {
  async test() {
    // Fresh runtime-owned test key only. The harness denies all external networking.
    const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const privateJwk = await crypto.subtle.exportKey('jwk', keys.privateKey);
    const verify = (text, signature) => crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, keys.publicKey, Buffer.from(signature, 'base64url'), Buffer.from(text));
    const canonical = 'ephemeral local Worker challenge';
    // Invoke the real primitive directly first, retaining its actual exception for diagnosis.
    const signature = defaultCanonical(privateJwk, canonical);
    assert.equal(await verify(canonical, signature), true);
    signDpopProof({ privateKey: privateJwk, method: 'GET', url: 'https://opentask.ai/api/agent/contracts', accessToken: 'local-rotated' });
    const values = new Map();
    let calls = 0;
    const client = createOpenTaskClient({ storage: { async get(k) { return values.get(k); }, async put(k,v) { values.set(k,v); } },
      initialCredential: { privateJwk, credentialId: 'ephemeral', accessToken: 'local-seed', refreshToken: 'local-unused', expiresAt: Date.now() + 3600000 },
      fetchImpl: async (url, init) => {
        calls++;
        if (url.endsWith('/assert/challenge')) return Response.json({ assertion_id: 'local', canonical_payload: canonical });
        if (url.endsWith('/assert/complete')) {
          assert.equal(values.get('opentask/auth').pendingRefresh, true);
          assert.equal(await verify(canonical, JSON.parse(init.body).signature), true);
          return Response.json({ access_token: 'local-rotated', refresh_token: 'local-rotated-refresh', expires_in: 3600 });
        }
        const parts = init.headers.dpop.split('.');
        const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url'));
        assert.equal(header.typ, 'dpop+jwt'); assert.equal(header.jwk.d, undefined);
        assert.equal(payload.htm, 'GET'); assert.equal(payload.htu, 'https://opentask.ai/api/agent/contracts');
        assert.equal(payload.ath, createHash('sha256').update('local-rotated').digest('base64url'));
        assert.equal(await verify(parts.slice(0,2).join('.'), parts[2]), true);
        return Response.json({ contracts: [] });
      } });
    assert.deepEqual(await client.request('/api/agent/contracts'), { contracts: [] });
    assert.equal(calls, 3);
    assert.equal(values.get('opentask/auth').accessToken, 'local-rotated');
  },
};
