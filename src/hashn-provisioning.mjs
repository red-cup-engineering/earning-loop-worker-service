import { hashnCredential, hashnError, hashnRequest, UUID } from './hashn-client.mjs';

export const HASHN_CREDENTIAL_ID = 'earning-loops.hashn-credential-json';
const NAME = '561-group earning-loops';

/** Explicit operator-only one-time provisioning. The caller supplies original
 * durable attempt custody and sealed credential custody; no tokens are returned
 * or written to the attempt receipt. This is never called by the Worker. */
export async function provisionHashnAgent({ custody: storage, fetchImpl = fetch, now = () => Date.now() } = {}) {
  if (!storage || ['getAttempt','putAttempt','getCredential','putCredential'].some(k => typeof storage[k] !== 'function'))
    throw new TypeError('durable attempt and sealed credential custody required');
  let attempt = await storage.getAttempt();
  const existingRaw = await storage.getCredential(HASHN_CREDENTIAL_ID);
  const existing = hashnCredential(existingRaw);
  if (existingRaw && !existing) throw hashnError('hashn-credential-invalid');
  if (existing) {
    const { data } = await hashnRequest('/agents/me', { credential: existing, fetchImpl, now });
    if ((data.agent_id ?? data.id) !== existing.agentId || data.name !== NAME) throw hashnError('hashn-account-mismatch');
    await storage.putAttempt({ ...attempt, stage: 'credential-received', agentId: existing.agentId, observedAt: new Date(now()).toISOString() });
    return { stage: 'credential-received', agentId: existing.agentId, created: false, newCashExpenseUsd: 0 };
  }
  if (attempt) return { stage: 'signup-outcome-held', created: false, newCashExpenseUsd: 0 };
  attempt = { stage: 'signup-intent', method: 'POST', path: '/agents', body: { name: NAME }, at: new Date(now()).toISOString() };
  await storage.putAttempt(attempt); // write-ahead: an ambiguous signup is never repeated
  try {
    const { status, data, providerReceipt } = await hashnRequest('/agents', { method: 'POST', body: attempt.body, fetchImpl, now });
    const credential = hashnCredential({ agentId: data.agent_id, apiToken: data.api_token });
    if (status !== 201 || !UUID.test(data.agent_id ?? '') || !credential) throw Object.assign(hashnError('hashn-signup-response-invalid'),{providerReceipt});
    await storage.putCredential(HASHN_CREDENTIAL_ID, credential); // original seal before a success receipt
    await storage.putAttempt({ ...attempt, stage: 'credential-received', agentId: credential.agentId, observedAt: new Date(now()).toISOString() });
    return { stage: 'credential-received', agentId: credential.agentId, created: true, newCashExpenseUsd: 0 };
  } catch (error) {
    await storage.putAttempt({ ...attempt, stage: 'signup-outcome-held', code: /^hashn-[a-z-]+$/.test(error.code ?? '') ? error.code : 'hashn-custody-failure',
      ...(error.providerReceipt ? { providerReceipt: error.providerReceipt } : {}) });
    return { stage: 'signup-outcome-held', created: false, newCashExpenseUsd: 0 };
  }
}
