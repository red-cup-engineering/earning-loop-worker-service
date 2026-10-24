import { canonicalJson } from '@red-cup-engineering/json-services-section/canonical-json';
import { hashnCredential, hashnError, hashnRequest, UUID } from './hashn-client.mjs';

export const HASHN_STATE = 'hashn/acquisition';
export const HASHN_SUMMARY = 'hashn/public-summary';
const AUTH = 'hashn/auth';
const SIX_HOURS = 6 * 60 * 60 * 1000;
const WEEK = 7 * 24 * 60 * 60 * 1000;
const hash = async value => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalJson(value)))), n => n.toString(16).padStart(2,'0')).join('');

export function hashnInstanceProblem(instance) {
  if (!instance?.enabled) return 'hashn-disabled';
  if (!UUID.test(instance.workspaceId ?? '') || !UUID.test(instance.buyerAgentId ?? '') ||
    !/^[a-zA-Z0-9_-]{1,100}$/.test(instance.offerId ?? '') || typeof instance.note !== 'string' ||
    [...instance.note].length < 1 || [...instance.note].length > 500 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(instance.note) ||
    instance.maximumNewCashExpenseUsd !== 0 || instance.maximumProviderRequestsPerPass !== 3 ||
    instance.pollIntervalMs !== SIX_HOURS) return 'hashn-instance-refused';
  return null;
}

/** The caller is the existing singleton DO queue. This operation can only send
 * one frozen knock and observe its disposition. A response is never an agreement
 * or delivery instruction. Token, note, replies and workspace ids stay private. */
export async function runHashnAcquisition({ storage, instance, initialCredential, fetchImpl = fetch, now = () => Date.now() } = {}) {
  const refusal = hashnInstanceProblem(instance);
  if (refusal) return { stage: refusal, requests: 0, newCashExpenseUsd: 0 };
  let state = await storage.get(HASHN_STATE) ?? {};
  let calls = 0;
  const finish = async (stage, terminal = false, delay = SIX_HOURS) => {
    state.stage = stage; state.terminal = terminal;
    state.nextAttemptAt = terminal || state.retryBlocked ? null : Math.max(now() + delay, state.retryAt ?? 0);
    await storage.put(HASHN_STATE, state);
    const summary = { stage, requests: calls, newCashExpenseUsd: 0, at: new Date(now()).toISOString(),
      offerId: instance.offerId, knockStatus: state.knockStatus ?? null,
      agreementReceived: false, deliverySubmitted: false, recognizedOutsideRevenue: null };
    await storage.put(HASHN_SUMMARY, summary);
    return summary;
  };
  const wire = async (path, options = {}) => {
    if (calls >= instance.maximumProviderRequestsPerPass) throw hashnError('hashn-request-budget');
    if (state.retryBlocked || state.retryAt > now()) throw hashnError('hashn-retry-deferred');
    calls++;
    return hashnRequest(path, { ...options, fetchImpl, now, onRetry: async retry => {
      Object.assign(state,retry); await storage.put(HASHN_STATE,state);
    } });
  };
  try {
    const credential = hashnCredential(initialCredential);
    if (!credential) return finish('hashn-credential-held');
    const bound = { agentId: credential.agentId, workspaceId: instance.workspaceId,
      buyerAgentId: instance.buyerAgentId, offerId: instance.offerId, note: instance.note };
    const binding = await hash(bound);
    if (state.binding && state.binding !== binding) return finish('hashn-binding-drift',true);
    const priorAuth = await storage.get(AUTH);
    if (priorAuth && (priorAuth.agentId !== credential.agentId || priorAuth.apiToken !== credential.apiToken)) return finish('hashn-credential-drift',true);
    if (state.terminal) return finish(state.stage,true);
    if (state.retryBlocked || state.nextAttemptAt > now()) return { stage: state.stage, requests: 0, newCashExpenseUsd: 0 };
    if (state.monitoringUntil && now() >= state.monitoringUntil) return finish('hashn-reconciliation-deadline-held',true);
    if (!priorAuth) {
      const { data } = await wire('/agents/me',{credential});
      if ((data.agent_id ?? data.id) !== credential.agentId) return finish('hashn-account-mismatch',true);
      await storage.put(AUTH,credential);
    }
    state.binding ??= binding;
    state.scope ??= bound;
    if (state.intent && !state.reconciliationAttempted) state.reconciliationAttempted = true;
    await storage.put(HASHN_STATE,state);
    const { data, providerReceipt } = await wire('/knocks',{credential});
    state.knocksReadbackReceipt = providerReceipt;
    // Provider OpenAPI deliberately leaves this response untyped. Admit only
    // its independently received outgoing shape; never infer absence otherwise.
    if (!Array.isArray(data.outgoing)) throw hashnError('hashn-knocks-shape-held');
    if (data.has_more === true || data.next_cursor || data.nextCursor) throw hashnError('hashn-knocks-truncated-held');
    if (data.outgoing.some(k => !k || !UUID.test(k.workspace_id ?? ''))) throw hashnError('hashn-knocks-shape-held');
    const related = data.outgoing.filter(k => k.workspace_id === instance.workspaceId);
    if (related.length > 1) return finish('hashn-knock-conflict-held',true);
    const knock = related[0];
    if (knock) {
      if (!['knock_id','from_agent_id','to_agent_id','note','status'].every(key => Object.hasOwn(knock,key)))
        return finish('hashn-knock-shape-held');
      if (!UUID.test(knock.knock_id ?? '') || knock.from_agent_id !== credential.agentId ||
          knock.to_agent_id !== instance.buyerAgentId || knock.note !== instance.note ||
          !['pending','accepted','declined','expired'].includes(knock.status)) return finish('hashn-knock-scope-held',true);
      if (state.knockId && state.knockId !== knock.knock_id) return finish('hashn-knock-identity-held',true);
      state.knockId = knock.knock_id; state.knockStatus = knock.status;
      state.monitoringUntil ??= now() + WEEK + SIX_HOURS;
      if (knock.status === 'accepted') {
        if (!UUID.test(knock.result_workspace_id ?? '')) return finish('hashn-acceptance-shape-held',true);
        state.resultWorkspaceId = knock.result_workspace_id;
        return finish('hashn-accepted-terms-held',true);
      }
      return finish('hashn-' + knock.status, knock.status !== 'pending');
    }
    if (state.intent) return finish('hashn-knock-readback-pending'); // absolutely no POST replay after uncertainty/absence
    state.intent = { method: 'POST', path: `/workspaces/${instance.workspaceId}/knock`, body: { note: instance.note },
      payloadSha256: await hash({ note: instance.note }), at: new Date(now()).toISOString() };
    state.monitoringUntil = now() + WEEK + SIX_HOURS;
    await storage.put(HASHN_STATE,state); // before the only permissible mutation
    const result = await wire(state.intent.path,{method:'POST',body:state.intent.body,credential});
    state.knockWriteReceipt = result.providerReceipt;
    await storage.put(HASHN_STATE,state);
    if (result.status !== 201) throw hashnError('hashn-knock-response-held');
    // Even a successful write is reconciled from GET /knocks; raw provider
    // response stays untrusted and is never exposed or treated as a deal.
    return finish('hashn-knock-sent-readback-pending',false,30000);
  } catch (e) {
    const code = /^hashn-[a-z-]{1,80}$/.test(e.code ?? '') ? e.code : 'hashn-failure';
    state.lastFailure = code;
    if (e.providerReceipt) state.providerReceipt = e.providerReceipt;
    return finish(code,[400,401,403,404,402,410,422].includes(e.status) || e.status === 409 && !state.intent || code === 'hashn-redirect-refused',
      state.intent && !state.reconciliationAttempted ? 30000 : SIX_HOURS);
  }
}
