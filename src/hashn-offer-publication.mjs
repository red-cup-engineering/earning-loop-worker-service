import { canonicalJson } from '@red-cup-engineering/json-services-section/canonical-json';
import { hashnCredential, hashnRequest, UUID } from './hashn-client.mjs';

const digest = async value => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',
  new TextEncoder().encode(canonicalJson(value)))), n => n.toString(16).padStart(2, '0')).join('');

// Source-owned Public offers are published explicitly; the clock cannot invoke
// this operation. A publication never creates a deal or authorizes production.
export async function publishHashnOffer({ descriptor, credential: rawCredential, custody, fetchImpl = fetch, now = () => Date.now() }) {
  const credential = hashnCredential(rawCredential);
  const listing = descriptor?.listing;
  if (!credential || descriptor?.provider !== 'https://api.hashn.com' || descriptor.agentId !== credential.agentId ||
      !UUID.test(descriptor.agentId) || !/^[a-z0-9][a-z0-9.-]{1,99}$/.test(listing?.name ?? '') ||
      listing.path !== `listings/${listing.name}.md` || listing.convention !== 'agent-services' ||
      !Number.isSafeInteger(descriptor.price?.amount) || descriptor.price.amount <= 0 || descriptor.price.currency !== 'USDC' ||
      typeof listing.can !== 'string' || !listing.can || Object.hasOwn(listing, 'need') ||
      listing.contact_method !== 'hashn knock' ||
      listing.contact_info !== `POST https://api.hashn.com/agents/${credential.agentId}/knock`)
    throw new TypeError('source-owned seller offer and matching admitted credential required');
  const payloadSha256 = await digest(listing);
  let state = await custody.getAttempt();
  if (state?.payloadSha256 && state.payloadSha256 !== payloadSha256)
    return { stage: 'publication-scope-held', newCashExpenseUsd: 0 };
  // No blind replay after an unknown listing write. Native GET /listings and
  // the public source URL reconcile it without another publication mutation.
  if (state?.intent) return { stage: state.stage, newCashExpenseUsd: 0 };
  state = { payloadSha256, agentId: credential.agentId, path: listing.path, at: new Date(now()).toISOString() };
  try {
    const me = await hashnRequest('/agents/me', { credential, fetchImpl, now });
    if (me.data.agent_id !== credential.agentId) throw new Error('publication-account-mismatch');
    const check = await hashnRequest('/listings/check', { method: 'POST', body: listing, credential, fetchImpl, now });
    state.check = check.providerReceipt;
    if (check.data.ok !== true || check.data.in_forest !== true || check.data.path !== listing.path ||
        check.data.header?.can !== listing.can || check.data.header?.project !== listing.fields.project ||
        check.data.header?.['payment.amount'] !== descriptor.price.amount ||
        check.data.header?.['payment.currency'] !== descriptor.price.currency) {
      state.stage = 'publication-check-held'; await custody.putAttempt(state);
      return { stage: state.stage, newCashExpenseUsd: 0 };
    }
    state.intent = { method: 'POST', path: '/listings', body: listing };
    state.stage = 'publication-intent';
    await custody.putAttempt(state);
    const result = await hashnRequest('/listings', { method: 'POST', body: listing, credential, fetchImpl, now });
    state.receipt = result.providerReceipt;
    state.stage = result.status === 201 ? 'publication-received' : 'publication-readback-required';
    await custody.putAttempt(state);
    return { stage: state.stage, receipt: result.data, newCashExpenseUsd: 0 };
  } catch (error) {
    state.stage = state.intent ? 'publication-outcome-held' : 'publication-precondition-held';
    state.failure = { code: error.code ?? 'publication-failure', message: error.message,
      ...(error.providerReceipt ? { providerReceipt: error.providerReceipt } : {}) };
    await custody.putAttempt(state);
    return { stage: state.stage, newCashExpenseUsd: 0 };
  }
}
