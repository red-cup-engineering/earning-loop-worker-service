// The existing seller credential and private clock own acquisition as well as delivery.
// Provider: /api/openapi and /docs/agent-developer-quickstart, received 2026-10-26.
const id = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,200}$/.test(value);

export function commercialOffers(instance) {
  if (instance?.offers === undefined) return [instance];
  if (!Array.isArray(instance.offers) || instance.offers.length > 3) throw new TypeError('commercial offers exceed allocation');
  const { offers, ...original } = instance;
  const selected = [...offers.map(offer => ({ ...original, ...offer, profileId: original.profileId,
    maximumNewCashExpenseUsd: original.maximumNewCashExpenseUsd })), original];
  if (new Set(selected.map(offer => offer.taskId)).size !== selected.length) throw new TypeError('duplicate acquisition target');
  return selected;
}

export function bidAcquisitionProblem(instance) {
  if (!id(instance.taskId) || !id(instance.buyerId) || !id(instance.profileId) ||
      typeof instance.taskDescription !== 'string' || !instance.taskDescription ||
      typeof instance.expectedTaskUpdatedAt !== 'string' || !Number.isFinite(Date.parse(instance.expectedTaskUpdatedAt)) ||
      typeof instance.bidApproach !== 'string' || !instance.bidApproach || instance.bidApproach.length > 10000 ||
      instance.maximumNewCashExpenseUsd !== 0) return 'acquisition-instance-refused';
  return null;
}

export async function acquirePreparedBid({ client, instance, state, save, now }) {
  const problem = bidAcquisitionProblem(instance);
  if (problem) return problem;
  // Reconcile prior effects before every attempted creation. A bid is unique
  // per profile/task; a lost creation response is never blindly repeated.
  const page = await client.request(`/api/agent/bids?taskId=${instance.taskId}&limit=20`);
  if (!Array.isArray(page.bids) || page.nextCursor) return 'bid-history-held';
  const bids = page.bids.filter(bid => bid.task?.id === instance.taskId);
  if (bids.length > 1) return 'multiple-bids-held';
  if (bids.length) {
    const bid = bids[0];
    if (!id(bid.id) || bid.priceText !== instance.priceText || bid.approach !== instance.bidApproach) return 'existing-bid-terms-held';
    if (!['active', 'accepted'].includes(bid.status)) return `bid-${['withdrawn','expired','rejected'].includes(bid.status) ? bid.status : 'status-held'}`;
    state.bidId = bid.id;
    state.bidPending = null;
    return 'bid-received';
  }
  if (state.bidPending) return 'bid-effect-readback-pending';
  const context = await client.request(`/api/agent/tasks/${instance.taskId}`);
  const task = context.task;
  if (task?.id !== instance.taskId || task.owner?.id !== instance.buyerId || task.owner.kind !== 'agent' ||
      task.status !== 'open' || task.executionMode !== 'pitch' || task.updatedAt !== instance.expectedTaskUpdatedAt ||
      task.description !== instance.taskDescription || (task.capabilityRequirements ?? []).length) return 'buyer-scope-held';
  const permitted = context.availableActions?.some(action => action.schemaVersion === 'opentask-available-actions-v1' &&
    action.action === 'create_bid' && action.state === 'available' && action.entity?.id === instance.taskId &&
    action.actor?.role === 'worker' && (!action.actor.eligibleProfileId || action.actor.eligibleProfileId === instance.profileId) &&
    action.invocation?.method === 'POST' && action.invocation.endpoint === `/api/agent/tasks/${instance.taskId}/bids` &&
    action.invocation.bodyTemplate?.expectedTaskUpdatedAt === task.updatedAt && action.confirmation?.required === false &&
    (!action.payment || action.payment.required === false && [null, undefined, '0'].includes(action.payment.amountAtomic)) &&
    action.actor.requiredScopeMode === 'all' && Array.isArray(action.actor.requiredScopes) && action.actor.requiredScopes.length > 0 &&
    action.actor.requiredScopes.every(scope => scope === 'bids:write') &&
    (!action.availableAfter || Date.parse(action.availableAfter) <= now.getTime()) &&
    (!action.availableUntil || Date.parse(action.availableUntil) > now.getTime()));
  if (!permitted) return 'bid-action-held';
  const body = { expectedTaskUpdatedAt: task.updatedAt, priceText: instance.priceText, etaDays: 1,
    approach: instance.bidApproach, expiresAt: new Date(now.getTime() + 604800000).toISOString() };
  state.bidPending = { path: `/api/agent/tasks/${instance.taskId}/bids`, body, at: now.toISOString() };
  await save();
  const result = await client.request(state.bidPending.path, { method: 'POST', body,
    key: `prepared-bid:${instance.taskId}` });
  if (!id(result.bid?.id)) return 'bid-effect-readback-pending';
  state.bidId = result.bid.id;
  state.bidPending = null;
  return 'bid-created';
}

export const commercialStateKey = (original, selected) => selected.taskId === original.taskId ? 'opentask/commercial' : `opentask/commercial/${selected.taskId}`;
