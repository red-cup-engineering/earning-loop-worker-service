/** R2 keeps the reading; original CSE custody owns distributed pending effects. */
import { register, record, read, put } from './registers.mjs';

export const FINANCIAL_RESOURCE_PROVIDER = 'financial-arena';
const stages = ['monitor', 'analyze', 'plan', 'publish', 'learn'];
const outcomes = ['externally-reconciled', 'intents-awaiting-external-reconciliation', 'observed-no-dispatchable-strategy'];
const unsettled = reading => ['resource-pending', 'resource-uncertain', 'legacy-pending', 'legacy-uncertain', 'unreachable'].includes(reading?.status)
  || /^http-[0-9]+$/u.test(reading?.status ?? '');
const identity = original => {
  if (!original || typeof original.effect !== 'string' || !original.effect || typeof original.request !== 'string' || !original.request
      || typeof original.input?.run !== 'string' || !original.input.run || Object.keys(original.input).some(key => key !== 'run'))
    throw new TypeError('Original financial invocation custody is unavailable');
  return Object.freeze({ effect: original.effect, request: original.request, input: Object.freeze({ run: original.input.run }) });
};
const checkedReply = (reply, original) => {
  const event = reply?.event, content = event?.content, status = reply?.status;
  const nextCycle = content?.stage === 'learn' && content?.status === 'complete';
  const expectedNext = content?.status === 'complete' ? stages[(stages.indexOf(content?.stage) + 1) % stages.length] : content?.stage;
  if (typeof event?.id !== 'string' || !event.id || content?.type !== 'FinancialArenaEvent' || content.version !== 1
      || content.run !== original.input.run || !Number.isSafeInteger(content.cycle) || content.cycle < 1 || !stages.includes(content.stage)
      || !['complete', 'pending', 'blocked', 'needs-human'].includes(content.status) || !content.execute || !content.knowledge || !Number.isFinite(Date.parse(content.at))
      || status?.type !== 'FinancialArenaStatus' || status.version !== 1 || status.run !== content.run
      || status.cycle !== content.cycle + (nextCycle ? 1 : 0) || status.next !== expectedNext || status.lastRun !== content.at || status.backlog !== 1
      || !Array.isArray(status.stages) || status.stages.length !== stages.length
      || status.stages.some((row, index) => row.stage !== stages[index] || row.status !== (nextCycle ? 'pending'
        : index < stages.indexOf(content.stage) ? 'complete' : index === stages.indexOf(content.stage) ? content.status : 'pending'))
      || !Array.isArray(status.blockers) || !Number.isSafeInteger(status.interventions?.total) || status.interventions.total < 0)
    throw new TypeError('Financial provider did not receive its original typed turn');
  return { event: event.id, cycle: content.cycle, stage: content.stage, status: content.status,
    usefulWork: content.status === 'complete' ? (content.execute.effect === 'intent-only' ? 'intent-only' : 'stage-evidence-received') : 'not-established',
    externalReconciliation: content.stage === 'learn' && outcomes.includes(content.execute.outcome) ? content.execute.outcome : 'not-established', accountedEarnings: 'not-established' };
};

/** Public reading excludes original calls, state selectors, raw diagnostics and
 * retained replies. Those remain in original state/actor custody for receiving. */
export function onchainPublicReading(reading) {
  if (!reading) return null;
  const received = reading.received ? Object.fromEntries(['event', 'cycle', 'stage', 'status', 'usefulWork', 'externalReconciliation', 'accountedEarnings']
    .filter(key => Object.hasOwn(reading.received, key)).map(key => [key, reading.received[key]])) : null;
  return { at: reading.at, status: reading.status ?? null, occurrence: reading.occurrence ?? null,
    driver: reading.status === 'resource-received' ? 'original-turn-received' : 'not-established', received,
    usefulWork: received?.usefulWork ?? 'not-established', externalReconciliation: received?.externalReconciliation ?? 'not-established',
    accountedEarnings: 'not-established', ...(Number.isInteger(reading.httpStatus) ? { httpStatus: reading.httpStatus } : {}) };
}

export async function runOnchainHook(env, { now = new Date(), cron = null, onchain, url = env.ONCHAIN_SCAN_URL, fetchImpl = fetch } = {}) {
  const occurrence = Object.freeze({ at: now.toISOString(), cron });
  const key = register('onchain');
  // These private closures already name original authority/state. Public Worker
  // variables and generated configuration cannot construct them.
  if (onchain !== undefined && ['identify', 'checkpoint', 'provider', 'reconcile'].some(name => typeof onchain?.[name] !== 'function'))
    throw new TypeError('Financial turns require a complete private original resource port');
  let fenceFailure;
  const checkpoint = async () => {
    if (fenceFailure) throw fenceFailure;
    try { if (onchain) await onchain.checkpoint(); }
    catch (error) { fenceFailure = error; throw error; }
  };
  await checkpoint();
  const prior = await read(env.STATE, key);
  await checkpoint();
  const retain = async reading => {
    await checkpoint(); await put(env.STATE, key, reading); await checkpoint();
    if (JSON.stringify(await read(env.STATE, key)) !== JSON.stringify(reading)) throw new TypeError('Original onchain reading was not received');
    await checkpoint(); return reading;
  };
  const archive = async reading => {
    if (!reading) return undefined;
    await checkpoint();
    const bytes = new TextEncoder().encode(JSON.stringify(reading));
    const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), byte => byte.toString(16).padStart(2, '0')).join('');
    const reference = record('onchain', `${encodeURIComponent(reading.at ?? 'undated')}-${digest}`);
    const retained = await read(env.STATE, reference); await checkpoint();
    if (retained === null) { await put(env.STATE, reference, reading); await checkpoint(); }
    if (JSON.stringify(await read(env.STATE, reference)) !== JSON.stringify(reading)) throw new TypeError('Original dated onchain reading was not received');
    await checkpoint(); return reference;
  };
  if (unsettled(prior) && (!onchain || !prior.original || prior.status.startsWith('legacy-')))
    return { status: prior.status, occurrence: prior.occurrence, reconciliation: 'original-receiving-required' };
  if (onchain) {
    await checkpoint();
    const reconciling = unsettled(prior);
    const original = identity(reconciling ? prior.original : await onchain.identify(occurrence));
    if (!reconciling && prior?.status === 'resource-received' && prior.original?.effect === original.effect) {
      if (JSON.stringify(prior.original) !== JSON.stringify(original)) throw new TypeError('Received financial identity was substituted');
      return { status: prior.status, received: prior.received };
    }
    const previousReading = reconciling ? undefined : await archive(prior);
    const pending = reconciling ? prior : { at: occurrence.at, occurrence, original, status: 'resource-pending',
      ...(previousReading ? { previousReading } : {}), ...(prior?.received ? { lastReceived: prior.received } : {}) };
    await retain(pending);
    try {
      const reply = reconciling
        ? await onchain.reconcile({ provider: FINANCIAL_RESOURCE_PROVIDER, ...original })
        : await onchain.provider(FINANCIAL_RESOURCE_PROVIDER, original);
      await checkpoint();
      const received = checkedReply(reply, original);
      await retain({ ...pending, status: 'resource-received', received, answer: reply });
      return { status: 'resource-received', received };
    } catch {
      // A lost fence forbids writes too: the earlier pending reading and original
      // authority reservation survive even if receiving this uncertainty fails.
      await retain({ ...pending, status: 'resource-uncertain', reason: 'original-provider-receiving-unconfirmed' });
      return { status: 'resource-uncertain', occurrence: pending.occurrence };
    }
  }
  if (!url) {
    if (prior) return { status: 'no-engine-attached', retainedStatus: prior.status };
    await retain({ at: occurrence.at, occurrence, status: 'no-engine-attached' });
    return { status: 'no-engine-attached' };
  }
  // Compatibility is transport-only. A potentially delivered POST has no
  // automatic retry or alternate receiver, even on another clock occurrence.
  if (prior?.status === 'legacy-response-received' && prior.occurrence?.at === occurrence.at && prior.occurrence.cron === cron)
    return { status: prior.status, httpStatus: prior.httpStatus };
  const previousReading = await archive(prior);
  const pending = { at: occurrence.at, occurrence, status: 'legacy-pending',
    original: { url, body: { at: occurrence.at, cron } }, ...(previousReading ? { previousReading } : {}) };
  await retain(pending);
  try {
    const response = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/json',
      ...(env.ONCHAIN_SCAN_TOKEN ? { authorization: `Bearer ${env.ONCHAIN_SCAN_TOKEN}` } : {}) }, body: JSON.stringify(pending.original.body) });
    const answer = response.headers.get('content-type')?.includes('json') ? await response.json() : null;
    const result = await retain({ ...pending, status: 'legacy-response-received', httpStatus: response.status, answer,
      usefulWork: 'not-established', externalReconciliation: 'not-established', accountedEarnings: 'not-established' });
    return { status: result.status, httpStatus: result.httpStatus };
  } catch {
    await retain({ ...pending, status: 'legacy-uncertain', reason: 'original-http-receiving-unconfirmed' });
    return { status: 'legacy-uncertain', occurrence };
  }
}
