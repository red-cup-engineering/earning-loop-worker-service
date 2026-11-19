import { register, read, put } from './registers.mjs';

// Preserve the provider's complete delay. An unrepresentable positive delay
// blocks acquisition instead of silently retrying earlier than permitted.
export function retryDelayMs(value, now) {
  if (typeof value !== 'string') return 0;
  const text = value.trim();
  const seconds = /^\d+$/.test(text);
  const delay = seconds ? Number(text) * 1000
    : /^[A-Za-z]{3}, /.test(text) ? Date.parse(text) - now.getTime() : 0;
  if (seconds && (!Number.isSafeInteger(delay) || !Number.isFinite(new Date(now.getTime() + delay).getTime()))) return Infinity;
  return Number.isFinite(delay) ? Math.max(0, delay) : 0;
}

export async function refreshIssuerResearch(env, configuration, { now = new Date(), prepare } = {}) {
  if (!configuration) return { status: 'not-configured' };
  const key = register('issuer-research');
  const previous = await read(env.STATE, key);
  if (previous?.retryBlocked) return { ...previous, status: 'deferred' };
  if (previous?.cacheKey === configuration.cacheKey && Date.parse(previous.nextAttemptAt) > now.getTime())
    return { ...previous, status: 'deferred' };
  let reading;
  try {
    const producer = prepare ?? (await import('@red-cup-engineering/issuer-research-media-service/prepared-cohort')).prepareIssuerRevenueCohort;
    const complete = await producer(configuration);
    // The producer owns completeness and provenance. Publish only its completed
    // return value; failures before this point leave the last serving object intact.
    await put(env.STATE, configuration.cacheKey, complete);
    reading = { status: 'prepared', at: now.toISOString(), cacheKey: configuration.cacheKey,
      observedAt: complete.observedAt ?? null, nextAttemptAt: new Date(now.getTime() + 900_000).toISOString() };
  } catch (error) {
    const delay = Math.max(900_000, retryDelayMs(error.retryAfter, now));
    reading = { status: 'unavailable', at: now.toISOString(), cacheKey: configuration.cacheKey,
      error: error.message, code: error.code ?? null, reason: error.reason ?? null,
      retryable: error.retryable ?? true, retryAfter: typeof error.retryAfter === 'string' ? error.retryAfter : null,
      retryBlocked: !Number.isFinite(delay),
      nextAttemptAt: Number.isFinite(delay) ? new Date(now.getTime() + delay).toISOString() : null };
  }
  await put(env.STATE, key, reading);
  return reading;
}
