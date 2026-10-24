// Hashn 0.61.2 control API: fixed origin, no redirects or automatic replay.
import { readTextBody } from '@red-cup-engineering/http-services-section/body/web';
import { retryAfterDelayMs } from '@red-cup-engineering/http-services-section/retry-after';
import { admitCanonicalJson, JSON_RESOURCE_ENVELOPE } from '@red-cup-engineering/json-services-section/canonical-json';

export const HASHN_ORIGIN = 'https://api.hashn.com';
export const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const LIMIT = 32768;
const envelope = { ...JSON_RESOURCE_ENVELOPE, maxSourceBytes: LIMIT, maxCanonicalBytes: LIMIT, maxDepth: 20, maxNodes: 12000 };
export const hashnError = (code, status = 0) => Object.assign(new Error(code), { code, status });
export function privateHashnReceipt(value, credential) {
  const redact = v => {
    if (typeof v === 'string') return v.replace(/aw_[A-Za-z0-9._~-]+/g,'[redacted-token]')
      .split(credential?.apiToken || '\u0000').join('[redacted-token]');
    if (Array.isArray(v)) return v.map(redact);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k,x]) =>
      [k,/authorization|token|secret|password|credential/i.test(k) ? '[redacted]' : redact(x)]));
    return v;
  };
  const safe = redact(value);
  if (new TextEncoder().encode(JSON.stringify(safe)).length > LIMIT)
    return { status: safe.status, requestId: safe.requestId, cfRay: safe.cfRay, coverage: 'redacted-receipt-exceeds-storage-limit', bodyOmitted: true };
  return safe;
}
export function hashnCredential(value) {
  let c;
  try { c = typeof value === 'string' ? JSON.parse(value) : value; } catch { return null; }
  return UUID.test(c?.agentId ?? '') && typeof c.apiToken === 'string' && /^aw_[A-Za-z0-9_-]{8,512}$/.test(c.apiToken)
    ? { agentId: c.agentId, apiToken: c.apiToken } : null;
}

export async function hashnRequest(path, { method = 'GET', body, credential, fetchImpl = fetch, now = () => Date.now(), onRetry = async () => {} } = {}) {
  const allowed = method === 'GET' && ['/agents/me', '/knocks', '/listings'].includes(path) && credential ||
    method === 'POST' && (path === '/agents' && !credential ||
      (/^\/workspaces\/[a-f0-9-]{36}\/knock$/i.test(path) || ['/listings/check','/listings'].includes(path)) && credential);
  if (!allowed) throw hashnError('hashn-endpoint-refused');
  const signal = AbortSignal.timeout(15000);
  let response;
  try {
    response = await fetchImpl(HASHN_ORIGIN + path, { method, redirect: 'manual', signal,
      headers: { accept: 'application/json', ...(credential ? { authorization: `Bearer ${credential.apiToken}` } : {}),
        ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  } catch { throw Object.assign(hashnError('hashn-response-unknown'), { providerReceipt: { status: null, coverage: 'response-not-received' } }); }
  const receipt = { status: response.status, requestId: response.headers.get('x-request-id')?.slice(0,256) ?? null,
    cfRay: response.headers.get('cf-ray')?.slice(0,256) ?? null, coverage: 'headers-only' };
  const refuse = code => Object.assign(hashnError(code,response.status), { providerReceipt: privateHashnReceipt(receipt,credential) });
  const retry = response.headers.get('retry-after');
  if (retry) {
    const delay = retry.length <= 256 ? retryAfterDelayMs(retry, now()) : null;
    const retryBlocked = retry.length > 256 || delay === null && /^\d+$/.test(retry.trim()) || delay !== null && !Number.isFinite(new Date(now() + delay).getTime());
    if (retryBlocked || delay !== null) await onRetry({ retryBlocked, retryAt: retryBlocked ? null : now() + delay });
  }
  if (Number(response.headers.get('content-length')) > LIMIT) {
    receipt.coverage = 'declared-body-too-large';
    void response.body?.cancel().catch(() => {}); throw refuse('hashn-response-too-large');
  }
  let text;
  try {
    text = await readTextBody({ body: response.body, headers: response.headers, signal }, { maxBytes: LIMIT, decodeContentEncoding: false });
  } catch { receipt.coverage = 'body-unreceived-or-limit'; throw refuse('hashn-response-invalid'); }
  receipt.coverage = 'complete-bounded-body';
  let data;
  try { data = admitCanonicalJson(text, envelope).value; receipt.body = data; }
  catch { receipt.body = text; if (response.ok) throw refuse('hashn-response-invalid'); }
  if (!response.ok) throw refuse(response.status >= 300 && response.status < 400 ? 'hashn-redirect-refused' : response.status === 402 ? 'hashn-payment-refused' : 'hashn-provider-refused');
  return { status: response.status, data, providerReceipt: privateHashnReceipt(receipt,credential) };
}
