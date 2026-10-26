// Provider protocol: https://opentask.ai/docs/agent-auth-integration
// This client owns HTTP/custody; RFC 9449 proof construction belongs to OAuth.
import { sign } from "node:crypto";
import { Buffer } from 'node:buffer';
import { retryAfterDelayMs } from '@red-cup-engineering/http-services-section/retry-after';

const ORIGIN = "https://opentask.ai";
const ID = "[A-Za-z0-9_-]{1,200}";
const RESOURCE = new RegExp(`^/api/agent/(?:bids(?:/${ID})?|tasks/${ID}|contracts(?:/${ID}(?:/messages|/payout-destination|/crypto-payment-requests(?:/${ID})?|/deliveries(?:/${ID})?)?)?)$`);
const BID_CREATE = new RegExp(`^/api/agent/tasks/${ID}/bids$`);
const MESSAGE = new RegExp(`^/api/agent/contracts/${ID}/messages$`);
const DRAFT = new RegExp(`^/api/agent/contracts/${ID}/deliveries$`);
const EDIT = new RegExp(`^/api/agent/contracts/${ID}/deliveries/${ID}$`);
const EFFECT = new RegExp(`^/api/agent/contracts/${ID}/deliveries/${ID}/(?:external-artifacts|submit)$`);
const AUTH = new Set(["/api/agent/auth/token", "/api/agent/auth/assert/challenge", "/api/agent/auth/assert/complete"]);
const AUTH_KEY = "opentask/auth";
const REPLAY = new Set(["refresh_reuse", "refresh_token_reuse_detected"]);
const TERMINAL = new Set(['invalid_access_token', 'access_denied', 'insufficient_scope', 'reauthentication_required']);
const BACKOFF = 'opentask/provider-backoff';

export class OpenTaskError extends Error {
  constructor(code, status = 0) { super(code); this.code = code; this.status = status; }
}

export function allowedRequest(method, path) {
  if (typeof path !== "string" || path.includes("#") || path.includes("\\")) return false;
  const url = new URL(path, ORIGIN);
  if (url.origin !== ORIGIN || !path.startsWith("/api/agent/") || url.pathname.includes("%")) return false;
  if (method === "GET") {
    if (!RESOURCE.test(url.pathname)) return false;
    for (const [key, value] of url.searchParams) {
      if (key === "taskId" && url.pathname === "/api/agent/bids" && /^[A-Za-z0-9_-]{1,200}$/.test(value)) continue;
      if (key === "role" && value === "seller") continue;
      if (key === "limit" && /^\d{1,2}$/.test(value) && +value <= 20 && +value > 0) continue;
      if (key === "cursor" && /^[A-Za-z0-9_=-]{1,1000}$/.test(value)) continue;
      return false;
    }
    return true;
  }
  return url.search === "" && ((method === "PATCH" && EDIT.test(path)) ||
    (method === "POST" && (BID_CREATE.test(path) || DRAFT.test(path) || EFFECT.test(path) || MESSAGE.test(path))));
}

const defaultProof = async (options) => (await import("@red-cup-engineering/oauth-services-section/dpop")).signDpopProof(options);
export const defaultCanonical = (privateJwk, canonical) => sign("sha256", Buffer.from(canonical), {
  key: privateJwk, format: "jwk", dsaEncoding: "ieee-p1363",
}).toString("base64url");

/** Must be called only under the owning Durable Object's single-writer queue.
 * No error or returned operational summary contains credentials/provider bodies.
 */
export function createOpenTaskClient({ storage, initialCredential, fetchImpl = fetch,
  proof = defaultProof, signCanonical = defaultCanonical, now = () => Date.now(), budget = 12 } = {}) {
  let calls = 0, nonce;
  const count = () => { if (calls >= budget) throw new OpenTaskError("commercial-request-budget"); calls++; };
  async function checkBackoff() {
    const held = await storage.get(BACKOFF);
    if (held?.retryBlocked || held?.retryAt > now()) {
      const error = new OpenTaskError('provider-retry-deferred');
      error.retryBlocked = held.retryBlocked; error.retryAt = held.retryAt;
      throw error;
    }
  }
  async function wire(path, { method = "GET", body, credential, token = true, key } = {}) {
    await checkBackoff();
    count();
    if (!AUTH.has(path) && !allowedRequest(method, path)) throw new OpenTaskError("endpoint-refused");
    const headers = { accept: "application/json" };
    if (body !== undefined) headers["content-type"] = body instanceof URLSearchParams ? "application/x-www-form-urlencoded" : "application/json";
    if (key) headers["idempotency-key"] = key;
    if (credential) {
      try {
        headers.dpop = await proof({ privateKey: credential.privateJwk, method, url: ORIGIN + path,
          ...(token ? { accessToken: credential.accessToken } : {}), ...(nonce ? { nonce } : {}) });
      } catch { throw new OpenTaskError('proof-generation-failed'); }
      if (token) headers.authorization = `DPoP ${credential.accessToken}`;
    }
    let response;
    try { response = await fetchImpl(ORIGIN + path, { method, headers, redirect: "manual",
      signal: AbortSignal.timeout(15000), ...(body === undefined ? {} : { body: body instanceof URLSearchParams ? body.toString() : JSON.stringify(body) }) }); }
    catch { throw new OpenTaskError("response-unknown"); }
    // Header authority survives gateway HTML, truncated bodies and size refusals.
    const retryFacts = {}, receivedAt = now(), retry = response.headers.get('retry-after');
    if (retry) {
      const delay = retry.length <= 256 ? retryAfterDelayMs(retry, receivedAt) : null;
      const blocked = retry.length > 256 || delay === null && /^\d+$/.test(retry.trim()) || delay !== null && !Number.isFinite(new Date(receivedAt + delay).getTime());
      if (blocked || delay !== null) {
        Object.assign(retryFacts, { retryBlocked: blocked, retryAt: blocked ? null : receivedAt + delay, retryAfter: retry.slice(0, 256) });
        await storage.put(BACKOFF, { ...retryFacts, receivedAt });
      }
    }
    const responseError = (code) => Object.assign(new OpenTaskError(code, response.status), retryFacts);
    if (response.status >= 300 && response.status < 400) throw responseError("redirect-refused");
    const receivedNonce = response.headers.get("dpop-nonce");
    if (receivedNonce && receivedNonce.length <= 512) nonce = receivedNonce;
    if (Number(response.headers.get("content-length")) > 262144) throw responseError("response-too-large");
    let bytes = 0, text = "";
    try {
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      if (reader) for (;;) {
        const part = await reader.read();
        if (part.done) break;
        bytes += part.value.byteLength;
        if (bytes > 262144) { await reader.cancel(); throw responseError("response-too-large"); }
        text += decoder.decode(part.value, { stream: true });
      }
      text += decoder.decode();
    } catch (error) { throw error instanceof OpenTaskError ? error : responseError('response-read-failed'); }
    let data;
    try { data = JSON.parse(text); } catch { throw responseError("invalid-response"); }
    if (!response.ok) {
      const identifiers = [data.code, data.error?.code, typeof data.error === 'string' ? data.error : undefined,
        data.reason, data.revocation_reason, data.recovery?.code, data.error?.recovery?.code];
      const code = identifiers.find(value => REPLAY.has(value)) ?? identifiers.find(value => typeof value === 'string') ?? "provider-error";
      // Retain only a bounded protocol identifier, never an arbitrary error body.
      const error = responseError(/^[a-z0-9_]{1,100}$/.test(code) ? code : "provider-error");
      if (TERMINAL.has(error.code) && credential) await storage.put(AUTH_KEY, { ...credential, pendingRefresh: false, authFailure: error.code });
      throw error;
    }
    return data;
  }
  async function load() {
    let c = await storage.get(AUTH_KEY);
    if (!c) {
      let seed;
      try { seed = typeof initialCredential === "string" ? JSON.parse(initialCredential) : initialCredential; } catch { throw new OpenTaskError("credential-invalid"); }
      if (!seed?.accessToken || !seed.refreshToken || !seed.credentialId || seed.privateJwk?.kty !== "EC" || seed.privateJwk.crv !== "P-256" || !seed.privateJwk.d || !Number.isFinite(seed.expiresAt)) throw new OpenTaskError("credential-invalid");
      // Whitelist operational material; offline recovery keys never enter runtime.
      c = { accessToken: seed.accessToken, refreshToken: seed.refreshToken, credentialId: seed.credentialId,
        privateJwk: seed.privateJwk, expiresAt: seed.expiresAt, pendingRefresh: true };
      // A deployment seed may retain an already consumed refresh token after
      // DO recovery. First establish this runtime's custody by key assertion.
      await storage.put(AUTH_KEY, c);
    }
    if (c.authFailure) throw new OpenTaskError("credential-terminal");
    return c;
  }
  async function assertion(c) {
    const challenge = await wire("/api/agent/auth/assert/challenge", { method: "POST", body: { credential_id: c.credentialId } });
    if (typeof challenge.assertion_id !== "string" || typeof challenge.canonical_payload !== "string" || challenge.canonical_payload.length > 20000) throw new OpenTaskError("assertion-invalid");
    let signature;
    try { signature = await signCanonical(c.privateJwk, challenge.canonical_payload); }
    catch { throw new OpenTaskError('challenge-sign-failed'); }
    return wire("/api/agent/auth/assert/complete", { method: "POST", body: { assertion_id: challenge.assertion_id, signature } });
  }
  async function refresh(c) {
    const resume = !!c.pendingRefresh;
    c = { ...c, pendingRefresh: true };
    await storage.put(AUTH_KEY, c); // durable BEFORE a possibly consumed refresh
    try {
      let response;
      try {
        response = resume ? await assertion(c) : await wire("/api/agent/auth/token", { method: "POST", credential: c, token: false,
          body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: c.refreshToken }) });
      } catch (error) {
        if (resume || REPLAY.has(error.code) || (error.status >= 400 && error.status < 500 && error.code !== "invalid_grant")) throw error;
        response = await assertion(c); // one key assertion, never replay refresh
      }
      if (typeof response.access_token !== "string" || typeof response.refresh_token !== "string" ||
          !Number.isFinite(response.expires_in) || response.expires_in <= 0 || response.expires_in > 86400) throw new OpenTaskError("token-response-invalid");
      const replacement = { privateJwk: c.privateJwk, credentialId: c.credentialId,
        accessToken: response.access_token, refreshToken: response.refresh_token, expiresAt: now() + response.expires_in * 1000 };
      await storage.put(AUTH_KEY, replacement); // persist rotation BEFORE using it
      return replacement;
    } catch (error) {
      if ((TERMINAL.has(error.code) || ["invalid_grant", "refresh_reuse", "refresh_token_reuse_detected"].includes(error.code)) && error.status >= 400 && error.status < 500) {
        await storage.put(AUTH_KEY, { ...c, pendingRefresh: false, authFailure: error.code });
      }
      throw error;
    }
  }
  return {
    get calls() { return calls; },
    async request(path, { method = "GET", body, key } = {}) {
      if (!allowedRequest(method, path)) throw new OpenTaskError("endpoint-refused");
      if (method !== "GET" && (!key || !/^[A-Za-z0-9:._-]{8,200}$/.test(key))) throw new OpenTaskError("idempotency-required");
      await checkBackoff();
      let c = await load();
      if (c.pendingRefresh || c.expiresAt - now() < 300000) c = await refresh(c);
      try { return await wire(path, { method, body, credential: c, key }); }
      catch (error) {
        if (error.code === "use_dpop_nonce" && nonce) return wire(path, { method, body, credential: c, key });
        if (error.code !== "expired_access_token") throw error;
        c = await refresh(c);
        return wire(path, { method, body, credential: c, key });
      }
    },
  };
}
