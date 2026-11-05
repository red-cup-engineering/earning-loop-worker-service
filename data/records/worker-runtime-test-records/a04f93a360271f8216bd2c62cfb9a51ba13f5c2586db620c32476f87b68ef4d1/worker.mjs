var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res, err) => function __init() {
  if (err) throw err[0];
  try {
    return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
  } catch (e) {
    throw err = [e], e;
  }
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// node_modules/@red-cup-engineering/oauth-services-section/node_modules/@red-cup-engineering/cryptographic-computer-data-engineering-services-section/src/hash.mjs
import crypto2 from "node:crypto";
function sha256(buf) {
  return crypto2.createHash("sha256").update(buf).digest();
}
var NATIVE_RIPEMD160;
var init_hash = __esm({
  "node_modules/@red-cup-engineering/oauth-services-section/node_modules/@red-cup-engineering/cryptographic-computer-data-engineering-services-section/src/hash.mjs"() {
    NATIVE_RIPEMD160 = (() => {
      try {
        if (!crypto2.getHashes().includes("ripemd160")) return false;
        crypto2.createHash("ripemd160").update(Buffer.alloc(0)).digest();
        return true;
      } catch {
        return false;
      }
    })();
  }
});

// node_modules/@red-cup-engineering/oauth-services-section/node_modules/@red-cup-engineering/cryptographic-computer-data-engineering-services-section/src/integrity.mjs
import { Buffer as Buffer2 } from "node:buffer";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
function sha256Base64Url(value) {
  return sha256(Buffer2.from(value, "utf8")).toString("base64url");
}
function randomBase64Url(byteLength) {
  if (!Number.isInteger(byteLength) || byteLength <= 0) {
    throw new TypeError("randomBase64Url requires a positive integer byteLength");
  }
  return randomBytes(byteLength).toString("base64url");
}
var init_integrity = __esm({
  "node_modules/@red-cup-engineering/oauth-services-section/node_modules/@red-cup-engineering/cryptographic-computer-data-engineering-services-section/src/integrity.mjs"() {
    init_hash();
  }
});

// node_modules/@red-cup-engineering/oauth-services-section/src/json-web-token.mjs
import { Buffer as Buffer3 } from "node:buffer";
import { createPrivateKey, sign as cryptoSign } from "node:crypto";
function signJsonWebToken(claims, { privateKey, kid, alg = "RS256", typ = "JWT", header = {} } = {}) {
  const algorithm = ALGORITHMS[alg];
  if (!algorithm) throw new TypeError(`unsupported JWT algorithm ${alg}`);
  const key = typeof privateKey === "object" && privateKey?.kty ? createPrivateKey({ key: privateKey, format: "jwk" }) : privateKey;
  const protectedHeader = { ...header, alg, typ, ...kid === void 0 ? {} : { kid } };
  const signingInput = `${encodePart(protectedHeader)}.${encodePart(claims)}`;
  const signature = cryptoSign(algorithm.digest, Buffer3.from(signingInput, "ascii"), { key, ...algorithm.options });
  return `${signingInput}.${signature.toString("base64url")}`;
}
var ALGORITHMS, encodePart;
var init_json_web_token = __esm({
  "node_modules/@red-cup-engineering/oauth-services-section/src/json-web-token.mjs"() {
    ALGORITHMS = Object.freeze({
      RS256: { digest: "sha256", options: {}, verify: { members: ["kty", "n", "e"], importAs: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verifyAs: { name: "RSASSA-PKCS1-v1_5" } } },
      ES256: { digest: "sha256", options: { dsaEncoding: "ieee-p1363" }, verify: { members: ["kty", "crv", "x", "y"], importAs: { name: "ECDSA", namedCurve: "P-256" }, verifyAs: { name: "ECDSA", hash: "SHA-256" } } },
      EdDSA: { digest: null, options: {}, verify: { members: ["kty", "crv", "x"], importAs: { name: "Ed25519" }, verifyAs: { name: "Ed25519" } } }
    });
    encodePart = (value) => Buffer3.from(JSON.stringify(value), "utf8").toString("base64url");
  }
});

// node_modules/@red-cup-engineering/oauth-services-section/src/dpop.mjs
var dpop_exports = {};
__export(dpop_exports, {
  signDpopProof: () => signDpopProof
});
import { createPrivateKey as createPrivateKey2, createPublicKey, KeyObject } from "node:crypto";
function signDpopProof({
  privateKey,
  method,
  url,
  accessToken,
  nonce,
  iat = Math.floor(Date.now() / 1e3)
} = {}) {
  if (typeof method !== "string" || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(method)) {
    throw new TypeError("DPoP method must be the actual HTTP method token");
  }
  const target = new URL(url);
  if (target.protocol !== "https:" || target.username || target.password) {
    throw new TypeError("DPoP target must be an HTTPS URI without user information");
  }
  if (!Number.isSafeInteger(iat) || iat < 0) throw new TypeError("DPoP iat must be integer Unix seconds");
  if (accessToken !== void 0 && (typeof accessToken !== "string" || !/^[\x21-\x7e]+$/u.test(accessToken))) {
    throw new TypeError("DPoP access token must be nonempty ASCII without whitespace");
  }
  if (nonce !== void 0 && (typeof nonce !== "string" || !/^[\x21\x23-\x5b\x5d-\x7e]+$/u.test(nonce))) {
    throw new TypeError("DPoP nonce must match RFC 9449 NQCHAR syntax");
  }
  const key = privateKey instanceof KeyObject ? privateKey : createPrivateKey2(privateKey?.kty ? { key: privateKey, format: "jwk" } : privateKey);
  if (key.type !== "private") throw new TypeError("DPoP requires a private P-256 key");
  const publicKey = createPublicKey(key).export({ format: "jwk" });
  if (publicKey.kty !== "EC" || publicKey.crv !== "P-256") throw new TypeError("DPoP ES256 requires a P-256 key");
  const { kty, crv, x, y } = publicKey;
  target.search = "";
  target.hash = "";
  return signJsonWebToken({
    jti: randomBase64Url(16),
    htm: method,
    htu: target.href,
    iat,
    ...accessToken === void 0 ? {} : { ath: sha256Base64Url(accessToken) },
    ...nonce === void 0 ? {} : { nonce }
  }, { privateKey: key, alg: "ES256", typ: "dpop+jwt", header: { jwk: { kty, crv, x, y } } });
}
var init_dpop = __esm({
  "node_modules/@red-cup-engineering/oauth-services-section/src/dpop.mjs"() {
    init_integrity();
    init_json_web_token();
  }
});

// test/workerd-auth-worker.mjs
import assert from "node:assert/strict";
import { Buffer as Buffer5 } from "node:buffer";
import { createHash as createHash2, createPublicKey as createPublicKey2, verify } from "node:crypto";

// src/opentask-client.mjs
import { createPrivateKey as createPrivateKey3, sign } from "node:crypto";
import { Buffer as Buffer4 } from "node:buffer";

// node_modules/@red-cup-engineering/http-services-section/src/retry-after.mjs
function retryAfterDelayMs(value, receivedAt = Date.now()) {
  if (!Number.isFinite(receivedAt)) throw new TypeError("finite response receipt clock required");
  if (typeof value !== "string") return null;
  const text = value.trim();
  if (/^\d+$/u.test(text)) {
    const seconds = Number(text);
    return Number.isSafeInteger(seconds) && seconds <= Number.MAX_SAFE_INTEGER / 1e3 ? seconds * 1e3 : null;
  }
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  let match, year, month, day, hour, minute, second;
  if (match = /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{2}):(\d{2}):(\d{2}) GMT$/u.exec(text)) {
    [, day, month, year, hour, minute, second] = match;
  } else if (match = /^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\d{2})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-(\d{2}) (\d{2}):(\d{2}):(\d{2}) GMT$/u.exec(text)) {
    [, day, month, year, hour, minute, second] = match;
    const current = new Date(receivedAt).getUTCFullYear();
    year = Math.floor(current / 100) * 100 + Number(year);
    if (year > current + 50) year -= 100;
  } else if (match = /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?: (\d)|([0-3]\d)) (\d{2}):(\d{2}):(\d{2}) (\d{4})$/u.exec(text)) {
    month = match[1];
    day = match[2] ?? match[3];
    hour = match[4];
    minute = match[5];
    second = match[6];
    year = match[7];
  } else return null;
  const date = /* @__PURE__ */ new Date(0);
  date.setUTCFullYear(Number(year), months.indexOf(month), Number(day));
  date.setUTCHours(Number(hour), Number(minute), Number(second), 0);
  if (!Number.isFinite(date.getTime()) || date.getUTCFullYear() !== Number(year) || date.getUTCMonth() !== months.indexOf(month) || date.getUTCDate() !== Number(day) || date.getUTCHours() !== Number(hour) || date.getUTCMinutes() !== Number(minute) || date.getUTCSeconds() !== Number(second)) return null;
  return Math.max(0, date.getTime() - receivedAt);
}

// src/opentask-client.mjs
var ORIGIN = "https://opentask.ai";
var ID = "[A-Za-z0-9_-]{1,200}";
var RESOURCE = new RegExp(`^/api/agent/(?:bids/${ID}|contracts(?:/${ID}(?:/messages|/payout-destination|/crypto-payment-requests(?:/${ID})?|/deliveries(?:/${ID})?)?)?)$`);
var MESSAGE = new RegExp(`^/api/agent/contracts/${ID}/messages$`);
var DRAFT = new RegExp(`^/api/agent/contracts/${ID}/deliveries$`);
var EDIT = new RegExp(`^/api/agent/contracts/${ID}/deliveries/${ID}$`);
var EFFECT = new RegExp(`^/api/agent/contracts/${ID}/deliveries/${ID}/(?:external-artifacts|submit)$`);
var AUTH = /* @__PURE__ */ new Set(["/api/agent/auth/token", "/api/agent/auth/assert/challenge", "/api/agent/auth/assert/complete"]);
var AUTH_KEY = "opentask/auth";
var REPLAY = /* @__PURE__ */ new Set(["refresh_reuse", "refresh_token_reuse_detected"]);
var TERMINAL = /* @__PURE__ */ new Set(["invalid_access_token", "access_denied", "insufficient_scope", "reauthentication_required"]);
var BACKOFF = "opentask/provider-backoff";
var OpenTaskError = class extends Error {
  constructor(code, status = 0) {
    super(code);
    this.code = code;
    this.status = status;
  }
};
function allowedRequest(method, path) {
  if (typeof path !== "string" || path.includes("#") || path.includes("\\")) return false;
  const url = new URL(path, ORIGIN);
  if (url.origin !== ORIGIN || !path.startsWith("/api/agent/") || url.pathname.includes("%")) return false;
  if (method === "GET") {
    if (!RESOURCE.test(url.pathname)) return false;
    for (const [key, value] of url.searchParams) {
      if (key === "role" && value === "seller") continue;
      if (key === "limit" && /^\d{1,2}$/.test(value) && +value <= 20 && +value > 0) continue;
      if (key === "cursor" && /^[A-Za-z0-9_=-]{1,1000}$/.test(value)) continue;
      return false;
    }
    return true;
  }
  return url.search === "" && (method === "PATCH" && EDIT.test(path) || method === "POST" && (DRAFT.test(path) || EFFECT.test(path) || MESSAGE.test(path)));
}
var defaultProof = async (options) => (await Promise.resolve().then(() => (init_dpop(), dpop_exports))).signDpopProof(options);
var defaultCanonical = (privateJwk, canonical) => sign("sha256", Buffer4.from(canonical), {
  key: createPrivateKey3({ key: privateJwk, format: "jwk" }),
  dsaEncoding: "ieee-p1363"
}).toString("base64url");
function createOpenTaskClient({
  storage,
  initialCredential,
  fetchImpl = fetch,
  proof = defaultProof,
  signCanonical = defaultCanonical,
  now = () => Date.now(),
  budget = 12
} = {}) {
  let calls = 0, nonce;
  const count = () => {
    if (calls >= budget) throw new OpenTaskError("commercial-request-budget");
    calls++;
  };
  async function checkBackoff() {
    const held = await storage.get(BACKOFF);
    if (held?.retryBlocked || held?.retryAt > now()) {
      const error = new OpenTaskError("provider-retry-deferred");
      error.retryBlocked = held.retryBlocked;
      error.retryAt = held.retryAt;
      throw error;
    }
  }
  async function wire(path, { method = "GET", body, credential, token = true, key } = {}) {
    await checkBackoff();
    count();
    if (!AUTH.has(path) && !allowedRequest(method, path)) throw new OpenTaskError("endpoint-refused");
    const headers = { accept: "application/json" };
    if (body !== void 0) headers["content-type"] = body instanceof URLSearchParams ? "application/x-www-form-urlencoded" : "application/json";
    if (key) headers["idempotency-key"] = key;
    if (credential) {
      try {
        headers.dpop = await proof({
          privateKey: credential.privateJwk,
          method,
          url: ORIGIN + path,
          ...token ? { accessToken: credential.accessToken } : {},
          ...nonce ? { nonce } : {}
        });
      } catch {
        throw new OpenTaskError("proof-generation-failed");
      }
      if (token) headers.authorization = `DPoP ${credential.accessToken}`;
    }
    let response;
    try {
      response = await fetchImpl(ORIGIN + path, {
        method,
        headers,
        redirect: "manual",
        signal: AbortSignal.timeout(15e3),
        ...body === void 0 ? {} : { body: body instanceof URLSearchParams ? body.toString() : JSON.stringify(body) }
      });
    } catch {
      throw new OpenTaskError("response-unknown");
    }
    const retryFacts = {}, receivedAt = now(), retry = response.headers.get("retry-after");
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
      if (reader) for (; ; ) {
        const part = await reader.read();
        if (part.done) break;
        bytes += part.value.byteLength;
        if (bytes > 262144) {
          await reader.cancel();
          throw responseError("response-too-large");
        }
        text += decoder.decode(part.value, { stream: true });
      }
      text += decoder.decode();
    } catch (error) {
      throw error instanceof OpenTaskError ? error : responseError("response-read-failed");
    }
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      throw responseError("invalid-response");
    }
    if (!response.ok) {
      const identifiers = [
        data.code,
        data.error?.code,
        typeof data.error === "string" ? data.error : void 0,
        data.reason,
        data.revocation_reason,
        data.recovery?.code,
        data.error?.recovery?.code
      ];
      const code = identifiers.find((value) => REPLAY.has(value)) ?? identifiers.find((value) => typeof value === "string") ?? "provider-error";
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
      try {
        seed = typeof initialCredential === "string" ? JSON.parse(initialCredential) : initialCredential;
      } catch {
        throw new OpenTaskError("credential-invalid");
      }
      if (!seed?.accessToken || !seed.refreshToken || !seed.credentialId || seed.privateJwk?.kty !== "EC" || seed.privateJwk.crv !== "P-256" || !seed.privateJwk.d || !Number.isFinite(seed.expiresAt)) throw new OpenTaskError("credential-invalid");
      c = {
        accessToken: seed.accessToken,
        refreshToken: seed.refreshToken,
        credentialId: seed.credentialId,
        privateJwk: seed.privateJwk,
        expiresAt: seed.expiresAt,
        pendingRefresh: true
      };
      await storage.put(AUTH_KEY, c);
    }
    if (c.authFailure) throw new OpenTaskError("credential-terminal");
    return c;
  }
  async function assertion(c) {
    const challenge = await wire("/api/agent/auth/assert/challenge", { method: "POST", body: { credential_id: c.credentialId } });
    if (typeof challenge.assertion_id !== "string" || typeof challenge.canonical_payload !== "string" || challenge.canonical_payload.length > 2e4) throw new OpenTaskError("assertion-invalid");
    let signature;
    try {
      signature = await signCanonical(c.privateJwk, challenge.canonical_payload);
    } catch {
      throw new OpenTaskError("challenge-sign-failed");
    }
    return wire("/api/agent/auth/assert/complete", { method: "POST", body: { assertion_id: challenge.assertion_id, signature } });
  }
  async function refresh(c) {
    const resume = !!c.pendingRefresh;
    c = { ...c, pendingRefresh: true };
    await storage.put(AUTH_KEY, c);
    try {
      let response;
      try {
        response = resume ? await assertion(c) : await wire("/api/agent/auth/token", {
          method: "POST",
          credential: c,
          token: false,
          body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: c.refreshToken })
        });
      } catch (error) {
        if (resume || REPLAY.has(error.code) || error.status >= 400 && error.status < 500 && error.code !== "invalid_grant") throw error;
        response = await assertion(c);
      }
      if (typeof response.access_token !== "string" || typeof response.refresh_token !== "string" || !Number.isFinite(response.expires_in) || response.expires_in <= 0 || response.expires_in > 86400) throw new OpenTaskError("token-response-invalid");
      const replacement = {
        privateJwk: c.privateJwk,
        credentialId: c.credentialId,
        accessToken: response.access_token,
        refreshToken: response.refresh_token,
        expiresAt: now() + response.expires_in * 1e3
      };
      await storage.put(AUTH_KEY, replacement);
      return replacement;
    } catch (error) {
      if ((TERMINAL.has(error.code) || ["invalid_grant", "refresh_reuse", "refresh_token_reuse_detected"].includes(error.code)) && error.status >= 400 && error.status < 500) {
        await storage.put(AUTH_KEY, { ...c, pendingRefresh: false, authFailure: error.code });
      }
      throw error;
    }
  }
  return {
    get calls() {
      return calls;
    },
    async request(path, { method = "GET", body, key } = {}) {
      if (!allowedRequest(method, path)) throw new OpenTaskError("endpoint-refused");
      if (method !== "GET" && (!key || !/^[A-Za-z0-9:._-]{8,200}$/.test(key))) throw new OpenTaskError("idempotency-required");
      await checkBackoff();
      let c = await load();
      if (c.pendingRefresh || c.expiresAt - now() < 3e5) c = await refresh(c);
      try {
        return await wire(path, { method, body, credential: c, key });
      } catch (error) {
        if (error.code === "use_dpop_nonce" && nonce) return wire(path, { method, body, credential: c, key });
        if (error.code !== "expired_access_token") throw error;
        c = await refresh(c);
        return wire(path, { method, body, credential: c, key });
      }
    }
  };
}

// test/workerd-auth-worker.mjs
var testNativeAuthentication = {
  async test() {
    const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const privateJwk = await crypto.subtle.exportKey("jwk", keys.privateKey);
    const publicJwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
    const canonical = "ephemeral local Worker challenge";
    const signature = defaultCanonical(privateJwk, canonical);
    assert.equal(verify("sha256", Buffer5.from(canonical), { key: createPublicKey2({ key: publicJwk, format: "jwk" }), dsaEncoding: "ieee-p1363" }, Buffer5.from(signature, "base64url")), true);
    const values = /* @__PURE__ */ new Map();
    let calls = 0;
    const client = createOpenTaskClient({
      storage: { async get(k) {
        return values.get(k);
      }, async put(k, v) {
        values.set(k, v);
      } },
      initialCredential: { privateJwk, credentialId: "ephemeral", accessToken: "local-seed", refreshToken: "local-unused", expiresAt: Date.now() + 36e5 },
      fetchImpl: async (url, init) => {
        calls++;
        if (url.endsWith("/assert/challenge")) return Response.json({ assertion_id: "local", canonical_payload: canonical });
        if (url.endsWith("/assert/complete")) {
          assert.equal(values.get("opentask/auth").pendingRefresh, true);
          assert.equal(verify("sha256", Buffer5.from(canonical), { key: createPublicKey2({ key: publicJwk, format: "jwk" }), dsaEncoding: "ieee-p1363" }, Buffer5.from(JSON.parse(init.body).signature, "base64url")), true);
          return Response.json({ access_token: "local-rotated", refresh_token: "local-rotated-refresh", expires_in: 3600 });
        }
        const parts = init.headers.dpop.split(".");
        const header = JSON.parse(Buffer5.from(parts[0], "base64url"));
        const payload = JSON.parse(Buffer5.from(parts[1], "base64url"));
        assert.equal(header.typ, "dpop+jwt");
        assert.equal(header.jwk.d, void 0);
        assert.equal(payload.htm, "GET");
        assert.equal(payload.htu, "https://opentask.ai/api/agent/contracts");
        assert.equal(payload.ath, createHash2("sha256").update("local-rotated").digest("base64url"));
        assert.equal(verify("sha256", Buffer5.from(parts.slice(0, 2).join(".")), { key: createPublicKey2({ key: publicJwk, format: "jwk" }), dsaEncoding: "ieee-p1363" }, Buffer5.from(parts[2], "base64url")), true);
        return Response.json({ contracts: [] });
      }
    });
    assert.deepEqual(await client.request("/api/agent/contracts"), { contracts: [] });
    assert.equal(calls, 3);
    assert.equal(values.get("opentask/auth").accessToken, "local-rotated");
  }
};
export {
  testNativeAuthentication
};
