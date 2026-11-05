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
function randomBase64Url(byteLength2) {
  if (!Number.isInteger(byteLength2) || byteLength2 <= 0) {
    throw new TypeError("randomBase64Url requires a positive integer byteLength");
  }
  return randomBytes(byteLength2).toString("base64url");
}
var init_integrity = __esm({
  "node_modules/@red-cup-engineering/oauth-services-section/node_modules/@red-cup-engineering/cryptographic-computer-data-engineering-services-section/src/integrity.mjs"() {
    init_hash();
  }
});

// node_modules/@red-cup-engineering/oauth-services-section/src/json-web-token.mjs
import { Buffer as Buffer3 } from "node:buffer";
import { KeyObject, sign as cryptoSign } from "node:crypto";
function signJsonWebToken(claims, { privateKey, kid, alg = "RS256", typ = "JWT", header = {} } = {}) {
  const algorithm = ALGORITHMS[alg];
  if (!algorithm) throw new TypeError(`unsupported JWT algorithm ${alg}`);
  const key = privateKey instanceof KeyObject ? privateKey.export({ format: "jwk" }) : privateKey;
  const keyOptions = key?.kty ? { key, format: "jwk" } : { key };
  const protectedHeader = { ...header, alg, typ, ...kid === void 0 ? {} : { kid } };
  const signingInput = `${encodePart(protectedHeader)}.${encodePart(claims)}`;
  const signature = cryptoSign(algorithm.digest, Buffer3.from(signingInput, "ascii"), { ...keyOptions, ...algorithm.options });
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
import { createPrivateKey, createPublicKey, KeyObject as KeyObject2 } from "node:crypto";
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
  const key = privateKey instanceof KeyObject2 ? privateKey : createPrivateKey(privateKey?.kty ? { key: privateKey, format: "jwk" } : privateKey);
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
import assert2 from "node:assert/strict";
import { Buffer as Buffer5 } from "node:buffer";
import { createHash as createHash2 } from "node:crypto";

// src/opentask-client.mjs
import { sign } from "node:crypto";
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
  key: privateJwk,
  format: "jwk",
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
      const error2 = new OpenTaskError("provider-retry-deferred");
      error2.retryBlocked = held.retryBlocked;
      error2.retryAt = held.retryAt;
      throw error2;
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
    } catch (error2) {
      throw error2 instanceof OpenTaskError ? error2 : responseError("response-read-failed");
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
      const error2 = responseError(/^[a-z0-9_]{1,100}$/.test(code) ? code : "provider-error");
      if (TERMINAL.has(error2.code) && credential) await storage.put(AUTH_KEY, { ...credential, pendingRefresh: false, authFailure: error2.code });
      throw error2;
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
      } catch (error2) {
        if (resume || REPLAY.has(error2.code) || error2.status >= 400 && error2.status < 500 && error2.code !== "invalid_grant") throw error2;
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
    } catch (error2) {
      if ((TERMINAL.has(error2.code) || ["invalid_grant", "refresh_reuse", "refresh_token_reuse_detected"].includes(error2.code)) && error2.status >= 400 && error2.status < 500) {
        await storage.put(AUTH_KEY, { ...c, pendingRefresh: false, authFailure: error2.code });
      }
      throw error2;
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
      } catch (error2) {
        if (error2.code === "use_dpop_nonce" && nonce) return wire(path, { method, body, credential: c, key });
        if (error2.code !== "expired_access_token") throw error2;
        c = await refresh(c);
        return wire(path, { method, body, credential: c, key });
      }
    }
  };
}

// test/workerd-auth-worker.mjs
init_dpop();

// test/workerd-research-worker.mjs
import assert from "node:assert/strict";

// node_modules/@red-cup-engineering/json-services-section/scripts/canonical-json.mjs
var UNBOUNDED_JSON_ENVELOPE = Object.freeze({
  maxSourceBytes: Infinity,
  maxCanonicalBytes: Infinity,
  maxDepth: Infinity,
  maxNodes: Infinity,
  maxObjectMembers: Infinity,
  maxArrayLength: Infinity,
  maxStringBytes: Infinity,
  maxKeyBytes: Infinity
});
var JSON_RESOURCE_ENVELOPE = Object.freeze({
  maxSourceBytes: 1048576,
  maxCanonicalBytes: 1048576,
  maxDepth: 64,
  maxNodes: 1e5,
  maxObjectMembers: 4096,
  maxArrayLength: 65536,
  maxStringBytes: 262144,
  maxKeyBytes: 1024
});
var utf8Encoder = new TextEncoder();
var numberGrammar = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/u;
function byteLength(value) {
  return utf8Encoder.encode(value).byteLength;
}
function pathText(path) {
  const parts = [];
  let base = "$";
  for (let node = path; node !== null && typeof node === "object"; node = node.parent) {
    parts.push(node);
  }
  if (typeof path === "string") base = path;
  let text = base;
  for (let index = parts.length - 1; index >= 0; index -= 1) {
    const part = parts[index];
    text += part.kind === "index" ? `[${part.value}]` : `.${part.value}`;
  }
  return text;
}
function continuesSpine(container, index, child) {
  return index === 2 && Array.isArray(container) && container[0] === "pair" && Array.isArray(child) && child[0] === "pair";
}
function spineLimit(spine, envelope, path) {
  if (spine > envelope.maxArrayLength) fail("array-length-limit", path, `list spine exceeds ${envelope.maxArrayLength} links`);
}
function propertyPath(path, key) {
  return { parent: path, kind: "property", value: key };
}
function indexPath(path, index) {
  return { parent: path, kind: "index", value: index };
}
function fail(code, path, message) {
  const renderedPath = pathText(path);
  const error2 = new TypeError(`${code} at ${renderedPath}: ${message}`);
  error2.code = code;
  error2.path = renderedPath;
  throw error2;
}
function assertUnicodeScalars(value, path) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 55296 && unit <= 56319) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 56320 && next <= 57343)) {
        fail("unicode-scalar", path, "must not contain a lone Unicode surrogate (high)");
      }
      index += 1;
    } else if (unit >= 56320 && unit <= 57343) {
      fail("unicode-scalar", path, "must not contain a lone Unicode surrogate (low)");
    }
  }
}
function stringText(value, path, limit, code) {
  assertUnicodeScalars(value, path);
  if (byteLength(value) > limit) fail(code, path, `UTF-8 string exceeds ${limit} bytes`);
  return JSON.stringify(value);
}
function chargeCanonical(state, amount, path) {
  state.canonicalBytes += amount;
  if (state.canonicalBytes > state.envelope.maxCanonicalBytes) {
    fail("canonical-limit", path, `canonical JSON exceeds ${state.envelope.maxCanonicalBytes} bytes`);
  }
}
function projectValue(value, path, depth, state) {
  const tokens = [];
  const frames = [{ source: value, path, depth, spine: 0, entered: false }];
  let result;
  while (frames.length > 0) {
    const frame = frames[frames.length - 1];
    if (!frame.entered) {
      frame.entered = true;
      state.nodes += 1;
      if (state.nodes > state.envelope.maxNodes) {
        fail("node-limit", frame.path, `JSON value exceeds ${state.envelope.maxNodes} nodes`);
      }
      const item = frame.source;
      if (item === null) {
        chargeCanonical(state, 4, frame.path);
        tokens.push("null");
        result = null;
        frames.pop();
        continue;
      }
      if (typeof item === "boolean") {
        const text = item ? "true" : "false";
        chargeCanonical(state, text.length, frame.path);
        tokens.push(text);
        result = item;
        frames.pop();
        continue;
      }
      if (typeof item === "string") {
        const text = stringText(item, frame.path, state.envelope.maxStringBytes, "string-limit");
        chargeCanonical(state, byteLength(text), frame.path);
        tokens.push(text);
        result = item;
        frames.pop();
        continue;
      }
      if (typeof item === "number") {
        if (!Number.isFinite(item)) fail("invalid-json-value", frame.path, "JCS admits only finite IEEE-754 numbers");
        const text = JSON.stringify(item);
        chargeCanonical(state, byteLength(text), frame.path);
        tokens.push(text);
        result = Object.is(item, -0) ? 0 : item;
        frames.pop();
        continue;
      }
      if (typeof item !== "object") {
        fail("invalid-json-value", frame.path, `unsupported JSON value type: ${typeof item}`);
      }
      if (frame.depth >= state.envelope.maxDepth) {
        fail("depth-limit", frame.path, `JSON nesting exceeds depth ${state.envelope.maxDepth}`);
      }
      if (state.active.has(item)) fail("invalid-json-value", frame.path, "must not contain a cycle");
      state.active.add(item);
      frame.container = item;
      frame.index = 0;
      if (Array.isArray(item)) {
        if (item.length > state.envelope.maxArrayLength) {
          fail("array-length-limit", frame.path, `array exceeds ${state.envelope.maxArrayLength} elements`);
        }
        const ownKeys = Reflect.ownKeys(item);
        if (ownKeys.some((key) => key !== "length" && (typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(key) || Number(key) >= item.length))) {
          fail("invalid-json-value", frame.path, "arrays may not carry symbol or non-index properties");
        }
        chargeCanonical(state, 2 + Math.max(0, item.length - 1), frame.path);
        tokens.push("[");
        frame.array = true;
        frame.carried = [];
        frame.length = item.length;
      } else {
        if (Object.getPrototypeOf(item) !== Object.prototype) {
          fail("invalid-json-value", frame.path, "only ordinary JSON objects with Object.prototype are admitted");
        }
        const keys = Reflect.ownKeys(item);
        if (keys.some((key) => typeof key !== "string")) {
          fail("invalid-json-value", frame.path, "symbol properties are outside the JSON data model");
        }
        if (keys.length > state.envelope.maxObjectMembers) {
          fail("object-member-limit", frame.path, `object exceeds ${state.envelope.maxObjectMembers} members`);
        }
        frame.keys = keys.sort();
        chargeCanonical(state, 2 + Math.max(0, frame.keys.length - 1) + frame.keys.length, frame.path);
        tokens.push("{");
        frame.carried = {};
        frame.array = false;
      }
      continue;
    }
    const count = frame.array ? frame.length : frame.keys.length;
    if (frame.awaitingChild) {
      if (frame.array) {
        frame.carried.push(result);
      } else {
        Object.defineProperty(frame.carried, frame.key, {
          value: result,
          enumerable: true,
          configurable: false,
          writable: false
        });
      }
      frame.awaitingChild = false;
      frame.index += 1;
    }
    if (frame.index === count) {
      tokens.push(frame.array ? "]" : "}");
      const carried = Object.freeze(frame.carried);
      state.active.delete(frame.container);
      result = carried;
      frames.pop();
      continue;
    }
    if (frame.index > 0) tokens.push(",");
    let child;
    let childPath;
    if (frame.array) {
      const index = frame.index;
      const descriptor = Object.getOwnPropertyDescriptor(frame.container, String(index));
      childPath = indexPath(frame.path, index);
      if (descriptor === void 0) {
        fail("invalid-json-value", childPath, "sparse arrays are outside the admitted JSON value model");
      }
      if (!("value" in descriptor) || !descriptor.enumerable) {
        fail("invalid-json-value", childPath, "array accessors and non-enumerable elements are outside the JSON data model");
      }
      child = descriptor.value;
    } else {
      const key = frame.keys[frame.index];
      const descriptor = Object.getOwnPropertyDescriptor(frame.container, key);
      childPath = propertyPath(frame.path, key);
      if (descriptor === void 0 || !("value" in descriptor) || !descriptor.enumerable) {
        fail("invalid-json-value", childPath, "accessor and non-enumerable properties are outside the JSON data model");
      }
      const keyText = stringText(key, childPath, state.envelope.maxKeyBytes, "key-limit");
      chargeCanonical(state, byteLength(keyText), childPath);
      tokens.push(keyText, ":");
      frame.key = key;
      child = descriptor.value;
    }
    frame.awaitingChild = true;
    const onSpine = frame.array && continuesSpine(frame.container, frame.index, child);
    const spine = onSpine ? frame.spine + 1 : 0;
    spineLimit(spine, state.envelope, childPath);
    frames.push({ source: child, path: childPath, depth: onSpine ? frame.depth : frame.depth + 1, spine, entered: false });
  }
  return { value: result, text: tokens.join("") };
}
var StrictJsonParser = class {
  index = 0;
  nodes = 0;
  source;
  envelope;
  frames = [];
  completed;
  constructor(source, envelope) {
    this.source = source;
    this.envelope = envelope;
  }
  parse() {
    this.space();
    const value = this.value("$", 0);
    let root = this.frames.length === 0 ? value : void 0;
    while (this.frames.length > 0) {
      const frame = this.frames[this.frames.length - 1];
      if (frame.state === "awaiting") {
        if (frame.array) {
          frame.out.push(this.completed);
        } else {
          Object.defineProperty(frame.out, frame.key, {
            value: this.completed,
            enumerable: true,
            configurable: false,
            writable: false
          });
        }
        frame.state = "afterValue";
      }
      if (frame.array) {
        if (frame.state === "valueOrClose" && this.take("]")) {
          this.finishFrame();
          continue;
        }
        if (frame.state === "valueOrClose" || frame.state === "value") {
          if (frame.out.length >= this.envelope.maxArrayLength) {
            fail("array-length-limit", frame.path, `array exceeds ${this.envelope.maxArrayLength} elements`);
          }
          const childPath = indexPath(frame.path, frame.out.length);
          frame.state = "awaiting";
          const frameCount = this.frames.length;
          const onSpine = frame.out.length === 2 && frame.out[0] === "pair" && this.pairLead();
          const spine = onSpine ? frame.spine + 1 : 0;
          spineLimit(spine, this.envelope, childPath);
          const child = this.value(childPath, onSpine ? frame.depth : frame.depth + 1, spine);
          if (this.frames.length === frameCount) {
            frame.out.push(child);
            frame.state = "afterValue";
          }
          continue;
        }
        this.space();
        if (this.take("]")) {
          this.finishFrame();
          continue;
        }
        if (!this.take(",")) {
          fail("malformed-json", frame.path, `comma or array close expected at UTF-16 offset ${this.index}`);
        }
        this.space();
        frame.state = "value";
        continue;
      }
      if (frame.state === "keyOrClose" && this.take("}")) {
        this.finishFrame();
        continue;
      }
      if (frame.state === "keyOrClose" || frame.state === "key") {
        if (this.source[this.index] !== '"') {
          fail("malformed-json", frame.path, `object name expected at UTF-16 offset ${this.index}`);
        }
        const key = this.string(frame.path, this.envelope.maxKeyBytes, "key-limit");
        if (frame.names.has(key)) {
          fail("duplicate-key", propertyPath(frame.path, key), `duplicate object name: ${JSON.stringify(key)}`);
        }
        frame.names.add(key);
        frame.members += 1;
        if (frame.members > this.envelope.maxObjectMembers) {
          fail("object-member-limit", frame.path, `object exceeds ${this.envelope.maxObjectMembers} members`);
        }
        this.space();
        const childPath = propertyPath(frame.path, key);
        if (!this.take(":")) {
          fail("malformed-json", childPath, `colon expected at UTF-16 offset ${this.index}`);
        }
        this.space();
        frame.key = key;
        frame.state = "awaiting";
        const frameCount = this.frames.length;
        const child = this.value(childPath, frame.depth + 1);
        if (this.frames.length === frameCount) {
          Object.defineProperty(frame.out, key, {
            value: child,
            enumerable: true,
            configurable: false,
            writable: false
          });
          frame.state = "afterValue";
        }
        continue;
      }
      this.space();
      if (this.take("}")) {
        this.finishFrame();
        continue;
      }
      if (!this.take(",")) {
        fail("malformed-json", frame.path, `comma or object close expected at UTF-16 offset ${this.index}`);
      }
      this.space();
      frame.state = "key";
    }
    if (this.frames.length === 0 && value === void 0) root = this.completed;
    this.space();
    if (this.index !== this.source.length) fail("malformed-json", "$", `unexpected input at UTF-16 offset ${this.index}`);
    return root;
  }
  finishFrame() {
    const frame = this.frames.pop();
    this.completed = Object.freeze(frame.out);
  }
  /** Whether the array opening at the cursor starts with the string "pair". */
  pairLead() {
    return /^\[[\t\n\r ]*"pair"[\t\n\r ]*[,\]]/u.test(this.source.slice(this.index, this.index + 32));
  }
  value(path, depth, spine = 0) {
    this.nodes += 1;
    if (this.nodes > this.envelope.maxNodes) {
      fail("node-limit", path, `JSON value exceeds ${this.envelope.maxNodes} nodes`);
    }
    const lead = this.source[this.index];
    if (lead === "{" || lead === "[") {
      if (depth >= this.envelope.maxDepth) {
        fail("depth-limit", path, `JSON nesting exceeds depth ${this.envelope.maxDepth}`);
      }
      this.index += 1;
      this.space();
      if (lead === "{") {
        this.frames.push({
          path,
          depth,
          array: false,
          out: {},
          names: /* @__PURE__ */ new Set(),
          members: 0,
          state: "keyOrClose"
        });
      } else {
        this.frames.push({ path, depth, spine, array: true, out: [], state: "valueOrClose" });
      }
      return void 0;
    }
    if (lead === '"') return this.string(path, this.envelope.maxStringBytes, "string-limit");
    if (this.source.startsWith("true", this.index)) return this.literal("true", true);
    if (this.source.startsWith("false", this.index)) return this.literal("false", false);
    if (this.source.startsWith("null", this.index)) return this.literal("null", null);
    return this.number(path);
  }
  literal(token, value) {
    this.index += token.length;
    return value;
  }
  string(path, limit, code) {
    const start = this.index;
    this.index += 1;
    while (this.index < this.source.length) {
      const unit = this.source.charCodeAt(this.index);
      if (unit === 34) {
        this.index += 1;
        const raw = this.source.slice(start, this.index);
        let decoded;
        try {
          decoded = JSON.parse(raw);
        } catch {
          fail("malformed-json", path, `invalid JSON string at UTF-16 offset ${start}`);
        }
        if (typeof decoded !== "string") fail("malformed-json", path, "internal JSON string decoding failure");
        stringText(decoded, path, limit, code);
        return decoded;
      }
      if (unit < 32) fail("malformed-json", path, `unescaped control character at UTF-16 offset ${this.index}`);
      if (unit === 92) {
        this.index += 1;
        const escape = this.source[this.index];
        if (escape === void 0 || !'"\\/bfnrtu'.includes(escape)) {
          fail("malformed-json", path, `invalid string escape at UTF-16 offset ${this.index}`);
        }
        if (escape === "u") {
          const digits = this.source.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/u.test(digits)) fail("malformed-json", path, `invalid Unicode escape at UTF-16 offset ${this.index}`);
          this.index += 4;
        }
      }
      this.index += 1;
    }
    fail("malformed-json", path, `unterminated JSON string at UTF-16 offset ${start}`);
  }
  number(path) {
    const start = this.index;
    while (this.index < this.source.length && !/[\u0009\u000a\u000d\u0020,\]}]/u.test(this.source[this.index])) this.index += 1;
    const token = this.source.slice(start, this.index);
    if (!numberGrammar.test(token)) fail("malformed-json", path, `invalid JSON token at UTF-16 offset ${start}`);
    const value = Number(token);
    if (!Number.isFinite(value)) fail("invalid-json-value", path, "JCS admits only finite IEEE-754 numbers");
    return Object.is(value, -0) ? 0 : value;
  }
  space() {
    while (this.index < this.source.length && /[\u0009\u000a\u000d\u0020]/u.test(this.source[this.index])) this.index += 1;
  }
  take(token) {
    if (this.source[this.index] !== token) return false;
    this.index += 1;
    return true;
  }
};
function canonicalizeJson(value, envelope = UNBOUNDED_JSON_ENVELOPE) {
  const state = { nodes: 0, canonicalBytes: 0, active: /* @__PURE__ */ new WeakSet(), envelope };
  const projected = projectValue(value, "$", 0, state);
  return Object.freeze({ value: projected.value, text: projected.text, byteLength: state.canonicalBytes });
}
function admitCanonicalJson(source, envelope = JSON_RESOURCE_ENVELOPE) {
  const sourceBytes = typeof source === "string" ? byteLength(source) : source.byteLength;
  if (sourceBytes > envelope.maxSourceBytes) fail("source-limit", "$", `source exceeds ${envelope.maxSourceBytes} bytes`);
  let text;
  try {
    text = typeof source === "string" ? source : new TextDecoder("utf-8", { fatal: true }).decode(source);
  } catch {
    fail("malformed-utf8", "$", "source is not well-formed UTF-8");
  }
  return canonicalizeJson(new StrictJsonParser(text, envelope).parse(), envelope);
}
function canonicalJson(value, envelope = UNBOUNDED_JSON_ENVELOPE) {
  return canonicalizeJson(value, envelope).text;
}
if (import.meta.main) {
  const { readFileSync } = globalThis.process?.getBuiltinModule?.("node:fs") ?? {};
  process.stdout.write(
    JSON.stringify(canonicalJson(JSON.parse(readFileSync(0, "utf8")))) + "\n"
  );
}

// src/settlements.mjs
var BASE_USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
var BASE_PROVIDERS = [
  "https://base-rpc.publicnode.com",
  "https://base.drpc.org",
  "https://base-mainnet.public.blastapi.io",
  "https://mainnet.base.org"
];
var TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
var TX = /^0x[\da-f]{64}$/i;
var ADDRESS = /^0x[\da-f]{40}$/i;
var topic = (address) => `0x${"0".repeat(24)}${address.slice(2).toLowerCase()}`;
function matchingTransfers(receipt, witness) {
  return (receipt?.logs ?? []).filter((log) => log.address?.toLowerCase() === BASE_USDC && log.topics?.[0]?.toLowerCase() === TRANSFER && log.topics?.[1]?.toLowerCase() === topic(witness.payer) && log.topics?.[2]?.toLowerCase() === topic(witness.payTo) && /^0x[\da-f]{64}$/i.test(log.data ?? "") && BigInt(log.data).toString() === witness.amount);
}
function witnessProblem(witness) {
  if (witness?.network !== "eip155:8453" || !TX.test(witness.transaction ?? "")) return "invalid-transaction";
  if (!ADDRESS.test(witness.payer ?? "") || !ADDRESS.test(witness.payTo ?? "")) return "invalid-address";
  if (witness.asset?.toLowerCase() !== BASE_USDC) return "not-base-usdc";
  if (!/^[1-9]\d*$/.test(witness.amount ?? "")) return "invalid-amount";
  return null;
}
function corroborate(witness, receipts) {
  const problem = witnessProblem(witness);
  if (problem) return { ok: false, reason: problem };
  if (!Array.isArray(receipts) || receipts.length < 2) return { ok: false, reason: "two-provider-receipts-required", retry: true };
  const [a, b] = receipts;
  if (!a || !b || !["0x0", "0x1"].includes(a.status) || a.status !== b.status || !Array.isArray(a.logs) || !Array.isArray(b.logs)) return { ok: false, reason: "provider-disagreement", retry: true };
  if (a.status === "0x0") return { ok: false, reason: "failed-transaction" };
  if (!TX.test(a.blockHash ?? "") || !TX.test(b.blockHash ?? "") || a.blockHash.toLowerCase() !== b.blockHash.toLowerCase() || a.transactionHash?.toLowerCase() !== witness.transaction.toLowerCase() || b.transactionHash?.toLowerCase() !== witness.transaction.toLowerCase() || !/^0x[\da-f]+$/i.test(a.blockNumber ?? "") || a.blockNumber !== b.blockNumber || matchingTransfers(a, witness).length !== matchingTransfers(b, witness).length) return { ok: false, reason: "provider-disagreement", retry: true };
  const transfers = matchingTransfers(a, witness);
  if (transfers.length !== 1) return { ok: false, reason: "exactly-one-matching-usdc-transfer-required" };
  if (!/^0x[\da-f]+$/i.test(transfers[0].logIndex ?? "") || transfers[0].logIndex !== matchingTransfers(b, witness)[0].logIndex || transfers[0].removed === true || matchingTransfers(b, witness)[0].removed === true)
    return { ok: false, reason: "provider-disagreement", retry: true };
  return { ok: true, receipt: a, transfer: transfers[0] };
}

// src/ln-church-research.mjs
var ORIGIN2 = "https://kari.mayim-mayim.com";
var RESEARCH_STATE = "ln-church/research";
var RESEARCH_SUMMARY = "ln-church/public-summary";
var ID2 = /^[A-Za-z0-9._~-]{1,128}$/;
var HASH = /^[a-f0-9]{64}$/;
var ADDRESS2 = /^0x[\da-f]{40}$/i;
var TX2 = /^0x[\da-f]{64}$/i;
var LIMIT = 131072;
var TERMS = ["task_type", "task_definition_version", "task_definition_digest", "question", "candidates", "reveal_correct_set_after_answer", "evaluation_profile_id", "reward", "plan_id", "registration_amount_atomic", "capacity_total", "economic_policy_id", "capacity_profile_id", "evaluation_profile_digest", "economic_terms_revision", "creator_amount_atomic"];
var ENVELOPE = { ...JSON_RESOURCE_ENVELOPE, maxSourceBytes: LIMIT, maxCanonicalBytes: LIMIT, maxDepth: 24, maxNodes: 12e3 };
var equal = (a, b) => canonicalJson(a) === canonicalJson(b);
var hash = async (text) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))), (n) => n.toString(16).padStart(2, "0")).join("");
var error = (code, status = 0) => Object.assign(new Error(code), { code, status });
var finiteDate = (value) => typeof value === "string" && Number.isFinite(Date.parse(value));
function researchProductProblem(instance, product, merchant2) {
  if (instance?.enabled !== true) return "disabled";
  if (instance.provider !== "ln-church" || !ID2.test(instance.taskId ?? "") || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(instance.agentId ?? "") || !ID2.test(instance.productId ?? "") || instance.maximumNewCashExpenseUsd !== 0 || instance.maximumProviderRequestsPerPass !== 12 || !ADDRESS2.test(merchant2 ?? "")) return "research-instance-refused";
  if (!product || product.taskId !== instance.taskId || product.taskType !== "endpoint_choice_reason.v2" || product.taskDefinitionVersion !== "2.3.0" || ![product.taskDefinitionDigest, product.termsDigest, product.questionSha256].every((v) => HASH.test(v ?? "")) || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(product.selectedCandidateId ?? "") || typeof product.answerReason !== "string" || !product.answerReason.trim() || new TextEncoder().encode(product.answerReason).length > 8192 || product.reward?.network !== "eip155:8453" || product.reward.asset !== "USDC" || product.reward.asset_address?.toLowerCase() !== BASE_USDC || product.reward.full_reward_threshold !== "0.7" || product.reward.rounding !== "FLOOR_ATOMIC" || ![product.reward.correct_amount_atomic, product.reward.incorrect_amount_atomic].every((v) => /^[1-9]\d{0,77}$/.test(v ?? "") && BigInt(v) < 2n ** 256n)) return "research-product-refused";
  try {
    canonicalJson(product, ENVELOPE);
  } catch {
    return "research-product-refused";
  }
  return null;
}
async function matchesTerms(value, product) {
  return value?.task_type === product.taskType && value.task_definition_version === product.taskDefinitionVersion && value.task_definition_digest === product.taskDefinitionDigest && typeof value.question === "string" && await hash(value.question) === product.questionSha256 && equal(value.reward, product.reward) && Array.isArray(value.candidates) && value.candidates.some((c) => c.candidate_id === product.selectedCandidateId);
}
async function runResearchPass({ storage, instance, products, merchant: merchant2, groupPayers = /* @__PURE__ */ new Set(), fetchImpl = fetch, now = () => Date.now() } = {}) {
  const product = products?.[instance?.productId];
  const refusal = researchProductProblem(instance, product, merchant2);
  if (refusal) return { stage: refusal, requests: 0, newCashExpenseUsd: 0 };
  let state = await storage.get(RESEARCH_STATE) ?? { stage: "unclaimed", completionPosts: 0 };
  let calls = 0;
  const base = `/api/agent/tasks/${instance.taskId}`;
  const binding = await hash(canonicalJson({ instance, product, merchant: merchant2.toLowerCase() }));
  async function finish(stage, { terminal = false, delay = 3e4 } = {}) {
    if (!terminal && Number.isFinite(state.monitoringUntil) && now() >= state.monitoringUntil) {
      state.reconciliationPending = true;
      stage = "research-monitoring-held";
      terminal = true;
    }
    state.stage = stage;
    state.observedAt = new Date(now()).toISOString();
    state.terminal = terminal;
    state.nextAttemptAt = terminal || state.retryBlocked ? null : Math.max(now() + delay, state.retryAt ?? 0);
    await storage.put(RESEARCH_STATE, state);
    const summary = {
      stage,
      requests: calls,
      newCashExpenseUsd: 0,
      at: state.observedAt,
      taskId: instance.taskId,
      productId: instance.productId,
      receiptAccepted: !!state.receipt || !!state.status,
      evaluationState: state.status?.evaluation?.state ?? null,
      approvedAmountAtomic: state.status?.evaluation?.approved_amount_atomic ?? null,
      providerPayoutState: state.status?.payout?.state ?? null,
      payoutTx: TX2.test(state.status?.payout?.transaction_hash ?? "") ? state.status.payout.transaction_hash : null,
      independentlyVerifiedCashAtomic: state.verifiedCashAtomic ?? null,
      recognizedOutsideRevenue: null
    };
    await storage.put(RESEARCH_SUMMARY, summary);
    return summary;
  }
  if (state.binding && state.binding !== binding) return finish("research-binding-drift", { terminal: true });
  if (state.terminal) return finish(state.stage, { terminal: true });
  if (Number.isFinite(state.monitoringUntil) && now() >= state.monitoringUntil) {
    state.reconciliationPending = true;
    return finish("research-monitoring-held", { terminal: true });
  }
  if (state.retryBlocked || state.nextAttemptAt > now()) return { stage: state.stage, requests: 0, newCashExpenseUsd: 0 };
  async function wire(path, { method = "GET", body, headers = {}, rpc = false } = {}) {
    if (calls >= 12) throw error("research-request-budget");
    if (state.retryBlocked || state.retryAt > now()) throw error("research-retry-deferred");
    const statusPath = state.submissionId ? `${base}/submissions/${state.submissionId}/status` : null;
    if (rpc ? !BASE_PROVIDERS.includes(path) : ![base, base + "/claim", base + "/completion", statusPath].includes(path)) throw error("research-endpoint-refused");
    calls++;
    let response;
    try {
      response = await fetchImpl(rpc ? path : ORIGIN2 + path, {
        method,
        redirect: "manual",
        signal: AbortSignal.timeout(15e3),
        headers: { accept: "application/json", ...body === void 0 ? {} : { "content-type": "application/json" }, ...headers },
        ...body === void 0 ? {} : { body }
      });
    } catch {
      throw error("research-response-unknown");
    }
    const retry = response.headers.get("retry-after");
    if (retry) {
      const delay = retry.length <= 256 ? retryAfterDelayMs(retry, now()) : null;
      state.retryBlocked = retry.length > 256 || delay === null && /^\d+$/.test(retry.trim()) || delay !== null && !Number.isFinite(new Date(now() + delay).getTime());
      if (state.retryBlocked || delay !== null) {
        state.retryAt = state.retryBlocked ? null : now() + delay;
        state.retryAfter = retry.slice(0, 256);
        await storage.put(RESEARCH_STATE, state);
      }
    }
    if (response.status >= 300 && response.status < 400) throw error("research-redirect-refused", response.status);
    if (Number(response.headers.get("content-length")) > LIMIT) throw error("research-response-too-large", response.status);
    let text = "", bytes = 0;
    try {
      const reader = response.body?.getReader(), decoder = new TextDecoder("utf-8", { fatal: true });
      if (reader) for (; ; ) {
        const part = await reader.read();
        if (part.done) break;
        bytes += part.value.byteLength;
        if (bytes > LIMIT) {
          await reader.cancel();
          throw error("research-response-too-large", response.status);
        }
        text += decoder.decode(part.value, { stream: true });
      }
      text += decoder.decode();
    } catch (e) {
      throw e.code?.startsWith("research-") ? e : error("research-response-read-failed", response.status);
    }
    let value;
    try {
      value = admitCanonicalJson(text, ENVELOPE).value;
    } catch {
      throw error("research-invalid-response", response.status);
    }
    if (!response.ok) throw error(response.status === 402 ? "research-payment-refused" : "research-provider-refused", response.status);
    return value;
  }
  async function save() {
    await storage.put(RESEARCH_STATE, state);
  }
  const pending = async (stage) => {
    if (Number.isFinite(state.monitoringUntil) && now() >= state.monitoringUntil) {
      state.reconciliationPending = true;
      return finish("research-monitoring-held", { terminal: true });
    }
    return finish(stage);
  };
  const tokenHeaders = () => ({ "X-LN-Task-Claim-Token": state.claim.claim_token });
  const statusRead = () => wire(`${base}/submissions/${state.submissionId}/status`, { headers: tokenHeaders() });
  async function receiveStatus(status) {
    if (status.schema_version !== "ln_church.task_submission_status.endpoint_choice_reason.v2_3" || !sameSubmission(status) || status.selected_candidate_id !== product.selectedCandidateId || status.answer_reason !== product.answerReason || !["PENDING", "GRADED", "COMPENSATED"].includes(status.evaluation?.state) || !(status.evaluation.approved_amount_atomic === null || /^(0|[1-9]\d{0,77})$/.test(status.evaluation.approved_amount_atomic ?? "")) || !["not_applicable", "pending", "processing", "retryable", "ambiguous", "failed", "paid_confirmed"].includes(status.payout?.state) || !validEvaluationTimes(status) || state.monitoring && !equal(state.monitoring, { receivedAt: status.received_at, evaluationDeadline: status.evaluation_deadline })) throw error("research-status-mismatch");
    state.monitoring = { receivedAt: status.received_at, evaluationDeadline: status.evaluation_deadline };
    state.monitoringUntil = Date.parse(status.evaluation_deadline) + 3e4;
    state.status = status;
    await save();
    if (status.payout.state === "paid_confirmed") {
      const paid = status.payout.confirmed_paid_amount_atomic, approved = status.evaluation.approved_amount_atomic;
      if (!TX2.test(status.payout.transaction_hash ?? "") || !/^[1-9]\d{0,77}$/.test(paid ?? "") || paid !== approved || BigInt(paid) > BigInt(product.reward.correct_amount_atomic) && BigInt(paid) > BigInt(product.reward.incorrect_amount_atomic)) throw error("research-payout-mismatch");
      const receipts = [];
      for (const url of BASE_PROVIDERS) {
        if (receipts.length >= 2 || calls >= 12) break;
        try {
          const data = await wire(url, { rpc: true, method: "POST", body: canonicalJson({ jsonrpc: "2.0", id: 1, method: "eth_getTransactionReceipt", params: [status.payout.transaction_hash] }) });
          if (data.result && !data.error) receipts.push(data.result);
        } catch (e) {
          if (state.retryAt > now() || state.retryBlocked) throw e;
        }
      }
      const topic2 = "0x" + "0".repeat(24) + merchant2.slice(2).toLowerCase();
      const matching = receipts[0]?.logs?.filter((log) => log.address?.toLowerCase() === BASE_USDC && log.topics?.[2]?.toLowerCase() === topic2 && /^0x0{24}[a-f\d]{40}$/i.test(log.topics?.[1] ?? "") && /^0x[a-f\d]{64}$/i.test(log.data ?? "") && BigInt(log.data).toString() === paid) ?? [];
      if (matching.length === 1) {
        const payer2 = "0x" + matching[0].topics[1].slice(-40).toLowerCase();
        const checked = corroborate({ transaction: status.payout.transaction_hash, network: "eip155:8453", asset: BASE_USDC, payer: payer2, payTo: merchant2, amount: paid }, receipts);
        if (checked.ok && !groupPayers.has(payer2) && payer2 !== merchant2.toLowerCase()) {
          state.verifiedCashAtomic = paid;
          state.payer = payer2;
          state.blockNumber = checked.receipt.blockNumber;
          state.logIndex = checked.transfer.logIndex;
          return finish("research-cash-corroborated", { terminal: true });
        }
      }
      return pending("research-provider-paid-unverified");
    }
    if (status.payout.state === "failed" || status.payout.state === "not_applicable" && status.evaluation.state !== "PENDING")
      return finish("research-no-payout", { terminal: true });
    return pending("research-evaluation-pending");
  }
  function sameSubmission(value) {
    return value.task_id === instance.taskId && value.execution_id === state.claim.execution_id && value.submission_id === state.submissionId && value.terms_digest === product.termsDigest && value.report_sha256 === state.reportSha256;
  }
  function validEvaluationTimes(value) {
    return finiteDate(value.received_at) && finiteDate(value.evaluation_deadline) && Date.parse(value.evaluation_deadline) > Date.parse(value.received_at) && Date.parse(value.evaluation_deadline) - Date.parse(value.received_at) <= 18e5;
  }
  try {
    if (!state.claim && Number.isFinite(state.claimIntentAt) && now() >= state.claimIntentAt + 6e5)
      return finish("research-claim-recovery-held", { terminal: true });
    if (!state.binding) {
      const task = await wire(base);
      if (task.schema_version !== "ln_church.agent_task.endpoint_choice_reason.v2_3" || task.task_id !== instance.taskId || task.terms_digest !== product.termsDigest || TERMS.some((key) => !Object.hasOwn(task, key)) || !await matchesTerms(task, product)) return finish("research-task-mismatch", { terminal: true });
      if (task.status !== "OPEN" || !Number.isSafeInteger(task.capacity_available) || task.capacity_available < 1 || !finiteDate(task.listing_ends_at) || Date.parse(task.listing_ends_at) <= now()) return finish("research-unavailable", { terminal: true });
      state.binding = binding;
      state.task = task;
      state.claimKey = "claim-" + crypto.randomUUID();
      state.submissionId = "sub_" + crypto.randomUUID().replaceAll("-", "");
      state.claimBody = canonicalJson({ schema_version: "ln_church.agent_task_claim_request.v1", agent_id: instance.agentId, reward_address: merchant2.toLowerCase() });
      state.stage = "claim-intent";
      state.claimIntentAt = now();
      await save();
      state.freshClaim = true;
    }
    if (!state.claim) {
      const fresh = state.freshClaim === true;
      state.freshClaim = false;
      await save();
      const claim = await wire(base + "/claim", {
        method: "POST",
        body: state.claimBody,
        headers: { "Idempotency-Key": state.claimKey, ...fresh ? {} : { "X-LN-Claim-Recovery": "1" } }
      });
      if (claim.schema_version !== "ln_church.agent_task_claim_response.endpoint_choice_reason.v2_3" || claim.task_id !== instance.taskId || !await matchesTerms(claim, product) || claim.terms_digest !== product.termsDigest || !/^exec_[a-f0-9]{32}$/.test(claim.execution_id ?? "") || !/^[\x21-\x7e]{1,8192}$/.test(claim.claim_token ?? "") || claim.reward_address !== merchant2.toLowerCase() || claim.reward_address_control_verified !== false || !finiteDate(claim.report_deadline) || !finiteDate(claim.claim_accepted_at) || Date.parse(claim.report_deadline) <= Date.parse(claim.claim_accepted_at) || Date.parse(claim.report_deadline) - Date.parse(claim.claim_accepted_at) > 6e5 || Date.parse(claim.claim_accepted_at) > now() + 15e3 || !await matchesTerms(claim.terms_snapshot, product) || !equal(claim.terms_snapshot, Object.fromEntries(TERMS.map((key) => [key, state.task[key]]))) || !equal(claim.candidates, state.task.candidates)) throw error("research-claim-mismatch");
      state.claim = claim;
      state.stage = "claimed";
      state.completionBody = canonicalJson({
        schema_version: "ln_church.task_completion.endpoint_choice_reason.v2_3",
        task_id: instance.taskId,
        task_type: product.taskType,
        task_definition_version: product.taskDefinitionVersion,
        task_definition_digest: product.taskDefinitionDigest,
        terms_digest: product.termsDigest,
        execution_id: claim.execution_id,
        submission_id: state.submissionId,
        selected_candidate_id: product.selectedCandidateId,
        answer_reason: product.answerReason
      });
      if (new TextEncoder().encode(state.completionBody).length > 16384) throw error("research-report-too-large");
      state.reportSha256 = await hash(state.completionBody);
      await save();
    }
    if (state.receipt || state.completionPosts > 0) {
      try {
        return await receiveStatus(await statusRead());
      } catch (e) {
        if (e.status !== 404 || state.receipt) throw e;
      }
    }
    if (Date.parse(state.claim.report_deadline) <= now() || state.completionPosts >= 3) return finish("research-report-recovery-held", { terminal: true });
    state.completionPosts++;
    state.stage = "completion-intent";
    state.monitoringUntil ??= Date.parse(state.claim.report_deadline) + 18e5 + 3e4;
    await save();
    const receipt = await wire(base + "/completion", { method: "POST", body: state.completionBody, headers: { ...tokenHeaders(), "Idempotency-Key": state.submissionId } });
    if (receipt.schema_version !== "ln_church.task_completion_receipt.endpoint_choice_reason.v2_3" || !sameSubmission(receipt) || receipt.receipt_state !== "accepted" || new URL(receipt.status_url, ORIGIN2).href !== ORIGIN2 + `${base}/submissions/${state.submissionId}/status` || !validEvaluationTimes(receipt)) throw error("research-receipt-mismatch");
    state.receipt = receipt;
    state.monitoring = { receivedAt: receipt.received_at, evaluationDeadline: receipt.evaluation_deadline };
    state.monitoringUntil = Date.parse(receipt.evaluation_deadline) + 3e4;
    await save();
    return await receiveStatus(await statusRead());
  } catch (e) {
    const code = /^research-[a-z-]{1,80}$/.test(e.code ?? "") ? e.code : "research-failure";
    state.lastFailure = code;
    if (Number.isFinite(state.monitoringUntil) && now() >= state.monitoringUntil) {
      state.reconciliationPending = true;
      return finish("research-monitoring-held", { terminal: true });
    }
    const terminal = code.includes("mismatch") || code === "research-payment-refused" || code === "research-redirect-refused" || [400, 401, 403, 404, 409, 410, 422].includes(e.status);
    return finish(code, { terminal });
  }
}

// test/ln-church-fixture.mjs
var merchant = "0x" + "12".repeat(20);
var payer = "0x" + "34".repeat(20);
var time = Date.parse("2026-10-24T22:00:00Z");
var sha = async (text) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))), (v) => v.toString(16).padStart(2, "0")).join("");
async function fixture() {
  const question = "Select the primary explicitly disclosed operator purpose.";
  const product = {
    taskId: "task_fixture",
    taskType: "endpoint_choice_reason.v2",
    taskDefinitionVersion: "2.3.0",
    taskDefinitionDigest: "a".repeat(64),
    termsDigest: "b".repeat(64),
    questionSha256: await sha(question),
    selectedCandidateId: "o04",
    answerReason: "The operator explicitly requested paid work for external customers. This is a test answer, not a paid result.",
    reward: { network: "eip155:8453", asset: "USDC", asset_address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", correct_amount_atomic: "25000", incorrect_amount_atomic: "10000", full_reward_threshold: "0.7", rounding: "FLOOR_ATOMIC" }
  };
  const instance = { enabled: true, provider: "ln-church", agentId: "fixture-agent", taskId: product.taskId, productId: "operator-purpose-v1", maximumNewCashExpenseUsd: 0, maximumProviderRequestsPerPass: 12 };
  const products = { [instance.productId]: product };
  const terms = {
    task_type: product.taskType,
    task_definition_version: product.taskDefinitionVersion,
    task_definition_digest: product.taskDefinitionDigest,
    question,
    candidates: [{ candidate_id: "o04", url: "https://kari.mayim-mayim.com/example/o04" }],
    reward: product.reward,
    reveal_correct_set_after_answer: true,
    evaluation_profile_id: "endpoint-choice-reason-jev-v2_1",
    plan_id: "C21",
    registration_amount_atomic: "1000000",
    capacity_total: 21,
    economic_policy_id: "endpoint-choice-reason-economics-terms-v1",
    capacity_profile_id: "endpoint-choice-reason-rpah.v2_1",
    evaluation_profile_digest: "f".repeat(64),
    economic_terms_revision: "fixture-terms",
    creator_amount_atomic: "100000"
  };
  const task = { ...terms, schema_version: "ln_church.agent_task.endpoint_choice_reason.v2_3", task_id: product.taskId, terms_digest: product.termsDigest, status: "OPEN", capacity_available: 9, listing_ends_at: new Date(time + 864e5).toISOString() };
  const claim = {
    ...terms,
    schema_version: "ln_church.agent_task_claim_response.endpoint_choice_reason.v2_3",
    task_id: product.taskId,
    terms_digest: product.termsDigest,
    execution_id: "exec_" + "c".repeat(32),
    claim_token: "private-fixture-capability",
    reward_address: merchant,
    reward_address_control_verified: false,
    claim_accepted_at: new Date(time).toISOString(),
    report_deadline: new Date(time + 6e5).toISOString(),
    terms_snapshot: terms
  };
  const values = /* @__PURE__ */ new Map();
  const storage = { async get(k) {
    return values.get(k);
  }, async put(k, v) {
    values.set(k, structuredClone(v));
  } };
  const base = "https://kari.mayim-mayim.com/api/agent/tasks/" + product.taskId;
  let calls = [];
  async function receipt() {
    const s = await storage.get(RESEARCH_STATE);
    return {
      schema_version: "ln_church.task_completion_receipt.endpoint_choice_reason.v2_3",
      task_id: product.taskId,
      execution_id: claim.execution_id,
      submission_id: s.submissionId,
      terms_digest: product.termsDigest,
      report_sha256: await sha(s.completionBody),
      receipt_state: "accepted",
      received_at: new Date(time).toISOString(),
      evaluation_deadline: new Date(time + 18e5).toISOString(),
      status_url: "/api/agent/tasks/" + product.taskId + "/submissions/" + s.submissionId + "/status"
    };
  }
  async function status() {
    const r = await receipt();
    return {
      ...r,
      schema_version: "ln_church.task_submission_status.endpoint_choice_reason.v2_3",
      selected_candidate_id: product.selectedCandidateId,
      answer_reason: product.answerReason,
      evaluation: { state: "PENDING", approved_amount_atomic: null },
      payout: { state: "pending", transaction_hash: null, confirmed_paid_amount_atomic: null }
    };
  }
  async function fetchImpl(url, init) {
    calls.push({ url, ...init });
    if (url === base) return Response.json(task);
    if (url === base + "/claim") return Response.json(claim);
    if (url === base + "/completion") return Response.json(await receipt(), { status: 202 });
    if (url.includes("/submissions/")) return Response.json(await status());
    throw new Error("unexpected external request");
  }
  return {
    product,
    instance,
    products,
    task,
    claim,
    storage,
    values,
    base,
    calls,
    receipt,
    status,
    fetchImpl,
    options: { storage, instance, products, merchant, fetchImpl, now: () => time },
    canonicalJson
  };
}

// test/workerd-research-worker.mjs
var testNativeResearch = { async test() {
  const f = await fixture();
  const result = await runResearchPass(f.options);
  assert.equal(result.stage, "research-evaluation-pending");
  assert.equal(result.requests, 4);
  const state = await f.storage.get(RESEARCH_STATE);
  assert.equal(state.completionPosts, 1);
  assert.equal(state.receipt.report_sha256, state.reportSha256);
  assert.equal(result.independentlyVerifiedCashAtomic, null);
} };

// test/workerd-auth-worker.mjs
var testNativeAuthentication = {
  async test() {
    const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const privateJwk = await crypto.subtle.exportKey("jwk", keys.privateKey);
    const verify = (text, signature2) => crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, keys.publicKey, Buffer5.from(signature2, "base64url"), Buffer5.from(text));
    const canonical = "ephemeral local Worker challenge";
    const signature = defaultCanonical(privateJwk, canonical);
    assert2.equal(await verify(canonical, signature), true);
    signDpopProof({ privateKey: privateJwk, method: "GET", url: "https://opentask.ai/api/agent/contracts", accessToken: "local-rotated" });
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
          assert2.equal(values.get("opentask/auth").pendingRefresh, true);
          assert2.equal(await verify(canonical, JSON.parse(init.body).signature), true);
          return Response.json({ access_token: "local-rotated", refresh_token: "local-rotated-refresh", expires_in: 3600 });
        }
        const parts = init.headers.dpop.split(".");
        const header = JSON.parse(Buffer5.from(parts[0], "base64url"));
        const payload = JSON.parse(Buffer5.from(parts[1], "base64url"));
        assert2.equal(header.typ, "dpop+jwt");
        assert2.equal(header.jwk.d, void 0);
        assert2.equal(payload.htm, "GET");
        assert2.equal(payload.htu, "https://opentask.ai/api/agent/contracts");
        assert2.equal(payload.ath, createHash2("sha256").update("local-rotated").digest("base64url"));
        assert2.equal(await verify(parts.slice(0, 2).join("."), parts[2]), true);
        return Response.json({ contracts: [] });
      }
    });
    assert2.deepEqual(await client.request("/api/agent/contracts"), { contracts: [] });
    assert2.equal(calls, 3);
    assert2.equal(values.get("opentask/auth").accessToken, "local-rotated");
  }
};
export {
  testNativeAuthentication,
  testNativeResearch
};
