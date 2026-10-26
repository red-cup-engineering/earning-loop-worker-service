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

// node_modules/@red-cup-engineering/cryptographic-computer-data-engineering-services-section/src/hash.mjs
import crypto2 from "node:crypto";
function sha256(buf) {
  return crypto2.createHash("sha256").update(buf).digest();
}
var NATIVE_RIPEMD160;
var init_hash = __esm({
  "node_modules/@red-cup-engineering/cryptographic-computer-data-engineering-services-section/src/hash.mjs"() {
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

// node_modules/@red-cup-engineering/cryptographic-computer-data-engineering-services-section/src/integrity.mjs
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
function sha256Base64Url(value) {
  return sha256(Buffer.from(value, "utf8")).toString("base64url");
}
function randomBase64Url(byteLength) {
  if (!Number.isInteger(byteLength) || byteLength <= 0) {
    throw new TypeError("randomBase64Url requires a positive integer byteLength");
  }
  return randomBytes(byteLength).toString("base64url");
}
var init_integrity = __esm({
  "node_modules/@red-cup-engineering/cryptographic-computer-data-engineering-services-section/src/integrity.mjs"() {
    init_hash();
  }
});

// node_modules/@red-cup-engineering/oauth-services-section/src/json-web-token.mjs
import { createPrivateKey, sign as cryptoSign } from "node:crypto";
function signJsonWebToken(claims, { privateKey, kid, alg = "RS256", typ = "JWT", header = {} } = {}) {
  const algorithm = ALGORITHMS[alg];
  if (!algorithm) throw new TypeError(`unsupported JWT algorithm ${alg}`);
  const key = typeof privateKey === "object" && privateKey?.kty ? createPrivateKey({ key: privateKey, format: "jwk" }) : privateKey;
  const protectedHeader = { ...header, alg, typ, ...kid === void 0 ? {} : { kid } };
  const signingInput = `${encodePart(protectedHeader)}.${encodePart(claims)}`;
  const signature = cryptoSign(algorithm.digest, Buffer.from(signingInput, "ascii"), { key, ...algorithm.options });
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
    encodePart = (value) => Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
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

// data/operation.mjs
var operation_default = {
  "worker": "earning-loops-561-group",
  "crons": {
    "pass": "*/15 * * * *",
    "directives": "30 13 * * *",
    "scorecard": "0 14 * * 1"
  },
  "limits": {
    "routeProbesPerPass": 4,
    "settlementsPerPass": 1
  },
  "buckets": {
    "state": "561-group-working-state",
    "settlementWitnesses": "market-561-group-settlements"
  },
  "catalogUrl": "https://market.561.group/v1/catalog",
  "economics": {
    "burnUsdPerMonth": 600,
    "burnBasis": "leader-estimate, 2026-10-23",
    "floorUsdPerDay": 20,
    "goalUsdPerDay": 200
  },
  "merchantPayTo": "0x32886F6F361C1d570255c2762967A2e41D0E9B1a",
  "clock": "durable-object-alarm",
  "repair": {
    "brokenStreakBeforeRepair": 3,
    "repository": null
  },
  "onchainScanUrl": null,
  "commercial": {
    "enabled": true,
    "productId": "flat-json-to-csv-python",
    "profileId": "cmvmqp1ix000707lb9dqgf2qx",
    "taskId": "cmpupoqmm0027kw04351wcfhz",
    "bidId": "cmvmqtuh6003208l33gt5hljn",
    "buyerId": "cmpupoexm001akw04lxk1gaqf",
    "priceAmountAtomic": "50000000",
    "priceCurrency": "USDC",
    "network": "BASE",
    "maximumNewCashExpenseUsd": 0,
    "taskDescription": "Need a Python 3.10+ script that reads a JSON file (array of flat objects) and converts it to a CSV file. Should handle missing keys gracefully (fill with empty string). Include a README with usage instructions and at least one test using pytest.",
    "bidApproach": "Conditional offer: 50 USDC for a Python 3.10+ standard-library JSON-array-to-CSV CLI, usage README and pytest tests. The proposed contract preserves the union of first-seen keys, fills absent values with empty strings, handles UTF-8/comma/quote/newline fields using RFC 4180 quoting, and rejects non-array/non-flat inputs. Deliver source plus reproducible test results. Please confirm null/scalar formatting, expected maximum input size and automatic acceptance command. Payment must be buyer-funded Base USDC with no seller gas, bond, paid dependency or self-purchase; no human buying/selling. ETA begins once scope and machine acceptance/settlement terms are agreed. No paid work starts until agreement.",
    "maximumInputBytes": 1048576,
    "products": "public-services-section/services/public-agent-services-section/data/machine-delivery-products.json",
    "sourceWork": "https://github.com/561-group/561-group-opportunity-services-section/issues/35",
    "allocation": "Commercial stages run in an isolated bounded pulse, at most 12 provider calls and one seller mutation; they do not append requests to the maintenance allocation.",
    "admission": "Source parameters prepared for the new commercial consumer; existing deployed revision has not consumed them. No contract, buyer acceptance or revenue received.",
    "priceText": "50 USDC"
  }
};

// data/group-payers.mjs
var group_payers_default = [
  "0x224c08a8526751887a83e2711b167f890c6d078d",
  "0x42f72c0a340a4a55c082fe42483e87691d2bff64",
  "0xcd6fa157359e3b9f88c31b95dd63a3d73a1f34ca",
  "0xec2abd3eda89bed90124736e317e847d5fb6d034"
];

// data/products.mjs
var products_default = {
  "flat-json-to-csv-python": {
    "name": "Python flat JSON to CSV executable",
    "artifactUrl": "https://github.com/red-cup-engineering/csv-engineering-services-section/releases/download/v0.1.2/red-cup-engineering-csv-services-section-0.1.2.tgz",
    "artifactSha256": "96f323ddf8b2d6200b5e2edf5a94bc3734c9b00242d0d4284a777149edfae9f1",
    "sourceCommit": "d9ea3253c6e877aa9128526ff318ddc4b71d52c5",
    "sourceUrl": "https://github.com/red-cup-engineering/csv-engineering-services-section/tree/d9ea3253c6e877aa9128526ff318ddc4b71d52c5",
    "runtime": "Python 3.10+; standard library only for conversion; pytest for the supplied tests",
    "verificationInstructions": "Verify the archive SHA-256 is 96f323ddf8b2d6200b5e2edf5a94bc3734c9b00242d0d4284a777149edfae9f1. Extract it, enter package/, run python3 -m pytest -q test/test_json_to_csv.py, then run python3 scripts/json_to_csv.py input.json output.csv. The source producer observed 18 passing Python cases and 3 passing existing JavaScript tests; buyer acceptance remains independent.",
    "criteriaEvidence": {
      "Need a Python 3.10+ script that reads a JSON file (array of flat objects) and converts it to a CSV file. Should handle missing keys gracefully (fill with empty string). Include a README with usage instructions and at least one test using pytest.": "The frozen archive contains scripts/json_to_csv.py, README.md with the executable command, and test/test_json_to_csv.py with 18 observed passing cases. The converter uses the first-seen union of object keys and writes missing or null values as empty cells; the tests cover differing keys, quoting, UTF-8 and rejection of nested inputs before output replacement.",
      "Python 3.10+": "scripts/json_to_csv.py uses Python 3.10-compatible syntax and standard-library modules; the producer ran the tests under Python 3.12.3. A Python 3.10 runtime was not independently exercised.",
      "missing keys": "The first-seen union of keys defines CSV columns; absent fields serialize as empty strings. test/test_json_to_csv.py exercises differing keys and missing values.",
      "README": "README.md in the frozen archive documents python3 scripts/json_to_csv.py input.json output.csv, supported input shape, scalar formatting and failure behavior.",
      "pytest": "test/test_json_to_csv.py is included in the frozen archive. The source producer observed 18 passing tests with python3 -m pytest -q test/test_json_to_csv.py."
    },
    "maximumInputBytes": 1048576
  }
};

// src/opentask-client.mjs
import { createPrivateKey as createPrivateKey3, sign } from "node:crypto";

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
var defaultCanonical = (privateJwk, canonical) => sign("sha256", Buffer.from(canonical), {
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
      headers.dpop = await proof({
        privateKey: credential.privateJwk,
        method,
        url: ORIGIN + path,
        ...token ? { accessToken: credential.accessToken } : {},
        ...nonce ? { nonce } : {}
      });
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
    if (response.status >= 300 && response.status < 400) throw new OpenTaskError("redirect-refused", response.status);
    const receivedNonce = response.headers.get("dpop-nonce");
    if (receivedNonce && receivedNonce.length <= 512) nonce = receivedNonce;
    if (Number(response.headers.get("content-length")) > 262144) throw new OpenTaskError("response-too-large");
    let bytes = 0, text = "";
    const reader = response.body?.getReader();
    const decoder = new TextDecoder();
    if (reader) for (; ; ) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.byteLength;
      if (bytes > 262144) {
        await reader.cancel();
        throw new OpenTaskError("response-too-large");
      }
      text += decoder.decode(part.value, { stream: true });
    }
    text += decoder.decode();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      throw new OpenTaskError("invalid-response", response.status);
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
      const error = new OpenTaskError(/^[a-z0-9_]{1,100}$/.test(code) ? code : "provider-error", response.status);
      const receivedAt = now(), retry = response.headers.get("retry-after");
      if (retry) {
        const delay = retry.length <= 256 ? retryAfterDelayMs(retry, receivedAt) : null;
        const blocked = retry.length > 256 || delay === null && /^\d+$/.test(retry.trim()) || delay !== null && !Number.isFinite(new Date(receivedAt + delay).getTime());
        if (blocked || delay !== null) {
          error.retryBlocked = blocked;
          error.retryAt = blocked ? null : receivedAt + delay;
          error.retryAfter = retry.slice(0, 256);
          await storage.put(BACKOFF, { retryAfter: error.retryAfter, receivedAt, retryBlocked: blocked, retryAt: error.retryAt });
        }
      }
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
    return wire("/api/agent/auth/assert/complete", { method: "POST", body: {
      assertion_id: challenge.assertion_id,
      signature: await signCanonical(c.privateJwk, challenge.canonical_payload)
    } });
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

// src/registers.mjs
var PREFIX = "registers/earning-loops";
var RECORDS = "records/earning-loops";
var read = async (bucket, key) => (await bucket.get(key))?.json() ?? null;
var put = (bucket, key, value) => bucket.put(key, JSON.stringify(value), { httpMetadata: { contentType: "application/json" } });
var register = (name) => `${PREFIX}/${name}.json`;
var record = (name, at) => `${RECORDS}/${name}/${at}.json`;

// src/settlements.mjs
var BASE_USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
var BASE_PROVIDERS = [
  "https://base-rpc.publicnode.com",
  "https://base.drpc.org",
  "https://base-mainnet.public.blastapi.io",
  "https://mainnet.base.org"
];
var TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
var PREFIX2 = "settlements/eip155:8453/";
var TX = /^0x[\da-f]{64}$/i;
var ADDRESS = /^0x[\da-f]{40}$/i;
var topic = (address2) => `0x${"0".repeat(24)}${address2.slice(2).toLowerCase()}`;
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
var usdc = (atomic) => Number(BigInt(atomic)) / 1e6;
async function receiptsFor(hash, fetchImpl) {
  const read2 = async (url) => {
    try {
      const response = await fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getTransactionReceipt", params: [hash] }),
        signal: AbortSignal.timeout(1e4)
      });
      const body = await response.json();
      return response.ok && !body.error && body.result ? body.result : null;
    } catch {
      return null;
    }
  };
  const found = [];
  for (const url of BASE_PROVIDERS) {
    if (found.length === 2) break;
    const receipt = await read2(url);
    if (receipt) found.push(receipt);
  }
  return found;
}
async function receiveSettlements(env, { now = /* @__PURE__ */ new Date(), limit = 8, groupPayers: groupPayers2 = /* @__PURE__ */ new Set(), fetchImpl = fetch } = {}) {
  const key = register("settlements");
  const state = await read(env.STATE, key) ?? { settlements: {}, refused: {} };
  const seen = /* @__PURE__ */ new Set([...Object.values(state.settlements).filter((s) => s.evidenceVersion === 2).map((s) => s.witnessKey), ...Object.keys(state.refused).filter((k) => !state.refused[k].retry)]);
  const fresh = [];
  const page = await env.MARKET_SETTLEMENTS.list({ prefix: PREFIX2, cursor: state.scanCursor ?? void 0, limit });
  for (const object of page.objects) if (!seen.has(object.key)) fresh.push(object.key);
  const received = [];
  for (const witnessKey of fresh.slice(0, limit)) {
    const witness = await (await env.MARKET_SETTLEMENTS.get(witnessKey))?.json();
    const problem = witness ? witnessProblem(witness) : "witness-disappeared";
    const checked = problem ? { ok: false, reason: problem } : corroborate(witness, await receiptsFor(witness.transaction, fetchImpl));
    if (!checked.ok) {
      state.refused[witnessKey] = { reason: checked.reason, retry: !!checked.retry, at: now.toISOString() };
      continue;
    }
    delete state.refused[witnessKey];
    const payer = witness.payer.toLowerCase();
    const sourceId = `evm:eip155:8453:${BASE_USDC}:${witness.payTo.toLowerCase()}:${witness.transaction.toLowerCase()}:${BigInt(checked.transfer.logIndex)}`;
    const settlement = {
      evidenceVersion: 2,
      sourceId,
      witnessKey,
      transactionHash: witness.transaction.toLowerCase(),
      payer,
      receiver: witness.payTo.toLowerCase(),
      amount: witness.amount,
      usd: usdc(witness.amount),
      payerClass: groupPayers2.has(payer) ? "group" : "unclassified",
      paymentObservation: witness.paymentObservation ?? null,
      deliveryObservation: witness.deliveryObservation ?? null,
      responsePreparation: witness.responsePreparation ?? null,
      witnessId: witness.witnessId ?? null,
      classificationBasis: groupPayers2.has(payer) ? "current Group payer register" : "absence from Group register does not establish outside ownership",
      route: witness.route ?? null,
      method: witness.method ?? null,
      gateway: witness.gateway ?? null,
      sku: witness.sku ?? null,
      ledgerAccount: witness.ledgerAccount ?? null,
      blockNumber: Number(BigInt(checked.receipt.blockNumber)),
      recordedAt: witness.recordedAt ?? null,
      corroboratedAt: now.toISOString()
    };
    state.settlements[sourceId] = settlement;
    received.push(settlement);
  }
  state.at = now.toISOString();
  state.scanCursor = page.truncated ? page.cursor : null;
  await put(env.STATE, key, state);
  return { received, refused: Object.keys(state.refused).length, total: Object.keys(state.settlements).length };
}

// src/opentask-commercial-pass.mjs
var STATE = "opentask/commercial";
var stable = (value) => value && typeof value === "object" ? Array.isArray(value) ? value.map(stable) : Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])])) : value;
async function fingerprint(value) {
  const bytes = new TextEncoder().encode(JSON.stringify(stable(value)));
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (n) => n.toString(16).padStart(2, "0")).join("");
}
var publicResult = (stage, calls = 0) => ({ stage, requests: calls, newCashExpenseUsd: 0 });
var address = (v) => typeof v === "string" && /^0x[0-9a-f]{40}$/i.test(v);
var https = (v) => {
  try {
    const u = new URL(v);
    return u.protocol === "https:" && !u.username && !u.password && !u.search && !u.hash;
  } catch {
    return false;
  }
};
var same = (a, b) => JSON.stringify(stable(a)) === JSON.stringify(stable(b));
function qualifiedInstance(instance, product, merchant) {
  if (!instance?.enabled) return "disabled";
  if (["productId", "profileId", "taskId", "bidId", "buyerId"].some((key) => !/^[A-Za-z0-9_-]{1,200}$/.test(instance[key] ?? "")) || !/^[1-9][0-9]{0,17}$/.test(instance.priceAmountAtomic ?? "") || typeof instance.priceText !== "string" || !instance.priceText || instance.priceText.length > 100 || instance.priceCurrency !== "USDC" || instance.network !== "BASE" || instance.maximumNewCashExpenseUsd !== 0 || !address(merchant)) return "instance-refused";
  const amount = /^(\d+)(?:\.(\d{1,6}))? USDC$/.exec(instance.priceText);
  if (!amount || BigInt(amount[1]) * 1000000n + BigInt((amount[2] ?? "").padEnd(6, "0")) !== BigInt(instance.priceAmountAtomic)) return "price-refused";
  if (!product || !https(product.artifactUrl) || !https(product.sourceUrl) || !/^[a-f0-9]{64}$/.test(product.artifactSha256 ?? "") || !/^[a-f0-9]{40}$/.test(product.sourceCommit ?? "") || typeof product.verificationInstructions !== "string" || !product.criteriaEvidence || typeof product.criteriaEvidence !== "object" || !Number.isSafeInteger(product.maximumInputBytes) || product.maximumInputBytes <= 0 || !Number.isSafeInteger(instance.maximumInputBytes) || instance.maximumInputBytes <= 0 || instance.maximumInputBytes > product.maximumInputBytes) return "product-refused";
  return null;
}
function contractMatches(contract, instance) {
  return contract?.source === "bid" && contract.task?.id === instance.taskId && contract.bid?.id === instance.bidId && contract.seller?.id === instance.profileId && contract.buyer?.id === instance.buyerId && contract.bid?.priceText === instance.priceText && ["in_progress", "submitted", "accepted", "rejected"].includes(contract.status);
}
function deliveryAllowed(context, instance) {
  const c = context.contract;
  const feature = c.nativeDeliveryAvailability;
  return feature?.globallyEnabled === true && feature.eligible === true && feature.enabled === true && (context.availableActions ?? c.availableActions ?? []).some((action) => action.schemaVersion === "opentask-available-actions-v1" && ["prepare_delivery", "revise_delivery"].includes(action.action) && action.entity?.type === "contract" && action.entity.id === c.id && action.state === "available" && action.actor?.eligibleProfileId === instance.profileId && action.actor.role === "worker" && action.actor.requiredScopeMode === "all" && Array.isArray(action.actor.requiredScopes) && action.actor.requiredScopes.length > 0 && action.actor.requiredScopes.every((scope) => ["deliveries:read", "deliveries:write"].includes(scope)) && (action.payment === null || action.payment?.required === false && [null, "0"].includes(action.payment.amountAtomic)) && ["GET", "POST"].includes(action.invocation?.method) && action.invocation?.endpoint === `/api/agent/contracts/${c.id}/deliveries` && (!action.availableAfter || Date.parse(action.availableAfter) <= Date.now()) && (!action.availableUntil || Date.parse(action.availableUntil) > Date.now()));
}
function criterionClaims(pkg, product, artifactId) {
  if (!Array.isArray(pkg.criteria)) return null;
  const claims = [];
  for (const criterion of pkg.criteria) {
    const note = Object.hasOwn(product.criteriaEvidence, criterion.text) ? product.criteriaEvidence[criterion.text] : null;
    if (typeof criterion.id !== "string" || typeof note !== "string" || !note) return null;
    claims.push({ criterionId: criterion.id, claim: "satisfied", note, artifactIds: [artifactId] });
  }
  return claims;
}
function receivedPackage(pkg, contractId, product) {
  const artifact = pkg.artifacts?.find((a) => a.externalUrl === product.artifactUrl && a.description === `SHA-256 ${product.artifactSha256}; source ${product.sourceCommit}`);
  if (pkg.contractId !== contractId || pkg.milestoneId || !artifact || !Number.isSafeInteger(pkg.revision) || pkg.revision < 1 || !/^(?:sha256:)?[a-f0-9]{64}$/i.test(pkg.manifestDigest ?? "")) return false;
  const expected = criterionClaims(pkg, product, artifact.id);
  return expected && same(expected, pkg.criteria.map((c) => ({ criterionId: c.id, claim: c.sellerClaim, note: c.sellerNote, artifactIds: c.artifactIds })));
}
function buyerConfirmation(message, expected, buyerId) {
  if (message?.author?.id !== buyerId || message.author.kind !== "agent" || typeof message.body !== "string" || message.body.length > 8e3) return null;
  let value;
  try {
    value = JSON.parse(message.body);
  } catch {
    return null;
  }
  if (!value || !same(Object.keys(value).sort(), Object.keys(expected).sort())) return null;
  if (!Number.isSafeInteger(value.maximumInputBytes) || value.maximumInputBytes <= 0 || value.maximumInputBytes > expected.maximumInputBytes) return null;
  return same({ ...value, maximumInputBytes: expected.maximumInputBytes }, expected) ? value : null;
}
async function runCommercialPass({
  storage,
  initialCredential,
  instance,
  products,
  merchant,
  now = /* @__PURE__ */ new Date(),
  clientFactory = createOpenTaskClient,
  fetchImpl = fetch,
  clock = () => Date.now()
} = {}) {
  const product = products?.[instance?.productId];
  const refusal = qualifiedInstance(instance, product, merchant);
  if (refusal) return publicResult(refusal);
  const client = clientFactory({ storage, initialCredential, fetchImpl, budget: 12, now: clock });
  let state = await storage.get(STATE) ?? { stage: "discover", revisions: 0, observations: {} };
  const finish = async (stage) => {
    state.stage = stage;
    state.observedAt = now.toISOString();
    await storage.put(STATE, state);
    return publicResult(stage, client.calls);
  };
  if (state.retryBlocked || Date.parse(state.nextAttemptAt) > now.getTime()) return publicResult("provider-retry-deferred");
  try {
    if (!state.contractId) {
      const page = await client.request(`/api/agent/contracts?role=seller&limit=20${state.cursor ? `&cursor=${encodeURIComponent(state.cursor)}` : ""}`);
      const found = page.contracts?.filter((c) => contractMatches(c, instance)) ?? [];
      if (found.length > 1) return finish("multiple-contracts-held");
      if (!found.length) {
        state.cursor = page.nextCursor ?? null;
        return finish("awaiting-hire");
      }
      state.contractId = found[0].id;
      state.cursor = null;
      return finish("hire-discovered");
    }
    if (!/^[A-Za-z0-9_-]{1,200}$/.test(state.contractId)) return finish("contract-id-held");
    const base = `/api/agent/contracts/${state.contractId}`;
    const context = await client.request(base), contract = context.contract;
    if (!contractMatches(contract, instance)) return finish("contract-mismatch");
    if (!contract.termsSnapshot || typeof contract.termsSnapshot !== "object" || Array.isArray(contract.termsSnapshot)) return finish("terms-shape-held");
    const termsDigest = await fingerprint(contract.termsSnapshot);
    state.observations.hire = { contractId: contract.id, termsSnapshotSha256: termsDigest, source: "bid", status: contract.status };
    const productDigest = await fingerprint(product);
    if (state.productDigest && state.productDigest !== productDigest) return finish("product-drift-held");
    if (state.termsDigest && state.termsDigest !== termsDigest) return finish("terms-drift-held");
    state.productDigest = productDigest;
    state.termsDigest = termsDigest;
    const payout = await client.request(base + "/payout-destination");
    const destination = payout.currentDestination;
    const payee = destination?.address;
    if (payout.contractId !== contract.id || payout.role !== "seller" || payout.currentDestinationActive !== true || payout.blockedReason || !address(payee) || payee.toLowerCase() !== merchant.toLowerCase() || destination.token !== "USDC" || !["BASE", "EVM"].includes(destination.network)) return finish("payee-held");
    state.observations.payee = { address: merchant.toLowerCase(), at: now.toISOString() };
    const expected = {
      schema: "opentask-csv-agreement-v1",
      contractId: contract.id,
      productId: instance.productId,
      sourceCommit: product.sourceCommit,
      artifactSha256: product.artifactSha256,
      termsSnapshotSha256: termsDigest,
      nullEncoding: "empty-string",
      missingEncoding: "empty-string",
      booleanEncoding: "lowercase",
      columns: "first-seen-union",
      maximumInputBytes: instance.maximumInputBytes,
      acceptanceCommand: "python3 -m pytest -q test/test_json_to_csv.py",
      machineAcceptance: true,
      buyerFundsSettlement: true,
      maximumSellerCashExpenseUsd: 0
    };
    const permissionBasis = { availability: contract.nativeDeliveryAvailability, actions: context.availableActions ?? contract.availableActions };
    if (!state.agreement || state.agreement.termsSnapshotSha256 !== termsDigest) {
      const page = await client.request(`${base}/messages?limit=20${state.messageCursor ? `&cursor=${encodeURIComponent(state.messageCursor)}` : ""}`);
      const agreed = (page.messages ?? []).map((message) => ({ message, confirmation: buyerConfirmation(message, expected, instance.buyerId) })).find((v) => v.confirmation);
      if (agreed) {
        state.agreement = agreed.confirmation;
        state.agreementMessageId = agreed.message.id;
        state.messageCursor = null;
        if (state.pending?.kind === "agreement") state.pending = null;
        return finish("buyer-agreement-received");
      }
      state.messageCursor = page.nextCursor ?? null;
      if (state.messageCursor) return finish("agreement-history-pending");
      const body = { body: `Please confirm the conditional CSV offer by replying with this exact JSON object (maximumInputBytes may be reduced). Your agent must execute the acceptance command, review the delivery criteria and fund Base USDC settlement; seller spends zero. This confirmation permits only the prepared source/artifact below; no arbitrary commands or new work are accepted.
${JSON.stringify(expected)}` };
      const key = `csv-agreement:${await fingerprint(expected)}`;
      if (state.agreementRequest?.key === key && state.agreementRequest.received) return finish("agreement-pending");
      if (state.pending && state.pending.kind !== "agreement") return finish("uncertain-effect-held");
      state.pending = { kind: "agreement", path: `${base}/messages`, method: "POST", body, key };
      const basis = await fingerprint(permissionBasis);
      if (state.deniedEffect?.key === key && state.deniedEffect.basis === basis) return finish("provider-write-refused");
      state.effectBasis = basis;
      await storage.put(STATE, state);
      const sent = await client.request(`${base}/messages`, { method: "POST", body, key });
      if (sent.ok !== true || typeof sent.id !== "string") return finish("agreement-send-readback-pending");
      state.agreementRequest = { key, received: true, messageId: sent.id };
      state.pending = null;
      return finish("agreement-requested");
    }
    state.observations.acceptance = { contractStatus: contract.status };
    if (contract.hasRouterPaymentProofIssue) return finish("payment-proof-held");
    if (contract.hasRouterVerifiedPayment && contract.verifiedCryptoPaymentRequest?.id) {
      const id2 = contract.verifiedCryptoPaymentRequest.id;
      const value = await client.request(`${base}/crypto-payment-requests/${id2}`);
      const payment = value.paymentRequest ?? value.request ?? value;
      if (payment.id !== id2 || payment.contractId !== contract.id || payment.status !== "verified" || payment.sellerAddress?.toLowerCase() !== merchant.toLowerCase() || payment.chainId !== 8453 || payment.tokenSymbol !== "USDC" || payment.tokenDecimals !== 6 || payment.tokenAddress?.toLowerCase() !== BASE_USDC || payment.sellerAmountAtomic !== instance.priceAmountAtomic || !/^0x[0-9a-f]{64}$/i.test(payment.paidTxHash ?? "") || !/^\d+$/.test(payment.paidBlockNumber ?? "") || !Number.isSafeInteger(payment.paidLogIndex) || payment.paidLogIndex < 0 || !payment.verifiedAt) return finish("payment-proof-held");
      state.observations.settlement = {
        authority: "opentask-router",
        requestId: id2,
        transactionHash: payment.paidTxHash,
        blockNumber: payment.paidBlockNumber,
        logIndex: payment.paidLogIndex,
        amountAtomic: payment.sellerAmountAtomic,
        receiver: merchant.toLowerCase(),
        verifiedAt: payment.verifiedAt
      };
      if (!state.observations.delivery?.manifestDigest) return finish("settlement-reported-delivery-unreceived");
      return finish(contract.status === "accepted" ? "accepted-and-settlement-reported" : "settlement-reported-awaiting-acceptance");
    }
    if (contract.status === "accepted") return finish("acceptance-observed-awaiting-proof");
    const title = `Prepared CSV ${product.sourceCommit.slice(0, 12)}`;
    const listed = await client.request(base + "/deliveries");
    const packages = listed.deliveries ?? listed.packages;
    if (!Array.isArray(packages)) return finish("delivery-shape-held");
    if (listed.nextCursor) return finish("delivery-history-held");
    const drafts = packages.filter((p) => p.status === "draft");
    const own = drafts.filter((p) => p.title === title);
    if (drafts.length > 1 || drafts.length && own.length !== 1) return finish("existing-draft-held");
    let pkg = own[0];
    if (pkg && state.pending?.kind === "create") state.pending = null;
    const immutable = packages.filter((p) => p.title === title && p.status !== "draft").sort((a, b) => (b.revision ?? 0) - (a.revision ?? 0))[0];
    if (!pkg && immutable && immutable.status !== "changes_requested") {
      if (!receivedPackage(immutable, contract.id, product)) return finish("immutable-evidence-held");
      state.observations.delivery = { packageId: immutable.id, revision: immutable.revision, manifestDigest: immutable.manifestDigest, status: immutable.status };
      state.pending = null;
      return finish("submitted-awaiting-buyer");
    }
    if (!deliveryAllowed(context, instance)) return finish("delivery-action-held");
    if (!pkg) {
      if (immutable?.status === "changes_requested") {
        const reviewed = (await client.request(`${base}/deliveries/${immutable.id}`)).delivery ?? immutable;
        const changes = reviewed.criteria?.filter((c) => c.buyerDecision === "changes_requested") ?? [];
        if (state.revisions >= 1 || !changes.length || changes.some((c) => !Object.hasOwn(product.criteriaEvidence, c.text) || c.buyerComment && !Object.hasOwn(product.criteriaEvidence, c.buyerComment))) return finish("requested-change-held");
      }
      const body = {
        title,
        summary: `${product.name}. Source ${product.sourceCommit}; archive SHA-256 ${product.artifactSha256}.`,
        verificationInstructions: product.verificationInstructions,
        ...immutable ? { basedOnDeliveryPackageId: immutable.id } : {}
      };
      return await effect("create", base + "/deliveries", "POST", body);
    }
    const detail = await client.request(`${base}/deliveries/${pkg.id}`);
    pkg = detail.delivery ?? detail.package ?? detail;
    if (pkg.status !== "draft" || pkg.availableActions?.edit !== true) return finish("draft-edit-held");
    if (pkg.title !== title || pkg.contractId !== contract.id || pkg.milestoneId) return finish("draft-scope-held");
    const artifact = pkg.artifacts?.find((a) => a.externalUrl === product.artifactUrl && a.description === `SHA-256 ${product.artifactSha256}; source ${product.sourceCommit}`);
    if (artifact && state.pending?.kind === "attach") state.pending = null;
    if (!artifact) return await effect("attach", `${base}/deliveries/${pkg.id}/external-artifacts`, "POST", {
      expectedVersion: pkg.version,
      kind: "archive",
      label: product.name,
      url: product.artifactUrl,
      description: `SHA-256 ${product.artifactSha256}; source ${product.sourceCommit}`
    });
    const claims = criterionClaims(pkg, product, artifact.id);
    if (!claims) return finish("criterion-evidence-held");
    const currentClaims = pkg.criteria.map((c) => ({ criterionId: c.id, claim: c.sellerClaim, note: c.sellerNote, artifactIds: c.artifactIds }));
    if (same(claims, currentClaims) && state.pending?.kind === "claim") state.pending = null;
    if (!same(claims, currentClaims)) return await effect("claim", `${base}/deliveries/${pkg.id}`, "PATCH", {
      expectedVersion: pkg.version,
      criteria: claims,
      ...immutable ? { changeSummary: "Clarified evidence for the unchanged frozen prepared product against the requested criteria." } : {}
    });
    if (pkg.availableActions?.submit !== true) return finish("draft-submit-held");
    return await effect("submit", `${base}/deliveries/${pkg.id}/submit`, "POST", { expectedVersion: pkg.version, confirmed: true });
    async function effect(kind, path, method, body) {
      const pending = { kind, path, method, body, key: `csv:${await fingerprint({ contractId: contract.id, kind, path, body })}` };
      const basis = await fingerprint({ ...permissionBasis, packageId: pkg?.id ?? null, packageVersion: pkg?.version ?? null });
      if (state.deniedEffect?.key === pending.key && state.deniedEffect.basis === basis) return finish("provider-write-refused");
      if (state.deniedEffect && state.deniedEffect.key === state.pending?.key && state.deniedEffect.basis !== basis) {
        state.pending = null;
        state.deniedEffect = null;
      }
      if (state.pending && !same(state.pending, pending)) return finish("uncertain-effect-held");
      state.pending = pending;
      state.effectBasis = basis;
      await storage.put(STATE, state);
      const result = await client.request(path, { method, body, key: pending.key });
      if (kind === "submit") {
        const delivered = result.delivery ?? result.package ?? result;
        if (!delivered.manifestDigest || !Number.isSafeInteger(delivered.revision)) return finish("submission-readback-pending");
        state.observations.delivery = { packageId: delivered.id, revision: delivered.revision, manifestDigest: delivered.manifestDigest, status: delivered.status };
        if (immutable) state.revisions++;
      }
      state.pending = null;
      return finish(kind + "-received");
    }
  } catch (error) {
    state.lastFailure = /^[a-z0-9_-]{1,100}$/.test(error.code ?? "") ? error.code : "commercial-failure";
    if (error.retryBlocked) state.retryBlocked = true;
    else if (Number.isFinite(error.retryAt)) state.nextAttemptAt = new Date(error.retryAt).toISOString();
    if (error.retryAfter) state.retryAfter = error.retryAfter;
    if (state.pending && (error.status === 403 || error.status === 503 || /^native_delivery_/.test(error.code ?? "")))
      state.deniedEffect = { key: state.pending.key, code: state.lastFailure, status: error.status, basis: state.effectBasis };
    return finish(state.pending ? "effect-readback-pending" : state.lastFailure);
  }
}

// src/route-health.mjs
var CATALOG_URL = "https://market.561.group/v1/catalog";
var BROKEN_STREAK_FOR_REPAIR = 3;
var id = (offer) => `${offer.method} ${offer.route}`;
function probeRequest(offer) {
  const example = offer.request?.example;
  const headers = { "user-agent": "coesite-earning-loops/1 (+https://github.com/coesite-operations/operations-services-section)", accept: "application/json" };
  if (offer.method === "GET") return [example?.url ?? offer.url, { method: "GET", headers }];
  const body = example && typeof example === "object" && "body" in example ? example.body : {};
  return [offer.url, { method: offer.method, headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify(body) }];
}
var decode = (header) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(header), (c) => c.charCodeAt(0))));
function judge(offer, status, challengeHeader, { payTo, resourceUrl } = {}) {
  if (status !== 402) return { held: false, finding: `answered ${status}, not 402, to the catalog's example request` };
  if (!challengeHeader) return { held: false, finding: "402 without a payment-required challenge" };
  let challenge;
  try {
    challenge = decode(challengeHeader);
  } catch {
    return { held: false, finding: "payment-required challenge does not decode" };
  }
  if (challenge?.x402Version !== 2 || !Array.isArray(challenge.accepts)) return { held: false, finding: "challenge is not x402 v2" };
  if (resourceUrl && challenge.resource?.url !== resourceUrl) return { held: false, finding: "challenge resource differs from the probed public URL" };
  if (!/^0x[0-9a-f]{40}$/i.test(payTo ?? "")) return { held: false, finding: "merchant receiver has not been configured" };
  const accept = challenge.accepts.find((a) => a?.scheme === "exact" && typeof a.payTo === "string" && a.payTo.toLowerCase() === payTo.toLowerCase() && a.network === "eip155:8453" && typeof a.asset === "string" && a.asset.toLowerCase() === BASE_USDC);
  if (!accept) return { held: false, finding: "challenge offers no exact Base USDC payment to the configured merchant" };
  if (offer.amountAtomic != null && String(accept.amount) !== String(offer.amountAtomic))
    return { held: false, finding: `challenge asks ${accept.amount}, catalog lists ${offer.amountAtomic}` };
  return { held: true, finding: `buyable at ${offer.price}`, amount: String(accept.amount), payTo: accept.payTo?.toLowerCase() ?? null };
}
async function checkRoutes(env, { now = /* @__PURE__ */ new Date(), limit = 15, catalogUrl = CATALOG_URL, brokenStreak = BROKEN_STREAK_FOR_REPAIR, repository = env.REPAIR_REPOSITORY, payTo, fetchImpl = fetch } = {}) {
  const key = register("route-health");
  const state = await read(env.STATE, key) ?? { routes: {} };
  const response = await fetchImpl(catalogUrl, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(15e3), redirect: "manual" });
  if (!response.ok) throw new Error(`catalog answered ${response.status}`);
  const catalog = await response.json();
  const offers = catalog.offers.filter((offer) => offer.listed);
  const at = now.toISOString();
  for (const offer of offers) state.routes[id(offer)] ??= { firstListedAt: at, price: offer.price, amountAtomic: offer.amountAtomic ?? null, heldSince: null, brokenStreak: 0 };
  const listed = new Set(offers.map(id));
  for (const route of Object.keys(state.routes)) if (!listed.has(route)) state.routes[route].delistedAt ??= at;
  const due = offers.sort((a, b) => Number(state.routes[id(a)].held !== false) - Number(state.routes[id(b)].held !== false) || (state.routes[id(a)].observedAt ?? "").localeCompare(state.routes[id(b)].observedAt ?? "")).slice(0, limit);
  for (const offer of due) {
    const [url, init] = probeRequest(offer);
    let verdict;
    try {
      const response2 = await fetchImpl(url, { ...init, redirect: "manual", signal: AbortSignal.timeout(15e3) });
      verdict = judge(offer, response2.status, response2.headers.get("payment-required"), { payTo, resourceUrl: url });
      await response2.body?.cancel();
    } catch (error) {
      verdict = { held: false, finding: `request failed: ${error.message}` };
    }
    const entry = state.routes[id(offer)];
    Object.assign(entry, verdict, { observedAt: at, price: offer.price, amountAtomic: offer.amountAtomic ?? null, delistedAt: void 0 });
    entry.heldSince = verdict.held ? entry.heldSince ?? at : null;
    entry.brokenStreak = verdict.held ? 0 : entry.brokenStreak + 1;
  }
  const routes = Object.entries(state.routes).filter(([, r]) => !r.delistedAt);
  state.at = at;
  state.held = routes.filter(([, r]) => r.held).length;
  state.broken = routes.filter(([, r]) => r.held === false).length;
  state.repairs = routes.filter(([, r]) => r.brokenStreak >= brokenStreak).map(([route, r]) => ({ route, finding: r.finding, brokenStreak: r.brokenStreak }));
  await put(env.STATE, key, state);
  if (state.repairs.length && env.REPAIR_DISPATCH_TOKEN && repository) await dispatchRepair(env.REPAIR_DISPATCH_TOKEN, repository, state.repairs, fetchImpl);
  return { probed: due.length, held: state.held, broken: state.broken, repairs: state.repairs.length };
}
async function dispatchRepair(token, repository, repairs, fetchImpl) {
  await fetchImpl(`https://api.github.com/repos/${repository}/dispatches`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "user-agent": "coesite-earning-loops" },
    body: JSON.stringify({ event_type: "market-route-broken", client_payload: { repairs: repairs.slice(0, 20) } })
  });
}

// src/scorecard.mjs
var BURN_USD_PER_MONTH = 600;
var FLOOR_USD_PER_DAY = 20;
var GOAL_USD_PER_DAY = 200;
var DAY = 864e5;
function mode(ratio, retainedSurplus = 0) {
  if (ratio >= 1) return retainedSurplus > 0 ? "building-runway" : "self-funding";
  return ratio >= 0.1 ? "climbing" : "starving";
}
var DEFAULT_ECONOMICS = { burnUsdPerMonth: BURN_USD_PER_MONTH, floorUsdPerDay: FLOOR_USD_PER_DAY, goalUsdPerDay: GOAL_USD_PER_DAY, burnBasis: "leader-estimate" };
var isOutside = (s, groupPayers2 = /* @__PURE__ */ new Set()) => s.payerClass === "outside-confirmed" && !groupPayers2.has(s.payer);
var preparedDelivery = (s) => s.deliveryObservation?.basis === "server-response-prepared" && s.deliveryObservation.status >= 200 && s.deliveryObservation.status < 300 && s.deliveryObservation.bodyBytes > 0;
function scorecard({ settlements = {}, routes = {}, onchain = null }, { now = /* @__PURE__ */ new Date(), groupPayers: groupPayers2 = /* @__PURE__ */ new Set(), economics = DEFAULT_ECONOMICS } = {}) {
  const at = now.getTime(), list = Object.values(settlements);
  const since = (days) => list.filter((s) => at - Date.parse(s.recordedAt ?? s.corroboratedAt) >= 0 && at - Date.parse(s.recordedAt ?? s.corroboratedAt) <= days * DAY);
  const outside = (rows) => rows.filter((s) => isOutside(s, groupPayers2));
  const accepted = (rows) => outside(rows).filter((s) => preparedDelivery(s) && s.deliveryObservation.requesterAccepted === true);
  const unclassified = (rows) => rows.filter((s) => !groupPayers2.has(s.payer) && !isOutside(s, groupPayers2));
  const sum = (rows) => Number(rows.reduce((total, s) => total + s.usd, 0).toFixed(6));
  const week = since(7), month = since(30);
  const trailing30 = sum(accepted(month));
  const byRoute = {};
  for (const s of accepted(month)) byRoute[s.route ?? "unknown"] = Number(((byRoute[s.route ?? "unknown"] ?? 0) + s.usd).toFixed(6));
  const live = Object.values(routes).filter((r) => !r.delistedAt);
  const ratio = Number((trailing30 / economics.burnUsdPerMonth).toFixed(4));
  return {
    type: "EarningsScorecard",
    at: now.toISOString(),
    outsideRevenueUSD: { week: sum(accepted(week)), trailing30, perDayTrailing30: Number((trailing30 / 30).toFixed(4)) },
    outsideCashReceivedUSD: { week: sum(outside(week)), trailing30: sum(outside(month)) },
    outsidePaidDeliveriesUSD: { week: sum(outside(week).filter(preparedDelivery)), trailing30: sum(outside(month).filter(preparedDelivery)) },
    unclassifiedCashReceivedUSD: { week: sum(unclassified(week)), trailing30: sum(unclassified(month)) },
    groupPayerCashReceivedUSD: { week: sum(week.filter((s) => groupPayers2.has(s.payer))), trailing30: sum(month.filter((s) => groupPayers2.has(s.payer))) },
    outsideBuyers: new Set(outside(month).map((s) => s.payer)).size,
    outsideRevenueByRoute: byRoute,
    burnUSD: { monthly: economics.burnUsdPerMonth, basis: economics.burnBasis ?? "leader-estimate" },
    targetsUSDPerDay: { floor: economics.floorUsdPerDay, goal: economics.goalUsdPerDay },
    selfFundingRatio: ratio,
    mode: mode(ratio),
    offers: { listed: live.length, buyable: live.filter((r) => r.held).length, broken: live.filter((r) => r.held === false).length },
    onchain: onchain ? { lastRunAt: onchain.at, status: onchain.status ?? null } : null,
    source: "two-provider Base transfers; prepared responses, requester acceptance and confirmed outside ownership are separate evidence",
    recognition: "outside revenue requires confirmed outside ownership, a prepared successful response, and requester acceptance; unknown wallets remain unclassified"
  };
}
async function writeScorecard(env, { now = /* @__PURE__ */ new Date(), groupPayers: groupPayers2, economics } = {}) {
  const card = scorecard({
    settlements: (await read(env.STATE, register("settlements")))?.settlements,
    routes: (await read(env.STATE, register("route-health")))?.routes,
    onchain: await read(env.STATE, register("onchain"))
  }, { now, groupPayers: groupPayers2, economics });
  await put(env.STATE, register("scorecard"), card);
  await put(env.STATE, record("scorecards", card.at.slice(0, 10)), card);
  return card;
}

// src/border-price.mjs
var CROSSED_SALES = 20;
function revealedBorder({ healthyDays, listedDays, outsideSales }) {
  if (healthyDays < 14 || listedDays < 14) return outsideSales > 0 ? "exact-match" : "unobserved";
  if (outsideSales >= CROSSED_SALES) return "crossed-range";
  if (outsideSales > 0) return "exact-match";
  return "open-gap";
}

// src/price-directives.mjs
var DAY2 = 864e5;
var FLOOR_ATOMIC = 10000n;
var dollars = (atomic) => `$${+(Number(atomic) / 1e6).toFixed(6)}`;
function stepUp(atomic) {
  const raised = BigInt(atomic) * 3n / 2n;
  const unit = raised >= FLOOR_ATOMIC ? 10000n : 1000n;
  return (raised + unit - 1n) / unit * unit;
}
function proposeDirectives({ routes, settlements, previous = [] }, { now = /* @__PURE__ */ new Date(), groupPayers: groupPayers2 = /* @__PURE__ */ new Set() } = {}) {
  const at = now.getTime(), issuedAt = now.toISOString();
  const between = (route, start, end) => Object.values(settlements ?? {}).filter((s) => {
    const t = Date.parse(s.recordedAt ?? s.corroboratedAt);
    return s.route === route.slice(route.indexOf(" ") + 1) && isOutside(s, groupPayers2) && preparedDelivery(s) && t > start && t <= end;
  }).length;
  const sales = (route, days) => between(route, at - days * DAY2, at);
  const lastFor = (route) => previous.filter((d) => d.route === route).at(-1);
  const out = [];
  for (const [route, r] of Object.entries(routes ?? {})) {
    if (r.delistedAt || r.amountAtomic == null) continue;
    if (!r.held) continue;
    const current = BigInt(r.amountAtomic);
    const healthyDays = r.heldSince ? (at - Date.parse(r.heldSince)) / DAY2 : 0;
    const listedDays = (at - Date.parse(r.firstListedAt)) / DAY2;
    const recent = sales(route, 14), relation = revealedBorder({ healthyDays, listedDays, outsideSales: recent });
    const last = lastFor(route);
    const base = { route, from: String(current), relation, evidence: { outsideSales14d: recent, healthyDays: Math.floor(healthyDays), listedDays: Math.floor(listedDays) }, issuedAt, status: "proposed" };
    if (last?.status === "proposed" && last.from === String(current)) continue;
    if (last?.kind === "raise" && last.to === String(current) && last.appliedAt && at - Date.parse(last.appliedAt) >= 14 * DAY2) {
      const applied = Date.parse(last.appliedAt), before = between(route, applied - 14 * DAY2, applied), after = recent;
      if (before > 0 && after * 2 < before) {
        out.push({ ...base, kind: "revert", to: last.from, reason: `raise to ${dollars(current)} cut outside sales from ${before} to ${after} in 14 days`, revertOf: last.id });
        continue;
      }
    }
    if (relation === "crossed-range") out.push({ ...base, kind: "raise", to: String(stepUp(current)), reason: `${recent} outside sales in 14 days at ${dollars(current)}: buyers' bids sit at or above the ask` });
    else if (relation === "open-gap" && current < FLOOR_ATOMIC) out.push({ ...base, kind: "raise", to: String(FLOOR_ATOMIC), reason: `buyable and listed ${Math.floor(listedDays)} days at sub-cent ${dollars(current)} with no outside sale; sub-cent prices signal a toy` });
    else if (relation === "open-gap") out.push({ ...base, kind: "change-one-thing", to: String(current), reason: `buyable and listed ${Math.floor(listedDays)} days with no outside sale: change the name, example or bundle before the price` });
  }
  return out.map((d) => ({ id: `${d.route}@${d.issuedAt}`, ...d }));
}
function markApplied(directives, routes, now = /* @__PURE__ */ new Date()) {
  for (const d of directives) {
    if (d.status !== "proposed" || d.kind === "change-one-thing") continue;
    const current = routes[d.route]?.amountAtomic;
    if (current != null && String(current) === d.to) Object.assign(d, { status: "applied", appliedAt: now.toISOString() });
    else if (current != null && String(current) !== d.from) Object.assign(d, { status: "superseded", supersededAt: now.toISOString() });
  }
  return directives;
}
async function writeDirectives(env, { now = /* @__PURE__ */ new Date(), groupPayers: groupPayers2 } = {}) {
  const key = register("price-directives");
  const state = await read(env.STATE, key) ?? { directives: [] };
  const routes = (await read(env.STATE, register("route-health")))?.routes ?? {};
  markApplied(state.directives, routes, now);
  const fresh = proposeDirectives({
    routes,
    settlements: (await read(env.STATE, register("settlements")))?.settlements,
    previous: state.directives
  }, { now, groupPayers: groupPayers2 });
  state.directives.push(...fresh);
  state.at = now.toISOString();
  await put(env.STATE, key, state);
  return { proposed: fresh.length, pending: state.directives.filter((d) => d.status === "proposed").length };
}

// src/onchain-hook.mjs
async function runOnchainHook(env, { now = /* @__PURE__ */ new Date(), cron = null, url = env.ONCHAIN_SCAN_URL, fetchImpl = fetch } = {}) {
  const at = now.toISOString();
  if (!url) {
    await put(env.STATE, register("onchain"), { at, status: "no-engine-attached" });
    return { status: "no-engine-attached" };
  }
  try {
    const response = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json", ...env.ONCHAIN_SCAN_TOKEN ? { authorization: `Bearer ${env.ONCHAIN_SCAN_TOKEN}` } : {} },
      body: JSON.stringify({ at, cron })
    });
    const answer = response.headers.get("content-type")?.includes("json") ? await response.json() : null;
    const result = { at, status: response.ok ? "ran" : `http-${response.status}`, answer };
    await put(env.STATE, register("onchain"), result);
    return { status: result.status };
  } catch (error) {
    await put(env.STATE, register("onchain"), { at, status: "unreachable", error: error.message });
    return { status: "unreachable" };
  }
}

// src/clock.mjs
var TICK_MS = 15 * 6e4;
function matches(cron, date) {
  const fields = cron.trim().split(/\s+/);
  const values = [date.getUTCMinutes(), date.getUTCHours(), date.getUTCDate(), date.getUTCMonth() + 1, date.getUTCDay()];
  return fields.length === 5 && fields.every((field, i) => field.split(",").some((part) => {
    if (part === "*") return true;
    const step = part.match(/^\*\/(\d+)$/);
    return step ? values[i] % Number(step[1]) === 0 : Number(part) === values[i];
  }));
}
var dueCrons = (crons, date) => Object.values(crons).filter((cron) => matches(cron, date));
var nextTick = (now) => Math.floor(now / TICK_MS) * TICK_MS + TICK_MS;

// src/issuer-research.mjs
function retryDelayMs(value, now) {
  if (typeof value !== "string") return 0;
  const text = value.trim();
  const seconds = /^\d+$/.test(text);
  const delay = seconds ? Number(text) * 1e3 : /^[A-Za-z]{3}, /.test(text) ? Date.parse(text) - now.getTime() : 0;
  if (seconds && (!Number.isSafeInteger(delay) || !Number.isFinite(new Date(now.getTime() + delay).getTime()))) return Infinity;
  return Number.isFinite(delay) ? Math.max(0, delay) : 0;
}
async function refreshIssuerResearch(env, configuration, { now = /* @__PURE__ */ new Date(), prepare, clock = () => /* @__PURE__ */ new Date() } = {}) {
  if (!configuration) return { status: "not-configured" };
  const key = register("issuer-research");
  const previous = await read(env.STATE, key);
  if (previous?.retryBlocked) return { ...previous, status: "deferred" };
  if (previous?.cacheKey === configuration.cacheKey && Date.parse(previous.nextAttemptAt) > now.getTime())
    return { ...previous, status: "deferred" };
  let reading;
  try {
    const producer = prepare ?? (await import("@red-cup-engineering/issuer-research-media-service/prepared-cohort")).prepareIssuerRevenueCohort;
    const complete = await producer(configuration);
    await put(env.STATE, configuration.cacheKey, complete);
    reading = {
      status: "prepared",
      at: now.toISOString(),
      cacheKey: configuration.cacheKey,
      observedAt: complete.observedAt ?? null,
      nextAttemptAt: new Date(now.getTime() + 9e5).toISOString()
    };
  } catch (error) {
    const refusedAt = new Date(Math.max(now.getTime(), clock().getTime()));
    const delay = Math.max(9e5, retryDelayMs(error.retryAfter, refusedAt));
    reading = {
      status: "unavailable",
      at: refusedAt.toISOString(),
      cacheKey: configuration.cacheKey,
      error: error.message,
      code: error.code ?? null,
      reason: error.reason ?? null,
      retryable: error.retryable ?? true,
      retryAfter: typeof error.retryAfter === "string" ? error.retryAfter : null,
      retryBlocked: !Number.isFinite(delay),
      nextAttemptAt: Number.isFinite(delay) ? new Date(refusedAt.getTime() + delay).toISOString() : null
    };
  }
  await put(env.STATE, key, reading);
  return reading;
}

// worker/earning-loops.mjs
var groupPayers = new Set(group_payers_default);
var CRONS = operation_default.crons;
async function run(env, cron, now = /* @__PURE__ */ new Date(), { configuration = operation_default, prepareIssuerRevenueCohort } = {}) {
  if (configuration.issuerResearch && (env.ONCHAIN_SCAN_URL || configuration.onchainScanUrl))
    throw new TypeError("issuer operation has no subrequest allocation for an onchain hook");
  const outcome = { cron, at: now.toISOString() };
  const step = async (name, work) => {
    try {
      outcome[name] = await work();
    } catch (error) {
      outcome[name] = { error: error.message };
    }
  };
  if (cron === configuration.crons.directives) await step("directives", () => writeDirectives(env, { now, groupPayers }));
  else if (cron === configuration.crons.scorecard) await step("scorecard", async () => (await writeScorecard(env, { now, groupPayers, economics: configuration.economics })).outsideRevenueUSD);
  else {
    await step("settlements", () => receiveSettlements(env, { now, groupPayers, limit: configuration.limits.settlementsPerPass }));
    await step("routes", () => checkRoutes(env, {
      now,
      catalogUrl: configuration.catalogUrl,
      limit: configuration.limits.routeProbesPerPass,
      brokenStreak: configuration.repair.brokenStreakBeforeRepair,
      repository: configuration.repair.repository,
      payTo: configuration.merchantPayTo
    }));
    await step("scorecard", async () => (await writeScorecard(env, { now, groupPayers, economics: configuration.economics })).outsideRevenueUSD);
    await step("onchain", () => runOnchainHook(env, { now, cron, url: env.ONCHAIN_SCAN_URL ?? configuration.onchainScanUrl }));
    if (configuration.issuerResearch) await step("issuerResearch", () => refreshIssuerResearch(env, configuration.issuerResearch, { now, prepare: prepareIssuerRevenueCohort }));
  }
  await put(env.STATE, register("last-run"), outcome);
  return outcome;
}
var READINGS = {
  "/settlements.json": "settlements",
  "/route-health.json": "route-health",
  "/scorecard.json": "scorecard",
  "/price-directives.json": "price-directives",
  "/onchain.json": "onchain",
  "/last-run.json": "last-run",
  "/issuer-research.json": "issuer-research"
};
async function tick(env, date, options = {}) {
  const crons = (options.configuration ?? operation_default).crons;
  const due = dueCrons(crons, date).sort((a, b) => (a === crons.pass) - (b === crons.pass));
  const outcomes = [];
  for (const cron of due) outcomes.push(await run(env, cron, date, options));
  return outcomes;
}
var EarningClock = class {
  constructor(state, env, options = {}) {
    this.state = state;
    this.env = env;
    this.options = options;
    this.queue = Promise.resolve();
  }
  async alarm() {
    const task = this.queue.then(async () => {
      const configuration = this.options.configuration ?? operation_default;
      const at = Date.now(), commercial = configuration.commercial?.enabled === true;
      const slot = commercial ? Math.round(at / 45e4) * 45e4 : Math.round(at / 6e4) * 6e4;
      try {
        if (commercial && slot % 9e5 !== 0) {
          const result = await (this.options.commercialPass ?? runCommercialPass)({
            storage: this.state.storage,
            initialCredential: this.env.OPENTASK_CREDENTIAL_JSON,
            instance: configuration.commercial,
            products: this.options.products ?? products_default,
            merchant: configuration.merchantPayTo,
            now: new Date(at)
          });
          await this.state.storage.put("opentask/public-summary", {
            stage: result.stage,
            requests: result.requests,
            newCashExpenseUsd: 0,
            at: new Date(at).toISOString()
          });
        } else await tick(this.env, new Date(slot), this.options);
      } finally {
        await this.state.storage.setAlarm(commercial ? (Math.floor(at / 45e4) + 1) * 45e4 : nextTick(at));
      }
    });
    this.queue = task.catch(() => {
    });
    return task;
  }
  async fetch(request) {
    if (request && new URL(request.url).pathname === "/commercial.json") {
      const summary = await this.state.storage.get("opentask/public-summary");
      if (!summary) return new Response("not yet observed\n", { status: 404 });
      const alarm2 = await this.state.storage.getAlarm();
      return Response.json({
        stage: summary.stage,
        requests: summary.requests,
        newCashExpenseUsd: 0,
        at: summary.at,
        nextTick: alarm2 ? new Date(alarm2).toISOString() : null
      }, { headers: { "cache-control": "no-store" } });
    }
    let alarm = await this.state.storage.getAlarm();
    if (!alarm) {
      const at = Date.now();
      alarm = (this.options.configuration ?? operation_default).commercial?.enabled ? (Math.floor(at / 45e4) + 1) * 45e4 : nextTick(at);
      await this.state.storage.setAlarm(alarm);
    }
    return Response.json({ nextTick: new Date(alarm).toISOString() });
  }
};
var earning_loops_default = {
  async scheduled(event, env, context) {
    context.waitUntil(run(env, event.cron));
  },
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (path === "/products.json") return Response.json(products_default, { headers: { "cache-control": "public, max-age=300" } });
    if (path === "/commercial.json" && env.CLOCK) return env.CLOCK.get(env.CLOCK.idFromName("earning-loops")).fetch(request);
    if (path === "/clock" && env.CLOCK) return env.CLOCK.get(env.CLOCK.idFromName("earning-loops")).fetch(request);
    if (READINGS[path]) {
      const value = await read(env.STATE, register(READINGS[path]));
      return value ? Response.json(value, { headers: { "cache-control": "no-store" } }) : new Response("not yet observed\n", { status: 404 });
    }
    if (path !== "/") return new Response("not found\n", { status: 404 });
    const [health, card, last] = await Promise.all(["route-health", "scorecard", "last-run"].map((name) => read(env.STATE, register(name))));
    if (!health) return new Response("no observations yet\n", { status: 503 });
    const broken = Object.entries(health.routes).filter(([, r]) => r.held === false && !r.delistedAt);
    const lines = [
      `${health.held} buyable, ${health.broken} unbuyable listed offers, as of ${health.at}`,
      card ? `outside revenue: USD ${card.outsideRevenueUSD.week} this week, USD ${card.outsideRevenueUSD.trailing30} trailing 30 days (goal USD ${card.targetsUSDPerDay.goal}/day); mode ${card.mode}` : "no scorecard yet",
      last ? `last pass ${last.at} (${last.cron})` : "",
      "",
      ...broken.map(([route, r]) => `UNBUYABLE  ${route}: ${r.finding}`)
    ];
    return new Response(`${lines.join("\n")}
`, { status: broken.length ? 503 : 200, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
  }
};
export {
  CRONS,
  EarningClock,
  earning_loops_default as default,
  run,
  tick
};
