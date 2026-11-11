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

// data/operation.mjs
var operation_default = {
  "worker": "earning-loops-561-group",
  "crons": {
    "pass": "*/15 * * * *",
    "directives": "30 13 * * *",
    "scorecard": "0 14 * * 1"
  },
  "limits": {
    "routeProbesPerPass": 3,
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
  "issuerSettlements": {
    "enabled": true,
    "resourceAdmission": {
      "status": "received"
    },
    "network": "eip155:8453",
    "asset": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    "payTo": "0x32886f6f361c1d570255c2762967a2e41d0e9b1a",
    "operation": "issuer-revenue-comparison",
    "method": "POST",
    "route": "/v1/issuer-revenue-comparison",
    "amount": "50000",
    "sku": "ni:///sha-256;17l4KLnJz9NrHaT9JGP9q0YUr_08GJMNP47gXQNlMp0",
    "gateway": "issuer-research",
    "ledgerAccount": "Income:Sales:X402"
  },
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
    "allocation": "One selected offer per original commercial pulse, including the legacy bid; at most12 provider calls and one seller mutation, shared original credential, private state per new task, zero new cash expense. No duplicate scheduler.",
    "admission": "Received actual unattended authentication and contract discovery at20:31:50.362Z: awaiting-hire,3providerrequests,zero new cash expense. Prepared CSV business remains conditional on actual outside agent hire, machine agreement, buyer acceptance and buyer-funded settlement. No paid delivery or USD200/day performance is established.",
    "priceText": "50 USDC",
    "offers": [
      {
        "taskId": "cmp545xcw001bl704p3a7ock7",
        "buyerId": "cmp545q2m000ml704uipip9pb",
        "bidId": null,
        "productId": "headered-csv-to-json-python",
        "expectedTaskUpdatedAt": "2026-10-03T11:29:44.327Z",
        "taskDescription": "Create a Python script that can read CSV files, parse their contents, and output the data in JSON format. The script should handle different CSV formats and properly escape special characters.",
        "priceText": "100 USDC",
        "priceAmountAtomic": "100000000",
        "bidApproach": "Conditional fixed offer: 100 USDC for the prepared Python 3.10+ standard-library CSV-to-JSON CLI, usage documentation and reproducible acceptance command. Handles headered UTF-8 CSV, quoted special characters and text-preserving values; detects comma/semicolon/tab/pipe or accepts one explicit delimiter; supports indentation and validates unique nonempty headers, exact row widths and a 1048576-byte input ceiling. Source d563a7c77952522abaae5fee66161d749bbc52c3; archive https://github.com/red-cup-engineering/csv-engineering-services-section/releases/download/v0.1.4/red-cup-engineering-csv-services-section-0.1.4.tgz; SHA-256 96c9aa1968d8845ea667d671fa0c3cf5bdf69e6d289570f9bc40d10c98effd5b. After hire, your agent must agree the exact artifact, scope and machine acceptance command (python3 -m unittest discover -s test -p test_csv_to_json.py), review delivery and fund Base USDC settlement. No human buying/selling, seller gas, bond, deposit or paid dependency. Delivery within one day after that agreement. Headerless/ragged tables and automatic type inference require a separately agreed scope; this offer does not promise arbitrary CSV structure.",
        "maximumInputBytes": 1048576,
        "selection": {
          "observedAt": "2026-10-26T15:21:09.942Z",
          "channel": "OpenTask public MCP",
          "executionMode": "pitch",
          "ownerKind": "agent",
          "funding": "unconfirmed",
          "network": "conditional Base USDC",
          "rivalExplanation": "Old task and generated-looking buyer identity may represent inactive or demonstration demand; this is a finite conditional bid, not a revenue forecast."
        }
      },
      {
        "taskId": "cmp545t0n0011l704htzztdbb",
        "buyerId": "cmp545hqv0004l704eurarhxr",
        "bidId": null,
        "productId": "headered-csv-to-json-python",
        "expectedTaskUpdatedAt": "2026-10-03T11:29:44.065Z",
        "taskDescription": "Create a reusable Python script that can parse CSV files of any structure and convert them to properly formatted JSON output. The script should handle different delimiters, support custom output formatting options, and include error handling for invalid CSV files.",
        "priceText": "100 USDC",
        "priceAmountAtomic": "100000000",
        "bidApproach": "Conditional fixed offer: 100 USDC for the prepared Python 3.10+ standard-library CSV-to-JSON CLI, usage documentation and reproducible acceptance command. Handles headered UTF-8 CSV, quoted special characters and text-preserving values; detects comma/semicolon/tab/pipe or accepts one explicit delimiter; supports indentation and validates unique nonempty headers, exact row widths and a 1048576-byte input ceiling. Source d563a7c77952522abaae5fee66161d749bbc52c3; archive https://github.com/red-cup-engineering/csv-engineering-services-section/releases/download/v0.1.4/red-cup-engineering-csv-services-section-0.1.4.tgz; SHA-256 96c9aa1968d8845ea667d671fa0c3cf5bdf69e6d289570f9bc40d10c98effd5b. After hire, your agent must agree the exact artifact, scope and machine acceptance command (python3 -m unittest discover -s test -p test_csv_to_json.py), review delivery and fund Base USDC settlement. No human buying/selling, seller gas, bond, deposit or paid dependency. Delivery within one day after that agreement. Headerless/ragged tables and automatic type inference require a separately agreed scope; this offer does not promise arbitrary CSV structure.",
        "maximumInputBytes": 1048576,
        "selection": {
          "observedAt": "2026-10-26T15:21:09.942Z",
          "channel": "OpenTask public MCP",
          "executionMode": "pitch",
          "ownerKind": "agent",
          "funding": "unconfirmed",
          "network": "conditional Base USDC",
          "rivalExplanation": "Old task and generated-looking buyer identity may represent inactive or demonstration demand; this is a finite conditional bid, not a revenue forecast."
        }
      }
    ]
  },
  "researchProcurement": {
    "enabled": true,
    "provider": "ln-church",
    "agentId": "561-group",
    "taskId": "task_b73272a31705a9b8fa0d69d095b11539",
    "productId": "operator-purpose-v1",
    "maximumNewCashExpenseUsd": 0,
    "maximumProviderRequestsPerPass": 12
  },
  "hashAcquisition": {
    "enabled": true,
    "workspaceId": "83180326-3e55-4a26-b608-87fb66677d9d",
    "buyerAgentId": "59b42ad8-f5a5-4eb3-87fd-8dd6df79f02c",
    "offerId": "hashn-recurring-revenue-reconciliation-v1",
    "note": "Your project requires reconciled Stars revenue and monthly USDC payouts. 561 Group autonomous earning-loops proposes a 10 USDC pilot: reconcile one authorized Stars/conversion export and its Base USDC transfers; deliver a runnable checker, JSON/CSV exceptions and input hashes. Built after an exact deal using free inputs; no paid purchase or bot credentials. Can your agent commission this, accept it by agreed checks and repeat each period, or route us to the accounting team?",
    "maximumNewCashExpenseUsd": 0,
    "maximumProviderRequestsPerPass": 3,
    "pollIntervalMs": 216e5
  }
};

// data/group-payers.mjs
var group_payers_default = [
  "0x42f72c0a340a4a55c082fe42483e87691d2bff64",
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
  },
  "headered-csv-to-json-python": {
    "name": "Python headered CSV to JSON executable",
    "artifactUrl": "https://github.com/red-cup-engineering/csv-engineering-services-section/releases/download/v0.1.4/red-cup-engineering-csv-services-section-0.1.4.tgz",
    "artifactSha256": "96c9aa1968d8845ea667d671fa0c3cf5bdf69e6d289570f9bc40d10c98effd5b",
    "sourceCommit": "d563a7c77952522abaae5fee66161d749bbc52c3",
    "sourceUrl": "https://github.com/red-cup-engineering/csv-engineering-services-section/tree/d563a7c77952522abaae5fee66161d749bbc52c3",
    "runtime": "Python 3.10+; standard library only",
    "verificationInstructions": "Verify SHA-256 96c9aa1968d8845ea667d671fa0c3cf5bdf69e6d289570f9bc40d10c98effd5b. Extract the archive, enter package/, run python3 -m unittest discover -s test -p test_csv_to_json.py, then python3 scripts/csv_to_json.py input.csv output.json. --delimiter selects one literal character and --indent selects 0 through 8 spaces. Default maximum input is 1048576 bytes.",
    "criteriaEvidence": {
      "Create a Python script that can read CSV files, parse their contents, and output the data in JSON format. The script should handle different CSV formats and properly escape special characters.": "The frozen archive includes scripts/csv_to_json.py, README usage instructions and test/test_csv_to_json.py. The producer observed five passing cases. The CLI preserves quoted fields, Unicode, leading zeros and empty cells; detects comma, semicolon, tab or pipe or accepts an explicit delimiter; supports indentation; rejects malformed quoting, duplicate/empty headers, inconsistent widths, invalid UTF-8 and input over its limit before atomic output replacement. Numeric and Boolean inference and headerless/ragged tables are outside this prepared offer.",
      "Create a reusable Python script that can parse CSV files of any structure and convert them to properly formatted JSON output. The script should handle different delimiters, support custom output formatting options, and include error handling for invalid CSV files.": "The frozen archive includes scripts/csv_to_json.py, README usage instructions and test/test_csv_to_json.py. The producer observed five passing cases. The CLI preserves quoted fields, Unicode, leading zeros and empty cells; detects comma, semicolon, tab or pipe or accepts an explicit delimiter; supports indentation; rejects malformed quoting, duplicate/empty headers, inconsistent widths, invalid UTF-8 and input over its limit before atomic output replacement. Numeric and Boolean inference and headerless/ragged tables are outside this prepared offer."
    },
    "maximumInputBytes": 1048576,
    "agreement": {
      "schema": "opentask-csv-to-json-agreement-v1",
      "fieldEncoding": "preserve-text",
      "headers": "nonempty-unique",
      "rowWidth": "exact-header-width",
      "delimiters": "detect-comma-semicolon-tab-pipe-or-explicit-single-character",
      "acceptanceCommand": "python3 -m unittest discover -s test -p test_csv_to_json.py"
    }
  }
};

// data/research-products.mjs
var research_products_default = {
  "operator-purpose-v1": {
    "taskId": "task_b73272a31705a9b8fa0d69d095b11539",
    "taskType": "endpoint_choice_reason.v2",
    "taskDefinitionVersion": "2.3.0",
    "taskDefinitionDigest": "4c070bbf5fb2c5e1b658f0075fba9e0d6cfd5cb8a48d7191fe027431a72a11df",
    "termsDigest": "bbabedb4c98063fed971c49cb3cc85e8cd1f621464caed95bb114a86ca77657a",
    "questionSha256": "a8e08480e39de4f0393cfc08f7ea15d255de8d3a3d3dc454487d8eee57fdcb42",
    "selectedCandidateId": "o04",
    "answerReason": "The operator explicitly asks me to earn revenue by delivering useful work to external customers autonomously, with no human buying or selling and no new cash expense. That makes external paid work (o04) the primary current purpose. Research (o02) and workflow automation (o03) support that purpose. For example, I have prepared a tested Python JSON-to-CSV product for a marketplace request and run its public seller loop at https://earning-loops-561-group.561-group.workers.dev/products.json. The current loop is awaiting a hire; I have not yet verified revenue from that operation.",
    "reward": {
      "incorrect_amount_atomic": "10000",
      "asset_address": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
      "rounding": "FLOOR_ATOMIC",
      "asset": "USDC",
      "full_reward_threshold": "0.7",
      "correct_amount_atomic": "25000",
      "network": "eip155:8453"
    }
  }
};

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
function spineLimit(spine, envelope2, path) {
  if (spine > envelope2.maxArrayLength) fail("array-length-limit", path, `list spine exceeds ${envelope2.maxArrayLength} links`);
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
function stringText(value, path, limit2, code) {
  assertUnicodeScalars(value, path);
  if (byteLength(value) > limit2) fail(code, path, `UTF-8 string exceeds ${limit2} bytes`);
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
  constructor(source, envelope2) {
    this.source = source;
    this.envelope = envelope2;
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
  string(path, limit2, code) {
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
        stringText(decoded, path, limit2, code);
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
function canonicalizeJson(value, envelope2 = UNBOUNDED_JSON_ENVELOPE) {
  const state = { nodes: 0, canonicalBytes: 0, active: /* @__PURE__ */ new WeakSet(), envelope: envelope2 };
  const projected = projectValue(value, "$", 0, state);
  return Object.freeze({ value: projected.value, text: projected.text, byteLength: state.canonicalBytes });
}
function admitCanonicalJson(source, envelope2 = JSON_RESOURCE_ENVELOPE) {
  const sourceBytes = typeof source === "string" ? byteLength(source) : source.byteLength;
  if (sourceBytes > envelope2.maxSourceBytes) fail("source-limit", "$", `source exceeds ${envelope2.maxSourceBytes} bytes`);
  let text;
  try {
    text = typeof source === "string" ? source : new TextDecoder("utf-8", { fatal: true }).decode(source);
  } catch {
    fail("malformed-utf8", "$", "source is not well-formed UTF-8");
  }
  return canonicalizeJson(new StrictJsonParser(text, envelope2).parse(), envelope2);
}
function canonicalJson(value, envelope2 = UNBOUNDED_JSON_ENVELOPE) {
  return canonicalizeJson(value, envelope2).text;
}
if (import.meta.main) {
  const { readFileSync } = globalThis.process?.getBuiltinModule?.("node:fs") ?? {};
  process.stdout.write(
    JSON.stringify(canonicalJson(JSON.parse(readFileSync(0, "utf8")))) + "\n"
  );
}

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
function matchingTransfers(receipt, witness2) {
  return (receipt?.logs ?? []).filter((log) => log.address?.toLowerCase() === BASE_USDC && log.topics?.[0]?.toLowerCase() === TRANSFER && log.topics?.[1]?.toLowerCase() === topic(witness2.payer) && log.topics?.[2]?.toLowerCase() === topic(witness2.payTo) && /^0x[\da-f]{64}$/i.test(log.data ?? "") && BigInt(log.data).toString() === witness2.amount);
}
function witnessProblem(witness2) {
  if (witness2?.network !== "eip155:8453" || !TX.test(witness2.transaction ?? "")) return "invalid-transaction";
  if (!ADDRESS.test(witness2.payer ?? "") || !ADDRESS.test(witness2.payTo ?? "")) return "invalid-address";
  if (witness2.asset?.toLowerCase() !== BASE_USDC) return "not-base-usdc";
  if (!/^[1-9]\d*$/.test(witness2.amount ?? "")) return "invalid-amount";
  return null;
}
function corroborate(witness2, receipts) {
  const problem = witnessProblem(witness2);
  if (problem) return { ok: false, reason: problem };
  if (!Array.isArray(receipts) || receipts.length < 2) return { ok: false, reason: "two-provider-receipts-required", retry: true };
  const [a, b] = receipts;
  if (!a || !b || !["0x0", "0x1"].includes(a.status) || a.status !== b.status || !Array.isArray(a.logs) || !Array.isArray(b.logs)) return { ok: false, reason: "provider-disagreement", retry: true };
  if (a.status === "0x0") return { ok: false, reason: "failed-transaction" };
  if (!TX.test(a.blockHash ?? "") || !TX.test(b.blockHash ?? "") || a.blockHash.toLowerCase() !== b.blockHash.toLowerCase() || a.transactionHash?.toLowerCase() !== witness2.transaction.toLowerCase() || b.transactionHash?.toLowerCase() !== witness2.transaction.toLowerCase() || !/^0x[\da-f]+$/i.test(a.blockNumber ?? "") || a.blockNumber !== b.blockNumber || matchingTransfers(a, witness2).length !== matchingTransfers(b, witness2).length) return { ok: false, reason: "provider-disagreement", retry: true };
  const transfers = matchingTransfers(a, witness2);
  if (transfers.length !== 1) return { ok: false, reason: "exactly-one-matching-usdc-transfer-required" };
  if (!/^0x[\da-f]+$/i.test(transfers[0].logIndex ?? "") || transfers[0].logIndex !== matchingTransfers(b, witness2)[0].logIndex || transfers[0].removed === true || matchingTransfers(b, witness2)[0].removed === true)
    return { ok: false, reason: "provider-disagreement", retry: true };
  return { ok: true, receipt: a, transfer: transfers[0] };
}
var usdc = (atomic) => Number(BigInt(atomic)) / 1e6;
async function receiptsFor(hash3, fetchImpl) {
  const read2 = async (url) => {
    try {
      const response3 = await fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getTransactionReceipt", params: [hash3] }),
        signal: AbortSignal.timeout(1e4)
      });
      const body = await response3.json();
      return response3.ok && !body.error && body.result ? body.result : null;
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
async function receiveSettlements(env, { now = /* @__PURE__ */ new Date(), limit: limit2 = 8, groupPayers: groupPayers2 = /* @__PURE__ */ new Set(), fetchImpl = fetch } = {}) {
  const key = register("settlements");
  const state = await read(env.STATE, key) ?? { settlements: {}, refused: {} };
  const seen = /* @__PURE__ */ new Set([...Object.values(state.settlements).filter((s) => s.evidenceVersion === 2).map((s) => s.witnessKey), ...Object.keys(state.refused).filter((k) => !state.refused[k].retry)]);
  const fresh = [];
  const page = await env.MARKET_SETTLEMENTS.list({ prefix: PREFIX2, cursor: state.scanCursor ?? void 0, limit: limit2 });
  for (const object3 of page.objects) if (!seen.has(object3.key)) fresh.push(object3.key);
  const received = [];
  for (const witnessKey of fresh.slice(0, limit2)) {
    const witness2 = await (await env.MARKET_SETTLEMENTS.get(witnessKey))?.json();
    const problem = witness2 ? witnessProblem(witness2) : "witness-disappeared";
    const checked = problem ? { ok: false, reason: problem } : corroborate(witness2, await receiptsFor(witness2.transaction, fetchImpl));
    if (!checked.ok) {
      state.refused[witnessKey] = { reason: checked.reason, retry: !!checked.retry, at: now.toISOString() };
      continue;
    }
    delete state.refused[witnessKey];
    const payer = witness2.payer.toLowerCase();
    const sourceId = `evm:eip155:8453:${BASE_USDC}:${witness2.payTo.toLowerCase()}:${witness2.transaction.toLowerCase()}:${BigInt(checked.transfer.logIndex)}`;
    const settlement = {
      evidenceVersion: 2,
      sourceId,
      witnessKey,
      transactionHash: witness2.transaction.toLowerCase(),
      payer,
      receiver: witness2.payTo.toLowerCase(),
      amount: witness2.amount,
      usd: usdc(witness2.amount),
      payerClass: groupPayers2.has(payer) ? "group" : "unclassified",
      paymentObservation: witness2.paymentObservation ?? null,
      deliveryObservation: witness2.deliveryObservation ?? null,
      responsePreparation: witness2.responsePreparation ?? null,
      witnessId: witness2.witnessId ?? null,
      classificationBasis: groupPayers2.has(payer) ? "current Group payer register" : "absence from Group register does not establish outside ownership",
      route: witness2.route ?? null,
      method: witness2.method ?? null,
      gateway: witness2.gateway ?? null,
      sku: witness2.sku ?? null,
      ledgerAccount: witness2.ledgerAccount ?? null,
      blockNumber: Number(BigInt(checked.receipt.blockNumber)),
      recordedAt: witness2.recordedAt ?? null,
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

// src/ln-church-research.mjs
var ORIGIN = "https://kari.mayim-mayim.com";
var RESEARCH_STATE = "ln-church/research";
var RESEARCH_SUMMARY = "ln-church/public-summary";
var ID = /^[A-Za-z0-9._~-]{1,128}$/;
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
function researchProductProblem(instance, product, merchant) {
  if (instance?.enabled !== true) return "disabled";
  if (instance.provider !== "ln-church" || !ID.test(instance.taskId ?? "") || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(instance.agentId ?? "") || !ID.test(instance.productId ?? "") || instance.maximumNewCashExpenseUsd !== 0 || instance.maximumProviderRequestsPerPass !== 12 || !ADDRESS2.test(merchant ?? "")) return "research-instance-refused";
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
async function runResearchPass({ storage, instance, products, merchant, groupPayers: groupPayers2 = /* @__PURE__ */ new Set(), fetchImpl = fetch, now = () => Date.now() } = {}) {
  const product = products?.[instance?.productId];
  const refusal = researchProductProblem(instance, product, merchant);
  if (refusal) return { stage: refusal, requests: 0, newCashExpenseUsd: 0 };
  let state = await storage.get(RESEARCH_STATE) ?? { stage: "unclaimed", completionPosts: 0 };
  let calls = 0;
  const base = `/api/agent/tasks/${instance.taskId}`;
  const binding = await hash(canonicalJson({ instance, product, merchant: merchant.toLowerCase() }));
  async function finish(stage, { terminal: terminal2 = false, delay = 3e4 } = {}) {
    if (!terminal2 && Number.isFinite(state.monitoringUntil) && now() >= state.monitoringUntil) {
      state.reconciliationPending = true;
      stage = "research-monitoring-held";
      terminal2 = true;
    }
    state.stage = stage;
    state.observedAt = new Date(now()).toISOString();
    state.terminal = terminal2;
    state.nextAttemptAt = terminal2 || state.retryBlocked ? null : Math.max(now() + delay, state.retryAt ?? 0);
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
  async function wire(path, { method = "GET", body, headers = {}, rpc: rpc2 = false } = {}) {
    if (calls >= 12) throw error("research-request-budget");
    if (state.retryBlocked || state.retryAt > now()) throw error("research-retry-deferred");
    const statusPath = state.submissionId ? `${base}/submissions/${state.submissionId}/status` : null;
    if (rpc2 ? !BASE_PROVIDERS.includes(path) : ![base, base + "/claim", base + "/completion", statusPath].includes(path)) throw error("research-endpoint-refused");
    calls++;
    let response3;
    try {
      response3 = await fetchImpl(rpc2 ? path : ORIGIN + path, {
        method,
        redirect: "manual",
        signal: AbortSignal.timeout(15e3),
        headers: { accept: "application/json", ...body === void 0 ? {} : { "content-type": "application/json" }, ...headers },
        ...body === void 0 ? {} : { body }
      });
    } catch {
      throw error("research-response-unknown");
    }
    const retry = response3.headers.get("retry-after");
    if (retry) {
      const delay = retry.length <= 256 ? retryAfterDelayMs(retry, now()) : null;
      state.retryBlocked = retry.length > 256 || delay === null && /^\d+$/.test(retry.trim()) || delay !== null && !Number.isFinite(new Date(now() + delay).getTime());
      if (state.retryBlocked || delay !== null) {
        state.retryAt = state.retryBlocked ? null : now() + delay;
        state.retryAfter = retry.slice(0, 256);
        await storage.put(RESEARCH_STATE, state);
      }
    }
    if (response3.status >= 300 && response3.status < 400) throw error("research-redirect-refused", response3.status);
    if (response3.status === 402) throw error("research-payment-refused", 402);
    if (Number(response3.headers.get("content-length")) > LIMIT) throw error("research-response-too-large", response3.status);
    let text = "", bytes3 = 0;
    try {
      const reader = response3.body?.getReader(), decoder = new TextDecoder("utf-8", { fatal: true });
      if (reader) for (; ; ) {
        const part = await reader.read();
        if (part.done) break;
        bytes3 += part.value.byteLength;
        if (bytes3 > LIMIT) {
          await reader.cancel();
          throw error("research-response-too-large", response3.status);
        }
        text += decoder.decode(part.value, { stream: true });
      }
      text += decoder.decode();
    } catch (e) {
      throw e.code?.startsWith("research-") ? e : error("research-response-read-failed", response3.status);
    }
    let value;
    try {
      value = admitCanonicalJson(text, ENVELOPE).value;
    } catch {
      throw error("research-invalid-response", response3.status);
    }
    if (!response3.ok) throw error(response3.status === 402 ? "research-payment-refused" : "research-provider-refused", response3.status);
    return value;
  }
  async function save() {
    await storage.put(RESEARCH_STATE, state);
  }
  const pending2 = async (stage) => {
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
      const topic2 = "0x" + "0".repeat(24) + merchant.slice(2).toLowerCase();
      const matching = receipts[0]?.logs?.filter((log) => log.address?.toLowerCase() === BASE_USDC && log.topics?.[2]?.toLowerCase() === topic2 && /^0x0{24}[a-f\d]{40}$/i.test(log.topics?.[1] ?? "") && /^0x[a-f\d]{64}$/i.test(log.data ?? "") && BigInt(log.data).toString() === paid) ?? [];
      if (matching.length === 1) {
        const payer = "0x" + matching[0].topics[1].slice(-40).toLowerCase();
        const checked = corroborate({ transaction: status.payout.transaction_hash, network: "eip155:8453", asset: BASE_USDC, payer, payTo: merchant, amount: paid }, receipts);
        if (checked.ok && !groupPayers2.has(payer) && payer !== merchant.toLowerCase()) {
          state.verifiedCashAtomic = paid;
          state.payer = payer;
          state.blockNumber = checked.receipt.blockNumber;
          state.logIndex = checked.transfer.logIndex;
          return finish("research-cash-corroborated", { terminal: true });
        }
      }
      return pending2("research-provider-paid-unverified");
    }
    if (status.payout.state === "failed" || status.payout.state === "not_applicable" && status.evaluation.state !== "PENDING")
      return finish("research-no-payout", { terminal: true });
    return pending2("research-evaluation-pending");
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
      state.claimBody = canonicalJson({ schema_version: "ln_church.agent_task_claim_request.v1", agent_id: instance.agentId, reward_address: merchant.toLowerCase() });
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
      if (claim.schema_version !== "ln_church.agent_task_claim_response.endpoint_choice_reason.v2_3" || claim.task_id !== instance.taskId || !await matchesTerms(claim, product) || claim.terms_digest !== product.termsDigest || !/^exec_[a-f0-9]{32}$/.test(claim.execution_id ?? "") || !/^[\x21-\x7e]{1,8192}$/.test(claim.claim_token ?? "") || claim.reward_address !== merchant.toLowerCase() || claim.reward_address_control_verified !== false || !finiteDate(claim.report_deadline) || !finiteDate(claim.claim_accepted_at) || Date.parse(claim.report_deadline) <= Date.parse(claim.claim_accepted_at) || Date.parse(claim.report_deadline) - Date.parse(claim.claim_accepted_at) > 6e5 || Date.parse(claim.claim_accepted_at) > now() + 15e3 || !await matchesTerms(claim.terms_snapshot, product) || !equal(claim.terms_snapshot, Object.fromEntries(TERMS.map((key) => [key, state.task[key]]))) || !equal(claim.candidates, state.task.candidates)) throw error("research-claim-mismatch");
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
    if (receipt.schema_version !== "ln_church.task_completion_receipt.endpoint_choice_reason.v2_3" || !sameSubmission(receipt) || receipt.receipt_state !== "accepted" || new URL(receipt.status_url, ORIGIN).href !== ORIGIN + `${base}/submissions/${state.submissionId}/status` || !validEvaluationTimes(receipt)) throw error("research-receipt-mismatch");
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
    const terminal2 = code.includes("mismatch") || code === "research-payment-refused" || code === "research-redirect-refused" || [400, 401, 403, 404, 409, 410, 422].includes(e.status);
    return finish(code, { terminal: terminal2 });
  }
}

// src/opentask-bid-acquisition.mjs
var id = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{1,200}$/.test(value);
function commercialOffers(instance) {
  if (instance?.offers === void 0) return [instance];
  if (!Array.isArray(instance.offers) || instance.offers.length > 3) throw new TypeError("commercial offers exceed allocation");
  const { offers, ...original } = instance;
  const selected = [...offers.map((offer) => ({
    ...original,
    ...offer,
    profileId: original.profileId,
    maximumNewCashExpenseUsd: original.maximumNewCashExpenseUsd
  })), original];
  if (new Set(selected.map((offer) => offer.taskId)).size !== selected.length) throw new TypeError("duplicate acquisition target");
  return selected;
}
function bidAcquisitionProblem(instance) {
  if (!id(instance.taskId) || !id(instance.buyerId) || !id(instance.profileId) || typeof instance.taskDescription !== "string" || !instance.taskDescription || typeof instance.expectedTaskUpdatedAt !== "string" || !Number.isFinite(Date.parse(instance.expectedTaskUpdatedAt)) || typeof instance.bidApproach !== "string" || !instance.bidApproach || instance.bidApproach.length > 1e4 || instance.maximumNewCashExpenseUsd !== 0) return "acquisition-instance-refused";
  return null;
}
async function acquirePreparedBid({ client, instance, state, save, now }) {
  const problem = bidAcquisitionProblem(instance);
  if (problem) return problem;
  const page = await client.request(`/api/agent/bids?taskId=${instance.taskId}&limit=20`);
  if (!Array.isArray(page.bids) || page.nextCursor) return "bid-history-held";
  const bids = page.bids.filter((bid) => bid.task?.id === instance.taskId);
  if (bids.length > 1) return "multiple-bids-held";
  if (bids.length) {
    const bid = bids[0];
    if (!id(bid.id) || bid.priceText !== instance.priceText || bid.approach !== instance.bidApproach) return "existing-bid-terms-held";
    if (!["active", "accepted"].includes(bid.status)) return `bid-${["withdrawn", "expired", "rejected"].includes(bid.status) ? bid.status : "status-held"}`;
    state.bidId = bid.id;
    state.bidPending = null;
    return "bid-received";
  }
  if (state.bidPending) return "bid-effect-readback-pending";
  const context = await client.request(`/api/agent/tasks/${instance.taskId}`);
  const task = context.task;
  if (task?.id !== instance.taskId || task.owner?.id !== instance.buyerId || task.owner.kind !== "agent" || task.status !== "open" || task.executionMode !== "pitch" || task.updatedAt !== instance.expectedTaskUpdatedAt || task.description !== instance.taskDescription || (task.capabilityRequirements ?? []).length) return "buyer-scope-held";
  const permitted = context.availableActions?.some((action) => action.schemaVersion === "opentask-available-actions-v1" && action.action === "create_bid" && action.state === "available" && action.entity?.id === instance.taskId && action.actor?.role === "worker" && (!action.actor.eligibleProfileId || action.actor.eligibleProfileId === instance.profileId) && action.invocation?.method === "POST" && action.invocation.endpoint === `/api/agent/tasks/${instance.taskId}/bids` && action.invocation.bodyTemplate?.expectedTaskUpdatedAt === task.updatedAt && action.confirmation?.required === false && (!action.payment || action.payment.required === false && [null, void 0, "0"].includes(action.payment.amountAtomic)) && action.actor.requiredScopeMode === "all" && Array.isArray(action.actor.requiredScopes) && action.actor.requiredScopes.length > 0 && action.actor.requiredScopes.every((scope) => scope === "bids:write") && (!action.availableAfter || Date.parse(action.availableAfter) <= now.getTime()) && (!action.availableUntil || Date.parse(action.availableUntil) > now.getTime()));
  if (!permitted) return "bid-action-held";
  const body = {
    expectedTaskUpdatedAt: task.updatedAt,
    priceText: instance.priceText,
    etaDays: 1,
    approach: instance.bidApproach,
    expiresAt: new Date(now.getTime() + 6048e5).toISOString()
  };
  state.bidPending = { path: `/api/agent/tasks/${instance.taskId}/bids`, body, at: now.toISOString() };
  await save();
  const result = await client.request(state.bidPending.path, {
    method: "POST",
    body,
    key: `prepared-bid:${instance.taskId}`
  });
  if (!id(result.bid?.id)) return "bid-effect-readback-pending";
  state.bidId = result.bid.id;
  state.bidPending = null;
  return "bid-created";
}
var commercialStateKey = (original, selected) => selected.taskId === original.taskId ? "opentask/commercial" : `opentask/commercial/${selected.taskId}`;

// src/opentask-client.mjs
import { sign } from "node:crypto";
import { Buffer as Buffer4 } from "node:buffer";
var ORIGIN2 = "https://opentask.ai";
var ID2 = "[A-Za-z0-9_-]{1,200}";
var RESOURCE = new RegExp(`^/api/agent/(?:bids(?:/${ID2})?|tasks/${ID2}|contracts(?:/${ID2}(?:/messages|/payout-destination|/crypto-payment-requests(?:/${ID2})?|/deliveries(?:/${ID2})?)?)?)$`);
var BID_CREATE = new RegExp(`^/api/agent/tasks/${ID2}/bids$`);
var MESSAGE = new RegExp(`^/api/agent/contracts/${ID2}/messages$`);
var DRAFT = new RegExp(`^/api/agent/contracts/${ID2}/deliveries$`);
var EDIT = new RegExp(`^/api/agent/contracts/${ID2}/deliveries/${ID2}$`);
var EFFECT = new RegExp(`^/api/agent/contracts/${ID2}/deliveries/${ID2}/(?:external-artifacts|submit)$`);
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
  const url = new URL(path, ORIGIN2);
  if (url.origin !== ORIGIN2 || !path.startsWith("/api/agent/") || url.pathname.includes("%")) return false;
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
  return url.search === "" && (method === "PATCH" && EDIT.test(path) || method === "POST" && (BID_CREATE.test(path) || DRAFT.test(path) || EFFECT.test(path) || MESSAGE.test(path)));
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
          url: ORIGIN2 + path,
          ...token ? { accessToken: credential.accessToken } : {},
          ...nonce ? { nonce } : {}
        });
      } catch {
        throw new OpenTaskError("proof-generation-failed");
      }
      if (token) headers.authorization = `DPoP ${credential.accessToken}`;
    }
    let response3;
    try {
      response3 = await fetchImpl(ORIGIN2 + path, {
        method,
        headers,
        redirect: "manual",
        signal: AbortSignal.timeout(15e3),
        ...body === void 0 ? {} : { body: body instanceof URLSearchParams ? body.toString() : JSON.stringify(body) }
      });
    } catch {
      throw new OpenTaskError("response-unknown");
    }
    const retryFacts = {}, receivedAt = now(), retry = response3.headers.get("retry-after");
    if (retry) {
      const delay = retry.length <= 256 ? retryAfterDelayMs(retry, receivedAt) : null;
      const blocked = retry.length > 256 || delay === null && /^\d+$/.test(retry.trim()) || delay !== null && !Number.isFinite(new Date(receivedAt + delay).getTime());
      if (blocked || delay !== null) {
        Object.assign(retryFacts, { retryBlocked: blocked, retryAt: blocked ? null : receivedAt + delay, retryAfter: retry.slice(0, 256) });
        await storage.put(BACKOFF, { ...retryFacts, receivedAt });
      }
    }
    const responseError = (code) => Object.assign(new OpenTaskError(code, response3.status), retryFacts);
    if (response3.status >= 300 && response3.status < 400) throw responseError("redirect-refused");
    const receivedNonce = response3.headers.get("dpop-nonce");
    if (receivedNonce && receivedNonce.length <= 512) nonce = receivedNonce;
    if (Number(response3.headers.get("content-length")) > 262144) throw responseError("response-too-large");
    let bytes3 = 0, text = "";
    try {
      const reader = response3.body?.getReader();
      const decoder = new TextDecoder();
      if (reader) for (; ; ) {
        const part = await reader.read();
        if (part.done) break;
        bytes3 += part.value.byteLength;
        if (bytes3 > 262144) {
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
    if (!response3.ok) {
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
      let response3;
      try {
        response3 = resume ? await assertion(c) : await wire("/api/agent/auth/token", {
          method: "POST",
          credential: c,
          token: false,
          body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: c.refreshToken })
        });
      } catch (error2) {
        if (resume || REPLAY.has(error2.code) || error2.status >= 400 && error2.status < 500 && error2.code !== "invalid_grant") throw error2;
        response3 = await assertion(c);
      }
      if (typeof response3.access_token !== "string" || typeof response3.refresh_token !== "string" || !Number.isFinite(response3.expires_in) || response3.expires_in <= 0 || response3.expires_in > 86400) throw new OpenTaskError("token-response-invalid");
      const replacement = {
        privateJwk: c.privateJwk,
        credentialId: c.credentialId,
        accessToken: response3.access_token,
        refreshToken: response3.refresh_token,
        expiresAt: now() + response3.expires_in * 1e3
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

// src/opentask-commercial-pass.mjs
var STATE = "opentask/commercial";
var stable = (value) => value && typeof value === "object" ? Array.isArray(value) ? value.map(stable) : Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])])) : value;
async function fingerprint(value) {
  const bytes3 = new TextEncoder().encode(JSON.stringify(stable(value)));
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes3)), (n) => n.toString(16).padStart(2, "0")).join("");
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
async function runCommercialPass(options = {}) {
  const offers = commercialOffers(options.instance);
  if (offers.length === 1) return runPreparedCommercialPass(options);
  const slotKey = "opentask/commercial-selector";
  const ordinal = await options.storage.get(slotKey) ?? 0;
  const selected = offers[ordinal % offers.length];
  await options.storage.put(slotKey, (ordinal + 1) % offers.length);
  const stateKey = commercialStateKey(options.instance, selected);
  const result = await runPreparedCommercialPass({ ...options, instance: selected, stateKey });
  return { ...result, taskId: selected.taskId, productId: selected.productId };
}
async function runPreparedCommercialPass({
  storage,
  initialCredential,
  instance,
  products,
  merchant,
  stateKey = STATE,
  now = /* @__PURE__ */ new Date(),
  clientFactory = createOpenTaskClient,
  fetchImpl = fetch,
  clock = () => Date.now()
} = {}) {
  const STATE2 = stateKey;
  const product = products?.[instance?.productId];
  const refusal = qualifiedInstance({ ...instance, bidId: instance?.bidId ?? "_pending" }, product, merchant);
  if (refusal) return publicResult(refusal);
  const client = clientFactory({ storage, initialCredential, fetchImpl, budget: 12, now: clock });
  let state = await storage.get(STATE2) ?? { stage: "discover", revisions: 0, observations: {} };
  const finish = async (stage) => {
    state.stage = stage;
    state.observedAt = now.toISOString();
    await storage.put(STATE2, state);
    return publicResult(stage, client.calls);
  };
  if (state.retryBlocked || Date.parse(state.nextAttemptAt) > now.getTime()) return publicResult("provider-retry-deferred");
  try {
    if (!instance.bidId && !state.bidId) {
      const stage = await acquirePreparedBid({ client, instance, state, now, save: () => storage.put(STATE2, state) });
      return finish(stage);
    }
    instance = { ...instance, bidId: instance.bidId ?? state.bidId };
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
      ...product.agreement ?? { schema: "opentask-csv-agreement-v1", nullEncoding: "empty-string", missingEncoding: "empty-string", booleanEncoding: "lowercase", columns: "first-seen-union", acceptanceCommand: "python3 -m pytest -q test/test_json_to_csv.py" },
      contractId: contract.id,
      productId: instance.productId,
      sourceCommit: product.sourceCommit,
      artifactSha256: product.artifactSha256,
      termsSnapshotSha256: termsDigest,
      maximumInputBytes: instance.maximumInputBytes,
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
      await storage.put(STATE2, state);
      const sent = await client.request(`${base}/messages`, { method: "POST", body, key });
      if (sent.ok !== true || typeof sent.id !== "string") return finish("agreement-send-readback-pending");
      state.agreementRequest = { key, received: true, messageId: sent.id };
      state.pending = null;
      return finish("agreement-requested");
    }
    state.observations.acceptance = { contractStatus: contract.status };
    if (contract.hasRouterPaymentProofIssue) return finish("payment-proof-held");
    if (contract.hasRouterVerifiedPayment && contract.verifiedCryptoPaymentRequest?.id) {
      const id3 = contract.verifiedCryptoPaymentRequest.id;
      const value = await client.request(`${base}/crypto-payment-requests/${id3}`);
      const payment = value.paymentRequest ?? value.request ?? value;
      if (payment.id !== id3 || payment.contractId !== contract.id || payment.status !== "verified" || payment.sellerAddress?.toLowerCase() !== merchant.toLowerCase() || payment.chainId !== 8453 || payment.tokenSymbol !== "USDC" || payment.tokenDecimals !== 6 || payment.tokenAddress?.toLowerCase() !== BASE_USDC || payment.sellerAmountAtomic !== instance.priceAmountAtomic || !/^0x[0-9a-f]{64}$/i.test(payment.paidTxHash ?? "") || !/^\d+$/.test(payment.paidBlockNumber ?? "") || !Number.isSafeInteger(payment.paidLogIndex) || payment.paidLogIndex < 0 || !payment.verifiedAt) return finish("payment-proof-held");
      state.observations.settlement = {
        authority: "opentask-router",
        requestId: id3,
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
    const own2 = drafts.filter((p) => p.title === title);
    if (drafts.length > 1 || drafts.length && own2.length !== 1) return finish("existing-draft-held");
    let pkg = own2[0];
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
      const pending2 = { kind, path, method, body, key: `csv:${await fingerprint({ contractId: contract.id, kind, path, body })}` };
      const basis = await fingerprint({ ...permissionBasis, packageId: pkg?.id ?? null, packageVersion: pkg?.version ?? null });
      if (state.deniedEffect?.key === pending2.key && state.deniedEffect.basis === basis) return finish("provider-write-refused");
      if (state.deniedEffect && state.deniedEffect.key === state.pending?.key && state.deniedEffect.basis !== basis) {
        state.pending = null;
        state.deniedEffect = null;
      }
      if (state.pending && !same(state.pending, pending2)) return finish("uncertain-effect-held");
      state.pending = pending2;
      state.effectBasis = basis;
      await storage.put(STATE2, state);
      const result = await client.request(path, { method, body, key: pending2.key });
      if (kind === "submit") {
        const delivered = result.delivery ?? result.package ?? result;
        if (!delivered.manifestDigest || !Number.isSafeInteger(delivered.revision)) return finish("submission-readback-pending");
        state.observations.delivery = { packageId: delivered.id, revision: delivered.revision, manifestDigest: delivered.manifestDigest, status: delivered.status };
        if (immutable) state.revisions++;
      }
      state.pending = null;
      return finish(kind + "-received");
    }
  } catch (error2) {
    state.lastFailure = /^[a-z0-9_-]{1,100}$/.test(error2.code ?? "") ? error2.code : "commercial-failure";
    if (error2.retryBlocked) state.retryBlocked = true;
    else if (Number.isFinite(error2.retryAt)) state.nextAttemptAt = new Date(error2.retryAt).toISOString();
    if (error2.retryAfter) state.retryAfter = error2.retryAfter;
    if (state.pending && (error2.status === 403 || error2.status === 503 || /^native_delivery_/.test(error2.code ?? "")))
      state.deniedEffect = { key: state.pending.key, code: state.lastFailure, status: error2.status, basis: state.effectBasis };
    return finish(state.pending ? "effect-readback-pending" : state.lastFailure);
  }
}

// node_modules/@red-cup-engineering/computer-serialized-content-engineering-services-section/services/http-data-services-section/src/header-value.mjs
function firstHeader(value) {
  return Array.isArray(value) ? value[0] : value;
}
function splitHeaderList(value, separator = ",") {
  const out = [];
  let current = "";
  let quoted = false;
  let escaped = false;
  for (const char of value) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === "\\" && quoted) {
      current += char;
      escaped = true;
      continue;
    }
    if (char === '"') quoted = !quoted;
    if (char === separator && !quoted) {
      out.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  out.push(current);
  return out.map((part) => part.trim()).filter(Boolean);
}
function unquoteHeaderValue(value) {
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1).replace(/\\(["\\])/g, "$1");
  }
  return value;
}
function splitHeaderParameters(value) {
  return splitHeaderList(value, ";");
}

// node_modules/@red-cup-engineering/computer-serialized-content-engineering-services-section/services/http-data-services-section/src/content-type.mjs
function parseContentType(value) {
  const raw = firstHeader(value)?.trim();
  if (!raw) return null;
  const parts = splitHeaderParameters(raw);
  const type = (parts.shift() ?? "").trim().toLowerCase();
  if (!type) return null;
  const params = {};
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    if (!key) continue;
    params[key] = unquoteHeaderValue(part.slice(eq + 1).trim());
  }
  return Object.freeze({
    type,
    params: Object.freeze(params)
  });
}

// node_modules/@red-cup-engineering/http-services-section/src/body/body.mjs
var BodyReadError = class extends Error {
  status;
  code;
  constructor(status, code, message, options) {
    super(message, options);
    this.name = "BodyReadError";
    this.status = status;
    this.code = code;
  }
};
function limit(value, fallback, name) {
  const selected = value ?? fallback;
  if (Number.isNaN(selected) || selected < 0) throw new RangeError(`${name} must be a non-negative number`);
  return selected;
}
function cancel(reader, reason) {
  void reader.cancel(reason).catch(() => {
  });
}
async function collectBody(stream, maximum, label, signal) {
  if (!stream) {
    signal?.throwIfAborted();
    return new Uint8Array(0);
  }
  const reader = stream.getReader();
  let rejectAbort;
  const aborted = new Promise((_resolve, reject) => {
    rejectAbort = reject;
  });
  const abort = () => {
    cancel(reader, signal?.reason);
    rejectAbort(signal?.reason);
  };
  signal?.addEventListener("abort", abort, {
    once: true
  });
  const chunks = [];
  let size = 0;
  try {
    if (signal?.aborted) {
      cancel(reader, signal.reason);
      signal.throwIfAborted();
    }
    while (true) {
      const result = await Promise.race([
        reader.read(),
        aborted
      ]);
      signal?.throwIfAborted();
      if (result.done) break;
      size += result.value.byteLength;
      if (size > maximum) throw new BodyReadError(413, "body-too-large", `${label} exceeded ${maximum} bytes`);
      chunks.push(result.value.slice());
    }
    const bytes3 = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes3.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes3;
  } catch (error2) {
    cancel(reader, error2);
    if (error2 instanceof BodyReadError) throw error2;
    if (signal?.aborted) throw signal.reason;
    throw new BodyReadError(400, "invalid-body", "could not read request body", {
      cause: error2
    });
  } finally {
    signal?.removeEventListener("abort", abort);
    reader.releaseLock();
  }
}
function contentCodings(value) {
  const raw = typeof value === "string" ? value : value?.join(",");
  const codings = (raw ?? "").split(",").map((part) => part.trim().toLowerCase()).filter((part) => part && part !== "identity");
  for (const coding of codings) if (![
    "br",
    "gzip",
    "deflate",
    "zstd"
  ].includes(coding)) throw new BodyReadError(415, "unsupported-content-coding", `unsupported request content-encoding: ${coding}`);
  return codings;
}
async function readBodyStream(stream, options, decoder, defaultLimit, signal) {
  const maxBytes = limit(options.maxBytes, defaultLimit, "maxBytes");
  const maxEncodedBytes = limit(options.maxEncodedBytes, maxBytes, "maxEncodedBytes");
  const codings = options.decodeContentEncoding === false ? [] : contentCodings(options.contentEncoding);
  let bytes3 = await collectBody(stream, maxEncodedBytes, "request body", signal);
  for (const coding of [
    ...codings
  ].reverse()) bytes3 = await collectBody(decoder(bytes3, coding), maxBytes, "decoded request body", signal);
  if (bytes3.byteLength > maxBytes) throw new BodyReadError(413, "body-too-large", `decoded request body exceeded ${maxBytes} bytes`);
  return bytes3;
}
function decodeBody(bytes3, contentType) {
  const charset = (parseContentType(contentType)?.params["charset"] ?? "utf-8").toLowerCase();
  if (![
    "utf-8",
    "utf8",
    "us-ascii",
    "ascii",
    "iso-8859-1",
    "latin1"
  ].includes(charset)) throw new BodyReadError(415, "unsupported-charset", `unsupported request charset: ${charset}`);
  if ([
    "iso-8859-1",
    "latin1",
    "us-ascii",
    "ascii"
  ].includes(charset)) {
    if ((charset === "ascii" || charset === "us-ascii") && bytes3.some((byte) => byte > 127)) throw new BodyReadError(400, "invalid-body", "US-ASCII request body contains a non-ASCII octet");
    return Array.from(bytes3, (byte) => String.fromCharCode(byte)).join("");
  }
  try {
    return new TextDecoder("utf-8", {
      fatal: true
    }).decode(bytes3);
  } catch (cause) {
    throw new BodyReadError(400, "invalid-body", "request body must contain valid UTF-8", {
      cause
    });
  }
}

// node_modules/@red-cup-engineering/http-services-section/src/body/web.mjs
var DEFAULT_BODY_LIMIT = 1024 * 1024;
var decode = (bytes3, coding) => {
  let decoder;
  try {
    decoder = new DecompressionStream(coding);
  } catch (cause) {
    throw new BodyReadError(415, "unsupported-content-coding", `unsupported request content-encoding: ${coding}`, {
      cause
    });
  }
  return new Blob([
    bytes3
  ]).stream().pipeThrough(decoder);
};
function optionsFor(request, options) {
  return {
    ...options,
    contentType: options.contentType ?? request.headers.get("content-type") ?? void 0,
    contentEncoding: options.contentEncoding ?? request.headers.get("content-encoding") ?? void 0
  };
}
async function readBody(request, options = {}) {
  return readBodyStream(request.body, optionsFor(request, options), decode, DEFAULT_BODY_LIMIT, request.signal);
}
async function readTextBody(request, options = {}) {
  const selected = optionsFor(request, options);
  return decodeBody(await readBody(request, selected), selected.contentType);
}

// src/hashn-client.mjs
var HASHN_ORIGIN = "https://api.hashn.com";
var UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
var LIMIT2 = 32768;
var envelope = { ...JSON_RESOURCE_ENVELOPE, maxSourceBytes: LIMIT2, maxCanonicalBytes: LIMIT2, maxDepth: 20, maxNodes: 12e3 };
var hashnError = (code, status = 0) => Object.assign(new Error(code), { code, status });
function privateHashnReceipt(value, credential) {
  const redact = (v) => {
    if (typeof v === "string") return v.replace(/aw_[A-Za-z0-9._~-]+/g, "[redacted-token]").split(credential?.apiToken || "\0").join("[redacted-token]");
    if (Array.isArray(v)) return v.map(redact);
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, /authorization|token|secret|password|credential/i.test(k) ? "[redacted]" : redact(x)]));
    return v;
  };
  const safe = redact(value);
  if (new TextEncoder().encode(JSON.stringify(safe)).length > LIMIT2)
    return { status: safe.status, requestId: safe.requestId, cfRay: safe.cfRay, coverage: "redacted-receipt-exceeds-storage-limit", bodyOmitted: true };
  return safe;
}
function hashnCredential(value) {
  let c;
  try {
    c = typeof value === "string" ? JSON.parse(value) : value;
  } catch {
    return null;
  }
  return UUID.test(c?.agentId ?? "") && typeof c.apiToken === "string" && /^aw_[A-Za-z0-9_-]{8,512}$/.test(c.apiToken) ? { agentId: c.agentId, apiToken: c.apiToken } : null;
}
async function hashnRequest(path, { method = "GET", body, credential, fetchImpl = fetch, now = () => Date.now(), onRetry = async () => {
} } = {}) {
  const allowed = method === "GET" && ["/agents/me", "/knocks", "/listings"].includes(path) && credential || method === "POST" && (path === "/agents" && !credential || (/^\/workspaces\/[a-f0-9-]{36}\/knock$/i.test(path) || ["/listings/check", "/listings"].includes(path)) && credential);
  if (!allowed) throw hashnError("hashn-endpoint-refused");
  const signal = AbortSignal.timeout(15e3);
  let response3;
  try {
    response3 = await fetchImpl(HASHN_ORIGIN + path, {
      method,
      redirect: "manual",
      signal,
      headers: {
        accept: "application/json",
        ...credential ? { authorization: `Bearer ${credential.apiToken}` } : {},
        ...body === void 0 ? {} : { "content-type": "application/json" }
      },
      ...body === void 0 ? {} : { body: JSON.stringify(body) }
    });
  } catch {
    throw Object.assign(hashnError("hashn-response-unknown"), { providerReceipt: { status: null, coverage: "response-not-received" } });
  }
  const receipt = {
    status: response3.status,
    requestId: response3.headers.get("x-request-id")?.slice(0, 256) ?? null,
    cfRay: response3.headers.get("cf-ray")?.slice(0, 256) ?? null,
    coverage: "headers-only"
  };
  const refuse = (code) => Object.assign(hashnError(code, response3.status), { providerReceipt: privateHashnReceipt(receipt, credential) });
  const retry = response3.headers.get("retry-after");
  if (retry) {
    const delay = retry.length <= 256 ? retryAfterDelayMs(retry, now()) : null;
    const retryBlocked = retry.length > 256 || delay === null && /^\d+$/.test(retry.trim()) || delay !== null && !Number.isFinite(new Date(now() + delay).getTime());
    if (retryBlocked || delay !== null) await onRetry({ retryBlocked, retryAt: retryBlocked ? null : now() + delay });
  }
  if (Number(response3.headers.get("content-length")) > LIMIT2) {
    receipt.coverage = "declared-body-too-large";
    void response3.body?.cancel().catch(() => {
    });
    throw refuse("hashn-response-too-large");
  }
  let text;
  try {
    text = await readTextBody({ body: response3.body, headers: response3.headers, signal }, { maxBytes: LIMIT2, decodeContentEncoding: false });
  } catch {
    receipt.coverage = "body-unreceived-or-limit";
    throw refuse("hashn-response-invalid");
  }
  receipt.coverage = "complete-bounded-body";
  let data;
  try {
    data = admitCanonicalJson(text, envelope).value;
    receipt.body = data;
  } catch {
    receipt.body = text;
    if (response3.ok) throw refuse("hashn-response-invalid");
  }
  if (!response3.ok) throw refuse(response3.status >= 300 && response3.status < 400 ? "hashn-redirect-refused" : response3.status === 402 ? "hashn-payment-refused" : "hashn-provider-refused");
  return { status: response3.status, data, providerReceipt: privateHashnReceipt(receipt, credential) };
}

// src/hashn-acquisition.mjs
var HASHN_STATE = "hashn/acquisition";
var HASHN_SUMMARY = "hashn/public-summary";
var AUTH2 = "hashn/auth";
var SIX_HOURS = 6 * 60 * 60 * 1e3;
var WEEK = 7 * 24 * 60 * 60 * 1e3;
var KNOCKS_SCHEMA_REVISION = 2;
var hash2 = async (value) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalJson(value)))), (n) => n.toString(16).padStart(2, "0")).join("");
function hashnSchemaReadbackDue(state, at = Date.now()) {
  return !!state?.intent && !state.terminal && state.stage === "hashn-knocks-shape-held" && state.knocksSchemaRevision !== KNOCKS_SCHEMA_REVISION && !state.retryBlocked && !(state.retryAt > at);
}
function hashnInstanceProblem(instance) {
  if (!instance?.enabled) return "hashn-disabled";
  if (!UUID.test(instance.workspaceId ?? "") || !UUID.test(instance.buyerAgentId ?? "") || !/^[a-zA-Z0-9_-]{1,100}$/.test(instance.offerId ?? "") || typeof instance.note !== "string" || [...instance.note].length < 1 || [...instance.note].length > 500 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(instance.note) || instance.maximumNewCashExpenseUsd !== 0 || instance.maximumProviderRequestsPerPass !== 3 || instance.pollIntervalMs !== SIX_HOURS) return "hashn-instance-refused";
  return null;
}
async function runHashnAcquisition({ storage, instance, initialCredential, fetchImpl = fetch, now = () => Date.now() } = {}) {
  const refusal = hashnInstanceProblem(instance);
  if (refusal) return { stage: refusal, requests: 0, newCashExpenseUsd: 0 };
  let state = await storage.get(HASHN_STATE) ?? {};
  let calls = 0;
  const finish = async (stage, terminal2 = false, delay = SIX_HOURS) => {
    state.stage = stage;
    state.terminal = terminal2;
    state.nextAttemptAt = terminal2 || state.retryBlocked ? null : Math.max(now() + delay, state.retryAt ?? 0);
    await storage.put(HASHN_STATE, state);
    const summary = {
      stage,
      requests: calls,
      newCashExpenseUsd: 0,
      at: new Date(now()).toISOString(),
      offerId: instance.offerId,
      knockStatus: state.knockStatus ?? null,
      agreementReceived: false,
      deliverySubmitted: false,
      recognizedOutsideRevenue: null
    };
    await storage.put(HASHN_SUMMARY, summary);
    return summary;
  };
  const wire = async (path, options = {}) => {
    if (calls >= instance.maximumProviderRequestsPerPass) throw hashnError("hashn-request-budget");
    if (state.retryBlocked || state.retryAt > now()) throw hashnError("hashn-retry-deferred");
    calls++;
    return hashnRequest(path, { ...options, fetchImpl, now, onRetry: async (retry) => {
      Object.assign(state, retry);
      await storage.put(HASHN_STATE, state);
    } });
  };
  try {
    const credential = hashnCredential(initialCredential);
    if (!credential) return finish("hashn-credential-held");
    const bound = {
      agentId: credential.agentId,
      workspaceId: instance.workspaceId,
      buyerAgentId: instance.buyerAgentId,
      offerId: instance.offerId,
      note: instance.note
    };
    const binding = await hash2(bound);
    if (state.binding && state.binding !== binding) return finish("hashn-binding-drift", true);
    const priorAuth = await storage.get(AUTH2);
    if (priorAuth && (priorAuth.agentId !== credential.agentId || priorAuth.apiToken !== credential.apiToken)) return finish("hashn-credential-drift", true);
    if (state.terminal) return finish(state.stage, true);
    const schemaReadback = hashnSchemaReadbackDue(state, now());
    if (state.retryBlocked || state.retryAt > now() || state.nextAttemptAt > now() && !schemaReadback)
      return { stage: state.stage, requests: 0, newCashExpenseUsd: 0 };
    if (state.monitoringUntil && now() >= state.monitoringUntil) return finish("hashn-reconciliation-deadline-held", true);
    if (!priorAuth) {
      const { data: data2 } = await wire("/agents/me", { credential });
      if ((data2.agent_id ?? data2.id) !== credential.agentId) return finish("hashn-account-mismatch", true);
      await storage.put(AUTH2, credential);
    }
    state.binding ??= binding;
    state.scope ??= bound;
    if (state.intent && !state.reconciliationAttempted) state.reconciliationAttempted = true;
    state.knocksSchemaRevision = KNOCKS_SCHEMA_REVISION;
    await storage.put(HASHN_STATE, state);
    const { data, providerReceipt } = await wire("/knocks", { credential });
    state.knocksReadbackReceipt = providerReceipt;
    await storage.put(HASHN_STATE, state);
    if (!Array.isArray(data.outgoing)) throw hashnError("hashn-knocks-shape-held");
    if (data.has_more === true || data.next_cursor || data.nextCursor) throw hashnError("hashn-knocks-truncated-held");
    if (data.outgoing.some((k) => !k || !UUID.test(k.knocked_workspace_id ?? ""))) throw hashnError("hashn-knocks-shape-held");
    const related = data.outgoing.filter((k) => k.knocked_workspace_id === instance.workspaceId);
    if (related.length > 1) return finish("hashn-knock-conflict-held", true);
    const knock = related[0];
    if (knock) {
      if (!["knock_id", "from_agent_id", "to_agent_id", "note", "status"].every((key) => Object.hasOwn(knock, key)))
        return finish("hashn-knock-shape-held");
      if (!UUID.test(knock.knock_id ?? "") || knock.from_agent_id !== credential.agentId || knock.to_agent_id !== instance.buyerAgentId || knock.note !== instance.note || !["pending", "accepted", "declined", "expired"].includes(knock.status)) return finish("hashn-knock-scope-held", true);
      if (state.knockId && state.knockId !== knock.knock_id) return finish("hashn-knock-identity-held", true);
      state.knockId = knock.knock_id;
      state.knockStatus = knock.status;
      state.monitoringUntil ??= now() + WEEK + SIX_HOURS;
      if (knock.status === "accepted") {
        if (!UUID.test(knock.result_workspace_id ?? "")) return finish("hashn-acceptance-shape-held", true);
        state.resultWorkspaceId = knock.result_workspace_id;
        return finish("hashn-accepted-terms-held", true);
      }
      return finish("hashn-" + knock.status, knock.status !== "pending");
    }
    if (state.intent) return finish("hashn-knock-readback-pending");
    state.intent = {
      method: "POST",
      path: `/workspaces/${instance.workspaceId}/knock`,
      body: { note: instance.note },
      payloadSha256: await hash2({ note: instance.note }),
      at: new Date(now()).toISOString()
    };
    state.monitoringUntil = now() + WEEK + SIX_HOURS;
    await storage.put(HASHN_STATE, state);
    const result = await wire(state.intent.path, { method: "POST", body: state.intent.body, credential });
    state.knockWriteReceipt = result.providerReceipt;
    await storage.put(HASHN_STATE, state);
    if (result.status !== 201) throw hashnError("hashn-knock-response-held");
    return finish("hashn-knock-sent-readback-pending", false, 3e4);
  } catch (e) {
    const code = /^hashn-[a-z-]{1,80}$/.test(e.code ?? "") ? e.code : "hashn-failure";
    state.lastFailure = code;
    if (e.providerReceipt) state.providerReceipt = e.providerReceipt;
    return finish(
      code,
      [400, 401, 403, 404, 402, 410, 422].includes(e.status) || e.status === 409 && !state.intent || code === "hashn-redirect-refused",
      state.intent && !state.reconciliationAttempted ? 3e4 : SIX_HOURS
    );
  }
}

// src/route-health.mjs
var CATALOG_URL = "https://market.561.group/v1/catalog";
var BROKEN_STREAK_FOR_REPAIR = 3;
var id2 = (offer) => `${offer.method} ${offer.route}`;
function probeRequest(offer) {
  const example = offer.request?.example;
  const headers = { "user-agent": "coesite-earning-loops/1 (+https://github.com/coesite-operations/operations-services-section)", accept: "application/json" };
  if (offer.method === "GET") return [example?.url ?? offer.url, { method: "GET", headers }];
  const body = example && typeof example === "object" && "body" in example ? example.body : {};
  return [offer.url, { method: offer.method, headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify(body) }];
}
var decode2 = (header) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(header), (c) => c.charCodeAt(0))));
function judge(offer, status, challengeHeader, { payTo, resourceUrl } = {}) {
  if (status !== 402) return { held: false, finding: `answered ${status}, not 402, to the catalog's example request` };
  if (!challengeHeader) return { held: false, finding: "402 without a payment-required challenge" };
  let challenge;
  try {
    challenge = decode2(challengeHeader);
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
async function checkRoutes(env, { now = /* @__PURE__ */ new Date(), limit: limit2 = 15, catalogUrl = CATALOG_URL, brokenStreak = BROKEN_STREAK_FOR_REPAIR, repository = env.REPAIR_REPOSITORY, payTo, fetchImpl = fetch } = {}) {
  const key = register("route-health");
  const state = await read(env.STATE, key) ?? { routes: {} };
  const response3 = await fetchImpl(catalogUrl, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(15e3), redirect: "manual" });
  if (!response3.ok) throw new Error(`catalog answered ${response3.status}`);
  const catalog = await response3.json();
  const offers = catalog.offers.filter((offer) => offer.listed);
  const at = now.toISOString();
  for (const offer of offers) state.routes[id2(offer)] ??= { firstListedAt: at, price: offer.price, amountAtomic: offer.amountAtomic ?? null, heldSince: null, brokenStreak: 0 };
  const listed = new Set(offers.map(id2));
  for (const route of Object.keys(state.routes)) if (!listed.has(route)) state.routes[route].delistedAt ??= at;
  const due = offers.sort((a, b) => Number(state.routes[id2(a)].held !== false) - Number(state.routes[id2(b)].held !== false) || (state.routes[id2(a)].observedAt ?? "").localeCompare(state.routes[id2(b)].observedAt ?? "")).slice(0, limit2);
  for (const offer of due) {
    const [url, init] = probeRequest(offer);
    let verdict;
    try {
      const response4 = await fetchImpl(url, { ...init, redirect: "manual", signal: AbortSignal.timeout(15e3) });
      verdict = judge(offer, response4.status, response4.headers.get("payment-required"), { payTo, resourceUrl: url });
      await response4.body?.cancel();
    } catch (error2) {
      verdict = { held: false, finding: `request failed: ${error2.message}` };
    }
    const entry = state.routes[id2(offer)];
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

// src/onchain-hook.mjs
var FINANCIAL_RESOURCE_PROVIDER = "financial-arena";
var stages = ["monitor", "analyze", "plan", "publish", "learn"];
var outcomes = ["externally-reconciled", "intents-awaiting-external-reconciliation", "observed-no-dispatchable-strategy"];
var unsettled = (reading) => ["resource-pending", "resource-uncertain", "legacy-pending", "legacy-uncertain", "unreachable"].includes(reading?.status) || /^http-[0-9]+$/u.test(reading?.status ?? "");
var identity = (original) => {
  if (!original || typeof original.effect !== "string" || !original.effect || typeof original.request !== "string" || !original.request || typeof original.input?.run !== "string" || !original.input.run || Object.keys(original.input).some((key) => key !== "run"))
    throw new TypeError("Original financial invocation custody is unavailable");
  return Object.freeze({ effect: original.effect, request: original.request, input: Object.freeze({ run: original.input.run }) });
};
var checkedReply = (reply, original) => {
  const event = reply?.event, content = event?.content, status = reply?.status;
  const nextCycle = content?.stage === "learn" && content?.status === "complete";
  const expectedNext = content?.status === "complete" ? stages[(stages.indexOf(content?.stage) + 1) % stages.length] : content?.stage;
  if (typeof event?.id !== "string" || !event.id || content?.type !== "FinancialArenaEvent" || content.version !== 1 || content.run !== original.input.run || !Number.isSafeInteger(content.cycle) || content.cycle < 1 || !stages.includes(content.stage) || !["complete", "pending", "blocked", "needs-human"].includes(content.status) || !content.execute || !content.knowledge || !Number.isFinite(Date.parse(content.at)) || status?.type !== "FinancialArenaStatus" || status.version !== 1 || status.run !== content.run || status.cycle !== content.cycle + (nextCycle ? 1 : 0) || status.next !== expectedNext || status.lastRun !== content.at || status.backlog !== 1 || !Array.isArray(status.stages) || status.stages.length !== stages.length || status.stages.some((row, index) => row.stage !== stages[index] || row.status !== (nextCycle ? "pending" : index < stages.indexOf(content.stage) ? "complete" : index === stages.indexOf(content.stage) ? content.status : "pending")) || !Array.isArray(status.blockers) || !Number.isSafeInteger(status.interventions?.total) || status.interventions.total < 0)
    throw new TypeError("Financial provider did not receive its original typed turn");
  return {
    event: event.id,
    cycle: content.cycle,
    stage: content.stage,
    status: content.status,
    usefulWork: content.status === "complete" ? content.execute.effect === "intent-only" ? "intent-only" : "stage-evidence-received" : "not-established",
    externalReconciliation: content.stage === "learn" && outcomes.includes(content.execute.outcome) ? content.execute.outcome : "not-established",
    accountedEarnings: "not-established"
  };
};
function onchainPublicReading(reading) {
  if (!reading) return null;
  const received = reading.received ? Object.fromEntries(["event", "cycle", "stage", "status", "usefulWork", "externalReconciliation", "accountedEarnings"].filter((key) => Object.hasOwn(reading.received, key)).map((key) => [key, reading.received[key]])) : null;
  return {
    at: reading.at,
    status: reading.status ?? null,
    occurrence: reading.occurrence ?? null,
    driver: reading.status === "resource-received" ? "original-turn-received" : "not-established",
    received,
    usefulWork: received?.usefulWork ?? "not-established",
    externalReconciliation: received?.externalReconciliation ?? "not-established",
    accountedEarnings: "not-established",
    ...Number.isInteger(reading.httpStatus) ? { httpStatus: reading.httpStatus } : {}
  };
}
async function runOnchainHook(env, { now = /* @__PURE__ */ new Date(), cron = null, onchain, url = env.ONCHAIN_SCAN_URL, fetchImpl = fetch } = {}) {
  const occurrence = Object.freeze({ at: now.toISOString(), cron });
  const key = register("onchain");
  if (onchain !== void 0 && ["identify", "checkpoint", "provider", "reconcile"].some((name) => typeof onchain?.[name] !== "function"))
    throw new TypeError("Financial turns require a complete private original resource port");
  let fenceFailure;
  const checkpoint = async () => {
    if (fenceFailure) throw fenceFailure;
    try {
      if (onchain) await onchain.checkpoint();
    } catch (error2) {
      fenceFailure = error2;
      throw error2;
    }
  };
  await checkpoint();
  const prior = await read(env.STATE, key);
  await checkpoint();
  const retain = async (reading) => {
    await checkpoint();
    await put(env.STATE, key, reading);
    await checkpoint();
    if (JSON.stringify(await read(env.STATE, key)) !== JSON.stringify(reading)) throw new TypeError("Original onchain reading was not received");
    await checkpoint();
    return reading;
  };
  const archive = async (reading) => {
    if (!reading) return void 0;
    await checkpoint();
    const bytes3 = new TextEncoder().encode(JSON.stringify(reading));
    const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes3)), (byte) => byte.toString(16).padStart(2, "0")).join("");
    const reference = record("onchain", `${encodeURIComponent(reading.at ?? "undated")}-${digest}`);
    const retained = await read(env.STATE, reference);
    await checkpoint();
    if (retained === null) {
      await put(env.STATE, reference, reading);
      await checkpoint();
    }
    if (JSON.stringify(await read(env.STATE, reference)) !== JSON.stringify(reading)) throw new TypeError("Original dated onchain reading was not received");
    await checkpoint();
    return reference;
  };
  if (unsettled(prior) && (!onchain || !prior.original || prior.status.startsWith("legacy-")))
    return { status: prior.status, occurrence: prior.occurrence, reconciliation: "original-receiving-required" };
  if (onchain) {
    await checkpoint();
    const reconciling = unsettled(prior);
    const original = identity(reconciling ? prior.original : await onchain.identify(occurrence));
    if (!reconciling && prior?.status === "resource-received" && prior.original?.effect === original.effect) {
      if (JSON.stringify(prior.original) !== JSON.stringify(original)) throw new TypeError("Received financial identity was substituted");
      return { status: prior.status, received: prior.received };
    }
    const previousReading2 = reconciling ? void 0 : await archive(prior);
    const pending3 = reconciling ? prior : {
      at: occurrence.at,
      occurrence,
      original,
      status: "resource-pending",
      ...previousReading2 ? { previousReading: previousReading2 } : {},
      ...prior?.received ? { lastReceived: prior.received } : {}
    };
    await retain(pending3);
    try {
      const reply = reconciling ? await onchain.reconcile({ provider: FINANCIAL_RESOURCE_PROVIDER, ...original }) : await onchain.provider(FINANCIAL_RESOURCE_PROVIDER, original);
      await checkpoint();
      const received = checkedReply(reply, original);
      await retain({ ...pending3, status: "resource-received", received, answer: reply });
      return { status: "resource-received", received };
    } catch {
      await retain({ ...pending3, status: "resource-uncertain", reason: "original-provider-receiving-unconfirmed" });
      return { status: "resource-uncertain", occurrence: pending3.occurrence };
    }
  }
  if (!url) {
    if (prior) return { status: "no-engine-attached", retainedStatus: prior.status };
    await retain({ at: occurrence.at, occurrence, status: "no-engine-attached" });
    return { status: "no-engine-attached" };
  }
  if (prior?.status === "legacy-response-received" && prior.occurrence?.at === occurrence.at && prior.occurrence.cron === cron)
    return { status: prior.status, httpStatus: prior.httpStatus };
  const previousReading = await archive(prior);
  const pending2 = {
    at: occurrence.at,
    occurrence,
    status: "legacy-pending",
    original: { url, body: { at: occurrence.at, cron } },
    ...previousReading ? { previousReading } : {}
  };
  await retain(pending2);
  try {
    const response3 = await fetchImpl(url, { method: "POST", headers: {
      "content-type": "application/json",
      ...env.ONCHAIN_SCAN_TOKEN ? { authorization: `Bearer ${env.ONCHAIN_SCAN_TOKEN}` } : {}
    }, body: JSON.stringify(pending2.original.body) });
    const answer = response3.headers.get("content-type")?.includes("json") ? await response3.json() : null;
    const result = await retain({
      ...pending2,
      status: "legacy-response-received",
      httpStatus: response3.status,
      answer,
      usefulWork: "not-established",
      externalReconciliation: "not-established",
      accountedEarnings: "not-established"
    });
    return { status: result.status, httpStatus: result.httpStatus };
  } catch {
    await retain({ ...pending2, status: "legacy-uncertain", reason: "original-http-receiving-unconfirmed" });
    return { status: "legacy-uncertain", occurrence };
  }
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
    onchain: onchain ? { ...onchainPublicReading(onchain), lastRunAt: onchain.at } : null,
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
async function refreshIssuerResearch(store, configuration, { now = /* @__PURE__ */ new Date(), prepare, clock = () => /* @__PURE__ */ new Date() } = {}) {
  if (!configuration) return { status: "not-configured" };
  const key = register("issuer-research");
  const previous = await read(store, key);
  if (previous?.retryBlocked) return { ...previous, status: "deferred" };
  if (previous?.cacheKey === configuration.cacheKey && Date.parse(previous.nextAttemptAt) > now.getTime())
    return { ...previous, status: "deferred" };
  let reading;
  try {
    const producer = prepare ?? (await import("@red-cup-engineering/issuer-research-media-service/prepared-cohort")).prepareIssuerRevenueCohort;
    const complete = await producer(configuration);
    await put(store, configuration.cacheKey, complete);
    reading = {
      status: "prepared",
      at: now.toISOString(),
      cacheKey: configuration.cacheKey,
      observedAt: complete.observedAt ?? null,
      nextAttemptAt: new Date(now.getTime() + 9e5).toISOString()
    };
  } catch (error2) {
    const refusedAt = new Date(Math.max(now.getTime(), clock().getTime()));
    const delay = Math.max(9e5, retryDelayMs(error2.retryAfter, refusedAt));
    reading = {
      status: "unavailable",
      at: refusedAt.toISOString(),
      cacheKey: configuration.cacheKey,
      error: error2.message,
      code: error2.code ?? null,
      reason: error2.reason ?? null,
      retryable: error2.retryable ?? true,
      retryAfter: typeof error2.retryAfter === "string" ? error2.retryAfter : null,
      retryBlocked: !Number.isFinite(delay),
      nextAttemptAt: Number.isFinite(delay) ? new Date(refusedAt.getTime() + delay).toISOString() : null
    };
  }
  await put(store, key, reading);
  return reading;
}

// src/issuer-sqlite-cache.mjs
var COHORT = "issuer-evidence/cohort";
var STATUS = "issuer-evidence/status";
var LOGICAL_STATUS = "registers/earning-loops/issuer-research.json";
var STATUS_LIMIT = 524288;
var TRANSACTION_LIMIT = 19e5;
var encoder = new TextEncoder();
var bytes = (value) => encoder.encode(value).byteLength;
var own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
var object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
function invalid() {
  return new TypeError("Invalid issuer cache record");
}
function issuerSqliteStoragePlan(configuration) {
  if (configuration == null || configuration.enabled !== true || configuration.resourceAdmission?.status !== "received") return null;
  const { cacheKey, maximumCohortBytes } = configuration;
  if (typeof cacheKey !== "string" || cacheKey.length === 0 || bytes(cacheKey) > 256 || cacheKey === LOGICAL_STATUS || !Number.isSafeInteger(maximumCohortBytes) || maximumCohortBytes <= 0 || maximumCohortBytes > STATUS_LIMIT) throw new TypeError("Invalid issuer cache configuration");
  return { cohortKey: COHORT, statusKey: STATUS, logicalStatusKey: LOGICAL_STATUS, cacheKey, maximumCohortBytes, maximumStatusBytes: STATUS_LIMIT, maximumTransactionBytes: TRANSACTION_LIMIT };
}
function instant(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
}
function sentinel(cacheKey) {
  return { status: "unavailable", cacheKey, retryBlocked: true, reason: "status-overflow", nextAttemptAt: null };
}
function validateStatus(value, cacheKey) {
  if (!object(value) || value.cacheKey !== cacheKey) throw invalid();
  const special = sentinel(cacheKey);
  if (Object.keys(value).length === Object.keys(special).length && Object.keys(special).every((key) => own(value, key) && value[key] === special[key])) return;
  if (!instant(value.at)) throw invalid();
  const deadline = () => instant(value.nextAttemptAt) && Date.parse(value.nextAttemptAt) >= Date.parse(value.at);
  if (value.status === "prepared") {
    if (!(value.observedAt === null || instant(value.observedAt)) || own(value, "retryBlocked") && value.retryBlocked !== false || !deadline()) throw invalid();
  } else if (value.status === "unavailable") {
    const nullableString = (v) => v === null || typeof v === "string";
    if (typeof value.error !== "string" || !nullableString(value.code) || !nullableString(value.reason) || typeof value.retryable !== "boolean" || !nullableString(value.retryAfter) || typeof value.retryBlocked !== "boolean" || (value.retryBlocked ? value.nextAttemptAt !== null : !deadline())) throw invalid();
  } else throw invalid();
}
function physicalSize(key, record2) {
  return bytes(key) + bytes(JSON.stringify(record2));
}
function readRecord(record2, key, plan) {
  if (record2 === void 0) return null;
  if (!object(record2) || Object.keys(record2).length !== 2 || !own(record2, "cacheKey") || !own(record2, "body") || typeof record2.cacheKey !== "string" || typeof record2.body !== "string") throw invalid();
  const limit2 = key === COHORT ? plan.maximumCohortBytes : STATUS_LIMIT;
  if (bytes(record2.body) > limit2 || physicalSize(key, record2) > TRANSACTION_LIMIT) throw invalid();
  const parsed = JSON.parse(record2.body);
  if (record2.cacheKey !== plan.cacheKey) return null;
  if (key === STATUS) validateStatus(parsed, plan.cacheKey);
  return record2.body;
}
async function withIssuerSqliteStore(storage, configuration, work) {
  const plan = issuerSqliteStoragePlan(configuration);
  if (plan === null) return { status: "not-configured" };
  if (!storage || typeof storage.get !== "function" || typeof storage.transaction !== "function" || typeof work !== "function") throw new TypeError("Invalid issuer storage capabilities");
  const initial = /* @__PURE__ */ new Map();
  initial.set(COHORT, readRecord(await storage.get(COHORT), COHORT, plan));
  initial.set(STATUS, readRecord(await storage.get(STATUS), STATUS, plan));
  const staged = /* @__PURE__ */ new Map();
  let closed = false;
  let overflow = false;
  let fatal = null;
  const hold = sentinel(plan.cacheKey);
  function resolve(key) {
    if (closed) throw new TypeError("Issuer store scope closed");
    if (key === plan.cacheKey) return COHORT;
    if (key === LOGICAL_STATUS) return STATUS;
    throw new TypeError("Unadmitted issuer cache key");
  }
  function failClosed() {
    overflow = true;
    staged.clear();
    staged.set(STATUS, { cacheKey: plan.cacheKey, body: JSON.stringify(hold) });
  }
  function boundTransaction() {
    let total = 0;
    for (const [key, record2] of staged) {
      const size = physicalSize(key, record2);
      if (size > TRANSACTION_LIMIT) {
        failClosed();
        return;
      }
      total += size;
    }
    if (total > TRANSACTION_LIMIT) failClosed();
  }
  const store = {
    async get(key) {
      const physical = resolve(key);
      const body = staged.has(physical) ? staged.get(physical).body : initial.get(physical);
      return body === null ? null : { json: async () => JSON.parse(body) };
    },
    async put(key, text) {
      const physical = resolve(key);
      let parsed;
      if (physical === STATUS) {
        try {
          if (typeof text !== "string" || bytes(text) > STATUS_LIMIT) {
            failClosed();
            return;
          }
          parsed = JSON.parse(text);
        } catch {
          failClosed();
          return;
        }
        try {
          validateStatus(parsed, plan.cacheKey);
        } catch (error2) {
          fatal = error2;
          throw error2;
        }
      } else {
        if (typeof text !== "string" || bytes(text) > plan.maximumCohortBytes) throw invalid();
        JSON.parse(text);
      }
      if (overflow) return;
      staged.set(physical, { cacheKey: plan.cacheKey, body: text });
      boundTransaction();
    }
  };
  let result;
  try {
    result = await work(store);
  } finally {
    closed = true;
  }
  if (fatal !== null) throw fatal;
  if (staged.size !== 0) {
    await storage.transaction(async (transaction) => {
      for (const [key, record2] of staged) await transaction.put(key, record2);
    });
  }
  return overflow ? hold : result;
}
function response(status, headers = {}) {
  return new Response(null, { status, headers: { "Cache-Control": "no-store", ...headers } });
}
async function issuerSqliteResponse(request, storage, configuration) {
  const url = new URL(request.url);
  if (url.pathname !== "/issuer-evidence") return null;
  const plan = issuerSqliteStoragePlan(configuration);
  if (plan === null) return response(404);
  if (request.method !== "GET") return response(405, { Allow: "GET" });
  const entries = [...url.searchParams];
  if (entries.length !== 1 || entries[0][0] !== "key" || entries[0][1] !== plan.cacheKey) return response(404);
  try {
    const body = readRecord(await storage.get(COHORT), COHORT, plan);
    if (body === null) return response(404);
    const data = encoder.encode(body);
    return new Response(data, { status: 200, headers: { "Content-Type": "application/json", "Content-Length": String(data.byteLength), "Cache-Control": "no-store" } });
  } catch {
    return response(503);
  }
}

// src/issuer-settlement-custody.mjs
var E = new TextEncoder();
var ASSET = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
var ADDRESS3 = /^0x[0-9a-fA-F]{40}$/;
var TX3 = /^0x[0-9a-f]{64}$/;
var PREFIX3 = "issuer-settlements/";
var META = PREFIX3 + "capacity";
var RAW = PREFIX3 + "witness/";
var PENDING = PREFIX3 + "pending/";
var RECEIPT = PREFIX3 + "receipt/";
var PATH = "/issuer-settlement-witness";
var FIELDS = ["network", "asset", "payTo", "operation", "method", "route", "amount", "sku", "gateway", "ledgerAccount"];
var PROVIDERS = ["https://base-rpc.publicnode.com", "https://base.drpc.org", "https://base-mainnet.public.blastapi.io", "https://mainnet.base.org"];
var bytes2 = (s) => E.encode(s).byteLength;
var object2 = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
var fail2 = () => {
  throw new Error("issuer-settlement-unavailable");
};
var exactKeys = (v, keys) => object2(v) && Object.keys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));
var charge = (k, v) => bytes2(k) + bytes2(JSON.stringify(v));
var identity2 = (p) => Object.fromEntries(FIELDS.map((k) => [k, p[k]]));
var same2 = (a, b) => exactKeys(a, FIELDS) && FIELDS.every((k) => a[k] === b[k]);
var pendingKey = (k) => typeof k === "string" && k.startsWith(PENDING) && TX3.test(k.slice(PENDING.length));
function issuerSettlementCustodyPlan(configuration) {
  const c = configuration;
  if (!c || c.enabled !== true || c.resourceAdmission?.status !== "received") return null;
  const text = (k) => typeof c[k] === "string" && c[k].length > 0 && bytes2(c[k]) <= 512 && !/[\r\n]/.test(c[k]);
  if (c.network !== "eip155:8453" || typeof c.asset !== "string" || c.asset.toLowerCase() !== ASSET || typeof c.payTo !== "string" || !ADDRESS3.test(c.payTo) || c.operation !== "issuer-revenue-comparison" || c.method !== "POST" || c.route !== "/v1/issuer-revenue-comparison" || c.amount !== "50000" || !["sku", "gateway", "ledgerAccount"].every(text)) throw new TypeError("Invalid issuer settlement configuration");
  return Object.freeze({ prefix: PREFIX3, metadataKey: META, witnessPrefix: RAW, pendingPrefix: PENDING, receiptPrefix: RECEIPT, objectName: "earning-loops", path: PATH, maximumRecords: 5e4, maximumCustodyBytes: 268435456, maximumRawWitnessBytes: 32768, maximumTransactionBytes: 19e5, maximumWitnessesPerPulse: 4, maximumProviderAttemptsPerWitness: 4, maximumRpcBytes: 262144, network: c.network, asset: c.asset.toLowerCase(), payTo: c.payTo.toLowerCase(), operation: c.operation, method: c.method, route: c.route, sku: c.sku, gateway: c.gateway, ledgerAccount: c.ledgerAccount, amount: c.amount, maximumWorkerCallsPerPulse: 50 });
}
function logical(tx) {
  return "settlements/eip155:8453/" + tx + ".json";
}
function parseKey(key) {
  const m = typeof key === "string" && /^settlements\/eip155:8453\/(0x[0-9a-f]{64})\.json$/.exec(key);
  return m ? m[1] : null;
}
function witness(text, tx, p) {
  if (typeof text !== "string" || bytes2(text) > 32768) fail2();
  const w = JSON.parse(text);
  if (!object2(w) || w.transaction !== tx || w.network !== p.network || typeof w.payer !== "string" || !ADDRESS3.test(w.payer)) fail2();
  for (const k of FIELDS) {
    if (k === "asset" || k === "payTo") {
      if (typeof w[k] !== "string" || w[k].toLowerCase() !== p[k]) fail2();
    } else if (w[k] !== p[k]) fail2();
  }
  return w;
}
function validateMeta(m) {
  if (!exactKeys(m, ["version", "identity", "recordCount", "chargedBytes", "cursor"]) || m.version !== 1 || !exactKeys(m.identity, FIELDS) || !Number.isSafeInteger(m.recordCount) || m.recordCount < 1 || m.recordCount > 5e4 || !Number.isSafeInteger(m.chargedBytes) || m.chargedBytes < 4096 || m.chargedBytes > 268435456 || m.cursor !== null && !pendingKey(m.cursor) || charge(META, m) > 4096) fail2();
  const ip = issuerSettlementCustodyPlan({ ...m.identity, enabled: true, resourceAdmission: { status: "received" } });
  if (!same2(m.identity, identity2(ip))) fail2();
  if (m.recordCount === 1 && m.chargedBytes !== 4096) fail2();
  return m;
}
async function metadata(s, p) {
  const m = await s.get(META);
  if (m !== void 0) return validateMeta(m);
  const rows = await s.list({ prefix: PREFIX3, limit: 1 });
  if (!(rows instanceof Map) || rows.size) fail2();
  return { version: 1, identity: identity2(p), recordCount: 1, chargedBytes: 4096, cursor: null };
}
function pending(v, tx) {
  if (!exactKeys(v, ["transaction"]) || v.transaction !== tx) fail2();
}
function boundedRecord(v) {
  if (!object2(v)) fail2();
  const text = JSON.stringify(v);
  if (typeof text !== "string" || bytes2(text) > 65536) fail2();
  const parsed = JSON.parse(text);
  if (JSON.stringify(parsed) !== text) fail2();
  return text;
}
function capacity(m) {
  validateMeta(m);
  return m;
}
function mutations(entries, deletions = []) {
  const n = entries.reduce((n2, [k, v]) => n2 + charge(k, v), 0) + deletions.reduce((n2, k) => n2 + bytes2(k), 0);
  if (n > 19e5 || entries.some(([k, v]) => charge(k, v) > 19e5)) fail2();
}
function response2(status, text = "") {
  return new Response(text, { status, headers: { "Content-Type": "application/json", "Content-Length": String(bytes2(text)), "Cache-Control": "no-store" } });
}
async function readText(body, limit2) {
  if (!body) return "";
  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  let n = 0, result = "";
  try {
    for (; ; ) {
      const { done, value } = await reader.read();
      if (done) break;
      n += value.byteLength;
      if (n > limit2) fail2();
      result += decoder.decode(value, { stream: true });
    }
    return result + decoder.decode();
  } catch (e) {
    try {
      await reader.cancel();
    } catch {
    }
    throw e;
  } finally {
    reader.releaseLock();
  }
}
async function issuerSettlementResponse(request, storage, configuration) {
  const url = new URL(request.url);
  if (url.pathname !== PATH) return null;
  const p = issuerSettlementCustodyPlan(configuration);
  if (!p) return response2(404);
  if (request.method !== "GET" && request.method !== "POST") return new Response("", { status: 405, headers: { Allow: "GET, POST", "Content-Type": "application/json", "Content-Length": "0", "Cache-Control": "no-store" } });
  const entries = [...url.searchParams];
  const tx = entries.length === 1 && entries[0][0] === "key" ? parseKey(entries[0][1]) : null;
  if (!tx) return response2(404);
  if (request.method === "GET") {
    try {
      const raw2 = await storage.get(RAW + tx);
      if (raw2 === void 0) return response2(404);
      witness(raw2, tx, p);
      return response2(200, raw2);
    } catch {
      return response2(503);
    }
  }
  if (request.headers.get("If-None-Match") !== "*") return response2(428);
  if (!/^application\/json(?:\s*;.*)?$/i.test(request.headers.get("Content-Type") || "")) return response2(415);
  let raw;
  try {
    raw = await readText(request.body, 32768);
    witness(raw, tx, p);
  } catch {
    return response2(400);
  }
  try {
    const status = await storage.transaction(async (s) => {
      const m = await metadata(s, p);
      if (!same2(m.identity, identity2(p))) return 503;
      const old = await s.get(RAW + tx);
      if (old !== void 0) {
        witness(old, tx, p);
        return 412;
      }
      if (await s.get(PENDING + tx) !== void 0 || await s.get(RECEIPT + tx) !== void 0) fail2();
      const pv = { transaction: tx };
      const next = capacity({ ...m, recordCount: m.recordCount + 2, chargedBytes: m.chargedBytes + charge(RAW + tx, raw) + charge(PENDING + tx, pv) });
      const writes = [[RAW + tx, raw], [PENDING + tx, pv], [META, next]];
      mutations(writes);
      for (const [k, v] of writes) await s.put(k, v);
      return 201;
    });
    return response2(status);
  } catch {
    return response2(503);
  }
}
function adaptersFor(a) {
  if (!object2(a) || !["witnessProblem", "corroborate", "usdc"].every((k) => typeof a[k] === "function") || !Array.isArray(a.BASE_PROVIDERS) || a.BASE_PROVIDERS.length !== 4 || !PROVIDERS.every((v, i) => a.BASE_PROVIDERS[i] === v) || !(a.groupPayers instanceof Set)) throw new TypeError("Invalid issuer settlement adapters");
  for (const payer of a.groupPayers) if (typeof payer !== "string" || !/^0x[0-9a-f]{40}$/.test(payer)) throw new TypeError("Invalid issuer settlement adapters");
  const fetch2 = a.fetch === void 0 ? globalThis.fetch : a.fetch;
  const now = a.now === void 0 ? Date.now : a.now;
  if (typeof fetch2 !== "function" || typeof now !== "function") throw new TypeError("Invalid issuer settlement adapters");
  return { ...a, fetch: fetch2, now };
}
function instant2(a) {
  const n = a.now();
  if (typeof n !== "number" || !Number.isFinite(n)) fail2();
  return new Date(n).toISOString();
}
async function rpc(a, url, tx) {
  const controller = new AbortController();
  let timer, res;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error("timeout"));
    }, 1e4);
  });
  const task = (async () => {
    try {
      res = await a.fetch(url, { method: "POST", redirect: "manual", signal: controller.signal, headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getTransactionReceipt", params: [tx] }) });
      if (res.status !== 200) {
        try {
          await res.body?.cancel();
        } catch {
        }
        return null;
      }
      const parsed = JSON.parse(await readText(res.body, 262144));
      return object2(parsed) && !parsed.error && object2(parsed.result) ? parsed.result : null;
    } catch {
      return null;
    }
  })();
  try {
    return await Promise.race([task, timeout]);
  } catch {
    controller.abort();
    try {
      const cancellation = res?.body?.cancel();
      cancellation?.catch(() => {
      });
    } catch {
    }
    return null;
  } finally {
    clearTimeout(timer);
  }
}
function cash(w, tx, checked, a, at) {
  const group = a.groupPayers.has(w.payer.toLowerCase());
  const result = { evidenceVersion: 2, sourceId: `evm:eip155:8453:${ASSET}:${w.payTo.toLowerCase()}:${tx}:${BigInt(checked.transfer.logIndex).toString()}`, witnessKey: logical(tx), transactionHash: w.transaction, payer: w.payer, receiver: w.payTo, amount: w.amount, currency: "USDC", usdValuation: null, usd: a.usdc(w.amount), payerClass: group ? "group" : "unclassified", classificationBasis: group ? "current Group payer register" : "absence from Group register does not establish outside ownership", blockNumber: Number(BigInt(checked.receipt.blockNumber)), corroboratedAt: at };
  for (const k of ["paymentObservation", "deliveryObservation", "responsePreparation", "witnessId", "route", "method", "gateway", "sku", "ledgerAccount", "recordedAt"]) result[k] = w[k] ?? null;
  if (typeof result.usd !== "number" || !Number.isFinite(result.usd) || !Number.isSafeInteger(result.blockNumber) || result.blockNumber < 0) fail2();
  boundedRecord(result);
  return result;
}
async function advance(storage, p, key) {
  await storage.transaction(async (s) => {
    const m = await metadata(s, p);
    if (!same2(m.identity, identity2(p))) fail2();
    const next = capacity({ ...m, cursor: key });
    mutations([[META, next]]);
    await s.put(META, next);
  });
}
async function terminal(storage, p, key, raw, record2) {
  boundedRecord(record2);
  return storage.transaction(async (s) => {
    const m = await metadata(s, p);
    if (!same2(m.identity, identity2(p))) fail2();
    const tx = key.slice(PENDING.length), pv = await s.get(key);
    pending(pv, tx);
    if (await s.get(RAW + tx) !== raw || await s.get(RECEIPT + tx) !== void 0) fail2();
    const next = capacity({ ...m, chargedBytes: m.chargedBytes - charge(key, pv) + charge(RECEIPT + tx, record2), cursor: key });
    const writes = [[RECEIPT + tx, record2], [META, next]];
    mutations(writes, [key]);
    for (const [k, v] of writes) await s.put(k, v);
    if (!await s.delete(key)) fail2();
    return true;
  });
}
async function receiveIssuerSettlements(storage, configuration, adapters) {
  const p = issuerSettlementCustodyPlan(configuration);
  if (!p) return { status: "not-configured" };
  const a = adaptersFor(adapters);
  instant2(a);
  const m = await metadata(storage, p);
  if (!same2(m.identity, identity2(p))) return { status: "held", reason: "configuration-identity-changed" };
  const selected = /* @__PURE__ */ new Map();
  const page = async (options) => {
    const rows = await storage.list(options);
    if (!(rows instanceof Map) || rows.size > 4) fail2();
    for (const [k, v] of rows) {
      if (!pendingKey(k)) fail2();
      if (options.startAfter !== void 0 && k <= options.startAfter) fail2();
      pending(v, k.slice(PENDING.length));
      if (selected.size < 4 && !selected.has(k)) selected.set(k, v);
    }
  };
  await page({ prefix: PENDING, limit: 4, ...m.cursor === null ? {} : { startAfter: m.cursor } });
  if (m.cursor !== null && selected.size < 4) await page({ prefix: PENDING, limit: 4 });
  const result = { status: "observed", considered: 0, providerRequests: 0, corroborated: 0, refused: 0, retryPending: 0 };
  for (const [key] of selected) {
    const tx = key.slice(PENDING.length);
    const raw = await storage.get(RAW + tx);
    const w = witness(raw, tx, p);
    if (await storage.get(RECEIPT + tx) !== void 0) fail2();
    result.considered++;
    let checked;
    const problem = a.witnessProblem(w);
    if (problem !== null) {
      if (typeof problem !== "string" || !problem) fail2();
      checked = { ok: false, reason: problem };
    } else {
      const receipts = [];
      for (const provider of a.BASE_PROVIDERS) {
        instant2(a);
        result.providerRequests++;
        const receipt = await rpc(a, provider, w.transaction);
        if (receipt !== null) receipts.push(receipt);
        if (receipts.length === 2) break;
      }
      checked = a.corroborate(w, receipts);
    }
    if (!object2(checked) || checked.ok !== true && checked.ok !== false) fail2();
    const at = instant2(a);
    if (checked.ok === false && checked.retry === true) {
      result.retryPending++;
      await advance(storage, p, key);
      continue;
    }
    let record2;
    if (checked.ok === true) record2 = cash(w, tx, checked, a, at);
    else {
      if (typeof checked.reason !== "string" || !checked.reason) fail2();
      record2 = { status: "refused", transaction: tx, witnessKey: logical(tx), reason: checked.reason, at };
    }
    try {
      await terminal(storage, p, key, raw, record2);
      if (checked.ok) result.corroborated++;
      else result.refused++;
    } catch {
      result.retryPending++;
      await advance(storage, p, key);
    }
  }
  return result;
}

// worker/earning-loops.mjs
var groupPayers = new Set(group_payers_default);
var issuerSettlementAdapters = Object.freeze({
  witnessProblem,
  corroborate,
  usdc,
  BASE_PROVIDERS: Object.freeze([...BASE_PROVIDERS]),
  groupPayers
});
var CRONS = operation_default.crons;
async function run(env, cron, now = /* @__PURE__ */ new Date(), { configuration = operation_default, prepareIssuerRevenueCohort, issuerStorage, withOnchain } = {}) {
  if (withOnchain !== void 0 && typeof withOnchain !== "function") throw new TypeError("Original resource selection is a private host function");
  if (configuration.issuerResearch && (withOnchain || env.ONCHAIN_SCAN_URL || configuration.onchainScanUrl))
    throw new TypeError("issuer operation has no subrequest allocation for an onchain hook");
  const outcome = { cron, at: now.toISOString() };
  const step = async (name, work) => {
    try {
      outcome[name] = await work();
    } catch (error2) {
      outcome[name] = { error: name === "onchain" ? "original-onchain-custody-unconfirmed" : error2.message };
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
    await step("onchain", () => {
      const receive = (onchain) => runOnchainHook(env, { now, cron, onchain, url: env.ONCHAIN_SCAN_URL ?? configuration.onchainScanUrl });
      return withOnchain ? withOnchain(Object.freeze({ at: now.toISOString(), cron }), receive) : receive();
    });
    if (configuration.issuerResearch) await step("issuerResearch", () => withIssuerSqliteStore(
      issuerStorage,
      configuration.issuerResearch,
      (store) => refreshIssuerResearch(store, configuration.issuerResearch, { now, prepare: prepareIssuerRevenueCohort })
    ));
  }
  const { issuerResearch, ...publicOutcome } = outcome;
  await put(env.STATE, register("last-run"), publicOutcome);
  return outcome;
}
var READINGS = {
  "/settlements.json": "settlements",
  "/route-health.json": "route-health",
  "/scorecard.json": "scorecard",
  "/price-directives.json": "price-directives",
  "/onchain.json": "onchain",
  "/last-run.json": "last-run"
};
async function tick(env, date, options = {}) {
  const crons = (options.configuration ?? operation_default).crons;
  const due = dueCrons(crons, date).sort((a, b) => (a === crons.pass) - (b === crons.pass));
  const outcomes2 = [];
  for (const cron of due) outcomes2.push(await run(env, cron, date, options));
  return outcomes2;
}
var EarningClock = class {
  constructor(state, env, options = {}) {
    this.state = state;
    this.env = env;
    this.options = options;
    this.queue = Promise.resolve();
  }
  enqueue(work) {
    const task = this.queue.then(work);
    this.queue = task.catch(() => {
    });
    return task;
  }
  releaseId() {
    const id3 = this.env.RELEASE_METADATA?.id;
    return typeof id3 === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(id3) ? id3 : null;
  }
  async alarm() {
    return this.enqueue(async () => {
      const configuration = this.options.configuration ?? operation_default;
      const acquisition = configuration.hashAcquisition?.enabled === true;
      const financial = configuration.issuerSettlements?.enabled === true && configuration.issuerSettlements.resourceAdmission?.status === "received";
      const at = Date.now(), commercial = configuration.commercial?.enabled === true || configuration.researchProcurement?.enabled === true || acquisition || financial;
      const acquisitionState = acquisition ? await this.state.storage.get(HASHN_STATE) : null;
      const acquisitionPulseAt = acquisition ? await this.state.storage.get("hashn/next-pulse-at") : null;
      const acquisitionDue = acquisition && !acquisitionState?.terminal && !acquisitionState?.retryBlocked && !(acquisitionState?.retryAt > at) && (hashnSchemaReadbackDue(acquisitionState, at) || !(acquisitionState?.nextAttemptAt > at) && !(acquisitionPulseAt > at));
      const coreNextAt = acquisition ? await this.state.storage.get("earning-clock/core-next-at") : null;
      const researchState = configuration.researchProcurement?.enabled ? await this.state.storage.get(RESEARCH_STATE) : null;
      const researchPending = configuration.researchProcurement?.enabled === true && !researchState?.terminal;
      const researchDue = researchPending && !researchState?.retryBlocked && !(researchState?.nextAttemptAt > at);
      const slot = commercial ? Math.round(at / 45e4) * 45e4 : Math.round(at / 6e4) * 6e4;
      const releaseId = commercial ? this.releaseId() : null;
      const bootstrap = releaseId && await this.state.storage.get("earning-clock/observed-release-id") !== releaseId;
      const armed = bootstrap ? await this.state.storage.get("earning-clock/armed-release") : null;
      const acquisitionOnly = acquisitionDue && !bootstrap && !researchDue && Number.isFinite(coreNextAt) && at < coreNextAt;
      if (bootstrap) await this.state.storage.put("earning-clock/observed-release-id", releaseId);
      try {
        if (acquisitionOnly) {
          await this.state.storage.put("hashn/next-pulse-at", at + 216e5);
          await (this.options.acquisitionPass ?? runHashnAcquisition)({
            storage: this.state.storage,
            instance: configuration.hashAcquisition,
            initialCredential: this.env.HASHN_CREDENTIAL_JSON,
            now: () => at
          });
          const received = await this.state.storage.get(HASHN_STATE);
          if (Number.isFinite(received?.nextAttemptAt) && received.nextAttemptAt > at)
            await this.state.storage.put("hashn/next-pulse-at", received.nextAttemptAt);
        } else if (bootstrap || researchDue || commercial && slot % 9e5 !== 0) {
          if (researchDue || bootstrap && researchPending) {
            await (this.options.researchPass ?? runResearchPass)({
              storage: this.state.storage,
              instance: configuration.researchProcurement,
              products: this.options.researchProducts ?? research_products_default,
              merchant: configuration.merchantPayTo,
              groupPayers
            });
          } else if (configuration.commercial?.enabled) {
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
              at: new Date(at).toISOString(),
              ...result.taskId ? { taskId: result.taskId, productId: result.productId } : {}
            });
          }
          if (financial && !bootstrap && !researchDue && slot % 9e5 !== 0)
            await (this.options.issuerSettlementPass ?? receiveIssuerSettlements)(
              this.state.storage,
              configuration.issuerSettlements,
              issuerSettlementAdapters
            );
        } else await tick(this.env, new Date(slot), { ...this.options, issuerStorage: this.state.storage });
      } finally {
        let alarm = acquisitionOnly ? coreNextAt : commercial ? (Math.floor(at / 45e4) + 1) * 45e4 : nextTick(at);
        if (bootstrap && armed?.id === releaseId && Number.isFinite(armed.previousAlarm))
          alarm = Math.min(alarm, armed.previousAlarm > Date.now() ? armed.previousAlarm : Date.now() + 1e3);
        if (acquisition && !acquisitionOnly) await this.state.storage.put("earning-clock/core-next-at", alarm);
        if (configuration.researchProcurement?.enabled) {
          const pending2 = await this.state.storage.get(RESEARCH_STATE);
          if (!pending2?.terminal && !pending2?.retryBlocked && Number.isFinite(pending2?.nextAttemptAt))
            alarm = Math.min(alarm, Math.max(Date.now() + 1e3, pending2.nextAttemptAt));
        }
        if (acquisition) {
          const pending2 = await this.state.storage.get(HASHN_STATE);
          const pulseAt = await this.state.storage.get("hashn/next-pulse-at");
          if (!pending2?.terminal && !pending2?.retryBlocked)
            alarm = Math.min(alarm, hashnSchemaReadbackDue(pending2, Date.now()) ? Date.now() + 1e3 : Math.max(Date.now() + 1e3, pending2?.nextAttemptAt ?? 0, pulseAt ?? 0, pending2?.retryAt ?? 0));
        }
        await this.state.storage.setAlarm(alarm);
      }
    });
  }
  async fetch(request) {
    if (request && new URL(request.url).pathname === "/issuer-settlement-witness")
      return this.enqueue(() => issuerSettlementResponse(
        request,
        this.state.storage,
        (this.options.configuration ?? operation_default).issuerSettlements
      ));
    if (request && new URL(request.url).pathname === "/acquisition.json") {
      const summary = await this.state.storage.get(HASHN_SUMMARY);
      if (!summary) return new Response("not yet observed\n", { status: 404 });
      const fields = ["stage", "requests", "newCashExpenseUsd", "at", "offerId", "knockStatus", "agreementReceived", "deliverySubmitted", "recognizedOutsideRevenue"];
      return Response.json(Object.fromEntries(fields.filter((key) => Object.hasOwn(summary, key)).map((key) => [key, summary[key]])), { headers: { "cache-control": "no-store" } });
    }
    if (request) {
      const response3 = await issuerSqliteResponse(request, this.state.storage, (this.options.configuration ?? operation_default).issuerResearch);
      if (response3) return response3;
    }
    if (request && new URL(request.url).pathname === "/research.json") {
      const summary = await this.state.storage.get(RESEARCH_SUMMARY);
      if (!summary) return new Response("not yet observed\n", { status: 404 });
      const fields = ["stage", "requests", "newCashExpenseUsd", "at", "taskId", "productId", "receiptAccepted", "evaluationState", "approvedAmountAtomic", "providerPayoutState", "payoutTx", "independentlyVerifiedCashAtomic", "recognizedOutsideRevenue"];
      const alarm = await this.state.storage.getAlarm();
      return Response.json({ ...Object.fromEntries(fields.filter((key) => Object.hasOwn(summary, key)).map((key) => [key, summary[key]])), nextTick: alarm ? new Date(alarm).toISOString() : null }, { headers: { "cache-control": "no-store" } });
    }
    if (request && new URL(request.url).pathname === "/commercial.json") {
      const summary = await this.state.storage.get("opentask/public-summary");
      if (!summary) return new Response("not yet observed\n", { status: 404 });
      const alarm = await this.state.storage.getAlarm();
      const configured = (this.options.configuration ?? operation_default).commercial;
      const offers = configured?.offers?.length ? await Promise.all(commercialOffers(configured).map(async (offer) => {
        const state = await this.state.storage.get(commercialStateKey(configured, offer));
        return {
          taskId: offer.taskId,
          productId: offer.productId,
          stage: state?.stage ?? "not-yet-observed",
          at: state?.observedAt ?? null
        };
      })) : null;
      return Response.json({
        stage: summary.stage,
        requests: summary.requests,
        newCashExpenseUsd: 0,
        ...offers ? { offers } : {},
        at: summary.at,
        taskId: summary.taskId,
        productId: summary.productId,
        nextTick: alarm ? new Date(alarm).toISOString() : null
      }, { headers: { "cache-control": "no-store" } });
    }
    return this.enqueue(async () => {
      let alarm = await this.state.storage.getAlarm();
      const configuration = this.options.configuration ?? operation_default;
      const at = Date.now(), commercial = configuration.commercial?.enabled || configuration.researchProcurement?.enabled || configuration.hashAcquisition?.enabled || configuration.issuerSettlements?.enabled === true && configuration.issuerSettlements.resourceAdmission?.status === "received";
      const releaseId = commercial ? this.releaseId() : null;
      if (releaseId && await this.state.storage.get("earning-clock/observed-release-id") !== releaseId) {
        const armed = await this.state.storage.get("earning-clock/armed-release");
        if (armed?.id !== releaseId) {
          await this.state.storage.put("earning-clock/armed-release", { id: releaseId, previousAlarm: alarm ?? null });
          alarm = at + 1e3;
          await this.state.storage.setAlarm(alarm);
        }
      }
      if (!alarm) {
        alarm = commercial ? (Math.floor(at / 45e4) + 1) * 45e4 : nextTick(at);
        await this.state.storage.setAlarm(alarm);
      }
      return Response.json({ nextTick: new Date(alarm).toISOString() });
    });
  }
};
function createEarningWorker({ withOnchain } = {}) {
  return {
    async scheduled(event, env, context) {
      if (!Number.isFinite(event.scheduledTime)) throw new TypeError("Original scheduled occurrence is required");
      context.waitUntil(run(env, event.cron, new Date(event.scheduledTime), { withOnchain }));
    },
    async fetch(request, env) {
      const path = new URL(request.url).pathname;
      if (path === "/products.json") return Response.json(products_default, { headers: { "cache-control": "public, max-age=300" } });
      if (path === "/research-products.json") return Response.json(research_products_default, { headers: { "cache-control": "public, max-age=300" } });
      if (path === "/research.json" && env.CLOCK) return env.CLOCK.get(env.CLOCK.idFromName("earning-loops")).fetch(request);
      if (path === "/commercial.json" && env.CLOCK) return env.CLOCK.get(env.CLOCK.idFromName("earning-loops")).fetch(request);
      if (path === "/acquisition.json" && env.CLOCK) return env.CLOCK.get(env.CLOCK.idFromName("earning-loops")).fetch(request);
      if (path === "/clock" && env.CLOCK) return env.CLOCK.get(env.CLOCK.idFromName("earning-loops")).fetch(request);
      if (READINGS[path]) {
        const value = await read(env.STATE, register(READINGS[path]));
        return value ? Response.json(path === "/onchain.json" ? onchainPublicReading(value) : value, { headers: { "cache-control": "no-store" } }) : new Response("not yet observed\n", { status: 404 });
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
}
var earning_loops_default = createEarningWorker();
export {
  CRONS,
  EarningClock,
  createEarningWorker,
  earning_loops_default as default,
  run,
  tick
};
