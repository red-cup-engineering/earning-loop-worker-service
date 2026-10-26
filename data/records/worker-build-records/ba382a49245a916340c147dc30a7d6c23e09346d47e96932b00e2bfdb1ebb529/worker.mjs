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
function randomBase64Url(byteLength3) {
  if (!Number.isInteger(byteLength3) || byteLength3 <= 0) {
    throw new TypeError("randomBase64Url requires a positive integer byteLength");
  }
  return randomBytes(byteLength3).toString("base64url");
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

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/typeEncoderMap.js
var TypeEncoderMap;
var init_typeEncoderMap = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/typeEncoderMap.js"() {
    TypeEncoderMap = class {
      #types = /* @__PURE__ */ new Map();
      /**
       * Register an encoder for a given type.
       *
       * @param typ The class to encode.  This is the function for the constructor
       *   of objects of this type.  For example, Uint8Array the value of the
       *   constructor property of a Uint8Array instance.
       * @param encoder The function to use for encoding this type.
       * @returns Previous registration, or undefined if none.
       */
      registerEncoder(typ, encoder2) {
        const old = this.#types.get(typ);
        this.#types.set(typ, encoder2);
        return old;
      }
      /**
       * Get the encoder for a given class.
       *
       * @param typ Constructor function.
       * @returns Encoder, or undefined if none specified.
       */
      get(typ) {
        return this.#types.get(typ);
      }
      /**
       * Delete the encoder for a given class.
       *
       * @param typ Constructor function.
       * @returns True if class found and deleted, otherwise false.
       */
      delete(typ) {
        return this.#types.delete(typ);
      }
      /**
       * Remove all classes from the map.
       */
      clear() {
        this.#types.clear();
      }
    };
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/constants.js
var MT, TAG, NUMBYTES, SIMPLE, SYMS, DCBOR_INT;
var init_constants = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/constants.js"() {
    MT = {
      POS_INT: 0,
      NEG_INT: 1,
      BYTE_STRING: 2,
      UTF8_STRING: 3,
      ARRAY: 4,
      MAP: 5,
      TAG: 6,
      SIMPLE_FLOAT: 7
    };
    TAG = {
      DATE_STRING: 0,
      DATE_EPOCH: 1,
      POS_BIGINT: 2,
      NEG_BIGINT: 3,
      DECIMAL_FRAC: 4,
      BIGFLOAT: 5,
      BASE64URL_EXPECTED: 21,
      BASE64_EXPECTED: 22,
      BASE16_EXPECTED: 23,
      CBOR: 24,
      URI: 32,
      BASE64URL: 33,
      BASE64: 34,
      MIME: 36,
      DATE_EPOCH_DAYS: 100,
      // https://github.com/input-output-hk/cbor-sets-spec/blob/master/CBOR_SETS.md
      SET: 258,
      JSON: 262,
      WTF8: 273,
      // https://github.com/mishoo/cbor.lisp/blob/e1428a5/clext-spec.txt
      SYMBOL: 280,
      DATE_FULL: 1004,
      REGEXP: 21066,
      SELF_DESCRIBED: 55799,
      // Always invalid: https://www.ietf.org/archive/id/draft-bormann-cbor-notable-tags-10.html#name-invalid-tag
      INVALID_16: 65535,
      INVALID_32: 4294967295,
      INVALID_64: 0xffffffffffffffffn
    };
    NUMBYTES = {
      ZERO: 0,
      ONE: 24,
      TWO: 25,
      FOUR: 26,
      EIGHT: 27,
      INDEFINITE: 31
    };
    SIMPLE = {
      FALSE: 20,
      TRUE: 21,
      NULL: 22,
      UNDEFINED: 23
    };
    SYMS = class {
      /**
       * A 0xFF byte as been found in the stream.  Used as a sentinal.
       */
      static BREAK = /* @__PURE__ */ Symbol.for("github.com/hildjj/cbor2/break");
      /**
       * Original CBOR encoding for round-tripping and crypto.
       */
      static ENCODED = /* @__PURE__ */ Symbol.for("github.com/hildjj/cbor2/cbor-encoded");
      /**
       * Pre-encoded version of length for arrays and maps.  Must include the
       * major type.
       */
      static LENGTH = /* @__PURE__ */ Symbol.for("github.com/hildjj/cbor2/length");
    };
    DCBOR_INT = {
      MIN: -(2n ** 63n),
      MAX: 2n ** 64n - 1n
    };
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/sorts.js
function sortCoreDeterministic(a, b) {
  const [_ka, _va, a8] = a;
  const [_kb, _vb, b8] = b;
  const len = Math.min(a8.length, b8.length);
  for (let i = 0; i < len; i++) {
    const diff = a8[i] - b8[i];
    if (diff !== 0) {
      return diff;
    }
  }
  return 0;
}
var init_sorts = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/sorts.js"() {
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/writer.js
var Writer;
var init_writer = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/writer.js"() {
    Writer = class _Writer {
      static defaultOptions = {
        chunkSize: 4096
      };
      #opts;
      #chunks = [];
      #dv = null;
      // View over last chunk.
      #offset = 0;
      #length = 0;
      constructor(opts = {}) {
        this.#opts = {
          ..._Writer.defaultOptions,
          ...opts
        };
        if (this.#opts.chunkSize < 8) {
          throw new RangeError(`Expected size >= 8, got ${this.#opts.chunkSize}`);
        }
        this.#alloc();
      }
      get length() {
        return this.#length;
      }
      read() {
        this.#trim();
        const ret = new Uint8Array(this.#length);
        let len = 0;
        for (const u8 of this.#chunks) {
          ret.set(u8, len);
          len += u8.length;
        }
        this.#alloc();
        return ret;
      }
      write(buf) {
        const len = buf.length;
        if (len > this.#left()) {
          this.#trim();
          if (len > this.#opts.chunkSize) {
            this.#chunks.push(buf);
            this.#alloc();
          } else {
            this.#alloc();
            this.#chunks[this.#chunks.length - 1].set(buf);
            this.#offset = len;
          }
        } else {
          this.#chunks[this.#chunks.length - 1].set(buf, this.#offset);
          this.#offset += len;
        }
        this.#length += len;
      }
      writeUint8(n) {
        this.#makeSpace(1);
        this.#dv.setUint8(this.#offset, n);
        this.#advance(1);
      }
      writeUint16(n, littleEndian = false) {
        this.#makeSpace(2);
        this.#dv.setUint16(this.#offset, n, littleEndian);
        this.#advance(2);
      }
      writeUint32(n, littleEndian = false) {
        this.#makeSpace(4);
        this.#dv.setUint32(this.#offset, n, littleEndian);
        this.#advance(4);
      }
      writeBigUint64(n, littleEndian = false) {
        this.#makeSpace(8);
        this.#dv.setBigUint64(this.#offset, n, littleEndian);
        this.#advance(8);
      }
      writeInt16(n, littleEndian = false) {
        this.#makeSpace(2);
        this.#dv.setInt16(this.#offset, n, littleEndian);
        this.#advance(2);
      }
      writeInt32(n, littleEndian = false) {
        this.#makeSpace(4);
        this.#dv.setInt32(this.#offset, n, littleEndian);
        this.#advance(4);
      }
      writeBigInt64(n, littleEndian = false) {
        this.#makeSpace(8);
        this.#dv.setBigInt64(this.#offset, n, littleEndian);
        this.#advance(8);
      }
      writeFloat32(n, littleEndian = false) {
        this.#makeSpace(4);
        this.#dv.setFloat32(this.#offset, n, littleEndian);
        this.#advance(4);
      }
      writeFloat64(n, littleEndian = false) {
        this.#makeSpace(8);
        this.#dv.setFloat64(this.#offset, n, littleEndian);
        this.#advance(8);
      }
      clear() {
        this.#length = 0;
        this.#chunks = [];
        this.#alloc();
      }
      #alloc() {
        const buf = new Uint8Array(this.#opts.chunkSize);
        this.#chunks.push(buf);
        this.#offset = 0;
        this.#dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
      }
      // Always push a new chunk right after trimming.
      #trim() {
        if (this.#offset === 0) {
          this.#chunks.pop();
          return;
        }
        const last = this.#chunks.length - 1;
        this.#chunks[last] = this.#chunks[last].subarray(0, this.#offset);
        this.#offset = 0;
        this.#dv = null;
      }
      #left() {
        const last = this.#chunks.length - 1;
        return this.#chunks[last].length - this.#offset;
      }
      #makeSpace(sz) {
        if (this.#left() < sz) {
          this.#trim();
          this.#alloc();
        }
      }
      #advance(sz) {
        this.#offset += sz;
        this.#length += sz;
      }
    };
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/tag.js
var Tag;
var init_tag = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/tag.js"() {
    Tag = class _Tag {
      static #tags = /* @__PURE__ */ new Map();
      tag;
      contents;
      /**
       * A tag wrapped around another value.
       *
       * @param tag The tag number.
       * @param contents The value that follows the tag number.
       */
      constructor(tag, contents = void 0) {
        this.tag = tag;
        this.contents = contents;
      }
      /**
       * When constructing the commented version of this tag, should the contents
       * be written as well?  If true, the comment function should output the
       * contents values itself (only used for tag 24 so far).
       *
       * @type {boolean}
       * @readonly
       */
      get noChildren() {
        const decoder = _Tag.#tags.get(this.tag);
        return Boolean(decoder?.noChildren);
      }
      /**
       * Register a decoder for a give tag number.
       *
       * @param tag The tag number.
       * @param decoder Decoder function.
       * @param description If provided, use this when commenting to add a type
       *   name in parens after the tag number.
       * @returns Old decoder for this tag, if there was one.
       */
      static registerDecoder(tag, decoder, description) {
        const old = this.#tags.get(tag);
        this.#tags.set(tag, decoder);
        if (old) {
          if (!("comment" in decoder)) {
            decoder.comment = old.comment;
          }
          if (!("noChildren" in decoder)) {
            decoder.noChildren = old.noChildren;
          }
        }
        if (description && !decoder.comment) {
          decoder.comment = () => `(${description})`;
        }
        return old;
      }
      /**
       * Remove the encoder for this tag number.
       *
       * @param tag Tag number.
       * @returns Old decoder, if there was one.
       */
      static clearDecoder(tag) {
        const old = this.#tags.get(tag);
        this.#tags.delete(tag);
        return old;
      }
      /**
       * Get the decoder for a given tag number.
       *
       * @param tag The tag number.
       * @returns The decoder function, if there is one.
       */
      static getDecoder(tag) {
        return this.#tags.get(tag);
      }
      /**
       * Get all registered decoders clone of the map.
       *
       * @returns Map containing current decoders, as a copy.
       */
      static getAllDecoders() {
        return new Map(this.#tags);
      }
      /**
       * Iterate over just the contents, so that the tag works more like an
       * array.
       *
       * @yields One time, the contained value.
       */
      *[Symbol.iterator]() {
        yield this.contents;
      }
      /**
       * Makes Tag act like an array, so that no special casing is needed when
       * the tag's contents are available.
       *
       * @param contents The value associated with the tag.
       * @returns Always returns 1.
       */
      push(contents) {
        this.contents = contents;
        return 1;
      }
      /**
       * Convert this tagged value to a useful data type, if possible.
       *
       * @param options Options for decoding.
       * @returns The converted value.
       */
      decode(options) {
        const decoder = options?.tags?.get(this.tag) ?? (options?.ignoreGlobalTags ? void 0 : _Tag.#tags.get(this.tag));
        if (decoder) {
          return decoder(this, options);
        }
        return this;
      }
      comment(options, depth) {
        const decoder = options?.tags?.get(this.tag) ?? (options?.ignoreGlobalTags ? void 0 : _Tag.#tags.get(this.tag));
        if (decoder?.comment) {
          return decoder.comment(this, options, depth);
        }
        return void 0;
      }
      toCBOR() {
        return [this.tag, this.contents];
      }
      [/* @__PURE__ */ Symbol.for("nodejs.util.inspect.custom")](_depth, inspectOptions, inspect) {
        return `${this.tag}(${inspect(this.contents, inspectOptions)})`;
      }
    };
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/box.js
function getEncoded(obj) {
  if (obj != null && typeof obj === "object") {
    return obj[SYMS.ENCODED];
  }
  return void 0;
}
function getEncodedLength(obj) {
  if (obj != null && typeof obj === "object") {
    return obj[SYMS.LENGTH];
  }
  return void 0;
}
function saveEncoded(obj, orig) {
  Object.defineProperty(obj, SYMS.ENCODED, {
    configurable: true,
    enumerable: false,
    value: orig
  });
}
function box(value, orig) {
  const o = Object(value);
  saveEncoded(o, orig);
  return o;
}
var init_box = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/box.js"() {
    init_constants();
    init_tag();
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/float.js
function formatNAN(nan, _depth, inspectOptions, inspect) {
  let ret = "nan'";
  if (!nan.quiet) {
    ret += "!";
  }
  if (nan.sign === -1) {
    ret += "-";
  }
  ret += inspect(Math.abs(nan.payload), inspectOptions);
  ret += "'";
  ret += nan.encodingIndicator;
  return ret;
}
function parseHalf(buf, offset = 0, rejectSubnormals = false) {
  const sign2 = buf[offset] & 128 ? -1 : 1;
  const exp = (buf[offset] & 124) >> 2;
  const mant = (buf[offset] & 3) << 8 | buf[offset + 1];
  if (exp === 0) {
    if (rejectSubnormals && mant !== 0) {
      throw new Error(`Unwanted subnormal: ${sign2 * 5960464477539063e-23 * mant}`);
    }
    return sign2 * 5960464477539063e-23 * mant;
  } else if (exp === 31) {
    if (mant) {
      return NaN;
    }
    return sign2 * Infinity;
  }
  return sign2 * 2 ** (exp - 25) * (1024 + mant);
}
function halfToUint(half) {
  const dvu32 = new DataView(new ArrayBuffer(4));
  dvu32.setFloat32(0, half, false);
  const u = dvu32.getUint32(0, false);
  if ((u & 8191) !== 0) {
    return null;
  }
  let s16 = u >> 16 & 32768;
  const exp = u >> 23 & 255;
  const mant = u & 8388607;
  if (exp === 0 && mant === 0) {
  } else if (exp >= 113 && exp <= 142) {
    s16 += (exp - 112 << 10) + (mant >> 13);
  } else if (exp >= 103 && exp < 113) {
    if (mant & (1 << 126 - exp) - 1) {
      return null;
    }
    s16 += mant + 8388608 >> 126 - exp;
  } else if (exp === 255) {
    s16 |= 31744;
    s16 |= mant >> 13;
  } else {
    return null;
  }
  return s16;
}
function flushToZero(n) {
  if (n !== 0) {
    const a = new ArrayBuffer(8);
    const dv = new DataView(a);
    dv.setFloat64(0, n, false);
    const b = dv.getBigUint64(0, false);
    if ((b & 0x7ff0000000000000n) === 0n) {
      return b & 0x8000000000000000n ? -0 : 0;
    }
  }
  return n;
}
function checkSubnormal(buf) {
  switch (buf.length) {
    case 2:
      parseHalf(buf, 0, true);
      break;
    case 4: {
      const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
      const n = dv.getUint32(0, false);
      if ((n & 2139095040) === 0 && n & 8388607) {
        throw new Error(`Unwanted subnormal: ${dv.getFloat32(0, false)}`);
      }
      break;
    }
    case 8: {
      const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
      const n = dv.getBigUint64(0, false);
      if ((n & 0x7ff0000000000000n) === 0n && n & 0x000fffffffffffn) {
        throw new Error(`Unwanted subnormal: ${dv.getFloat64(0, false)}`);
      }
      break;
    }
    default:
      throw new TypeError(`Bad input to isSubnormal: ${buf}`);
  }
}
var F16_SIGN, F16_EXPONENT, F16_QUIET, F16_PAYLOAD, F16_SIGNIFICAND, F32_SIGN, F32_EXPONENT, F32_QUIET, F32_PAYLOAD, F32_SIGNIFICAND, F64_SIGN, F64_EXPONENT, F64_QUIET, F64_PAYLOAD, F64_SIGNIFICAND, NOT_F16, NOT_F32, RADIX_PREFIX, NAN_SIZE, NAN;
var init_float = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/float.js"() {
    F16_SIGN = 1n << 15n;
    F16_EXPONENT = 31n << 10n;
    F16_QUIET = 1n << 9n;
    F16_PAYLOAD = F16_QUIET - 1n;
    F16_SIGNIFICAND = F16_QUIET | F16_PAYLOAD;
    F32_SIGN = 1n << 31n;
    F32_EXPONENT = 255n << 23n;
    F32_QUIET = 1n << 22n;
    F32_PAYLOAD = F32_QUIET - 1n;
    F32_SIGNIFICAND = F32_QUIET | F32_PAYLOAD;
    F64_SIGN = 1n << 63n;
    F64_EXPONENT = 2047n << 52n;
    F64_QUIET = 1n << 51n;
    F64_PAYLOAD = F64_QUIET - 1n;
    F64_SIGNIFICAND = F64_QUIET | F64_PAYLOAD;
    NOT_F16 = F64_PAYLOAD - (F16_PAYLOAD << 42n);
    NOT_F32 = F64_PAYLOAD - (F32_PAYLOAD << 29n);
    RADIX_PREFIX = {
      2: "0b",
      8: "0o",
      16: "0x"
    };
    (function(NAN_SIZE2) {
      NAN_SIZE2[NAN_SIZE2["NATURAL"] = -2] = "NATURAL";
      NAN_SIZE2[NAN_SIZE2["UNKNOWN"] = -1] = "UNKNOWN";
      NAN_SIZE2[NAN_SIZE2["F16"] = 2] = "F16";
      NAN_SIZE2[NAN_SIZE2["F32"] = 4] = "F32";
      NAN_SIZE2[NAN_SIZE2["F64"] = 8] = "F64";
    })(NAN_SIZE || (NAN_SIZE = {}));
    NAN = class extends Number {
      // Full f64 as unsigned.
      #value;
      #size = NAN_SIZE.UNKNOWN;
      constructor(bytes2, quiet = true, size = NAN_SIZE.UNKNOWN) {
        super(NaN);
        const orig = bytes2;
        if (typeof bytes2 === "number") {
          if (!Number.isSafeInteger(bytes2)) {
            throw new Error(`Invalid NAN payload: ${bytes2}`);
          }
          bytes2 = BigInt(bytes2);
          let s = 0n;
          if (bytes2 < 0) {
            s = F64_SIGN;
            bytes2 = -bytes2;
          }
          if (bytes2 >= F64_QUIET) {
            throw new Error(`Payload too large: ${orig}`);
          }
          const q = quiet ? F64_QUIET : 0n;
          this.#value = s | F64_EXPONENT | q | bytes2;
          switch (size) {
            case NAN_SIZE.NATURAL:
              throw new Error("NAN_SIZE.NATURAL only valid for bigint constructor");
            case NAN_SIZE.UNKNOWN:
              size = this.preferredSize;
              break;
            case NAN_SIZE.F16:
              if (this.#value & NOT_F16) {
                throw new Error("Invalid size for payload");
              }
              break;
            case NAN_SIZE.F32:
              if (this.#value & NOT_F32) {
                throw new Error("Invalid size for payload");
              }
              break;
            case NAN_SIZE.F64:
              break;
            default:
              throw new Error(`Invalid size: ${size}`);
          }
          this.#size = size;
        } else if (typeof bytes2 === "bigint") {
          let nat = NAN_SIZE.UNKNOWN;
          if ((bytes2 & F64_EXPONENT) === F64_EXPONENT) {
            this.#value = bytes2;
            nat = NAN_SIZE.F64;
          } else if ((bytes2 & F32_EXPONENT) === F32_EXPONENT) {
            const s = (bytes2 & F32_SIGN) << 32n;
            this.#value = s | F64_EXPONENT | (bytes2 & F32_SIGNIFICAND) << 29n;
            nat = NAN_SIZE.F32;
          } else if ((bytes2 & F16_EXPONENT) === F16_EXPONENT) {
            const s = (bytes2 & F16_SIGN) << 48n;
            this.#value = s | F64_EXPONENT | (bytes2 & F16_SIGNIFICAND) << 42n;
            nat = NAN_SIZE.F16;
          } else {
            throw new Error(`Invalid raw NaN value: ${bytes2}`);
          }
          if (size === NAN_SIZE.UNKNOWN) {
            this.#size = this.preferredSize;
          } else if (size === NAN_SIZE.NATURAL) {
            this.#size = nat;
          } else {
            if (size < nat) {
              throw new Error("Invalid bigint NaN size");
            }
            this.#size = size;
          }
        } else {
          const dv = new DataView(bytes2.buffer, bytes2.byteOffset, bytes2.byteLength);
          switch (bytes2.length) {
            case 3: {
              if (bytes2[0] !== 249) {
                throw new Error("Invalid CBOR encoding for half float");
              }
              const val = BigInt(dv.getUint16(1, false));
              if ((val & F16_EXPONENT) !== F16_EXPONENT) {
                throw new Error("Not a NaN");
              }
              const s = (val & F16_SIGN) << 48n;
              this.#value = s | F64_EXPONENT | (val & F16_SIGNIFICAND) << 42n;
              this.#size = NAN_SIZE.F16;
              break;
            }
            case 5: {
              if (bytes2[0] !== 250) {
                throw new Error("Invalid CBOR encoding for single float");
              }
              const val = BigInt(dv.getUint32(1, false));
              if ((val & F32_EXPONENT) !== F32_EXPONENT) {
                throw new Error("Not a NaN");
              }
              const s = (val & F32_SIGN) << 32n;
              this.#value = s | F64_EXPONENT | (val & F32_SIGNIFICAND) << 29n;
              this.#size = NAN_SIZE.F32;
              break;
            }
            case 9: {
              if (bytes2[0] !== 251) {
                throw new Error("Invalid CBOR encoding for double float");
              }
              this.#value = dv.getBigUint64(1, false);
              if ((this.#value & F64_EXPONENT) !== F64_EXPONENT) {
                throw new Error("Not a NaN (NaNaN)");
              }
              this.#size = NAN_SIZE.F64;
              break;
            }
            default:
              throw new RangeError(`Invalid NAN size (should be 2, 4, or 8): ${bytes2.length - 1}`);
          }
        }
        if (!this.payload && !this.quiet) {
          throw new Error("Signalling NaN with zero payload");
        }
      }
      /**
       * Get the CBOR bytes for this NaN.
       */
      get bytes() {
        const buf = new ArrayBuffer(this.#size + 1);
        const dv = new DataView(buf);
        switch (this.#size) {
          case NAN_SIZE.F16: {
            dv.setUint8(0, 249);
            const s = this.#value & F64_SIGN ? F16_SIGN : 0n;
            const val = s | F16_EXPONENT | (this.#value & F64_SIGNIFICAND) >> 42n;
            dv.setUint16(1, Number(val), false);
            break;
          }
          case NAN_SIZE.F32: {
            dv.setUint8(0, 250);
            const s = this.#value & F64_SIGN ? F32_SIGN : 0n;
            const val = s | F32_EXPONENT | (this.#value & F64_SIGNIFICAND) >> 29n;
            dv.setUint32(1, Number(val), false);
            break;
          }
          case NAN_SIZE.F64:
            dv.setUint8(0, 251);
            dv.setBigUint64(1, this.#value);
            break;
        }
        return new Uint8Array(buf);
      }
      /**
       * Is the quiet bit set?
       */
      get quiet() {
        return Boolean(this.#value & F64_QUIET);
      }
      /**
       * If negative -1, otherwise 1.  Should never be 0, since you should use
       * a real NaN or Infinity for those.
       */
      get sign() {
        return this.#value & F64_SIGN ? -1 : 1;
      }
      /**
       * Payload, as in IEEE754-2019.
       */
      get payload() {
        return Number(this.#value & F64_PAYLOAD) * this.sign;
      }
      /**
       * Full 64-bit encoding, with sign and quiet bit intact.
       */
      get raw() {
        return this.#value;
      }
      /**
       * Encoding indicator, based on the preferred size.
       */
      get encodingIndicator() {
        switch (this.#size) {
          case NAN_SIZE.F16:
            return "_1";
          case NAN_SIZE.F32:
            return "_2";
        }
        return "_3";
      }
      /**
       * The desired encoding size (2, 4, or 8).
       */
      get size() {
        return this.#size;
      }
      /**
       * How many bytes should this NaN be encoded as in prefrerred encoding?
       */
      get preferredSize() {
        if ((this.#value & NOT_F16) === 0n) {
          return NAN_SIZE.F16;
        }
        if ((this.#value & NOT_F32) === 0n) {
          return NAN_SIZE.F32;
        }
        return NAN_SIZE.F64;
      }
      /**
       * Is this currrently configured for preferred encoding?
       */
      get isShortestEncoding() {
        return this.preferredSize === this.#size;
      }
      /**
       * Write to a CBOR stream.
       * @param w Writer.
       */
      toCBOR(w) {
        w.write(this.bytes);
      }
      /**
       * Convert to a string in the given radix.
       *
       * @param radix Base for output.  Valid values: 2, 8, 10, and 16.
       * @returns String in the selected radix, with the correct radix prefix if
       *   radix is not 10.
       */
      toString(radix = 10) {
        return formatNAN(this, 1, {}, (n) => (RADIX_PREFIX[radix] ?? "") + n.toString(radix));
      }
      [/* @__PURE__ */ Symbol.for("nodejs.util.inspect.custom")](depth, inspectOptions, inspect) {
        return formatNAN(this, depth, inspectOptions, inspect);
      }
    };
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@cto.af/wtf8/lib/errors.js
var init_errors = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@cto.af/wtf8/lib/errors.js"() {
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@cto.af/wtf8/lib/const.js
var EMPTY, WTF8;
var init_const = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@cto.af/wtf8/lib/const.js"() {
    EMPTY = new Uint8Array(0);
    WTF8 = "wtf-8";
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@cto.af/wtf8/lib/decode.js
var init_decode = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@cto.af/wtf8/lib/decode.js"() {
    init_const();
    init_errors();
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@cto.af/wtf8/lib/encode.js
function utf8length(str) {
  let len = 0;
  for (const s of str) {
    const cp = s.codePointAt(0);
    if (cp < 128) {
      len++;
    } else if (cp < 2048) {
      len += 2;
    } else if (cp < 65536) {
      len += 3;
    } else {
      len += 4;
    }
  }
  return len;
}
var Wtf8Encoder;
var init_encode = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@cto.af/wtf8/lib/encode.js"() {
    init_const();
    Wtf8Encoder = class {
      encoding = WTF8;
      encode(input) {
        if (!input) {
          return EMPTY;
        }
        const buf = new Uint8Array(utf8length(String(input)));
        this.encodeInto(input, buf);
        return buf;
      }
      encodeInto(source, destination) {
        const str = String(source);
        const len = str.length;
        const outLen = destination.length;
        let written = 0;
        let read2 = 0;
        for (read2 = 0; read2 < len; read2++) {
          const c = str.codePointAt(read2);
          if (c < 128) {
            if (written >= outLen) {
              break;
            }
            destination[written++] = c;
          } else if (c < 2048) {
            if (written >= outLen - 1) {
              break;
            }
            destination[written++] = 192 | c >> 6;
            destination[written++] = 128 | c & 63;
          } else if (c < 65536) {
            if (written >= outLen - 2) {
              break;
            }
            destination[written++] = 224 | c >> 12;
            destination[written++] = 128 | c >> 6 & 63;
            destination[written++] = 128 | c & 63;
          } else {
            if (written >= outLen - 3) {
              break;
            }
            destination[written++] = 240 | c >> 18;
            destination[written++] = 128 | c >> 12 & 63;
            destination[written++] = 128 | c >> 6 & 63;
            destination[written++] = 128 | c & 63;
            read2++;
          }
        }
        return {
          read: read2,
          written
        };
      }
    };
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@cto.af/wtf8/lib/decodeStream.js
var init_decodeStream = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@cto.af/wtf8/lib/decodeStream.js"() {
    init_decode();
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@cto.af/wtf8/lib/encodeStream.js
var init_encodeStream = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@cto.af/wtf8/lib/encodeStream.js"() {
    init_const();
    init_encode();
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@cto.af/wtf8/lib/index.js
var init_lib = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@cto.af/wtf8/lib/index.js"() {
    init_errors();
    init_decode();
    init_encode();
    init_decodeStream();
    init_encodeStream();
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/utils.js
function setRanges(u8, ranges) {
  Object.defineProperty(u8, CBOR_RANGES, {
    configurable: false,
    enumerable: false,
    writable: false,
    value: ranges
  });
}
function getRanges(u8) {
  return u8[CBOR_RANGES];
}
function hasRanges(u8) {
  return getRanges(u8) !== void 0;
}
function subarrayRanges(u8, begin = 0, end = u8.length - 1) {
  const ret = u8.subarray(begin, end);
  const ranges = getRanges(u8);
  if (ranges) {
    const rng = [];
    for (const r of ranges) {
      if (r[0] >= begin && r[0] + r[1] <= end) {
        const s = [...r];
        s[0] -= begin;
        rng.push(s);
      }
    }
    if (rng.length) {
      setRanges(ret, rng);
    }
  }
  return ret;
}
function hexToU8native(str) {
  return Uint8Array.fromHex(str);
}
function hexToU8fallback(str) {
  let len = Math.ceil(str.length / 2);
  const res = new Uint8Array(len);
  len--;
  for (let end = str.length, start = end - 2; end >= 0; end = start, start -= 2, len--) {
    res[len] = parseInt(str.substring(start, end), 16);
  }
  return res;
}
function u8toHexNative(u8) {
  return u8.toHex();
}
function u8toHexFallback(u8) {
  return u8.reduce((t, v) => t + v.toString(16).padStart(2, "0"), "");
}
function u8concat(u8s) {
  const sz = u8s.reduce((t, v) => t + v.length, 0);
  const ranged = u8s.some((v) => hasRanges(v));
  const ranges = [];
  const ret = new Uint8Array(sz);
  let len = 0;
  for (const u8 of u8s) {
    if (!(u8 instanceof Uint8Array)) {
      throw new TypeError(`Invalid array: ${u8}`);
    }
    ret.set(u8, len);
    if (ranged) {
      const rgs = u8[CBOR_RANGES] ?? [[0, u8.length]];
      for (const r of rgs) {
        r[0] += len;
      }
      ranges.push(...rgs);
    }
    len += u8.length;
  }
  if (ranged) {
    setRanges(ret, ranges);
  }
  return ret;
}
function base64ToBytesNative(base64) {
  return Uint8Array.fromBase64(base64);
}
function base64ToBytesFallback(base64) {
  const binString = atob(base64);
  return Uint8Array.from(binString, (m) => m.codePointAt(0));
}
function stringToHex(str) {
  let res = "";
  for (const c of str) {
    const cp = c.codePointAt(0)?.toString(16).padStart(4, "0");
    if (res) {
      res += ", ";
    }
    res += `U+${cp}`;
  }
  return res;
}
var CBOR_RANGES, hexToU8, u8toHex, base64ToBytes;
var init_utils = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/utils.js"() {
    CBOR_RANGES = /* @__PURE__ */ Symbol("CBOR_RANGES");
    hexToU8 = /* c8 ignore next */
    typeof Uint8Array.fromHex === "function" ? (
      /* c8 ignore next */
      hexToU8native
    ) : (
      /* c8 ignore next */
      hexToU8fallback
    );
    u8toHex = /* c8 ignore next */
    typeof Uint8Array.prototype.toHex === "function" ? (
      /* c8 ignore next */
      u8toHexNative
    ) : (
      /* c8 ignore next */
      u8toHexFallback
    );
    base64ToBytes = /* c8 ignore next */
    typeof Uint8Array.fromBase64 === "function" ? (
      /* c8 ignore next */
      base64ToBytesNative
    ) : (
      /* c8 ignore next */
      base64ToBytesFallback
    );
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/encoder.js
function cborAbs(value) {
  const neg = value < 0;
  if (typeof value === "bigint") {
    return [neg ? -value - 1n : value, neg];
  }
  return [neg ? -value - 1 : value, neg];
}
function writeFloat(val, w, opts) {
  if (opts.rejectFloats) {
    throw new Error(`Attempt to encode an unwanted floating point number: ${val}`);
  }
  if (isNaN(val)) {
    w.writeUint8(HALF);
    w.writeUint16(32256);
  } else if (!opts.float64 && Math.fround(val) === val) {
    const half = halfToUint(val);
    if (half === null) {
      w.writeUint8(FLOAT);
      w.writeFloat32(val);
    } else {
      w.writeUint8(HALF);
      w.writeUint16(half);
    }
  } else {
    w.writeUint8(DOUBLE);
    w.writeFloat64(val);
  }
}
function writeInt(val, w, mt) {
  const [pos, neg] = cborAbs(val);
  if (neg && mt) {
    throw new TypeError(`Negative size: ${val}`);
  }
  mt ??= neg ? MT.NEG_INT : MT.POS_INT;
  mt <<= 5;
  if (pos < 24) {
    w.writeUint8(mt | pos);
  } else if (pos <= 255) {
    w.writeUint8(mt | NUMBYTES.ONE);
    w.writeUint8(pos);
  } else if (pos <= 65535) {
    w.writeUint8(mt | NUMBYTES.TWO);
    w.writeUint16(pos);
  } else if (pos <= 4294967295) {
    w.writeUint8(mt | NUMBYTES.FOUR);
    w.writeUint32(pos);
  } else {
    w.writeUint8(mt | NUMBYTES.EIGHT);
    w.writeBigUint64(BigInt(pos));
  }
}
function writeTag(tag, w, opts) {
  if (typeof tag === "number") {
    writeInt(tag, w, MT.TAG);
  } else if (typeof tag === "object" && !opts.ignoreOriginalEncoding && SYMS.ENCODED in tag) {
    w.write(tag[SYMS.ENCODED]);
  } else if (tag <= Number.MAX_SAFE_INTEGER) {
    writeInt(Number(tag), w, MT.TAG);
  } else {
    w.writeUint8(MT.TAG << 5 | NUMBYTES.EIGHT);
    w.writeBigUint64(BigInt(tag));
  }
}
function writeBigInt(val, w, opts) {
  const [pos, neg] = cborAbs(val);
  if (opts.collapseBigInts && (!opts.largeNegativeAsBigInt || val >= -0x8000000000000000n)) {
    if (pos <= 0xffffffffn) {
      writeInt(Number(val), w);
      return;
    }
    if (pos <= 0xffffffffffffffffn) {
      const mt = (neg ? MT.NEG_INT : MT.POS_INT) << 5;
      w.writeUint8(mt | NUMBYTES.EIGHT);
      w.writeBigUint64(pos);
      return;
    }
  }
  if (opts.rejectBigInts) {
    throw new Error(`Attempt to encode unwanted bigint: ${val}`);
  }
  const tag = neg ? TAG.NEG_BIGINT : TAG.POS_BIGINT;
  const s = pos.toString(16);
  const z = s.length % 2 ? "0" : "";
  writeTag(tag, w, opts);
  const buf = hexToU8(z + s);
  writeInt(buf.length, w, MT.BYTE_STRING);
  w.write(buf);
}
function writeNumber(val, w, opts) {
  if (opts.flushToZero) {
    val = flushToZero(val);
  }
  if (Object.is(val, -0)) {
    if (opts.simplifyNegativeZero) {
      if (opts.avoidInts) {
        writeFloat(0, w, opts);
      } else {
        writeInt(0, w);
      }
    } else {
      writeFloat(val, w, opts);
    }
  } else if (!opts.avoidInts && Number.isSafeInteger(val)) {
    writeInt(val, w);
  } else if (opts.reduceUnsafeNumbers && Math.floor(val) === val && val >= DCBOR_INT.MIN && val <= DCBOR_INT.MAX) {
    writeBigInt(BigInt(val), w, opts);
  } else {
    writeFloat(val, w, opts);
  }
}
function writeString(val, w, opts) {
  const s = opts.stringNormalization ? val.normalize(opts.stringNormalization) : val;
  if (opts.wtf8 && !val.isWellFormed()) {
    const wtf8 = WE.encode(s);
    writeTag(TAG.WTF8, w, opts);
    writeInt(wtf8.length, w, MT.BYTE_STRING);
    w.write(wtf8);
  } else {
    const utf8 = TE.encode(s);
    writeInt(utf8.length, w, MT.UTF8_STRING);
    w.write(utf8);
  }
}
function writeArray(obj, w, opts) {
  const a = obj;
  writeLength(a, a.length, MT.ARRAY, w, opts);
  for (const i of a) {
    writeUnknown(i, w, opts);
  }
}
function writeUint8Array(u, w) {
  writeInt(u.length, w, MT.BYTE_STRING);
  w.write(u);
}
function writeLength(obj, len, mt, w, opts) {
  const enc = getEncodedLength(obj);
  if (enc && !opts.ignoreOriginalEncoding) {
    w.write(enc);
  } else {
    writeInt(len, w, mt);
  }
}
function writeObject(obj, w, opts) {
  if (obj === null) {
    w.writeUint8(NULL);
    return;
  }
  if (!opts.ignoreOriginalEncoding && SYMS.ENCODED in obj) {
    w.write(obj[SYMS.ENCODED]);
    return;
  }
  const constructor = obj.constructor;
  if (constructor) {
    const encoder2 = opts.types?.get(constructor) ?? (opts.ignoreGlobalTags ? void 0 : TYPES.get(constructor));
    if (encoder2) {
      const res = encoder2(obj, w, opts);
      if (res !== void 0) {
        if (!Array.isArray(res) || res.length !== 2) {
          throw new Error("Invalid encoder return value");
        }
        if (typeof res[0] === "bigint" || isFinite(Number(res[0]))) {
          writeTag(res[0], w, opts);
        }
        writeUnknown(res[1], w, opts);
      }
      return;
    }
  }
  if (typeof obj.toCBOR === "function") {
    const res = obj.toCBOR(w, opts);
    if (res) {
      if (typeof res[0] === "bigint" || isFinite(Number(res[0]))) {
        writeTag(res[0], w, opts);
      }
      writeUnknown(res[1], w, opts);
    }
    return;
  }
  if (typeof obj.toJSON === "function") {
    writeUnknown(obj.toJSON(), w, opts);
    return;
  }
  const entries = Object.entries(obj).map(
    // Circular
    (e) => [e[0], e[1], encode(e[0], opts)]
  );
  if (opts.sortKeys) {
    entries.sort(opts.sortKeys);
  }
  writeLength(obj, entries.length, MT.MAP, w, opts);
  for (const [_k, v, e] of entries) {
    w.write(e);
    writeUnknown(v, w, opts);
  }
}
function writeSymbol(sym, w, opts) {
  if (!sym.description || sym !== Symbol.for(sym.description)) {
    throw new TypeError(`Private or empty symbol: ${sym.toString()}`);
  }
  writeTag(280, w, opts);
  writeString(sym.description, w, opts);
}
function writeUnknown(val, w, opts) {
  switch (typeof val) {
    case "number":
      writeNumber(val, w, opts);
      break;
    case "bigint":
      writeBigInt(val, w, opts);
      break;
    case "string":
      writeString(val, w, opts);
      break;
    case "boolean":
      w.writeUint8(val ? TRUE : FALSE);
      break;
    case "undefined":
      if (opts.rejectUndefined) {
        throw new Error("Attempt to encode unwanted undefined.");
      }
      w.writeUint8(UNDEFINED);
      break;
    case "object":
      writeObject(val, w, opts);
      break;
    case "symbol":
      writeSymbol(val, w, opts);
      break;
    default:
      throw new TypeError(`Unknown type: ${typeof val}, ${String(val)}`);
  }
}
function encode(val, options = {}) {
  const opts = { ...defaultEncodeOptions };
  if (options.dcbor) {
    Object.assign(opts, dcborEncodeOptions);
  } else if (options.cde) {
    Object.assign(opts, cdeEncodeOptions);
  }
  Object.assign(opts, options);
  const w = new Writer(opts);
  writeUnknown(val, w, opts);
  return w.read();
}
var ENCODED, HALF, FLOAT, DOUBLE, TRUE, FALSE, UNDEFINED, NULL, TE, WE, defaultEncodeOptions, cdeEncodeOptions, dcborEncodeOptions, TYPES;
var init_encoder = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/encoder.js"() {
    init_typeEncoderMap();
    init_constants();
    init_sorts();
    init_writer();
    init_box();
    init_float();
    init_lib();
    init_utils();
    ({ ENCODED } = SYMS);
    HALF = MT.SIMPLE_FLOAT << 5 | NUMBYTES.TWO;
    FLOAT = MT.SIMPLE_FLOAT << 5 | NUMBYTES.FOUR;
    DOUBLE = MT.SIMPLE_FLOAT << 5 | NUMBYTES.EIGHT;
    TRUE = MT.SIMPLE_FLOAT << 5 | SIMPLE.TRUE;
    FALSE = MT.SIMPLE_FLOAT << 5 | SIMPLE.FALSE;
    UNDEFINED = MT.SIMPLE_FLOAT << 5 | SIMPLE.UNDEFINED;
    NULL = MT.SIMPLE_FLOAT << 5 | SIMPLE.NULL;
    TE = new TextEncoder();
    WE = new Wtf8Encoder();
    defaultEncodeOptions = {
      ...Writer.defaultOptions,
      avoidInts: false,
      cde: false,
      collapseBigInts: true,
      dateTag: TAG.DATE_EPOCH,
      dcbor: false,
      float64: false,
      flushToZero: false,
      forceEndian: null,
      ignoreOriginalEncoding: false,
      largeNegativeAsBigInt: false,
      reduceUnsafeNumbers: false,
      rejectBigInts: false,
      rejectCustomSimples: false,
      rejectDuplicateKeys: false,
      rejectFloats: false,
      rejectUndefined: false,
      simplifyNegativeZero: false,
      sortKeys: null,
      stringNormalization: null,
      types: null,
      wtf8: false,
      ignoreGlobalTags: false
    };
    cdeEncodeOptions = {
      cde: true,
      ignoreOriginalEncoding: true,
      sortKeys: sortCoreDeterministic
    };
    dcborEncodeOptions = {
      ...cdeEncodeOptions,
      dcbor: true,
      largeNegativeAsBigInt: true,
      reduceUnsafeNumbers: true,
      rejectCustomSimples: true,
      rejectDuplicateKeys: true,
      rejectUndefined: true,
      simplifyNegativeZero: true,
      stringNormalization: "NFC"
    };
    TYPES = new TypeEncoderMap();
    TYPES.registerEncoder(Array, writeArray);
    TYPES.registerEncoder(Uint8Array, writeUint8Array);
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/simple.js
var Simple;
var init_simple = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/simple.js"() {
    init_constants();
    init_encoder();
    Simple = class _Simple {
      static KnownSimple = /* @__PURE__ */ new Map([
        [SIMPLE.FALSE, false],
        [SIMPLE.TRUE, true],
        [SIMPLE.NULL, null],
        [SIMPLE.UNDEFINED, void 0]
      ]);
      value;
      constructor(value) {
        this.value = value;
      }
      static create(num) {
        if (!_Simple.KnownSimple.has(num)) {
          return new _Simple(num);
        }
        return _Simple.KnownSimple.get(num);
      }
      toCBOR(w, opts) {
        if (opts.rejectCustomSimples) {
          throw new Error(`Cannot encode non-standard Simple value: ${this.value}`);
        }
        writeInt(this.value, w, MT.SIMPLE_FLOAT);
      }
      toString() {
        return `simple(${this.value})`;
      }
      /**
       * Convert this simple value to a useful data type, if possible.
       *
       * @returns The converted value.
       */
      decode() {
        if (!_Simple.KnownSimple.has(this.value)) {
          return this;
        }
        return _Simple.KnownSimple.get(this.value);
      }
      [/* @__PURE__ */ Symbol.for("nodejs.util.inspect.custom")](_depth, inspectOptions, inspect) {
        return `simple(${inspect(this.value, inspectOptions)})`;
      }
    };
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/decodeStream.js
var TD, DecodeStream;
var init_decodeStream2 = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/decodeStream.js"() {
    init_constants();
    init_utils();
    init_simple();
    init_float();
    TD = new TextDecoder("utf8", { fatal: true, ignoreBOM: true });
    DecodeStream = class _DecodeStream {
      static defaultOptions = {
        maxDepth: 1024,
        encoding: "hex",
        requirePreferred: false
      };
      #src;
      #view;
      #offset = 0;
      #opts;
      constructor(src, opts) {
        this.#opts = {
          ..._DecodeStream.defaultOptions,
          ...opts
        };
        if (typeof src === "string") {
          switch (this.#opts.encoding) {
            case "hex":
              this.#src = hexToU8(src);
              break;
            case "base64":
              this.#src = base64ToBytes(src);
              break;
            default:
              throw new TypeError(`Encoding not implemented: "${this.#opts.encoding}"`);
          }
        } else {
          this.#src = src;
        }
        this.#view = new DataView(this.#src.buffer, this.#src.byteOffset, this.#src.byteLength);
      }
      /**
       * Get the chunk of this stream from the given position to the current offset.
       *
       * @param begin Position to read from.  Should be <= current offset.
       * @returns Subarray of input stream (not copy).
       */
      toHere(begin) {
        return subarrayRanges(this.#src, begin, this.#offset);
      }
      /**
       * Get the stream of events describing the CBOR item.  Yields Value tuples.
       *
       * @throws On invalid input or extra data in input.
       * @yields MtAiValue for each value in the stream.
       * @example
       * ```js
       * const s = new DecodeStream(buffer);
       * for (const [majorType, additionalInfo, value] of s) {
       *  ...
       * }
       * ```
       */
      *[Symbol.iterator]() {
        yield* this.#nextVal(0);
        if (this.#offset !== this.#src.length) {
          throw new Error("Extra data in input");
        }
      }
      /**
       * Get a stream of events describing all CBOR items in the input CBOR Sequence
       * consisting of multiple CBOR items. Yields Value tuples.
       *
       * Note that this includes items indicating the start of an array or map, and
       * the end of an indefinite-length item, and tag numbers separate from the tag
       * content. Does not guarantee that the input is valid.
       *
       * Will attempt to read all items in an array or map, even if indefinite.
       * Throws when there is insufficient data to do so. The same applies when
       * reading tagged items, byte strings and text strings.
       *
       * @throws On insufficient data.
       * @yields MtAiValue for each value in the sequence.
       * @example
       * ```js
       * const s = new DecodeStream(buffer);
       * for (const [majorType, additionalInfo, value] of s.seq()) {
       *  ...
       * }
       * ```
       */
      *seq() {
        while (this.#offset < this.#src.length) {
          yield* this.#nextVal(0);
        }
      }
      /**
       * Get the next CBOR value from the input stream.  Yields Value tuples.
       *
       * @param depth The current depth in the CBOR tree.
       * @throws Maximum depth exceeded, invalid input.
       * @yields Information about every sub-item found in the input.
       */
      *#nextVal(depth) {
        if (depth++ > this.#opts.maxDepth) {
          throw new Error(`Maximum depth ${this.#opts.maxDepth} exceeded`);
        }
        const prevOffset = this.#offset;
        const octet = this.#view.getUint8(this.#offset++);
        const mt = octet >> 5;
        const ai = octet & 31;
        let val = ai;
        let simple = false;
        let len = 0;
        switch (ai) {
          case NUMBYTES.ONE:
            len = 1;
            val = this.#view.getUint8(this.#offset);
            if (mt === MT.SIMPLE_FLOAT) {
              if (val < 32) {
                throw new Error(`Invalid simple encoding in extra byte: ${val}`);
              }
              simple = true;
            } else if (this.#opts.requirePreferred && val < 24) {
              throw new Error(`Unexpectedly long integer encoding (1) for ${val}`);
            }
            break;
          case NUMBYTES.TWO:
            len = 2;
            if (mt === MT.SIMPLE_FLOAT) {
              val = parseHalf(this.#src, this.#offset);
            } else {
              val = this.#view.getUint16(this.#offset, false);
              if (this.#opts.requirePreferred && val <= 255) {
                throw new Error(`Unexpectedly long integer encoding (2) for ${val}`);
              }
            }
            break;
          case NUMBYTES.FOUR:
            len = 4;
            if (mt === MT.SIMPLE_FLOAT) {
              val = this.#view.getFloat32(this.#offset, false);
            } else {
              val = this.#view.getUint32(this.#offset, false);
              if (this.#opts.requirePreferred && val <= 65535) {
                throw new Error(`Unexpectedly long integer encoding (4) for ${val}`);
              }
            }
            break;
          case NUMBYTES.EIGHT: {
            len = 8;
            if (mt === MT.SIMPLE_FLOAT) {
              val = this.#view.getFloat64(this.#offset, false);
            } else {
              val = this.#view.getBigUint64(this.#offset, false);
              if (val <= Number.MAX_SAFE_INTEGER) {
                val = Number(val);
              }
              if (this.#opts.requirePreferred && val <= 4294967295) {
                throw new Error(`Unexpectedly long integer encoding (8) for ${val}`);
              }
            }
            break;
          }
          case 28:
          case 29:
          case 30:
            throw new Error(`Additional info not implemented: ${ai}`);
          case NUMBYTES.INDEFINITE:
            switch (mt) {
              case MT.POS_INT:
              case MT.NEG_INT:
              case MT.TAG:
                throw new Error(`Invalid indefinite encoding for MT ${mt}`);
              case MT.SIMPLE_FLOAT:
                yield [mt, ai, SYMS.BREAK, prevOffset, 0];
                return;
            }
            val = Infinity;
            break;
          default:
            simple = true;
        }
        this.#offset += len;
        switch (mt) {
          case MT.POS_INT:
            yield [mt, ai, val, prevOffset, len];
            break;
          case MT.NEG_INT:
            yield [mt, ai, typeof val === "bigint" ? -1n - val : -1 - Number(val), prevOffset, len];
            break;
          case MT.BYTE_STRING:
            if (val === Infinity) {
              yield* this.#stream(mt, depth, prevOffset);
            } else {
              yield [mt, ai, this.#read(val), prevOffset, val];
            }
            break;
          case MT.UTF8_STRING:
            if (val === Infinity) {
              yield* this.#stream(mt, depth, prevOffset);
            } else {
              yield [mt, ai, TD.decode(this.#read(val)), prevOffset, val];
            }
            break;
          case MT.ARRAY:
            if (val === Infinity) {
              yield* this.#stream(mt, depth, prevOffset, false);
            } else {
              const nval = Number(val);
              yield [mt, ai, nval, prevOffset, len];
              for (let i = 0; i < nval; i++) {
                yield* this.#nextVal(depth + 1);
              }
            }
            break;
          case MT.MAP:
            if (val === Infinity) {
              yield* this.#stream(mt, depth, prevOffset, false);
            } else {
              const nval = Number(val);
              yield [mt, ai, nval, prevOffset, len];
              for (let i = 0; i < nval; i++) {
                yield* this.#nextVal(depth);
                yield* this.#nextVal(depth);
              }
            }
            break;
          case MT.TAG:
            yield [mt, ai, val, prevOffset, len];
            yield* this.#nextVal(depth);
            break;
          case MT.SIMPLE_FLOAT: {
            const oval = val;
            if (simple) {
              val = Simple.create(Number(val));
            }
            yield [mt, ai, val, prevOffset, oval];
            break;
          }
        }
      }
      #read(size) {
        const a = subarrayRanges(this.#src, this.#offset, this.#offset += size);
        if (a.length !== size) {
          throw new Error(`Unexpected end of stream reading ${size} bytes, got ${a.length}`);
        }
        return a;
      }
      *#stream(mt, depth, prevOffset, check = true) {
        yield [mt, NUMBYTES.INDEFINITE, Infinity, prevOffset, Infinity];
        while (true) {
          const child = this.#nextVal(depth);
          const first = child.next();
          const [nmt, ai, val] = first.value;
          if (val === SYMS.BREAK) {
            yield first.value;
            child.next();
            return;
          }
          if (check) {
            if (nmt !== mt) {
              throw new Error(`Unmatched major type.  Expected ${mt}, got ${nmt}.`);
            }
            if (ai === NUMBYTES.INDEFINITE) {
              throw new Error("New stream started in typed stream");
            }
          }
          yield first.value;
          yield* child;
        }
      }
    };
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/options.js
var DiagnosticSizes;
var init_options = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/options.js"() {
    (function(DiagnosticSizes2) {
      DiagnosticSizes2[DiagnosticSizes2["NEVER"] = -1] = "NEVER";
      DiagnosticSizes2[DiagnosticSizes2["PREFERRED"] = 0] = "PREFERRED";
      DiagnosticSizes2[DiagnosticSizes2["ALWAYS"] = 1] = "ALWAYS";
    })(DiagnosticSizes || (DiagnosticSizes = {}));
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/container.js
function createObject(kve, opts) {
  return !opts.boxed && !opts.preferMap && kve.every(([k]) => typeof k === "string") ? Object.fromEntries(kve) : new Map(kve);
}
var LENGTH_FOR_AI, EMPTY_BUF, CBORcontainer;
var init_container = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/container.js"() {
    init_constants();
    init_options();
    init_sorts();
    init_float();
    init_box();
    init_encoder();
    init_utils();
    init_decodeStream2();
    init_simple();
    init_tag();
    LENGTH_FOR_AI = /* @__PURE__ */ new Map([
      [NUMBYTES.ZERO, 1],
      [NUMBYTES.ONE, 2],
      [NUMBYTES.TWO, 3],
      [NUMBYTES.FOUR, 5],
      [NUMBYTES.EIGHT, 9]
    ]);
    EMPTY_BUF = new Uint8Array(0);
    CBORcontainer = class _CBORcontainer {
      static defaultDecodeOptions = {
        ...DecodeStream.defaultOptions,
        ParentType: _CBORcontainer,
        boxed: false,
        cde: false,
        dcbor: false,
        diagnosticSizes: DiagnosticSizes.PREFERRED,
        collapseBigInts: false,
        convertUnsafeIntsToFloat: false,
        createObject,
        keepNanPayloads: false,
        maxBigIntBytes: 1e4,
        pretty: false,
        preferBigInt: false,
        preferMap: false,
        rejectLargeNegatives: false,
        rejectBigInts: false,
        rejectDuplicateKeys: false,
        rejectFloats: false,
        rejectInts: false,
        rejectLongLoundNaN: false,
        rejectLongFloats: false,
        rejectNegativeZero: false,
        rejectSimple: false,
        rejectStreaming: false,
        rejectStringsNotNormalizedAs: null,
        rejectSubnormals: false,
        rejectUndefined: false,
        rejectUnsafeFloatInts: false,
        saveOriginal: false,
        sortKeys: null,
        tags: null,
        ignoreGlobalTags: false
      };
      /**
       * Throw errors when decoding for bytes that were not encoded with {@link
       * https://www.ietf.org/archive/id/draft-ietf-cbor-cde-05.html CBOR Common
       * Deterministic Encoding Profile}.
       *
       * CDE does not mandate this checking, so it is up to the application
       * whether it wants to ensure that inputs were not encoded incompetetently
       * or maliciously.  To turn all of these on at once, set the cbor option to
       * true.
       */
      static cdeDecodeOptions = {
        cde: true,
        rejectStreaming: true,
        requirePreferred: true,
        sortKeys: sortCoreDeterministic
      };
      /**
       * Throw errors when decoding for bytes that were not encoded with {@link
       * https://www.ietf.org/archive/id/draft-mcnally-deterministic-cbor-11.html
       * dCBOR: A Deterministic CBOR Application Profile}.
       *
       * The dCBOR spec mandates that these errors be thrown when decoding dCBOR.
       * Turn this on by setting the `dcbor` option to true, which also enables
       * `cde` mode.
       */
      static dcborDecodeOptions = {
        ...this.cdeDecodeOptions,
        dcbor: true,
        convertUnsafeIntsToFloat: true,
        rejectDuplicateKeys: true,
        rejectLargeNegatives: true,
        rejectLongLoundNaN: true,
        rejectLongFloats: true,
        rejectNegativeZero: true,
        rejectSimple: true,
        rejectUndefined: true,
        rejectUnsafeFloatInts: true,
        rejectStringsNotNormalizedAs: "NFC"
      };
      parent;
      mt;
      ai;
      left;
      offset;
      count = 0;
      children = [];
      depth = 0;
      #opts;
      #encodedChildren = null;
      // Only call new from create() and super().
      constructor(mav, left, parent, opts) {
        [this.mt, this.ai, , this.offset] = mav;
        this.left = left;
        this.parent = parent;
        this.#opts = opts;
        if (parent) {
          this.depth = parent.depth + 1;
        }
        if (this.mt === MT.MAP) {
          if (this.#opts.sortKeys || this.#opts.rejectDuplicateKeys) {
            this.#encodedChildren = [];
          }
        }
        if (this.#opts.rejectStreaming && this.ai === NUMBYTES.INDEFINITE) {
          throw new Error("Streaming not supported");
        }
      }
      get isStreaming() {
        return this.left === Infinity;
      }
      get done() {
        return this.left === 0;
      }
      /**
       * Factory method that returns the given ParentType if the mt/ai dictate
       * that is necessary, otherwise returns the given value.
       *
       * @param mav Major Type, Additional Information, and Associated value from
       *   token.
       * @param parent If this item is inside another item, the direct parent.
       * @param opts Options controlling creation.
       * @param stream The stream being decoded from.
       * @returns ParentType instance or value.
       * @throws Invalid major type, which should only occur from tests.
       */
      static create(mav, parent, opts, stream) {
        const [mt, ai, value, offset] = mav;
        switch (mt) {
          case MT.POS_INT:
          case MT.NEG_INT: {
            if (opts.rejectInts) {
              throw new Error(`Unexpected integer: ${value}`);
            }
            if (opts.rejectLargeNegatives && value < -0x8000000000000000n) {
              throw new Error(`Invalid 65bit negative number: ${value}`);
            }
            let val = value;
            if (opts.preferBigInt) {
              val = BigInt(val);
            } else if (opts.convertUnsafeIntsToFloat && val >= DCBOR_INT.MIN && val <= DCBOR_INT.MAX) {
              val = Number(value);
            }
            if (opts.boxed) {
              return box(val, stream.toHere(offset));
            }
            return val;
          }
          case MT.SIMPLE_FLOAT:
            if (ai > NUMBYTES.ONE) {
              if (typeof value === "symbol") {
                return value;
              }
              if (opts.rejectFloats) {
                throw new Error(`Decoding unwanted floating point number: ${value}`);
              }
              if (opts.rejectNegativeZero && Object.is(value, -0)) {
                throw new Error("Decoding negative zero");
              }
              if (isNaN(value)) {
                const buf = stream.toHere(offset);
                const val = new NAN(buf);
                if (opts.rejectLongLoundNaN) {
                  if (val.payload || buf.length > 3) {
                    throw new Error(`Invalid NaN encoding: "${u8toHex(buf)}"`);
                  }
                } else if (opts.keepNanPayloads) {
                  if (val.payload || val.sign === -1) {
                    if (opts.rejectLongFloats && !val.isShortestEncoding) {
                      throw new Error(`NaN should have been encoded shorter: ${value}`);
                    }
                    return val;
                  }
                }
              }
              if (opts.rejectSubnormals) {
                checkSubnormal(stream.toHere(offset + 1));
              }
              if (opts.rejectLongFloats) {
                const buf = encode(value, {
                  chunkSize: 9,
                  reduceUnsafeNumbers: opts.rejectUnsafeFloatInts
                });
                if (buf[0] >> 5 !== mt) {
                  throw new Error(`Should have been encoded as int, not float: ${value}`);
                }
                if (buf.length < LENGTH_FOR_AI.get(ai)) {
                  throw new Error(`Number should have been encoded shorter: ${value}`);
                }
              }
              if (typeof value === "number" && opts.boxed) {
                return box(value, stream.toHere(offset));
              }
            } else {
              if (opts.rejectSimple) {
                if (value instanceof Simple) {
                  throw new Error(`Invalid simple value: ${value}`);
                }
              }
              if (opts.rejectUndefined) {
                if (value === void 0) {
                  throw new Error("Unexpected undefined");
                }
              }
            }
            return value;
          case MT.BYTE_STRING:
          case MT.UTF8_STRING:
            if (value === Infinity) {
              return new opts.ParentType(mav, Infinity, parent, opts);
            }
            if (opts.rejectStringsNotNormalizedAs && typeof value === "string") {
              const n = value.normalize(opts.rejectStringsNotNormalizedAs);
              if (value !== n) {
                throw new Error(`String not normalized as "${opts.rejectStringsNotNormalizedAs}", got [${stringToHex(value)}] instead of [${stringToHex(n)}]`);
              }
            }
            if (opts.boxed) {
              return box(value, stream.toHere(offset));
            }
            return value;
          case MT.ARRAY:
            return new opts.ParentType(mav, value, parent, opts);
          case MT.MAP:
            return new opts.ParentType(mav, value * 2, parent, opts);
          case MT.TAG: {
            const ret = new opts.ParentType(mav, 1, parent, opts);
            ret.children = new Tag(value);
            return ret;
          }
        }
        throw new TypeError(`Invalid major type: ${mt}`);
      }
      static decodeToEncodeOpts(decode4) {
        return {
          ...defaultEncodeOptions,
          avoidInts: decode4.rejectInts,
          float64: !decode4.rejectLongFloats,
          flushToZero: decode4.rejectSubnormals,
          largeNegativeAsBigInt: decode4.rejectLargeNegatives,
          sortKeys: decode4.sortKeys
        };
      }
      /**
       * Add the given child to the list of children, and update how many are
       * still needed.
       *
       * @param child Any child item.
       * @param stream Stream being read from.
       * @param offset Offset of start of child in stream.
       * @returns The number of items still needed.
       */
      push(child, stream, offset) {
        this.children.push(child);
        if (this.#encodedChildren) {
          const buf = getEncoded(child) || stream.toHere(offset);
          this.#encodedChildren.push(buf);
        }
        return --this.left;
      }
      /**
       * Replace the last child with this one.  Usually after having called
       * convert on the most recent child.
       *
       * @param child New child value.
       * @param item The key or value container.  Used to check for dups.
       * @param stream The stream being read from.
       * @returns Previous child value.
       * @throws Duplicate key.
       */
      replaceLast(child, item, stream) {
        let ret = void 0;
        let last = -Infinity;
        if (this.children instanceof Tag) {
          last = 0;
          ret = this.children.contents;
          this.children.contents = child;
        } else {
          last = this.children.length - 1;
          ret = this.children[last];
          this.children[last] = child;
        }
        if (this.#encodedChildren) {
          const buf = getEncoded(child) || stream.toHere(item.offset);
          this.#encodedChildren[last] = buf;
        }
        return ret;
      }
      /**
       * Converts the childen to the most appropriate form known.
       *
       * @param stream Stream that we are reading from.
       * @returns Anything BUT a CBORcontainer.
       * @throws Invalid major type.  Only possible in testing.
       */
      convert(stream) {
        let ret = void 0;
        switch (this.mt) {
          case MT.ARRAY:
            ret = this.children;
            break;
          case MT.MAP: {
            const pu = this.#pairs();
            if (this.#opts.sortKeys) {
              let lastKey = void 0;
              for (const kve of pu) {
                if (lastKey) {
                  if (this.#opts.sortKeys(lastKey, kve) >= 0) {
                    throw new Error(`Duplicate or out of order key: "0x${kve[2]}"`);
                  }
                }
                lastKey = kve;
              }
            } else if (this.#opts.rejectDuplicateKeys) {
              const ks = /* @__PURE__ */ new Set();
              for (const [_k, _v, e] of pu) {
                const hex = u8toHex(e);
                if (ks.has(hex)) {
                  throw new Error(`Duplicate key: "0x${hex}"`);
                }
                ks.add(hex);
              }
            }
            ret = this.#opts.createObject(pu, this.#opts);
            break;
          }
          case MT.BYTE_STRING: {
            return u8concat(this.children);
          }
          case MT.UTF8_STRING: {
            const str = this.children.join("");
            ret = this.#opts.boxed ? box(str, stream.toHere(this.offset)) : str;
            break;
          }
          case MT.TAG:
            ret = this.children.decode(this.#opts);
            break;
          default:
            throw new TypeError(`Invalid mt on convert: ${this.mt}`);
        }
        if (this.#opts.saveOriginal && ret && typeof ret === "object") {
          saveEncoded(ret, stream.toHere(this.offset));
        }
        return ret;
      }
      #pairs() {
        const ary = this.children;
        const len = ary.length;
        if (len % 2) {
          throw new Error("Missing map value");
        }
        const ret = new Array(len / 2);
        if (this.#encodedChildren) {
          for (let i = 0; i < len; i += 2) {
            ret[i >> 1] = [ary[i], ary[i + 1], this.#encodedChildren[i]];
          }
        } else {
          for (let i = 0; i < len; i += 2) {
            ret[i >> 1] = [ary[i], ary[i + 1], EMPTY_BUF];
          }
        }
        return ret;
      }
    };
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/decoder.js
var init_decoder = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/cbor2/lib/decoder.js"() {
    init_decodeStream2();
    init_container();
    init_constants();
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/cryptographic-computer-data-engineering-services-section/src/portable-sha256.mjs
function rotr(x, n) {
  return x >>> n | x << 32 - n;
}
function sha256Bytes(bytes2) {
  if (nativeCrypto !== void 0) return nativeCrypto.createHash("sha256").update(bytes2).digest("hex");
  return portableSha256Bytes(bytes2);
}
function portableSha256Bytes(bytes2) {
  const bitLen = bytes2.length * 8;
  const padLen = (bytes2.length + 8 >> 6) + 1 << 6;
  const buf = new Uint8Array(padLen);
  buf.set(bytes2);
  buf[bytes2.length] = 128;
  const view = new DataView(buf.buffer);
  view.setUint32(padLen - 8, Math.floor(bitLen / 4294967296), false);
  view.setUint32(padLen - 4, bitLen >>> 0, false);
  const h = H0.slice();
  const w = new Uint32Array(64);
  for (let offset = 0; offset < padLen; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ w[i - 15] >>> 3;
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ w[i - 2] >>> 10;
      w[i] = w[i - 16] + s0 + w[i - 7] + s1 | 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = e & f ^ ~e & g;
      const t1 = hh + S1 + ch + K[i] + w[i] | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = a & b ^ a & c ^ b & c;
      const t2 = S0 + maj | 0;
      hh = g;
      g = f;
      f = e;
      e = d + t1 | 0;
      d = c;
      c = b;
      b = a;
      a = t1 + t2 | 0;
    }
    h[0] = h[0] + a | 0;
    h[1] = h[1] + b | 0;
    h[2] = h[2] + c | 0;
    h[3] = h[3] + d | 0;
    h[4] = h[4] + e | 0;
    h[5] = h[5] + f | 0;
    h[6] = h[6] + g | 0;
    h[7] = h[7] + hh | 0;
  }
  let hex = "";
  for (const word of h) hex += (word >>> 0).toString(16).padStart(8, "0");
  return hex;
}
var K, H0, nativeCrypto;
var init_portable_sha256 = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/cryptographic-computer-data-engineering-services-section/src/portable-sha256.mjs"() {
    K = new Uint32Array([
      1116352408,
      1899447441,
      3049323471,
      3921009573,
      961987163,
      1508970993,
      2453635748,
      2870763221,
      3624381080,
      310598401,
      607225278,
      1426881987,
      1925078388,
      2162078206,
      2614888103,
      3248222580,
      3835390401,
      4022224774,
      264347078,
      604807628,
      770255983,
      1249150122,
      1555081692,
      1996064986,
      2554220882,
      2821834349,
      2952996808,
      3210313671,
      3336571891,
      3584528711,
      113926993,
      338241895,
      666307205,
      773529912,
      1294757372,
      1396182291,
      1695183700,
      1986661051,
      2177026350,
      2456956037,
      2730485921,
      2820302411,
      3259730800,
      3345764771,
      3516065817,
      3600352804,
      4094571909,
      275423344,
      430227734,
      506948616,
      659060556,
      883997877,
      958139571,
      1322822218,
      1537002063,
      1747873779,
      1955562222,
      2024104815,
      2227730452,
      2361852424,
      2428436474,
      2756734187,
      3204031479,
      3329325298
    ]);
    H0 = new Uint32Array([
      1779033703,
      3144134277,
      1013904242,
      2773480762,
      1359893119,
      2600822924,
      528734635,
      1541459225
    ]);
    nativeCrypto = globalThis.process?.getBuiltinModule?.("node:crypto");
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/json-services-section/src/json-byte-carrier.mjs
var init_json_byte_carrier = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/json-services-section/src/json-byte-carrier.mjs"() {
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/cbor-services-section/node_modules/@red-cup-engineering/uri-services-section/src/ni-uri.mjs
var init_ni_uri = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/cbor-services-section/node_modules/@red-cup-engineering/uri-services-section/src/ni-uri.mjs"() {
    init_portable_sha256();
    init_json_byte_carrier();
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/cryptographic-computer-data-engineering-services-section/src/portable-bytes.mjs
function bytesEqual(left, right) {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) if (left[index] !== right[index]) return false;
  return true;
}
function bytesCompare(left, right) {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index += 1) if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
  return left.length === right.length ? 0 : left.length < right.length ? -1 : 1;
}
var HEX, ownedBytes;
var init_portable_bytes = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/cryptographic-computer-data-engineering-services-section/src/portable-bytes.mjs"() {
    HEX = Array.from({ length: 256 }, (_, byte) => byte.toString(16).padStart(2, "0"));
    ownedBytes = (bytes2) => globalThis.Buffer ? globalThis.Buffer.from(bytes2) : Uint8Array.from(bytes2);
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/cbor-services-section/src/cbor.mjs
function fail2(code, message) {
  const error2 = new Error(message);
  error2.code = code;
  throw error2;
}
function unsigned(value) {
  const integer = typeof value === "bigint" ? value : BigInt(value);
  if (integer < 0n || integer > 0xffffffffffffffffn) fail2("non-canonical-cbor", "CBOR argument is outside the CBOR uint64 profile");
  return integer;
}
function encode2(value) {
  const writer = new Writer(), ancestors = /* @__PURE__ */ new Set(), stack = [{ value }];
  while (stack.length) {
    const item = stack.pop();
    if (item.exit) {
      ancestors.delete(item.value);
      continue;
    }
    if (item.bytes) {
      writer.write(item.bytes);
      continue;
    }
    const member = item.value;
    if (member instanceof Tag) fail2("non-canonical-cbor", "CBOR tags are outside the supported CBOR codec profile");
    if (member instanceof Uint8Array) {
      writeUint8Array(member, writer);
      continue;
    }
    if (Array.isArray(member) || member && Object.getPrototypeOf(member) === Object.prototype) {
      if (ancestors.has(member)) fail2("non-canonical-cbor", "cyclic CBOR carrier");
      ancestors.add(member);
      stack.push({ exit: true, value: member });
      if (Array.isArray(member)) {
        writeInt(member.length, writer, 4);
        for (let index = member.length - 1; index >= 0; index--) stack.push({ value: member[index] });
      } else {
        const entries = Object.entries(member).filter(([, entry]) => entry !== void 0).map(([key, entry]) => ({ bytes: encode2(key), value: entry })).sort((left, right) => bytesCompare(left.bytes, right.bytes));
        writeInt(entries.length, writer, 5);
        for (let index = entries.length - 1; index >= 0; index--) {
          stack.push({ value: entries[index].value });
          stack.push({ bytes: entries[index].bytes });
        }
      }
      continue;
    }
    if (typeof member === "number" && !Number.isFinite(member)) fail2("non-canonical-cbor", "CBOR codec numbers must be finite");
    if (typeof member === "bigint") unsigned(member < 0n ? -1n - member : member);
    if (typeof member === "string" && !member.isWellFormed()) fail2("non-canonical-cbor", "CBOR text string contains an unpaired Unicode surrogate");
    if (member !== null && !["boolean", "number", "bigint", "string"].includes(typeof member)) fail2("non-canonical-cbor", `unsupported CBOR codec carrier value ${Object.prototype.toString.call(member)}`);
    writeUnknown(member, writer, OPTIONS);
  }
  return ownedBytes(writer.read());
}
function encodeCanonical(value) {
  return encode2(value);
}
var OPTIONS;
var init_cbor = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/cbor-services-section/src/cbor.mjs"() {
    init_encoder();
    init_decoder();
    init_writer();
    init_tag();
    init_ni_uri();
    init_portable_bytes();
    OPTIONS = Object.freeze({ ...defaultEncodeOptions, simplifyNegativeZero: true, ignoreOriginalEncoding: true, ignoreGlobalTags: true });
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-content-address-engineering-services-section/node_modules/@red-cup-engineering/uri-services-section/src/ni-uri.mjs
function base64url(bytes2) {
  let text2 = "";
  for (const byte of bytes2) text2 += String.fromCharCode(byte);
  return btoa(text2).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function sha2562(bytes2) {
  const hex = sha256Bytes(bytes2);
  return Uint8Array.from(hex.match(/../g), (pair) => Number.parseInt(pair, 16));
}
function byteString(value) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError("ni URI input must be a Uint8Array");
  }
  return value;
}
function makeNiUri2(bytes2) {
  const digest = base64url(sha2562(byteString(bytes2)));
  return `${NI_PREFIX}${digest}`;
}
var NI_PREFIX;
var init_ni_uri2 = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-content-address-engineering-services-section/node_modules/@red-cup-engineering/uri-services-section/src/ni-uri.mjs"() {
    init_portable_sha256();
    init_json_byte_carrier();
    NI_PREFIX = "ni:///sha-256;";
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-content-address-engineering-services-section/src/semiotic-content-address.mjs
function canonicalizeSemioticJson(value) {
  return copyCarrier(value, true);
}
function copyCarrier(value, normalizeText) {
  let canonical2;
  const pending = [{ source: value, place: (result) => {
    canonical2 = result;
  } }];
  const open = /* @__PURE__ */ new Set();
  while (pending.length > 0) {
    const item = pending.pop();
    if (item.close) {
      open.delete(item.close);
      continue;
    }
    const { source, place } = item;
    if (typeof source === "string") {
      place(normalizeText ? source.normalize("NFC") : source);
      continue;
    }
    if (source !== null && typeof source === "object" && (canonicalSnapshots.has(source) || !normalizeText && retainedSnapshots.has(source))) {
      place(source);
      continue;
    }
    if (source instanceof Uint8Array) {
      place(copyBytes(source));
      continue;
    }
    if (source === null || typeof source === "boolean" || typeof source === "bigint") {
      place(source);
      continue;
    }
    if (typeof source === "number") {
      if (!Number.isFinite(source)) throw new TypeError("semiotic JSON numbers must be finite");
      place(source);
      continue;
    }
    if ((Array.isArray(source) || source && typeof source === "object") && open.has(source)) throw new TypeError("semiotic JSON must not be cyclic");
    if (Array.isArray(source)) {
      open.add(source);
      pending.push({ close: source });
      const result = new Array(source.length);
      place(result);
      for (let index = source.length - 1; index >= 0; index -= 1)
        pending.push({ source: source[index], place: (member) => {
          result[index] = member;
        } });
      continue;
    }
    if (source && Object.getPrototypeOf(source) === Object.prototype) {
      open.add(source);
      pending.push({ close: source });
      const result = {};
      const members = [], normalizedKeys = /* @__PURE__ */ new Set();
      for (const [key, member] of Object.entries(source)) {
        if (member === void 0) continue;
        const canonicalKey = key.normalize("NFC");
        if (normalizedKeys.has(canonicalKey)) throw new TypeError(`semiotic JSON map keys collide after NFC normalization: ${canonicalKey}`);
        normalizedKeys.add(canonicalKey);
        const retainedKey = normalizeText ? canonicalKey : key;
        Object.defineProperty(result, retainedKey, { value: void 0, enumerable: true, writable: true, configurable: true });
        members.push([retainedKey, member]);
      }
      place(result);
      for (let index = members.length - 1; index >= 0; index -= 1) {
        const [key, member] = members[index];
        pending.push({ source: member, place: (canonicalMember) => {
          result[key] = canonicalMember;
        } });
      }
      continue;
    }
    throw new TypeError(`unsupported semiotic JSON value ${Object.prototype.toString.call(source)}`);
  }
  return canonical2;
}
function semanticBytes(value) {
  const memo = value !== null && typeof value === "object" && canonicalSnapshots.has(value);
  if (memo) {
    const cached = frozenBytes.get(value);
    if (cached !== void 0) return ownedBytes(cached);
  }
  const bytes2 = encodeCanonical(canonicalizeSemioticJson(value));
  if (memo) frozenBytes.set(value, bytes2);
  return ownedBytes(bytes2);
}
function semanticAddress(value) {
  const bytes2 = semanticBytes(value);
  return Object.freeze({ id: makeNiUri2(bytes2), bytes: bytes2 });
}
function semanticId(value) {
  return semanticAddress(value).id;
}
function coincides(left, right) {
  if (typeof left === "string" && typeof right === "string") return left === right || left.normalize("NFC") === right.normalize("NFC");
  if (isScalar(left) && isScalar(right) && typeof left !== "string" && typeof right !== "string") {
    if (typeof left === "number" && !Number.isFinite(left)) semanticBytes(left);
    if (typeof right === "number" && !Number.isFinite(right)) semanticBytes(right);
    return left === right;
  }
  return bytesEqual(semanticBytes(left), semanticBytes(right));
}
var canonicalSnapshots, retainedSnapshots, copyBytes, frozenBytes, isScalar;
var init_semiotic_content_address = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-content-address-engineering-services-section/src/semiotic-content-address.mjs"() {
    init_cbor();
    init_ni_uri2();
    init_portable_sha256();
    init_portable_bytes();
    init_portable_bytes();
    canonicalSnapshots = /* @__PURE__ */ new WeakSet();
    retainedSnapshots = /* @__PURE__ */ new WeakSet();
    copyBytes = (value) => value.constructor === Uint8Array ? Uint8Array.from(value) : ownedBytes(value);
    frozenBytes = /* @__PURE__ */ new WeakMap();
    isScalar = (value) => value === null || ["string", "number", "boolean"].includes(typeof value);
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/node_modules/@red-cup-engineering/uri-services-section/src/ni-uri.mjs
function base64url2(bytes2) {
  let text2 = "";
  for (const byte of bytes2) text2 += String.fromCharCode(byte);
  return btoa(text2).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromBase64url(value) {
  const text2 = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(text2, (character) => character.charCodeAt(0));
}
function digestBytes(value) {
  if (typeof value !== "string" || !NI_URI_PATTERN.test(value)) return null;
  const encoded = value.slice(NI_PREFIX2.length);
  const digest = fromBase64url(encoded);
  return digest.length === 32 && base64url2(digest) === encoded ? digest : null;
}
function isNiUri(value) {
  return digestBytes(value) !== null;
}
var NI_PREFIX2, NI_URI_PATTERN;
var init_ni_uri3 = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/node_modules/@red-cup-engineering/uri-services-section/src/ni-uri.mjs"() {
    init_portable_sha256();
    init_json_byte_carrier();
    NI_PREFIX2 = "ni:///sha-256;";
    NI_URI_PATTERN = /^ni:\/\/\/sha-256;[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u;
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/semiotic-expression-notation/notation/forms.mjs
var SEN_FORMS, SEN_TYPE_FORMS;
var init_forms = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/semiotic-expression-notation/notation/forms.mjs"() {
    SEN_FORMS = Object.freeze({
      var: { atoms: { 1: "natural" } },
      star: {},
      mark: { atoms: { 1: "text" } },
      lam: { terms: [1], binders: [1] },
      app: { terms: [1, 2] },
      pair: { terms: [1, 2] },
      fst: { terms: [1] },
      snd: { terms: [1] },
      coincide: { terms: [1, 2] },
      cond: { terms: [1, 2, 3] },
      fold: { terms: [1, 2, 3] },
      prim: { atoms: { 1: "text" }, terms: [2] },
      inl: { terms: [1], types: [2] },
      inr: { types: [1], terms: [2] },
      case: { terms: [1, 2, 3], binders: [2, 3] },
      abort: { terms: [1], types: [2] }
    });
    SEN_TYPE_FORMS = Object.freeze({
      base: {},
      unit: {},
      arrow: { types: [1, 2] },
      prod: { types: [1, 2] },
      list: { types: [1] },
      empty: {},
      sum: { types: [1, 2] }
    });
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/semiotic-expression-notation/notation/schema.mjs
function tuple(tag, form, references) {
  const width = 1 + Object.keys(form.atoms ?? {}).length + (form.terms?.length ?? 0) + (form.types?.length ?? 0);
  const items = Array.from({ length: width }, () => ({}));
  items[0] = { const: tag };
  for (const index of form.terms ?? [])
    items[index] = { $ref: references.term };
  for (const index of form.types ?? [])
    items[index] = { $ref: references.type };
  for (const [index, constraint] of Object.entries(form.atoms ?? {}))
    items[index] = atomSchemas[constraint];
  return {
    type: "array",
    prefixItems: items,
    minItems: width,
    maxItems: width,
    items: false
  };
}
var atomSchemas, TySchema, TmSchema;
var init_schema = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/semiotic-expression-notation/notation/schema.mjs"() {
    init_forms();
    atomSchemas = {
      natural: { type: "integer", minimum: 0 },
      text: { type: "string" }
    };
    TySchema = {
      $id: "semiotic-expression-notation/term/ty",
      title: "SEN Ty",
      anyOf: Object.entries(SEN_TYPE_FORMS).map(
        ([tag, form]) => tuple(tag, form, { term: "#", type: "#" })
      )
    };
    TmSchema = {
      $id: "semiotic-expression-notation/term/tm",
      title: "SEN Tm",
      anyOf: Object.entries(SEN_FORMS).map(
        ([tag, form]) => tuple(tag, form, { term: "#", type: "semiotic-expression-notation/term/ty" })
      )
    };
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/semiotic-expression-notation/notation/validator.mjs
var init_validator = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/semiotic-expression-notation/notation/validator.mjs"() {
    init_notation();
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/four.mjs
function familyOf(name) {
  const family = familyByName.get(name);
  if (family === void 0) throw new TypeError(`four: unknown reading ${String(name)}`);
  return family;
}
function readingOfSides(family, forTold, againstTold) {
  const names = readingFamilies[family];
  if (names === void 0) throw new TypeError(`four: unknown reading family ${String(family)}`);
  return names[(forTold ? 1 : 0) + (againstTold ? 2 : 0)];
}
function sidesOfReading(name) {
  const index = readingFamilies[familyOf(name)].indexOf(name);
  return Object.freeze([(index & 1) === 1, (index & 2) === 2]);
}
function sharedFamily(left, right) {
  const family = familyOf(left);
  if (familyOf(right) !== family) throw new TypeError(`four: ${left} (${family}) and ${right} (${familyOf(right)}) are named in different families`);
  return family;
}
function twistProduct({ bottom, top, one, leq, meet, join, fuse, imply }) {
  const value = (positive2, negative) => Object.freeze([positive2, negative]);
  const lift = (positive2, negative) => ({ left: a, right: b }) => value(positive2(a[0], b[0]), negative(a[1], b[1]));
  return Object.freeze({
    value,
    knowledgeBottom: value(bottom, bottom),
    knowledgeTop: value(top, top),
    truthBottom: value(bottom, top),
    truthTop: value(top, bottom),
    one: value(one, one),
    meetKnowledge: lift(meet, meet),
    joinKnowledge: lift(join, join),
    meetTruth: lift(meet, join),
    joinTruth: lift(join, meet),
    leqKnowledge: ({ left: a, right: b }) => leq(a[0], b[0]) && leq(a[1], b[1]),
    leqTruth: ({ left: a, right: b }) => leq(a[0], b[0]) && leq(b[1], a[1]),
    negate: (a) => value(a[1], a[0]),
    fuse: ({ left: a, right: b }) => value(fuse(a[0], b[0]), meet(imply(a[0], b[1]), imply(b[0], a[1]))),
    imply: ({ left: a, right: b }) => value(meet(imply(a[0], b[0]), imply(b[1], a[1])), fuse(a[0], b[1]))
  });
}
function gauge(element, name) {
  if (element === "negation") return negateReading(name);
  if (element === "conflation") return conflateReading(name);
  if (element === "double") return negateReading(conflateReading(name));
  if (element === "id") return name;
  throw new TypeError(`four: unknown gauge element ${String(element)}`);
}
function fail3(code, message) {
  const error2 = new Error(message);
  error2.code = code;
  throw error2;
}
function four(positiveEvidence, negativeEvidence) {
  if (typeof positiveEvidence !== "boolean" || typeof negativeEvidence !== "boolean") {
    fail3("malformed-four", "FOUR requires explicit Boolean positiveEvidence and negativeEvidence bits");
  }
  return Object.freeze({ positiveEvidence, negativeEvidence });
}
var readingFamilies, familyByName, samePoint, isReading, onReadings, knowledgeJoinReading, knowledgeMeetReading, knowledgeLeqReading, truthJoinReading, truthMeetReading, truthLeqReading, knowledgeImplyReading, truthImplyReading, symmetricEvidenceDifferenceReading, negateReading, conflateReading, two, viaTwo, fusionReading, residuumReading, linearUnit, knowledgeBottom, knowledgeTop, truthTop, truthBottom, tally, record2, recordJoinK, recordMeetK, recordJoinT, recordMeetT, recordAdd, recordLeqK, recordLeqT, readingOfRecord, topMass, attestationRecord, gaugeElementNames, points, wireOfReading, FOUR, obsmetrologiaRealization;
var init_four = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/four.mjs"() {
    readingFamilies = Object.freeze({
      /** Relational: the knowledge order's reading, by what has been told. */
      knowledge: Object.freeze(["absurd", "potential", "active", "stable"]),
      /** Told (Dunn 1976): each point named by which of true and false it has been told. */
      told: Object.freeze(["told none", "told true", "told false", "told both"]),
      /** Logical (Belnap): the truth order's reading. */
      truth: Object.freeze(["neither", "true", "false", "both"]),
      /** Extremal: each point named by the order it is an extreme of — unknown and contested the
       *  knowledge bottom and top, denied and held the truth bottom and top. SEN's reading marks
       *  and claim sessions use these. */
      extremal: Object.freeze(["unknown", "held", "denied", "contested"])
    });
    familyByName = new Map(Object.entries(readingFamilies).flatMap(([family, names]) => names.map((name) => [name, family])));
    samePoint = (left, right) => sidesOfReading(left).join() === sidesOfReading(right).join();
    isReading = (name, family) => familyByName.has(name) && (family === void 0 || familyByName.get(name) === family);
    onReadings = (combine) => (left, right) => readingOfSides(sharedFamily(left, right), ...combine(...sidesOfReading(left), ...sidesOfReading(right)));
    knowledgeJoinReading = onReadings((lf, la, rf, ra) => [lf || rf, la || ra]);
    knowledgeMeetReading = onReadings((lf, la, rf, ra) => [lf && rf, la && ra]);
    knowledgeLeqReading = (left, right) => samePoint(knowledgeJoinReading(left, right), right);
    truthJoinReading = onReadings((lf, la, rf, ra) => [lf || rf, la && ra]);
    truthMeetReading = onReadings((lf, la, rf, ra) => [lf && rf, la || ra]);
    truthLeqReading = (left, right) => samePoint(truthJoinReading(left, right), right);
    knowledgeImplyReading = onReadings((lf, la, rf, ra) => [!lf || rf, !la || ra]);
    truthImplyReading = onReadings((lf, la, rf, ra) => [!lf || rf, !la && ra]);
    symmetricEvidenceDifferenceReading = onReadings(
      (lf, la, rf, ra) => [lf !== rf, la !== ra]
    );
    negateReading = (name) => {
      const [f, a] = sidesOfReading(name);
      return readingOfSides(familyOf(name), a, f);
    };
    conflateReading = (name) => {
      const [f, a] = sidesOfReading(name);
      return readingOfSides(familyOf(name), !a, !f);
    };
    two = twistProduct({ bottom: false, top: true, one: true, leq: (a, b) => !a || b, meet: (a, b) => a && b, join: (a, b) => a || b, fuse: (a, b) => a && b, imply: (a, b) => !a || b });
    viaTwo = (operation) => (left, right) => readingOfSides(sharedFamily(left, right), ...operation({ left: sidesOfReading(left), right: sidesOfReading(right) }));
    fusionReading = viaTwo(two.fuse);
    residuumReading = viaTwo(two.imply);
    linearUnit = (family = "knowledge") => readingOfSides(family, true, true);
    knowledgeBottom = (family = "knowledge") => readingOfSides(family, false, false);
    knowledgeTop = (family = "knowledge") => readingOfSides(family, true, true);
    truthTop = (family = "knowledge") => readingOfSides(family, true, false);
    truthBottom = (family = "knowledge") => readingOfSides(family, false, true);
    tally = (count) => {
      if (!Number.isSafeInteger(count) || count < 0)
        throw new TypeError(`four: a tally must be an exactly representable natural number, not ${String(count)}`);
      return count;
    };
    record2 = (pos = 0, neg = 0) => Object.freeze({ pos: tally(pos), neg: tally(neg) });
    recordJoinK = (a, b) => record2(Math.max(a.pos, b.pos), Math.max(a.neg, b.neg));
    recordMeetK = (a, b) => record2(Math.min(a.pos, b.pos), Math.min(a.neg, b.neg));
    recordJoinT = (a, b) => record2(Math.max(a.pos, b.pos), Math.min(a.neg, b.neg));
    recordMeetT = (a, b) => record2(Math.min(a.pos, b.pos), Math.max(a.neg, b.neg));
    recordAdd = (a, b) => record2(a.pos + b.pos, a.neg + b.neg);
    recordLeqK = (a, b) => a.pos <= b.pos && a.neg <= b.neg;
    recordLeqT = (a, b) => a.pos <= b.pos && b.neg <= a.neg;
    readingOfRecord = (r, family = "knowledge") => readingOfSides(family, r.pos > 0, r.neg > 0);
    topMass = (r) => Math.min(r.pos, r.neg);
    attestationRecord = (counts) => {
      if (counts.some((count) => !Number.isSafeInteger(count) || count < 1)) throw new TypeError("four: a distinct state is attested at least once");
      const total = counts.reduce((sum, count) => tally(sum + count), 0);
      return record2(total - counts.length, Math.max(0, counts.length - 1));
    };
    gaugeElementNames = Object.freeze(["id", "negation", "conflation", "double"]);
    points = readingFamilies.knowledge;
    wireOfReading = (name) => four(...sidesOfReading(name));
    FOUR = Object.freeze(Object.fromEntries(readingFamilies.truth.map((name) => [name, wireOfReading(name)])));
    obsmetrologiaRealization = Object.freeze({
      "Obsmetrologia.Articulating.Corner.toStatus": sidesOfReading,
      "Obsmetrologia.Reading.kBot": () => knowledgeBottom(),
      "Obsmetrologia.Reading.kTop": () => knowledgeTop(),
      "Obsmetrologia.Reading.tTop": () => truthTop(),
      "Obsmetrologia.Reading.tBot": () => truthBottom(),
      "Obsmetrologia.Reading.joinK": knowledgeJoinReading,
      "Obsmetrologia.Reading.meetK": knowledgeMeetReading,
      "Obsmetrologia.Reading.joinT": truthJoinReading,
      "Obsmetrologia.Reading.meetT": truthMeetReading,
      "Obsmetrologia.Reading.leK": knowledgeLeqReading,
      "Obsmetrologia.Reading.leT": truthLeqReading,
      "Obsmetrologia.Reading.negate": negateReading,
      "Obsmetrologia.Reading.conflate": conflateReading,
      "Obsmetrologia.Reading.negConf": (name) => gauge("double", name),
      "Obsmetrologia.Reading.impK": knowledgeImplyReading,
      "Obsmetrologia.Positing.FiberAlgebra.Reading.impT": truthImplyReading,
      "Obsmetrologia.Order.TwistProduct.fuse": fusionReading,
      "Obsmetrologia.Order.TwistProduct.imp": residuumReading,
      "Obsmetrologia.Order.TwistProduct.one": () => linearUnit(),
      "Obsmetrologia.Record.joinK": recordJoinK,
      "Obsmetrologia.Record.meetK": recordMeetK,
      "Obsmetrologia.Record.joinT": recordJoinT,
      "Obsmetrologia.Record.meetT": recordMeetT,
      "Obsmetrologia.Record.add": recordAdd,
      "Obsmetrologia.Record.reading": (r) => readingOfRecord(r),
      "Obsmetrologia.Record.topMass": topMass,
      "Obsmetrologia.Record.leK": recordLeqK,
      "Obsmetrologia.Record.leT": recordLeqT,
      "ObsmetrologiaComputing.attestationRecord": attestationRecord
    });
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/semiotic-expression-notation/notation.mjs
function readingCase(subject, branch) {
  function go(remaining) {
    const [name, ...rest] = remaining;
    if (name === void 0)
      throw new TypeError("readingCase: no reading names to dispatch over");
    if (rest.length === 0) return branch(name);
    return tm.cond(
      tm.coincide(subject, tm.reading(name)),
      branch(name),
      go(rest)
    );
  }
  return go(readingNames);
}
function senFail(code, message) {
  const error2 = new Error(message);
  error2.code = code;
  throw error2;
}
function senTagged(value, kind) {
  if (!Array.isArray(value) || typeof value[0] !== "string")
    senFail("malformed-sen", `${kind} must be a tagged SEN sequence`);
  return value;
}
function validateAtom(constraint, value) {
  if (constraint === "natural" && Number.isInteger(value) && value >= 0) return;
  if (constraint === "text" && typeof value === "string") return;
  senFail("malformed-sen", `invalid SEN ${constraint} atom`);
}
function validateSenType(type) {
  const pending = [{ value: type }], open = /* @__PURE__ */ new Set();
  while (pending.length) {
    const task = pending.pop();
    if (task.close) {
      open.delete(task.close);
      continue;
    }
    const current = task.value;
    senTagged(current, "type");
    if (open.has(current)) senFail("malformed-sen", "cyclic SEN type");
    open.add(current);
    pending.push({ close: current });
    const form = SEN_TYPE_FORMS[current[0]];
    if (!form || current.length !== 1 + (form.types?.length ?? 0))
      senFail("malformed-sen", `unknown or malformed SEN type tag ${current[0]}`);
    for (const index of [...form.types ?? []].reverse()) pending.push({ value: current[index] });
  }
  return type;
}
function validateSenTerm(term) {
  const pending = [{ value: term }], open = /* @__PURE__ */ new Set();
  while (pending.length > 0) {
    const task = pending.pop();
    if (task.close) {
      open.delete(task.close);
      continue;
    }
    const current = task.value;
    senTagged(current, "term");
    if (open.has(current)) senFail("malformed-sen", "cyclic SEN term");
    open.add(current);
    pending.push({ close: current });
    const form = SEN_FORMS[current[0]];
    if (!form)
      senFail("malformed-sen", `unknown or malformed SEN term tag ${current[0]}`);
    const expected = 1 + Object.keys(form.atoms ?? {}).length + (form.terms?.length ?? 0) + (form.types?.length ?? 0);
    if (current.length !== expected) senFail("malformed-sen", `malformed SEN ${current[0]}`);
    for (const [index, constraint] of Object.entries(form.atoms ?? {})) validateAtom(constraint, current[index]);
    for (const index of form.types ?? []) validateSenType(current[index]);
    for (const index of [...form.terms ?? []].reverse()) pending.push({ value: current[index] });
  }
  return term;
}
var readingNames, isReadingName, onReadings2, tm;
var init_notation = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/semiotic-expression-notation/notation.mjs"() {
    init_schema();
    init_validator();
    init_forms();
    init_forms();
    init_four();
    readingNames = readingFamilies.extremal;
    isReadingName = (value) => isReading(value, "extremal");
    onReadings2 = (left, right, branch) => readingCase(left, (l) => readingCase(right, (r) => branch(l, r)));
    tm = {
      var: (index) => {
        if (!Number.isInteger(index) || index < 0)
          throw new TypeError(
            `tm.var: de-Bruijn index must be a natural number: ${index}`
          );
        return Object.freeze(["var", index]);
      },
      lam: (body) => Object.freeze(["lam", body]),
      app: (fn, arg) => Object.freeze(["app", fn, arg]),
      pair: (left, right) => Object.freeze(["pair", left, right]),
      fst: (value) => Object.freeze(["fst", value]),
      snd: (value) => Object.freeze(["snd", value]),
      star: () => Object.freeze(["star"]),
      mark: (surface) => Object.freeze(["mark", surface]),
      /** Construct exactly one of the four readings: a distinguished mark, type base. */
      reading: (name) => {
        if (!isReadingName(name))
          throw new TypeError(`tm.reading: unknown reading ${String(name)}`);
        return Object.freeze(["mark", name]);
      },
      /** `true`/`false` are the truth-axis readings, held and denied. */
      bool: (value) => {
        if (typeof value !== "boolean")
          throw new TypeError(`tm.bool: expected boolean, got ${typeof value}`);
        return tm.reading(value ? "held" : "denied");
      },
      /** Whether a reading is told for: its for-side as a truth-axis boolean, total over all four
       *  readings (unlike `boolOfTerm`, which recognizes only held and denied). */
      toldFor: (value) => readingCase(value, (name) => tm.bool(sidesOfReading(name)[0])),
      /** One of the four predication-site generator morphisms (converse/subjectProjection/
       *  objectProjection/specialization) — a bare distinguishable atom with no algebra
       *  defined over it in this grammar, so a mark. */
      generator: (name) => tm.mark(name),
      /** Negation: FOUR's side swap. */
      negate: (value) => readingCase(value, (name) => tm.reading(negateReading(name))),
      /** Conflation: FOUR's complemented swap. */
      conflate: (value) => readingCase(value, (name) => tm.reading(conflateReading(name))),
      /** Complement only (negation after conflation). */
      negConf: (value) => readingCase(value, (name) => tm.reading(negateReading(conflateReading(name)))),
      joinK: (left, right) => onReadings2(left, right, (l, r) => tm.reading(knowledgeJoinReading(l, r))),
      meetK: (left, right) => onReadings2(left, right, (l, r) => tm.reading(knowledgeMeetReading(l, r))),
      joinT: (left, right) => onReadings2(left, right, (l, r) => tm.reading(truthJoinReading(l, r))),
      meetT: (left, right) => onReadings2(left, right, (l, r) => tm.reading(truthMeetReading(l, r))),
      leK: (left, right) => onReadings2(left, right, (l, r) => tm.bool(knowledgeLeqReading(l, r))),
      leT: (left, right) => onReadings2(left, right, (l, r) => tm.bool(truthLeqReading(l, r))),
      /**
       * An assoc-list search over `fold` — the object's entries are `pair(mark(key), value)`
       * spine elements; `coincide` compares keys, `cond` picks. A missing key folds to
       * `mark("null")`, not a stuck redex.
       */
      field: (key, object2) => tm.fold(
        tm.lam(
          tm.lam(
            tm.cond(
              tm.coincide(tm.fst(tm.var(0)), tm.mark(JSON.stringify(key))),
              tm.snd(tm.var(0)),
              tm.var(1)
            )
          )
        ),
        tm.mark(JSON.stringify(null)),
        object2
      ),
      /** Prepend one element to an array term's spine — O(1), no `fold`: just a `pair` in
       *  front of the existing spine, reusing `array`'s OWN tag (`fst`) rather than a
       *  freshly hardcoded mark. This and `reverseArray` are the two array-combination
       *  primitives this kernel has; `append` (below) is not a third — there is no general
       *  two-arbitrary-list concatenation law in Obsmetrologia's proven math for it to
       *  answer to, so it is only ever the call-site composition of these two. */
      consArray: (elem, array) => tm.pair(tm.fst(array), tm.pair(elem, tm.snd(array))),
      /** Reverse an array term — the one real `fold` either of these needs. */
      reverseArray: (array) => tm.pair(
        tm.fst(array),
        tm.fold(tm.lam(tm.lam(tm.pair(tm.var(0), tm.var(1)))), tm.star(), array)
      ),
      /**
       * Concatenate two array terms, `left` then `right` in order — not a third kernel
       * primitive with its own `fold` shape (metroplat's own kernel comment: no
       * `Cell`/`Valuation`/bilattice/`Articulating` law anywhere concatenates two lists,
       * so there is nothing for a dedicated opcode to be sound against), but exactly the
       * call-site composition its comment prescribes: `reverseArray(left)` once, then a
       * single `fold` that `consArray`s each of its elements onto `right`. Reversed-left
       * yields left's elements last-to-first, so consing them onto `right` in that order
       * rebuilds left's original order in front of right; the result carries `right`'s
       * tag, since `right` is the accumulator being grown.
       */
      append: (left, right) => tm.fold(
        tm.lam(tm.lam(tm.consArray(tm.var(0), tm.var(1)))),
        right,
        tm.reverseArray(left)
      ),
      coincide: (left, right) => Object.freeze(["coincide", left, right]),
      /** The `eq`/`cond` elementary pair (McCarthy): dispatch by comparing an opaque mark. */
      cond: (test, then, otherwise) => Object.freeze(["cond", test, then, otherwise]),
      /** Left fold over an array-encoded list: `fold f init [x₀..xₙ] = f (… (f init x₀) …) xₙ`,
       *  with `f` a curried `λacc.λelem.…`. The one structural recursion. */
      fold: (combine, init, list) => Object.freeze(["fold", combine, init, list]),
      /** A δ-rule: the named host primitive applied to `arg` (JSON in, JSON out) once `arg` is a value. */
      prim: (name, arg) => {
        if (typeof name !== "string" || name === "") throw new TypeError("tm.prim: a primitive needs a name");
        return Object.freeze(["prim", name, arg]);
      },
      /** Left injection into a finite sum; the right summand remains explicit. */
      inl: (value, rightType) => Object.freeze(["inl", value, rightType]),
      /** Right injection into a finite sum; the left summand remains explicit. */
      inr: (leftType, value) => Object.freeze(["inr", leftType, value]),
      /** Eliminate a sum. Each branch is under one de Bruijn binder for its injection value. */
      case: (subject, whenLeft, whenRight) => Object.freeze(["case", subject, whenLeft, whenRight]),
      /** Eliminate an impossible empty value into the explicit target type. */
      abort: (subject, targetType) => Object.freeze(["abort", subject, targetType])
    };
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/semiotic-expression-notation/json-codec.mjs
function canonicalBytes(value) {
  return JSON.stringify(value);
}
function listTerm(items) {
  return items.reduceRight((tail, item) => tm.pair(item, tail), tm.star());
}
function jsonToTerm(value) {
  const frames = [];
  let result;
  const emit = (term) => {
    const frame = frames.at(-1);
    if (frame === void 0) {
      result = term;
      return;
    }
    if (frame.kind === "array") {
      frame.items.push(term);
      return;
    }
    frame.entries.push([frame.key, term]);
    frame.key = void 0;
  };
  traverseJson(value, {
    scalar(kind, payload) {
      if (kind === "null") emit(tm.pair(tm.mark(canonicalBytes(nullTag)), tm.star()));
      else if (kind === "boolean") emit(tm.pair(tm.mark(canonicalBytes(booleanTag)), tm.mark(payload ? "true" : "false")));
      else if (kind === "string") emit(tm.pair(tm.mark(canonicalBytes(stringTag)), tm.mark(canonicalBytes(payload))));
      else emit(tm.pair(tm.mark(canonicalBytes(numberTag)), tm.mark(canonicalBytes(payload))));
    },
    startArray() {
      frames.push({ kind: "array", items: [] });
    },
    endArray() {
      emit(tm.pair(tm.mark(canonicalBytes(arrayTag)), listTerm(frames.pop().items)));
    },
    startObject() {
      frames.push({ kind: "object", entries: [], key: void 0 });
    },
    key(key) {
      frames.at(-1).key = key;
    },
    endObject() {
      emit(tm.pair(tm.mark(canonicalBytes(objectTag)), listTerm(frames.pop().entries.map(([key, item]) => tm.pair(tm.mark(canonicalBytes(key)), item)))));
    }
  });
  return result;
}
function traverseJson(value, visitor, ancestors = /* @__PURE__ */ new Set(), path = "$") {
  const pending = [{ kind: "value", value, path }];
  let result;
  while (pending.length) {
    const task = pending.pop();
    if (task.kind === "end") {
      result = task.array ? visitor.endArray() : visitor.endObject();
      ancestors.delete(task.value);
      continue;
    }
    if (task.kind === "key") {
      visitor.key(task.key);
      continue;
    }
    if (task.kind === "item") {
      visitor.arrayItem?.(task.index);
      continue;
    }
    const value2 = task.value, path2 = task.path;
    if (value2 === null) {
      result = visitor.scalar("null");
      continue;
    }
    if (typeof value2 === "boolean" || typeof value2 === "string") {
      result = visitor.scalar(typeof value2, value2);
      continue;
    }
    if (typeof value2 === "number") {
      if (!Number.isFinite(value2) || Object.is(value2, -0)) throw new TypeError(`jsonToTerm: ${path2} must be one finite, non-negative-zero JSON number`);
      result = visitor.scalar("number", value2);
      continue;
    }
    if (typeof value2 !== "object") throw new TypeError(`jsonToTerm: ${path2} is not a JSON value`);
    if (ancestors.has(value2)) throw new TypeError(`jsonToTerm: ${path2} contains a cycle`);
    const array = Array.isArray(value2), names = Object.getOwnPropertyNames(value2);
    if (array) {
      if (Object.getOwnPropertySymbols(value2).length || names.length !== value2.length + 1 || !names.includes("length")) throw new TypeError(`jsonToTerm: ${path2} must be a dense JSON array with no extra properties`);
    } else {
      const prototype = Object.getPrototypeOf(value2);
      if (prototype !== Object.prototype && prototype !== null) throw new TypeError(`jsonToTerm: ${path2} must be a plain JSON record`);
      if (Object.getOwnPropertySymbols(value2).length) throw new TypeError(`jsonToTerm: ${path2} must not have symbol-keyed properties`);
    }
    const keys = array ? Array.from({ length: value2.length }, (_, i) => String(i)) : names.sort();
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value2, key);
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new TypeError(`jsonToTerm: ${path2}.${key} must be one enumerable data property`);
    }
    ancestors.add(value2);
    if (array) visitor.startArray(value2.length);
    else visitor.startObject(keys.length);
    pending.push({ kind: "end", value: value2, array });
    for (let i = keys.length - 1; i >= 0; i--) {
      const key = keys[i];
      pending.push({ kind: "value", value: Object.getOwnPropertyDescriptor(value2, key).value, path: array ? `${path2}[${key}]` : `${path2}.${key}` });
      pending.push(array ? { kind: "item", index: i } : { kind: "key", key });
    }
  }
  return result;
}
var arrayTag, objectTag, nullTag, booleanTag, stringTag, numberTag, nullDescriptor, booleanDescriptor, numberDescriptor, stringDescriptor;
var init_json_codec = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/semiotic-expression-notation/json-codec.mjs"() {
    init_notation();
    init_cbor();
    arrayTag = "sen.json.array";
    objectTag = "sen.json.object";
    nullTag = "sen.json.null";
    booleanTag = "sen.json.boolean";
    stringTag = "sen.json.string";
    numberTag = "sen.json.number";
    nullDescriptor = Object.freeze({ kind: "null" });
    booleanDescriptor = Object.freeze({ kind: "boolean" });
    numberDescriptor = Object.freeze({ kind: "number" });
    stringDescriptor = Object.freeze({ kind: "string" });
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/semiotic-expression-notation/typing.mjs
function tyEqual(left, right) {
  const pending = [[left, right]];
  while (pending.length) {
    const [a, b] = pending.pop();
    if (a === b) continue;
    if (Array.isArray(a) && Array.isArray(b)) {
      if (a.length !== b.length) return false;
      for (let i = a.length - 1; i >= 0; i--) pending.push([a[i], b[i]]);
    } else if (JSON.stringify(a) !== JSON.stringify(b)) return false;
  }
  return true;
}
function judgeSen(ctx, source, expected = void 0) {
  const checkedContext = ctx.map(validateSenType);
  const term = validateSenTerm(source);
  const want = expected === void 0 ? void 0 : validateSenType(expected);
  const valueType = inferClosedValueType(term);
  if (valueType !== void 0) {
    if (want === void 0) return valueType;
    if (tyEqual(valueType, want)) return true;
  }
  return judge2(checkedContext, term, want);
}
function inferClosedValueType(term) {
  const pending = [{ term, next: 0 }], results = [];
  while (pending.length) {
    const frame = pending.at(-1), value = frame.term;
    if (value[0] === "mark" || value[0] === "star") {
      results.push([value[0] === "mark" ? "base" : "unit"]);
      pending.pop();
    } else if (value[0] === "pair") {
      if (frame.next < 2) {
        pending.push({ term: value[++frame.next], next: 0 });
        continue;
      }
      const right = results.pop(), left = results.pop();
      results.push(["prod", left, right]);
      pending.pop();
    } else return void 0;
  }
  return results[0];
}
function judge2(ctx, term, want = void 0) {
  const infer = () => {
    switch (term[0]) {
      case "var":
        return ctx[term[1]] ?? null;
      case "star":
        return ["unit"];
      case "mark":
        return ["base"];
      case "app": {
        const fn = judge2(ctx, term[1]);
        if (fn?.[0] === "arrow" && judge2(ctx, term[2], fn[1])) return fn[2];
        const arg = judge2(ctx, term[2]);
        if (want && arg && judge2(ctx, term[1], ["arrow", arg, want]))
          return want;
        if (arg && term[1][0] === "lam") return judge2([arg, ...ctx], term[1][1]);
        const args = [];
        let head = term;
        while (head[0] === "app") {
          args.unshift(head[2]);
          head = head[1];
        }
        let scope = ctx;
        for (const argument of args) {
          if (head[0] !== "lam") return null;
          const argType = judge2(ctx, argument);
          if (!argType) return null;
          scope = [argType, ...scope];
          head = head[1];
        }
        return judge2(scope, head);
      }
      case "pair": {
        const cons = consOfArray(ctx, term);
        if (cons !== void 0) return cons;
        const leftTypes = [];
        let cursor = term;
        while (cursor[0] === "pair") {
          const left = judge2(ctx, cursor[1]);
          if (!left) return null;
          leftTypes.push(left);
          cursor = cursor[2];
        }
        let result = judge2(ctx, cursor);
        if (!result) return null;
        for (let index = leftTypes.length - 1; index >= 0; index -= 1)
          result = ["prod", leftTypes[index], result];
        return result;
      }
      case "fst":
      case "snd": {
        const pair = judge2(ctx, term[1]);
        return pair?.[0] === "prod" ? pair[term[0] === "fst" ? 1 : 2] : null;
      }
      case "coincide": {
        const left = judge2(ctx, term[1]), right = judge2(ctx, term[2]);
        return left && right && tyEqual(left, right) ? ["base"] : null;
      }
      case "cond": {
        const yes = judge2(ctx, term[2]), no = judge2(ctx, term[3]);
        return judge2(ctx, term[1], ["base"]) && yes && no ? joinBranchTypes(yes, no) : null;
      }
      case "inl": {
        const left = judge2(ctx, term[1]);
        return left ? ["sum", left, term[2]] : null;
      }
      case "inr": {
        const right = judge2(ctx, term[2]);
        return right ? ["sum", term[1], right] : null;
      }
      case "case": {
        const subject = judge2(ctx, term[1]);
        if (subject?.[0] !== "sum") return null;
        const left = judge2([subject[1], ...ctx], term[2]);
        const right = judge2([subject[2], ...ctx], term[3]);
        return left && right ? joinBranchTypes(left, right) : null;
      }
      case "abort":
        return judge2(ctx, term[1], ["empty"]) ? term[2] : null;
      case "fold": {
        const element = listElementOf(judge2(ctx, term[3])), initType = judge2(ctx, term[2]);
        if (element === void 0 || !initType) return null;
        const initElement = listElementOf(initType);
        const accumulator = want && judge2(ctx, term[2], want) ? want : initElement ? ["list", initElement] : initType;
        if (element === null) return term[1][0] === "lam" && term[1][1][0] === "lam" ? accumulator : null;
        const combines = (acc) => judge2(ctx, term[1], ["arrow", acc, ["arrow", element, acc]]);
        if (combines(accumulator)) return accumulator;
        if (initElement === null && term[1][0] === "lam" && term[1][1][0] === "lam") {
          const built = judge2([element, accumulator, ...ctx], term[1][1][1]);
          if (built && listElementOf(built) && combines(built)) return built;
        }
        return null;
      }
      default:
        return null;
    }
  };
  if (term[0] === "lam" && want)
    return want[0] === "arrow" && judge2([want[1], ...ctx], term[1], want[2]);
  if (term[0] === "pair" && want?.[0] === "prod") {
    let value = term, expected = want;
    while (value[0] === "pair" && expected[0] === "prod") {
      if (!judge2(ctx, value[1], expected[1])) return false;
      value = value[2];
      expected = expected[2];
    }
    return judge2(ctx, value, expected);
  }
  if (term[0] === "inl" && want?.[0] === "sum")
    return tyEqual(term[2], want[2]) && judge2(ctx, term[1], want[1]);
  if (term[0] === "inr" && want?.[0] === "sum")
    return tyEqual(term[1], want[1]) && judge2(ctx, term[2], want[2]);
  if (term[0] === "case" && want) {
    const subject = judge2(ctx, term[1]);
    return subject?.[0] === "sum" && judge2([subject[1], ...ctx], term[2], want) && judge2([subject[2], ...ctx], term[3], want);
  }
  if (want?.[0] === "list" && term[0] === "pair" && term[1][0] === "mark") {
    let spine = term[2];
    while (spine[0] === "pair") {
      if (!judge2(ctx, spine[1], want[1])) return false;
      spine = spine[2];
    }
    if (spine[0] === "star") return true;
  }
  const got = infer();
  if (want === void 0) return got;
  if (got === null) return false;
  if (want[0] === "list") {
    const element = listElementOf(got);
    return element === null || element !== void 0 && tyEqual(element, want[1]);
  }
  return tyEqual(got, want);
}
function joinBranchTypes(left, right) {
  if (tyEqual(left, right)) return left;
  const leftElement = listElementOf(left), rightElement = listElementOf(right);
  if (leftElement === void 0 || rightElement === void 0) return null;
  if (leftElement === null) return rightElement === null ? left : ["list", rightElement];
  if (rightElement === null || tyEqual(leftElement, rightElement)) return ["list", leftElement];
  return null;
}
function consOfArray(ctx, term) {
  const [, tag, rest] = term;
  if (tag[0] !== "fst" || rest[0] !== "pair" || rest[2][0] !== "snd") return void 0;
  if (JSON.stringify(tag[1]) !== JSON.stringify(rest[2][1])) return void 0;
  const element = listElementOf(judge2(ctx, tag[1]));
  if (element === void 0) return void 0;
  const head = judge2(ctx, rest[1]);
  if (!head || element !== null && !tyEqual(head, element)) return null;
  return ["list", head];
}
function listElementOf(type) {
  if (type?.[0] === "list") return type[1];
  if (type?.[0] !== "prod" || type[1]?.[0] !== "base") return void 0;
  let element = null;
  for (let spine = type[2]; ; spine = spine[2]) {
    if (spine?.[0] === "unit") return element;
    if (spine?.[0] !== "prod") return void 0;
    if (element !== null && !tyEqual(element, spine[1])) return void 0;
    element = spine[1];
  }
}
function illTyped(message) {
  const error2 = new Error(message);
  error2.code = "ill-typed-term";
  throw error2;
}
function validateType(source) {
  return validateSenType(canonicalizeSemioticJson(source));
}
function validateTerm(source) {
  return validateSenTerm(canonicalizeSemioticJson(source));
}
function inferTerm(source, context = []) {
  return judgeSen(context.map(validateType), validateTerm(source)) ?? illTyped("term has no SEN type");
}
function checkTerm(source, expectedSource, context = []) {
  return judgeSen(context.map(validateType), validateTerm(source), validateType(expectedSource)) || illTyped("term does not have expected SEN type");
}
var init_typing = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/semiotic-expression-notation/typing.mjs"() {
    init_semiotic_content_address();
    init_notation();
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/semiotic-expression-notation/semantic-content-identity.mjs
function semanticContentRefusal(code, message) {
  const error2 = new TypeError(message);
  error2.code = code;
  return error2;
}
function inhabitsDeclaredType(term, semanticType) {
  try {
    checkTerm(term, semanticType);
    return true;
  } catch {
    return false;
  }
}
function commitmentOf(value) {
  const { id: id3, bytes: bytes2 } = semanticAddress(value);
  return Object.freeze({ id: id3, token: id3, algorithm: "sha-256", mediaType: "application/sen+cbor", bytes: bytes2 });
}
function immutableCopy(value) {
  const copyOf = (node) => node === null || typeof node !== "object" ? node : Array.isArray(node) ? new Array(node.length) : {};
  const root = copyOf(value);
  const pending = root === value ? [] : [[value, root]];
  const finished = [];
  while (pending.length > 0) {
    const [source, target] = pending.pop();
    finished.push(target);
    for (const [key, member] of Object.entries(source)) {
      const copy = copyOf(member);
      Object.defineProperty(target, key, { value: copy, enumerable: true, writable: true, configurable: true });
      if (copy !== member) pending.push([member, copy]);
    }
  }
  for (const node of finished) Object.freeze(node);
  return root;
}
function canonicalNi(value, field) {
  if (!isNiUri(value)) {
    throw semanticContentRefusal("malformed-content-address", `${field} must be one canonical RFC 6920 SHA-256 ni URI`);
  }
  return value;
}
function canonicalString(value, field) {
  if (typeof value !== "string") throw semanticContentRefusal("malformed-normalized-content", `${field} must be a finite string`);
  return value.normalize("NFC");
}
function admitSemanticEnvelope(envelope2, { normalForm = void 0, typeChecked = false } = {}) {
  if (envelope2 === null || typeof envelope2 !== "object" || Array.isArray(envelope2)) {
    throw semanticContentRefusal("malformed-normalized-content", "normalized semantic content must be one envelope object");
  }
  const keys = Object.keys(envelope2).sort();
  if (keys.length !== V2_KEYS.length || !keys.every((key, index) => key === V2_SORTED_KEYS[index]) || envelope2.kind !== V2_KIND || envelope2.version !== ENVELOPE_VERSION) {
    throw semanticContentRefusal("malformed-normalized-content", "normalized semantic content has unknown fields, kind, or version");
  }
  const objectKind = canonicalString(envelope2.objectKind, "objectKind");
  if (objectKind.length === 0) throw semanticContentRefusal("malformed-normalized-content", "objectKind must not be empty");
  if (envelope2.normalizationProfile !== SEN_NORMALIZATION_PROFILE) {
    throw semanticContentRefusal("unsupported-normalization-profile", `unsupported normalization profile ${String(envelope2.normalizationProfile)}`);
  }
  if (envelope2.settlementProfile !== IDENTITY_SETTLEMENT_PROFILE) {
    throw semanticContentRefusal("unsupported-settlement-profile", `unsupported settlement profile ${String(envelope2.settlementProfile)}`);
  }
  const witnessRoot = canonicalNi(envelope2.witnessRoot, "witnessRoot");
  if (!typeChecked && !inhabitsDeclaredType(envelope2.settledBody, envelope2.semanticType)) {
    throw semanticContentRefusal("non-relational-content", "settledBody must be a closed SEN term inhabiting semanticType");
  }
  if (normalForm !== void 0) {
    let normalized;
    try {
      normalized = normalForm(envelope2.settledBody);
    } catch {
      throw semanticContentRefusal("normalization-failure", "settledBody could not be checked under the declared normalization profile");
    }
    if (!coincides(normalized, envelope2.settledBody)) {
      throw semanticContentRefusal("non-normal-content", "settledBody is not normal under the declared normalization profile");
    }
  }
  return immutableCopy({
    kind: V2_KIND,
    version: ENVELOPE_VERSION,
    objectKind,
    semanticType: envelope2.semanticType,
    normalizationProfile: SEN_NORMALIZATION_PROFILE,
    settlementProfile: envelope2.settlementProfile,
    settledBody: envelope2.settledBody,
    witnessRoot
  });
}
function commitSemanticEnvelope(envelope2, options = {}) {
  const admitted = admitSemanticEnvelope(envelope2, options);
  return Object.freeze({ ...commitmentOf(admitted), envelope: admitted });
}
function identifyJsonSemanticContent({ objectKind, value, witnessRoot } = {}) {
  let term;
  try {
    term = jsonToTerm(value);
  } catch {
    throw semanticContentRefusal("non-relational-content", "value must cross the admitted JSON-to-SEN boundary");
  }
  let semanticType;
  try {
    semanticType = inferTerm(term);
  } catch {
    throw semanticContentRefusal("non-relational-content", "admitted JSON did not derive an SEN type");
  }
  return commitSemanticEnvelope({
    kind: V2_KIND,
    version: ENVELOPE_VERSION,
    objectKind,
    semanticType,
    normalizationProfile: SEN_NORMALIZATION_PROFILE,
    settlementProfile: IDENTITY_SETTLEMENT_PROFILE,
    settledBody: term,
    witnessRoot
  }, { typeChecked: true });
}
function semanticIdOf(objectKind) {
  if (typeof objectKind !== "string" || objectKind.trim() === "") throw new TypeError("semantic-object-kind-required");
  return (value) => identifyJsonSemanticContent({ objectKind, value, witnessRoot: EMPTY_WITNESS_ROOT }).id;
}
var SEN_NORMALIZATION_PROFILE, IDENTITY_SETTLEMENT_PROFILE, SEMANTIC_ENVELOPE_KIND, SEMANTIC_ENVELOPE_VERSION, V2_KIND, ENVELOPE_VERSION, V2_KEYS, V2_SORTED_KEYS, EMPTY_WITNESS_ROOT;
var init_semantic_content_identity = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-data-engineering-services-section/src/semiotic-expression-notation/semantic-content-identity.mjs"() {
    init_semiotic_content_address();
    init_ni_uri3();
    init_json_codec();
    init_typing();
    init_json_byte_carrier();
    SEN_NORMALIZATION_PROFILE = "urn:rce:sen:normalize:0.1.0";
    IDENTITY_SETTLEMENT_PROFILE = "urn:rce:settlement:identity:0.0.1";
    SEMANTIC_ENVELOPE_KIND = "semiotic-expression-notation.normalized-semantic-content";
    SEMANTIC_ENVELOPE_VERSION = 3;
    V2_KIND = SEMANTIC_ENVELOPE_KIND;
    ENVELOPE_VERSION = SEMANTIC_ENVELOPE_VERSION;
    V2_KEYS = Object.freeze([
      "kind",
      "version",
      "objectKind",
      "semanticType",
      "normalizationProfile",
      "settlementProfile",
      "settledBody",
      "witnessRoot"
    ]);
    V2_SORTED_KEYS = Object.freeze([...V2_KEYS].sort());
    EMPTY_WITNESS_ROOT = semanticId({ kind: "semantic-content.empty-witness-bundle", version: 1 });
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/json-services-section/scripts/canonical-json.mjs
function byteLength2(value) {
  return utf8Encoder2.encode(value).byteLength;
}
function pathText2(path) {
  const parts = [];
  let base = "$";
  for (let node = path; node !== null && typeof node === "object"; node = node.parent) {
    parts.push(node);
  }
  if (typeof path === "string") base = path;
  let text2 = base;
  for (let index = parts.length - 1; index >= 0; index -= 1) {
    const part = parts[index];
    text2 += part.kind === "index" ? `[${part.value}]` : `.${part.value}`;
  }
  return text2;
}
function continuesSpine2(container, index, child) {
  return index === 2 && Array.isArray(container) && container[0] === "pair" && Array.isArray(child) && child[0] === "pair";
}
function spineLimit2(spine, envelope2, path) {
  if (spine > envelope2.maxArrayLength) fail4("array-length-limit", path, `list spine exceeds ${envelope2.maxArrayLength} links`);
}
function propertyPath2(path, key) {
  return { parent: path, kind: "property", value: key };
}
function indexPath2(path, index) {
  return { parent: path, kind: "index", value: index };
}
function fail4(code, path, message) {
  const renderedPath = pathText2(path);
  const error2 = new TypeError(`${code} at ${renderedPath}: ${message}`);
  error2.code = code;
  error2.path = renderedPath;
  throw error2;
}
function assertUnicodeScalars2(value, path) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 55296 && unit <= 56319) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 56320 && next <= 57343)) {
        fail4("unicode-scalar", path, "must not contain a lone Unicode surrogate (high)");
      }
      index += 1;
    } else if (unit >= 56320 && unit <= 57343) {
      fail4("unicode-scalar", path, "must not contain a lone Unicode surrogate (low)");
    }
  }
}
function stringText2(value, path, limit2, code) {
  assertUnicodeScalars2(value, path);
  if (byteLength2(value) > limit2) fail4(code, path, `UTF-8 string exceeds ${limit2} bytes`);
  return JSON.stringify(value);
}
function chargeCanonical2(state, amount, path) {
  state.canonicalBytes += amount;
  if (state.canonicalBytes > state.envelope.maxCanonicalBytes) {
    fail4("canonical-limit", path, `canonical JSON exceeds ${state.envelope.maxCanonicalBytes} bytes`);
  }
}
function projectValue2(value, path, depth, state) {
  const tokens = [];
  const frames = [{ source: value, path, depth, spine: 0, entered: false }];
  let result;
  while (frames.length > 0) {
    const frame = frames[frames.length - 1];
    if (!frame.entered) {
      frame.entered = true;
      state.nodes += 1;
      if (state.nodes > state.envelope.maxNodes) {
        fail4("node-limit", frame.path, `JSON value exceeds ${state.envelope.maxNodes} nodes`);
      }
      const item = frame.source;
      if (item === null) {
        chargeCanonical2(state, 4, frame.path);
        tokens.push("null");
        result = null;
        frames.pop();
        continue;
      }
      if (typeof item === "boolean") {
        const text2 = item ? "true" : "false";
        chargeCanonical2(state, text2.length, frame.path);
        tokens.push(text2);
        result = item;
        frames.pop();
        continue;
      }
      if (typeof item === "string") {
        const text2 = stringText2(item, frame.path, state.envelope.maxStringBytes, "string-limit");
        chargeCanonical2(state, byteLength2(text2), frame.path);
        tokens.push(text2);
        result = item;
        frames.pop();
        continue;
      }
      if (typeof item === "number") {
        if (!Number.isFinite(item)) fail4("invalid-json-value", frame.path, "JCS admits only finite IEEE-754 numbers");
        const text2 = JSON.stringify(item);
        chargeCanonical2(state, byteLength2(text2), frame.path);
        tokens.push(text2);
        result = Object.is(item, -0) ? 0 : item;
        frames.pop();
        continue;
      }
      if (typeof item !== "object") {
        fail4("invalid-json-value", frame.path, `unsupported JSON value type: ${typeof item}`);
      }
      if (frame.depth >= state.envelope.maxDepth) {
        fail4("depth-limit", frame.path, `JSON nesting exceeds depth ${state.envelope.maxDepth}`);
      }
      if (state.active.has(item)) fail4("invalid-json-value", frame.path, "must not contain a cycle");
      state.active.add(item);
      frame.container = item;
      frame.index = 0;
      if (Array.isArray(item)) {
        if (item.length > state.envelope.maxArrayLength) {
          fail4("array-length-limit", frame.path, `array exceeds ${state.envelope.maxArrayLength} elements`);
        }
        const ownKeys = Reflect.ownKeys(item);
        if (ownKeys.some((key) => key !== "length" && (typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(key) || Number(key) >= item.length))) {
          fail4("invalid-json-value", frame.path, "arrays may not carry symbol or non-index properties");
        }
        chargeCanonical2(state, 2 + Math.max(0, item.length - 1), frame.path);
        tokens.push("[");
        frame.array = true;
        frame.carried = [];
        frame.length = item.length;
      } else {
        if (Object.getPrototypeOf(item) !== Object.prototype) {
          fail4("invalid-json-value", frame.path, "only ordinary JSON objects with Object.prototype are admitted");
        }
        const keys = Reflect.ownKeys(item);
        if (keys.some((key) => typeof key !== "string")) {
          fail4("invalid-json-value", frame.path, "symbol properties are outside the JSON data model");
        }
        if (keys.length > state.envelope.maxObjectMembers) {
          fail4("object-member-limit", frame.path, `object exceeds ${state.envelope.maxObjectMembers} members`);
        }
        frame.keys = keys.sort();
        chargeCanonical2(state, 2 + Math.max(0, frame.keys.length - 1) + frame.keys.length, frame.path);
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
      childPath = indexPath2(frame.path, index);
      if (descriptor === void 0) {
        fail4("invalid-json-value", childPath, "sparse arrays are outside the admitted JSON value model");
      }
      if (!("value" in descriptor) || !descriptor.enumerable) {
        fail4("invalid-json-value", childPath, "array accessors and non-enumerable elements are outside the JSON data model");
      }
      child = descriptor.value;
    } else {
      const key = frame.keys[frame.index];
      const descriptor = Object.getOwnPropertyDescriptor(frame.container, key);
      childPath = propertyPath2(frame.path, key);
      if (descriptor === void 0 || !("value" in descriptor) || !descriptor.enumerable) {
        fail4("invalid-json-value", childPath, "accessor and non-enumerable properties are outside the JSON data model");
      }
      const keyText = stringText2(key, childPath, state.envelope.maxKeyBytes, "key-limit");
      chargeCanonical2(state, byteLength2(keyText), childPath);
      tokens.push(keyText, ":");
      frame.key = key;
      child = descriptor.value;
    }
    frame.awaitingChild = true;
    const onSpine = frame.array && continuesSpine2(frame.container, frame.index, child);
    const spine = onSpine ? frame.spine + 1 : 0;
    spineLimit2(spine, state.envelope, childPath);
    frames.push({ source: child, path: childPath, depth: onSpine ? frame.depth : frame.depth + 1, spine, entered: false });
  }
  return { value: result, text: tokens.join("") };
}
function canonicalizeJson2(value, envelope2 = UNBOUNDED_JSON_ENVELOPE2) {
  const state = { nodes: 0, canonicalBytes: 0, active: /* @__PURE__ */ new WeakSet(), envelope: envelope2 };
  const projected = projectValue2(value, "$", 0, state);
  return Object.freeze({ value: projected.value, text: projected.text, byteLength: state.canonicalBytes });
}
function canonicalJson2(value, envelope2 = UNBOUNDED_JSON_ENVELOPE2) {
  return canonicalizeJson2(value, envelope2).text;
}
var UNBOUNDED_JSON_ENVELOPE2, JSON_RESOURCE_ENVELOPE2, utf8Encoder2;
var init_canonical_json = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/json-services-section/scripts/canonical-json.mjs"() {
    UNBOUNDED_JSON_ENVELOPE2 = Object.freeze({
      maxSourceBytes: Infinity,
      maxCanonicalBytes: Infinity,
      maxDepth: Infinity,
      maxNodes: Infinity,
      maxObjectMembers: Infinity,
      maxArrayLength: Infinity,
      maxStringBytes: Infinity,
      maxKeyBytes: Infinity
    });
    JSON_RESOURCE_ENVELOPE2 = Object.freeze({
      maxSourceBytes: 1048576,
      maxCanonicalBytes: 1048576,
      maxDepth: 64,
      maxNodes: 1e5,
      maxObjectMembers: 4096,
      maxArrayLength: 65536,
      maxStringBytes: 262144,
      maxKeyBytes: 1024
    });
    utf8Encoder2 = new TextEncoder();
    if (import.meta.main) {
      const { readFileSync } = globalThis.process?.getBuiltinModule?.("node:fs") ?? {};
      process.stdout.write(
        JSON.stringify(canonicalJson2(JSON.parse(readFileSync(0, "utf8")))) + "\n"
      );
    }
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/issuer-research-media-service/src/evidence-packet.mjs
function validateIssuerEvidenceRequest({ ticker, issuer, asOf, sources, claims, events = [], license = "single-customer-analysis" } = {}) {
  if (typeof ticker !== "string" || ticker.trim() === "" || typeof issuer !== "string" || issuer.trim() === "") throw new TypeError("ticker-and-issuer-required");
  if (!Number.isFinite(Date.parse(asOf)) || !Array.isArray(sources) || sources.length === 0 || sources.some((s) => !s.uri || !s.observedAt || !s.digest)) throw new TypeError("dated-content-addressed-sources-required");
  if (!Array.isArray(claims) || claims.length === 0 || claims.some((c) => !c.statement || !Array.isArray(c.sourceDigests) || c.sourceDigests.length === 0)) throw new TypeError("source-bound-claims-required");
  const sourceIds = new Set(sources.map((s) => s.digest));
  if (claims.some((c) => c.sourceDigests.some((d) => !sourceIds.has(d)))) throw new TypeError("claim-cites-unknown-source");
  if (!Array.isArray(events) || typeof license !== "string" || license.trim() === "") throw new TypeError("events-or-license-invalid");
  return Object.freeze({ ticker, issuer, asOf, sources, claims, events, license });
}
function formIssuerEvidencePacket(input) {
  const { ticker, issuer, asOf, sources, claims, events, license } = validateIssuerEvidenceRequest(input);
  const body = {
    type: "IssuerEvidencePacket",
    version: 1,
    ticker: String(ticker).toUpperCase(),
    issuer: String(issuer),
    asOf,
    sources,
    claims,
    events,
    license,
    proofStatus: "research-evidence-not-mathematical-proof",
    brokerageEffect: false
  };
  return Object.freeze({ id: id2(body), ...body });
}
var semanticId2, id2;
var init_evidence_packet = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/issuer-research-media-service/src/evidence-packet.mjs"() {
    init_semantic_content_identity();
    init_canonical_json();
    semanticId2 = semanticIdOf("brokerage.issuer-research-media.record");
    id2 = (v) => semanticId2(v);
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/issuer-research-media-service/src/issuer-revenue-reconciliation.mjs
function calendarDay(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const milliseconds = Date.parse(value + "T00:00:00.000Z");
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString().slice(0, 10) !== value) return null;
  return milliseconds / DAY3;
}
function validIdentity(value, requested) {
  if (typeof value === "number") return Number.isSafeInteger(value) && value >= 0 && value === Number(requested);
  if (typeof value === "string" && /^\d+$/.test(value)) return BigInt(value) === BigInt(requested);
  return false;
}
function compareWitnesses(a, b) {
  return lexical(a.concept, b.concept) || lexical(a.filed, b.filed) || lexical(a.accession, b.accession) || (a.value < b.value ? -1 : a.value > b.value ? 1 : 0) || lexical(a.start, b.start) || lexical(a.form, b.form);
}
function equalWitness(a, b) {
  return a.concept === b.concept && a.start === b.start && a.end === b.end && a.durationDays === b.durationDays && Object.is(a.value, b.value) && a.unit === b.unit && a.form === b.form && a.filed === b.filed && a.accession === b.accession;
}
function reconcileIssuerRevenueFacts(input) {
  if (!record3(input)) throw new TypeError("Invalid input envelope");
  const { cik, asOf, periodKind, maximumAgeDays, companyfacts } = input;
  const asOfDay = calendarDay(asOf);
  if (typeof cik !== "string" || !/^\d{10}$/.test(cik) || asOfDay === null || periodKind !== "quarter" && periodKind !== "annual" || !Number.isInteger(maximumAgeDays) || maximumAgeDays <= 0 || !record3(companyfacts) || !validIdentity(companyfacts.cik, cik) || typeof companyfacts.entityName !== "string" || companyfacts.entityName.trim().length === 0 || !record3(companyfacts.facts)) throw new TypeError("Invalid input envelope or issuer identity");
  const eligible = [];
  const conceptCoverage = [];
  const taxonomy = companyfacts.facts["us-gaap"];
  for (const concept of CONCEPTS) {
    const entry = record3(taxonomy) ? taxonomy[concept] : void 0;
    const observations = record3(entry) && record3(entry.units) && Array.isArray(entry.units.USD) ? entry.units.USD : [];
    const witnesses = [];
    for (const observation of observations) {
      if (!record3(observation) || typeof observation.val !== "number" || !Number.isFinite(observation.val) || typeof observation.accn !== "string" || observation.accn.trim().length === 0 || !["10-Q", "10-Q/A", "10-K", "10-K/A"].includes(observation.form)) continue;
      const startDay = calendarDay(observation.start);
      const endDay = calendarDay(observation.end);
      const filedDay = calendarDay(observation.filed);
      if (startDay === null || endDay === null || filedDay === null || startDay > endDay || endDay > asOfDay || filedDay > asOfDay) continue;
      const witness = {
        concept,
        start: observation.start,
        end: observation.end,
        durationDays: endDay - startDay + 1,
        value: observation.val,
        unit: "USD",
        form: observation.form,
        filed: observation.filed,
        accession: observation.accn
      };
      if (!witnesses.some((existing) => equalWitness(existing, witness))) witnesses.push(witness);
    }
    let latestEnd = null;
    for (const witness of witnesses) {
      if (latestEnd === null || witness.end > latestEnd) latestEnd = witness.end;
      eligible.push(witness);
    }
    conceptCoverage.push({ concept, latestEnd, count: witnesses.length });
  }
  const result = {
    type: "IssuerRevenueReconciliation",
    version: 1,
    cik,
    issuer: companyfacts.entityName,
    asOf,
    periodKind,
    status: "missing",
    unit: "USD",
    period: null,
    value: null,
    witnesses: [],
    conceptCoverage,
    revision: "none"
  };
  const [minimum, maximum] = periodKind === "quarter" ? [70, 110] : [330, 380];
  const candidates = eligible.filter((w) => w.durationDays >= minimum && w.durationDays <= maximum);
  if (candidates.length === 0) return result;
  let greatestEnd = candidates[0].end;
  for (const witness of candidates) if (witness.end > greatestEnd) greatestEnd = witness.end;
  const selected = candidates.filter((w) => w.end === greatestEnd).sort(compareWitnesses);
  result.witnesses = selected;
  if (new Set(selected.map((w) => w.start)).size > 1) {
    result.status = "ambiguous";
    result.revision = "ambiguous";
    return result;
  }
  const first = selected[0];
  result.period = { start: first.start, end: first.end, durationDays: first.durationDays };
  const latestByConcept = /* @__PURE__ */ new Map();
  for (const witness of selected) {
    const previous = latestByConcept.get(witness.concept);
    if (previous === void 0 || witness.filed > previous) latestByConcept.set(witness.concept, witness.filed);
  }
  const latest = selected.filter((w) => w.filed === latestByConcept.get(w.concept));
  const values = new Set(latest.map((w) => w.value));
  if (values.size > 1) {
    result.status = "ambiguous";
    result.revision = "ambiguous";
    return result;
  }
  result.value = latest[0].value;
  if (selected.some((w) => w.filed < latestByConcept.get(w.concept) && w.value !== result.value)) {
    result.revision = "changed-reported-value";
  } else if (new Set(selected.map((w) => w.accession)).size > 1) {
    result.revision = "equal-value-rereport";
  }
  result.status = asOfDay - calendarDay(greatestEnd) > maximumAgeDays ? "stale" : "current";
  return result;
}
var CONCEPTS, DAY3, record3, lexical;
var init_issuer_revenue_reconciliation = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/issuer-research-media-service/src/issuer-revenue-reconciliation.mjs"() {
    CONCEPTS = Object.freeze(["Revenues", "SalesRevenueNet", "RevenueFromContractWithCustomerExcludingAssessedTax"]);
    DAY3 = 864e5;
    record3 = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
    lexical = (a, b) => a < b ? -1 : a > b ? 1 : 0;
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-content-address-engineering-services-section/src/content-address.mjs
function bytesOf(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new TypeError("content bytes must be Uint8Array or ArrayBuffer");
}
function addressContent(bytes2, {
  mediaType: mediaType2 = "application/octet-stream",
  source = void 0
} = {}) {
  const admitted = bytesOf(bytes2);
  if (typeof mediaType2 !== "string" || mediaType2.length === 0) {
    throw new TypeError("mediaType must be non-empty text");
  }
  const record5 = {
    kind: "semiotic-content.raw-carrier-address",
    version: 1,
    algorithm: "sha-256",
    size: admitted.byteLength,
    mediaType: mediaType2,
    ni: makeNiUri2(admitted)
  };
  if (source !== void 0) {
    if (source === null || typeof source !== "object" || Array.isArray(source)) {
      throw new TypeError("source must be an object when supplied");
    }
    record5.source = Object.freeze(structuredClone(source));
  }
  return Object.freeze(record5);
}
var init_content_address = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/computer-content-address-engineering-services-section/src/content-address.mjs"() {
    init_ni_uri2();
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/uri-services-section/src/ni-uri.mjs
function isNiUri3(value) {
  return typeof value === "string" && NI_URI_PATTERN2.test(value);
}
var NI_URI_PATTERN2;
var init_ni_uri4 = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/uri-services-section/src/ni-uri.mjs"() {
    init_portable_sha256();
    init_json_byte_carrier();
    NI_URI_PATTERN2 = /^ni:\/\/\/sha-256;[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u;
  }
});

// ../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/issuer-research-media-service/src/prepared-cohort.mjs
var prepared_cohort_exports = {};
__export(prepared_cohort_exports, {
  planIssuerRevenueAcquisition: () => planIssuerRevenueAcquisition,
  prepareIssuerRevenueCohort: () => prepareIssuerRevenueCohort,
  readPreparedIssuerRevenueComparison: () => readPreparedIssuerRevenueComparison,
  selectPreparedIssuerRevenueComparison: () => selectPreparedIssuerRevenueComparison,
  validateIssuerRevenueComparisonRequest: () => validateIssuerRevenueComparisonRequest
});
function config(c) {
  const bad = () => {
    throw new TypeError("Invalid issuer revenue configuration");
  };
  if (!record4(c) || !Number.isInteger(c.maximumIssuers) || c.maximumIssuers < 2 || c.maximumIssuers > 5) bad();
  if (!Array.isArray(c.issuers) || c.issuers.length < 2 || c.issuers.length > c.maximumIssuers) bad();
  const seen = /* @__PURE__ */ new Set();
  for (const i of c.issuers) {
    if (!record4(i) || typeof i.cik !== "string" || !/^\d{10}$/.test(i.cik) || !text(i.ticker) || seen.has(i.cik)) bad();
    seen.add(i.cik);
  }
  if (!text(c.userAgent) || /[\r\n]/.test(c.userAgent) || !c.userAgent.includes("@")) bad();
  for (const k of ["maximumBytes", "timeoutMs", "maximumSnapshotAgeMs", "maximumCohortBytes"]) if (!positive(c[k])) bad();
  if (!record4(c.maximumAgeDays) || !KINDS.every((k) => positive(c.maximumAgeDays[k]))) bad();
  if (!Number.isInteger(c.minimumIntervalMs) || c.minimumIntervalMs < 100 || !text(c.cacheKey)) bad();
  if (!Array.isArray(c.allowedPeriodKinds) || !c.allowedPeriodKinds.length || !c.allowedPeriodKinds.every((k) => KINDS.includes(k)) || new Set(c.allowedPeriodKinds).size !== c.allowedPeriodKinds.length || typeof c.allowAmbiguousEvidence !== "boolean") bad();
  return c;
}
function instant(v) {
  if (typeof v === "number") return Number.isInteger(v) && Number.isFinite(v) && Number.isFinite(new Date(v).getTime()) ? v : NaN;
  if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(v)) return NaN;
  const n = Date.parse(v);
  return Number.isFinite(n) && new Date(n).toISOString() === v ? n : NaN;
}
function day(v) {
  if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return NaN;
  const n = Date.parse(v + "T00:00:00.000Z");
  return Number.isFinite(n) && new Date(n).toISOString().slice(0, 10) === v ? n : NaN;
}
function canonical(v) {
  return typeof v === "string" && Number.isFinite(instant(v));
}
function unavailable() {
  return Object.assign(new Error("Issuer revenue unavailable"), { code: "issuer-revenue-unavailable", status: 503, retryable: true });
}
function refused(reason, retryable, retryAfter) {
  const e = Object.assign(new Error("Issuer revenue source unavailable: " + reason), { code: "issuer-revenue-source-unavailable", status: 503, retryable, reason });
  if (retryAfter !== void 0 && retryAfter !== null) e.retryAfter = String(retryAfter);
  return e;
}
function need(condition) {
  if (!condition) throw unavailable();
}
function ni(v) {
  return text(v) && isNiUri3(v);
}
function statement(r) {
  return "Received SEC companyfacts and reconciled " + r.periodKind + " USD revenue; status=" + r.status + "; period=" + (r.period ? r.period.start + ".." + r.period.end : "none") + "; value=" + String(r.value) + "; revision=" + r.revision + ".";
}
function comparability(issuers) {
  if (!issuers.every((i) => i.status === "current")) return "unresolved";
  const p = issuers[0].period;
  return issuers.every((i) => i.period && p && i.period.start === p.start && i.period.end === p.end) ? "aligned-periods" : "different-periods";
}
function planIssuerRevenueAcquisition(configuration) {
  const c = config(configuration);
  return { type: "IssuerRevenueAcquisitionPlan", version: 1, minimumIntervalMs: c.minimumIntervalMs, maximumCohortBytes: c.maximumCohortBytes, requests: c.issuers.map((i) => ({ cik: i.cik, ticker: i.ticker, url: urlFor(i.cik), headers: { "User-Agent": c.userAgent, Accept: "application/json" }, timeoutMs: c.timeoutMs, maximumBytes: c.maximumBytes })) };
}
function validateIssuerRevenueComparisonRequest(body, configuration) {
  const c = config(configuration);
  if (!record4(body) || Reflect.ownKeys(body).length !== 1 || !Object.hasOwn(body, "periodKind") || !c.allowedPeriodKinds.includes(body.periodKind)) throw new TypeError("Invalid issuer revenue comparison request");
  return { periodKind: body.periodKind };
}
function periodValid(p, kind, asOf, nowDay, maxAge) {
  if (!record4(p)) return false;
  const start = day(p.start), end = day(p.end);
  const length = (end - start) / DAY4 + 1;
  const [lo, hi] = kind === "quarter" ? [70, 110] : [330, 380];
  return Number.isFinite(start) && Number.isFinite(end) && start <= end && end <= day(asOf) && length === p.durationDays && length >= lo && length <= hi && (nowDay - end) / DAY4 <= maxAge;
}
function financial(r, kind, c, asOf, today) {
  need(r.status === "current" || c.allowAmbiguousEvidence && r.status === "ambiguous");
  need(Array.isArray(r.witnesses) && r.witnesses.length > 0);
  const latest = /* @__PURE__ */ new Map();
  for (const w of r.witnesses) {
    need(record4(w) && periodValid(w, kind, asOf, today, c.maximumAgeDays[kind]));
    need(Number.isFinite(w.value) && w.unit === "USD" && ["10-Q", "10-Q/A", "10-K", "10-K/A"].includes(w.form) && Number.isFinite(day(w.filed)) && w.filed <= asOf && text(w.accession) && text(w.concept));
    const old = latest.get(w.concept);
    if (!old || w.filed > old.filed) latest.set(w.concept, { filed: w.filed, values: [w.value] });
    else if (w.filed === old.filed) old.values.push(w.value);
  }
  const values = [...latest.values()].flatMap((x) => x.values);
  if (r.period !== null) {
    need(periodValid(r.period, kind, asOf, today, c.maximumAgeDays[kind]));
    need(r.witnesses.every((w) => w.start === r.period.start && w.end === r.period.end && w.durationDays === r.period.durationDays));
  }
  if (r.status === "current") {
    need(r.period !== null && Number.isFinite(r.value) && text(r.revision) && r.revision !== "ambiguous");
    need(values.every((v) => v === r.value));
  } else {
    need(r.value === null && r.revision === "ambiguous");
    if (r.period === null) {
      need(new Set(r.witnesses.map((w) => w.end)).size === 1 && new Set(r.witnesses.map((w) => w.start)).size > 1);
    } else need(new Set(values).size > 1);
  }
}
function selectPreparedIssuerRevenueComparison(input) {
  const { body, configuration, cohort, now } = input ?? {};
  const { periodKind } = validateIssuerRevenueComparisonRequest(body, configuration);
  const n = instant(now);
  if (!Number.isFinite(n)) throw new TypeError("Invalid explicit now");
  const c = configuration;
  try {
    need(record4(cohort) && cohort.type === "IssuerRevenuePreparedCohort" && cohort.version === 1 && canonical(cohort.observedAt));
    const observed = instant(cohort.observedAt);
    need(Number.isFinite(day(cohort.asOf)) && cohort.asOf === cohort.observedAt.slice(0, 10) && observed <= n && n - observed <= c.maximumSnapshotAgeMs);
    need(record4(cohort.results) && Object.hasOwn(cohort.results, "quarter") && Object.hasOwn(cohort.results, "annual"));
    const r = cohort.results[periodKind];
    need(record4(r) && r.type === "IssuerRevenueComparison" && r.version === 1 && r.observedAt === cohort.observedAt && r.asOf === cohort.asOf && r.periodKind === periodKind && r.datePolicy === "filing-date-cutoff-on-received-sources");
    need(Array.isArray(r.issuers) && Array.isArray(r.evidencePackets) && r.issuers.length === c.issuers.length && r.evidencePackets.length === c.issuers.length);
    const today = day(new Date(n).toISOString().slice(0, 10));
    for (let j = 0; j < c.issuers.length; j++) {
      const i = r.issuers[j], expected = c.issuers[j], p = r.evidencePackets[j];
      need(record4(i) && i.type === "IssuerRevenueReconciliation" && i.version === 1 && i.cik === expected.cik && i.ticker === expected.ticker && i.asOf === r.asOf && i.periodKind === periodKind && text(i.issuer) && i.unit === "USD");
      const s = i.source;
      need(record4(s) && s.uri === urlFor(expected.cik) && ni(s.digest) && positive(s.bytes) && s.bytes <= c.maximumBytes && canonical(s.observedAt));
      const sn = instant(s.observedAt);
      need(sn <= observed && n - sn <= c.maximumSnapshotAgeMs);
      financial(i, periodKind, c, r.asOf, today);
      need(record4(p) && p.type === "IssuerEvidencePacket" && p.version === 1 && p.ticker === String(expected.ticker).toUpperCase() && p.issuer === i.issuer && p.asOf === r.asOf && ni(p.id) && p.brokerageEffect === false);
      need(Array.isArray(p.sources) && p.sources.length === 1 && record4(p.sources[0]));
      need(p.sources[0].uri === s.uri && p.sources[0].digest === s.digest && p.sources[0].observedAt === s.observedAt);
      need(Array.isArray(p.claims) && p.claims.length === 1 && record4(p.claims[0]));
      const claim = p.claims[0];
      need(Array.isArray(claim.sourceDigests) && claim.sourceDigests.length === 1 && claim.sourceDigests[0] === s.digest && claim.statement === statement(i));
    }
    need(r.comparability === comparability(r.issuers));
    return r;
  } catch {
    throw unavailable();
  }
}
function abortable(promise, signal) {
  if (!signal) return Promise.resolve(promise);
  return new Promise((resolve, reject) => {
    const stop = () => reject(signal.reason ?? new Error("Acquisition timeout"));
    if (signal.aborted) {
      stop();
      return;
    }
    signal.addEventListener("abort", stop, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => signal.removeEventListener("abort", stop));
  });
}
async function boundedBody(stream, limit2, signal) {
  if (!stream || typeof stream.getReader !== "function") throw new Error("invalid-stream");
  const reader = stream.getReader();
  const chunks = [];
  let total = 0, complete = false;
  try {
    for (; ; ) {
      const part = await abortable(reader.read(), signal);
      if (!record4(part)) throw new Error("invalid-stream");
      if (part.done) {
        complete = true;
        break;
      }
      if (!(part.value instanceof Uint8Array)) throw new Error("invalid-stream");
      total += part.value.byteLength;
      if (total > limit2) throw new Error("byte-overflow");
      chunks.push(part.value.slice());
    }
    const bytes2 = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes2.set(chunk, offset);
      offset += chunk.length;
    }
    return bytes2;
  } finally {
    if (!complete) {
      try {
        Promise.resolve(reader.cancel()).catch(() => {
        });
      } catch {
      }
    }
    try {
      reader.releaseLock();
    } catch {
    }
  }
}
function parseBytes(bytes2) {
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes2));
}
async function platformSleep(ms) {
  let remaining = ms;
  while (remaining > 0) {
    const chunk = Math.min(remaining, 2147483647);
    await new Promise((resolve) => setTimeout(resolve, chunk));
    remaining -= chunk;
  }
}
async function acquire(request, fetcher, clock, fixedDay) {
  let signal;
  try {
    signal = AbortSignal.timeout(request.timeoutMs);
  } catch {
    throw refused("timeout-configuration", false);
  }
  let response2;
  try {
    response2 = await abortable(fetcher(request.url, { method: "GET", headers: request.headers, redirect: "manual", signal }), signal);
  } catch {
    throw refused("network-or-timeout", true);
  }
  const retryAfter = response2?.headers?.get?.("Retry-After");
  if (response2?.status !== 200) {
    try {
      Promise.resolve(response2?.body?.cancel?.()).catch(() => {
      });
    } catch {
    }
    const status = response2?.status;
    throw refused("http-" + String(status), status === 429 || status >= 500 && status <= 599, retryAfter);
  }
  let bytes2;
  try {
    const length = response2.headers?.get?.("Content-Length");
    if (length !== null && length !== void 0 && /^\d+$/.test(length) && Number(length) > request.maximumBytes) {
      try {
        Promise.resolve(response2.body?.cancel?.()).catch(() => {
        });
      } catch {
      }
      throw new Error("byte-overflow");
    }
    bytes2 = await boundedBody(response2.body, request.maximumBytes, signal);
  } catch (e) {
    throw refused(signal.aborted ? "network-or-timeout" : e?.message === "byte-overflow" ? "byte-overflow" : "body-unavailable", signal.aborted || e?.message !== "byte-overflow" && e?.message !== "invalid-stream", retryAfter);
  }
  const observed = instant(clock());
  if (!Number.isFinite(observed)) throw refused("invalid-clock", false);
  const observedAt = new Date(observed).toISOString();
  if (observedAt.slice(0, 10) !== fixedDay) throw refused("utc-day-changed", true);
  try {
    const companyfacts = parseBytes(bytes2);
    const address2 = await addressContent(bytes2, { mediaType: "application/json" });
    if (!record4(address2) || address2.kind !== "semiotic-content.raw-carrier-address" || address2.version !== 1 || address2.algorithm !== "sha-256" || address2.size !== bytes2.length || address2.mediaType !== "application/json" || !ni(address2.ni) || !positive(address2.size)) throw new Error("Invalid raw address");
    return { companyfacts, source: { uri: request.url, digest: address2.ni, bytes: address2.size, observedAt } };
  } catch {
    throw refused("invalid-source", false, retryAfter);
  }
}
async function compactIssuer(request, c, fetcher, clock, asOf) {
  const { companyfacts, source } = await acquire(request, fetcher, clock, asOf);
  const compact = {};
  for (const periodKind of KINDS) {
    let result;
    try {
      result = { ...reconcileIssuerRevenueFacts({ cik: request.cik, asOf, periodKind, maximumAgeDays: c.maximumAgeDays[periodKind], companyfacts }), ticker: request.ticker, source: { ...source } };
    } catch {
      throw refused("invalid-source-identity", false);
    }
    let packet;
    try {
      packet = await formIssuerEvidencePacket({ ticker: request.ticker, issuer: result.issuer, asOf, sources: [{ uri: source.uri, observedAt: source.observedAt, digest: source.digest }], claims: [{ statement: statement(result), sourceDigests: [source.digest] }] });
    } catch {
      throw refused("packet-construction", false);
    }
    compact[periodKind] = { result, packet };
  }
  return compact;
}
async function prepareIssuerRevenueCohort(configuration, adapters = {}) {
  const plan = planIssuerRevenueAcquisition(configuration);
  if (!record4(adapters)) throw new TypeError("Invalid adapters");
  const clock = adapters.now === void 0 ? Date.now : adapters.now;
  const fetcher = adapters.fetch === void 0 ? globalThis.fetch : adapters.fetch;
  const sleep = adapters.sleep === void 0 ? platformSleep : adapters.sleep;
  if (typeof clock !== "function" || typeof fetcher !== "function" || typeof sleep !== "function") throw new TypeError("Invalid adapters");
  const start = instant(clock());
  if (!Number.isFinite(start)) throw new TypeError("Invalid preparation clock");
  const asOf = new Date(start).toISOString().slice(0, 10);
  const parts = { quarter: { issuers: [], evidencePackets: [] }, annual: { issuers: [], evidencePackets: [] } };
  for (let j = 0; j < plan.requests.length; j++) {
    if (j) {
      try {
        await sleep(plan.minimumIntervalMs);
      } catch {
        throw refused("spacing-unavailable", true);
      }
    }
    const compact = await compactIssuer(plan.requests[j], configuration, fetcher, clock, asOf);
    for (const k of KINDS) {
      parts[k].issuers.push(compact[k].result);
      parts[k].evidencePackets.push(compact[k].packet);
    }
  }
  let completion;
  try {
    completion = instant(clock());
  } catch {
    throw refused("invalid-clock", false);
  }
  if (!Number.isFinite(completion)) throw refused("invalid-clock", false);
  const observedAt = new Date(completion).toISOString();
  if (observedAt.slice(0, 10) !== asOf) throw refused("utc-day-changed", true);
  if (completion < start || KINDS.some((k) => parts[k].issuers.some((i) => instant(i.source.observedAt) > completion))) throw refused("invalid-clock", false);
  const results = {};
  for (const k of KINDS) results[k] = { type: "IssuerRevenueComparison", version: 1, observedAt, asOf, periodKind: k, datePolicy: "filing-date-cutoff-on-received-sources", comparability: comparability(parts[k].issuers), issuers: parts[k].issuers, evidencePackets: parts[k].evidencePackets };
  const cohort = { type: "IssuerRevenuePreparedCohort", version: 1, observedAt, asOf, results };
  try {
    if (new TextEncoder().encode(JSON.stringify(cohort)).byteLength > configuration.maximumCohortBytes) throw new Error("overflow");
  } catch {
    throw refused("compact-output-overflow", false);
  }
  return cohort;
}
async function readPreparedIssuerRevenueComparison(body, env, configuration) {
  validateIssuerRevenueComparisonRequest(body, configuration);
  let cohort;
  try {
    const bucket = env?.ISSUER_EVIDENCE;
    if (!bucket || typeof bucket.get !== "function") throw unavailable();
    const object2 = await bucket.get(configuration.cacheKey);
    if (!object2 || object2.size !== void 0 && (!Number.isSafeInteger(object2.size) || object2.size < 0 || object2.size > configuration.maximumCohortBytes)) {
      try {
        Promise.resolve(object2?.body?.cancel?.()).catch(() => {
        });
      } catch {
      }
      throw unavailable();
    }
    cohort = parseBytes(await boundedBody(object2.body, configuration.maximumCohortBytes));
  } catch {
    throw unavailable();
  }
  return selectPreparedIssuerRevenueComparison({ body, configuration, cohort, now: Date.now() });
}
var KINDS, DAY4, record4, text, positive, urlFor;
var init_prepared_cohort = __esm({
  "../../../../../../../computer-code-engineering-services-section/services/javascript-engineering-services-section/services/javascript-code-fabrication-services-section/services/javascript-node-code-fabrication-services-section/services/jsnode-package-services-section/data/state/registry-package-installations/issuer-research-0.1.5/node_modules/@red-cup-engineering/issuer-research-media-service/src/prepared-cohort.mjs"() {
    init_evidence_packet();
    init_issuer_revenue_reconciliation();
    init_content_address();
    init_ni_uri4();
    KINDS = ["quarter", "annual"];
    DAY4 = 864e5;
    record4 = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
    text = (x) => typeof x === "string" && x.trim().length > 0;
    positive = (x) => Number.isSafeInteger(x) && x > 0;
    urlFor = (cik) => "https://data.sec.gov/api/xbrl/companyfacts/CIK" + cik + ".json";
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
    "admission": "Received actual unattended authentication and contract discovery at20:31:50.362Z: awaiting-hire,3providerrequests,zero new cash expense. Prepared CSV business remains conditional on actual outside agent hire, machine agreement, buyer acceptance and buyer-funded settlement. No paid delivery or USD200/day performance is established.",
    "priceText": "50 USDC"
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
  let text2 = base;
  for (let index = parts.length - 1; index >= 0; index -= 1) {
    const part = parts[index];
    text2 += part.kind === "index" ? `[${part.value}]` : `.${part.value}`;
  }
  return text2;
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
        const text2 = item ? "true" : "false";
        chargeCanonical(state, text2.length, frame.path);
        tokens.push(text2);
        result = item;
        frames.pop();
        continue;
      }
      if (typeof item === "string") {
        const text2 = stringText(item, frame.path, state.envelope.maxStringBytes, "string-limit");
        chargeCanonical(state, byteLength(text2), frame.path);
        tokens.push(text2);
        result = item;
        frames.pop();
        continue;
      }
      if (typeof item === "number") {
        if (!Number.isFinite(item)) fail("invalid-json-value", frame.path, "JCS admits only finite IEEE-754 numbers");
        const text2 = JSON.stringify(item);
        chargeCanonical(state, byteLength(text2), frame.path);
        tokens.push(text2);
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
  let text2;
  try {
    text2 = typeof source === "string" ? source : new TextDecoder("utf-8", { fatal: true }).decode(source);
  } catch {
    fail("malformed-utf8", "$", "source is not well-formed UTF-8");
  }
  return canonicalizeJson(new StrictJsonParser(text2, envelope2).parse(), envelope2);
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
  const text2 = value.trim();
  if (/^\d+$/u.test(text2)) {
    const seconds = Number(text2);
    return Number.isSafeInteger(seconds) && seconds <= Number.MAX_SAFE_INTEGER / 1e3 ? seconds * 1e3 : null;
  }
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  let match, year, month, day2, hour, minute, second;
  if (match = /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{2}):(\d{2}):(\d{2}) GMT$/u.exec(text2)) {
    [, day2, month, year, hour, minute, second] = match;
  } else if (match = /^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\d{2})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-(\d{2}) (\d{2}):(\d{2}):(\d{2}) GMT$/u.exec(text2)) {
    [, day2, month, year, hour, minute, second] = match;
    const current = new Date(receivedAt).getUTCFullYear();
    year = Math.floor(current / 100) * 100 + Number(year);
    if (year > current + 50) year -= 100;
  } else if (match = /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?: (\d)|([0-3]\d)) (\d{2}):(\d{2}):(\d{2}) (\d{4})$/u.exec(text2)) {
    month = match[1];
    day2 = match[2] ?? match[3];
    hour = match[4];
    minute = match[5];
    second = match[6];
    year = match[7];
  } else return null;
  const date = /* @__PURE__ */ new Date(0);
  date.setUTCFullYear(Number(year), months.indexOf(month), Number(day2));
  date.setUTCHours(Number(hour), Number(minute), Number(second), 0);
  if (!Number.isFinite(date.getTime()) || date.getUTCFullYear() !== Number(year) || date.getUTCMonth() !== months.indexOf(month) || date.getUTCDate() !== Number(day2) || date.getUTCHours() !== Number(hour) || date.getUTCMinutes() !== Number(minute) || date.getUTCSeconds() !== Number(second)) return null;
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
async function receiptsFor(hash3, fetchImpl) {
  const read2 = async (url) => {
    try {
      const response2 = await fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getTransactionReceipt", params: [hash3] }),
        signal: AbortSignal.timeout(1e4)
      });
      const body = await response2.json();
      return response2.ok && !body.error && body.result ? body.result : null;
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
  for (const object2 of page.objects) if (!seen.has(object2.key)) fresh.push(object2.key);
  const received = [];
  for (const witnessKey of fresh.slice(0, limit2)) {
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
var hash = async (text2) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text2))), (n) => n.toString(16).padStart(2, "0")).join("");
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
    let response2;
    try {
      response2 = await fetchImpl(rpc ? path : ORIGIN + path, {
        method,
        redirect: "manual",
        signal: AbortSignal.timeout(15e3),
        headers: { accept: "application/json", ...body === void 0 ? {} : { "content-type": "application/json" }, ...headers },
        ...body === void 0 ? {} : { body }
      });
    } catch {
      throw error("research-response-unknown");
    }
    const retry = response2.headers.get("retry-after");
    if (retry) {
      const delay = retry.length <= 256 ? retryAfterDelayMs(retry, now()) : null;
      state.retryBlocked = retry.length > 256 || delay === null && /^\d+$/.test(retry.trim()) || delay !== null && !Number.isFinite(new Date(now() + delay).getTime());
      if (state.retryBlocked || delay !== null) {
        state.retryAt = state.retryBlocked ? null : now() + delay;
        state.retryAfter = retry.slice(0, 256);
        await storage.put(RESEARCH_STATE, state);
      }
    }
    if (response2.status >= 300 && response2.status < 400) throw error("research-redirect-refused", response2.status);
    if (response2.status === 402) throw error("research-payment-refused", 402);
    if (Number(response2.headers.get("content-length")) > LIMIT) throw error("research-response-too-large", response2.status);
    let text2 = "", bytes2 = 0;
    try {
      const reader = response2.body?.getReader(), decoder = new TextDecoder("utf-8", { fatal: true });
      if (reader) for (; ; ) {
        const part = await reader.read();
        if (part.done) break;
        bytes2 += part.value.byteLength;
        if (bytes2 > LIMIT) {
          await reader.cancel();
          throw error("research-response-too-large", response2.status);
        }
        text2 += decoder.decode(part.value, { stream: true });
      }
      text2 += decoder.decode();
    } catch (e) {
      throw e.code?.startsWith("research-") ? e : error("research-response-read-failed", response2.status);
    }
    let value;
    try {
      value = admitCanonicalJson(text2, ENVELOPE).value;
    } catch {
      throw error("research-invalid-response", response2.status);
    }
    if (!response2.ok) throw error(response2.status === 402 ? "research-payment-refused" : "research-provider-refused", response2.status);
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
    const terminal = code.includes("mismatch") || code === "research-payment-refused" || code === "research-redirect-refused" || [400, 401, 403, 404, 409, 410, 422].includes(e.status);
    return finish(code, { terminal });
  }
}

// src/opentask-client.mjs
import { sign } from "node:crypto";
import { Buffer as Buffer4 } from "node:buffer";
var ORIGIN2 = "https://opentask.ai";
var ID2 = "[A-Za-z0-9_-]{1,200}";
var RESOURCE = new RegExp(`^/api/agent/(?:bids/${ID2}|contracts(?:/${ID2}(?:/messages|/payout-destination|/crypto-payment-requests(?:/${ID2})?|/deliveries(?:/${ID2})?)?)?)$`);
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
var defaultCanonical = (privateJwk, canonical2) => sign("sha256", Buffer4.from(canonical2), {
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
    let response2;
    try {
      response2 = await fetchImpl(ORIGIN2 + path, {
        method,
        headers,
        redirect: "manual",
        signal: AbortSignal.timeout(15e3),
        ...body === void 0 ? {} : { body: body instanceof URLSearchParams ? body.toString() : JSON.stringify(body) }
      });
    } catch {
      throw new OpenTaskError("response-unknown");
    }
    const retryFacts = {}, receivedAt = now(), retry = response2.headers.get("retry-after");
    if (retry) {
      const delay = retry.length <= 256 ? retryAfterDelayMs(retry, receivedAt) : null;
      const blocked = retry.length > 256 || delay === null && /^\d+$/.test(retry.trim()) || delay !== null && !Number.isFinite(new Date(receivedAt + delay).getTime());
      if (blocked || delay !== null) {
        Object.assign(retryFacts, { retryBlocked: blocked, retryAt: blocked ? null : receivedAt + delay, retryAfter: retry.slice(0, 256) });
        await storage.put(BACKOFF, { ...retryFacts, receivedAt });
      }
    }
    const responseError = (code) => Object.assign(new OpenTaskError(code, response2.status), retryFacts);
    if (response2.status >= 300 && response2.status < 400) throw responseError("redirect-refused");
    const receivedNonce = response2.headers.get("dpop-nonce");
    if (receivedNonce && receivedNonce.length <= 512) nonce = receivedNonce;
    if (Number(response2.headers.get("content-length")) > 262144) throw responseError("response-too-large");
    let bytes2 = 0, text2 = "";
    try {
      const reader = response2.body?.getReader();
      const decoder = new TextDecoder();
      if (reader) for (; ; ) {
        const part = await reader.read();
        if (part.done) break;
        bytes2 += part.value.byteLength;
        if (bytes2 > 262144) {
          await reader.cancel();
          throw responseError("response-too-large");
        }
        text2 += decoder.decode(part.value, { stream: true });
      }
      text2 += decoder.decode();
    } catch (error2) {
      throw error2 instanceof OpenTaskError ? error2 : responseError("response-read-failed");
    }
    let data;
    try {
      data = JSON.parse(text2);
    } catch {
      throw responseError("invalid-response");
    }
    if (!response2.ok) {
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
      let response2;
      try {
        response2 = resume ? await assertion(c) : await wire("/api/agent/auth/token", {
          method: "POST",
          credential: c,
          token: false,
          body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: c.refreshToken })
        });
      } catch (error2) {
        if (resume || REPLAY.has(error2.code) || error2.status >= 400 && error2.status < 500 && error2.code !== "invalid_grant") throw error2;
        response2 = await assertion(c);
      }
      if (typeof response2.access_token !== "string" || typeof response2.refresh_token !== "string" || !Number.isFinite(response2.expires_in) || response2.expires_in <= 0 || response2.expires_in > 86400) throw new OpenTaskError("token-response-invalid");
      const replacement = {
        privateJwk: c.privateJwk,
        credentialId: c.credentialId,
        accessToken: response2.access_token,
        refreshToken: response2.refresh_token,
        expiresAt: now() + response2.expires_in * 1e3
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
  const bytes2 = new TextEncoder().encode(JSON.stringify(stable(value)));
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes2)), (n) => n.toString(16).padStart(2, "0")).join("");
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
    const bytes2 = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes2.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes2;
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
  let bytes2 = await collectBody(stream, maxEncodedBytes, "request body", signal);
  for (const coding of [
    ...codings
  ].reverse()) bytes2 = await collectBody(decoder(bytes2, coding), maxBytes, "decoded request body", signal);
  if (bytes2.byteLength > maxBytes) throw new BodyReadError(413, "body-too-large", `decoded request body exceeded ${maxBytes} bytes`);
  return bytes2;
}
function decodeBody(bytes2, contentType) {
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
    if ((charset === "ascii" || charset === "us-ascii") && bytes2.some((byte) => byte > 127)) throw new BodyReadError(400, "invalid-body", "US-ASCII request body contains a non-ASCII octet");
    return Array.from(bytes2, (byte) => String.fromCharCode(byte)).join("");
  }
  try {
    return new TextDecoder("utf-8", {
      fatal: true
    }).decode(bytes2);
  } catch (cause) {
    throw new BodyReadError(400, "invalid-body", "request body must contain valid UTF-8", {
      cause
    });
  }
}

// node_modules/@red-cup-engineering/http-services-section/src/body/web.mjs
var DEFAULT_BODY_LIMIT = 1024 * 1024;
var decode = (bytes2, coding) => {
  let decoder;
  try {
    decoder = new DecompressionStream(coding);
  } catch (cause) {
    throw new BodyReadError(415, "unsupported-content-coding", `unsupported request content-encoding: ${coding}`, {
      cause
    });
  }
  return new Blob([
    bytes2
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
  let response2;
  try {
    response2 = await fetchImpl(HASHN_ORIGIN + path, {
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
    status: response2.status,
    requestId: response2.headers.get("x-request-id")?.slice(0, 256) ?? null,
    cfRay: response2.headers.get("cf-ray")?.slice(0, 256) ?? null,
    coverage: "headers-only"
  };
  const refuse = (code) => Object.assign(hashnError(code, response2.status), { providerReceipt: privateHashnReceipt(receipt, credential) });
  const retry = response2.headers.get("retry-after");
  if (retry) {
    const delay = retry.length <= 256 ? retryAfterDelayMs(retry, now()) : null;
    const retryBlocked = retry.length > 256 || delay === null && /^\d+$/.test(retry.trim()) || delay !== null && !Number.isFinite(new Date(now() + delay).getTime());
    if (retryBlocked || delay !== null) await onRetry({ retryBlocked, retryAt: retryBlocked ? null : now() + delay });
  }
  if (Number(response2.headers.get("content-length")) > LIMIT2) {
    receipt.coverage = "declared-body-too-large";
    void response2.body?.cancel().catch(() => {
    });
    throw refuse("hashn-response-too-large");
  }
  let text2;
  try {
    text2 = await readTextBody({ body: response2.body, headers: response2.headers, signal }, { maxBytes: LIMIT2, decodeContentEncoding: false });
  } catch {
    receipt.coverage = "body-unreceived-or-limit";
    throw refuse("hashn-response-invalid");
  }
  receipt.coverage = "complete-bounded-body";
  let data;
  try {
    data = admitCanonicalJson(text2, envelope).value;
    receipt.body = data;
  } catch {
    receipt.body = text2;
    if (response2.ok) throw refuse("hashn-response-invalid");
  }
  if (!response2.ok) throw refuse(response2.status >= 300 && response2.status < 400 ? "hashn-redirect-refused" : response2.status === 402 ? "hashn-payment-refused" : "hashn-provider-refused");
  return { status: response2.status, data, providerReceipt: privateHashnReceipt(receipt, credential) };
}

// src/hashn-acquisition.mjs
var HASHN_STATE = "hashn/acquisition";
var HASHN_SUMMARY = "hashn/public-summary";
var AUTH2 = "hashn/auth";
var SIX_HOURS = 6 * 60 * 60 * 1e3;
var WEEK = 7 * 24 * 60 * 60 * 1e3;
var hash2 = async (value) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalJson(value)))), (n) => n.toString(16).padStart(2, "0")).join("");
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
  const finish = async (stage, terminal = false, delay = SIX_HOURS) => {
    state.stage = stage;
    state.terminal = terminal;
    state.nextAttemptAt = terminal || state.retryBlocked ? null : Math.max(now() + delay, state.retryAt ?? 0);
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
    if (state.retryBlocked || state.nextAttemptAt > now()) return { stage: state.stage, requests: 0, newCashExpenseUsd: 0 };
    if (state.monitoringUntil && now() >= state.monitoringUntil) return finish("hashn-reconciliation-deadline-held", true);
    if (!priorAuth) {
      const { data: data2 } = await wire("/agents/me", { credential });
      if ((data2.agent_id ?? data2.id) !== credential.agentId) return finish("hashn-account-mismatch", true);
      await storage.put(AUTH2, credential);
    }
    state.binding ??= binding;
    state.scope ??= bound;
    if (state.intent && !state.reconciliationAttempted) state.reconciliationAttempted = true;
    await storage.put(HASHN_STATE, state);
    const { data, providerReceipt } = await wire("/knocks", { credential });
    state.knocksReadbackReceipt = providerReceipt;
    if (!Array.isArray(data.outgoing)) throw hashnError("hashn-knocks-shape-held");
    if (data.has_more === true || data.next_cursor || data.nextCursor) throw hashnError("hashn-knocks-truncated-held");
    if (data.outgoing.some((k) => !k || !UUID.test(k.workspace_id ?? ""))) throw hashnError("hashn-knocks-shape-held");
    const related = data.outgoing.filter((k) => k.workspace_id === instance.workspaceId);
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
var id = (offer) => `${offer.method} ${offer.route}`;
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
  const response2 = await fetchImpl(catalogUrl, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(15e3), redirect: "manual" });
  if (!response2.ok) throw new Error(`catalog answered ${response2.status}`);
  const catalog = await response2.json();
  const offers = catalog.offers.filter((offer) => offer.listed);
  const at = now.toISOString();
  for (const offer of offers) state.routes[id(offer)] ??= { firstListedAt: at, price: offer.price, amountAtomic: offer.amountAtomic ?? null, heldSince: null, brokenStreak: 0 };
  const listed = new Set(offers.map(id));
  for (const route of Object.keys(state.routes)) if (!listed.has(route)) state.routes[route].delistedAt ??= at;
  const due = offers.sort((a, b) => Number(state.routes[id(a)].held !== false) - Number(state.routes[id(b)].held !== false) || (state.routes[id(a)].observedAt ?? "").localeCompare(state.routes[id(b)].observedAt ?? "")).slice(0, limit2);
  for (const offer of due) {
    const [url, init] = probeRequest(offer);
    let verdict;
    try {
      const response3 = await fetchImpl(url, { ...init, redirect: "manual", signal: AbortSignal.timeout(15e3) });
      verdict = judge(offer, response3.status, response3.headers.get("payment-required"), { payTo, resourceUrl: url });
      await response3.body?.cancel();
    } catch (error2) {
      verdict = { held: false, finding: `request failed: ${error2.message}` };
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
    const response2 = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json", ...env.ONCHAIN_SCAN_TOKEN ? { authorization: `Bearer ${env.ONCHAIN_SCAN_TOKEN}` } : {} },
      body: JSON.stringify({ at, cron })
    });
    const answer = response2.headers.get("content-type")?.includes("json") ? await response2.json() : null;
    const result = { at, status: response2.ok ? "ran" : `http-${response2.status}`, answer };
    await put(env.STATE, register("onchain"), result);
    return { status: result.status };
  } catch (error2) {
    await put(env.STATE, register("onchain"), { at, status: "unreachable", error: error2.message });
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
  const text2 = value.trim();
  const seconds = /^\d+$/.test(text2);
  const delay = seconds ? Number(text2) * 1e3 : /^[A-Za-z]{3}, /.test(text2) ? Date.parse(text2) - now.getTime() : 0;
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
    const producer = prepare ?? (await Promise.resolve().then(() => (init_prepared_cohort(), prepared_cohort_exports))).prepareIssuerRevenueCohort;
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
function instant2(value) {
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
  if (!instant2(value.at)) throw invalid();
  const deadline = () => instant2(value.nextAttemptAt) && Date.parse(value.nextAttemptAt) >= Date.parse(value.at);
  if (value.status === "prepared") {
    if (!(value.observedAt === null || instant2(value.observedAt)) || own(value, "retryBlocked") && value.retryBlocked !== false || !deadline()) throw invalid();
  } else if (value.status === "unavailable") {
    const nullableString = (v) => v === null || typeof v === "string";
    if (typeof value.error !== "string" || !nullableString(value.code) || !nullableString(value.reason) || typeof value.retryable !== "boolean" || !nullableString(value.retryAfter) || typeof value.retryBlocked !== "boolean" || (value.retryBlocked ? value.nextAttemptAt !== null : !deadline())) throw invalid();
  } else throw invalid();
}
function physicalSize(key, record5) {
  return bytes(key) + bytes(JSON.stringify(record5));
}
function readRecord(record5, key, plan) {
  if (record5 === void 0) return null;
  if (!object(record5) || Object.keys(record5).length !== 2 || !own(record5, "cacheKey") || !own(record5, "body") || typeof record5.cacheKey !== "string" || typeof record5.body !== "string") throw invalid();
  const limit2 = key === COHORT ? plan.maximumCohortBytes : STATUS_LIMIT;
  if (bytes(record5.body) > limit2 || physicalSize(key, record5) > TRANSACTION_LIMIT) throw invalid();
  const parsed = JSON.parse(record5.body);
  if (record5.cacheKey !== plan.cacheKey) return null;
  if (key === STATUS) validateStatus(parsed, plan.cacheKey);
  return record5.body;
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
    for (const [key, record5] of staged) {
      const size = physicalSize(key, record5);
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
    async put(key, text2) {
      const physical = resolve(key);
      let parsed;
      if (physical === STATUS) {
        try {
          if (typeof text2 !== "string" || bytes(text2) > STATUS_LIMIT) {
            failClosed();
            return;
          }
          parsed = JSON.parse(text2);
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
        if (typeof text2 !== "string" || bytes(text2) > plan.maximumCohortBytes) throw invalid();
        JSON.parse(text2);
      }
      if (overflow) return;
      staged.set(physical, { cacheKey: plan.cacheKey, body: text2 });
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
      for (const [key, record5] of staged) await transaction.put(key, record5);
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

// worker/earning-loops.mjs
var groupPayers = new Set(group_payers_default);
var CRONS = operation_default.crons;
async function run(env, cron, now = /* @__PURE__ */ new Date(), { configuration = operation_default, prepareIssuerRevenueCohort: prepareIssuerRevenueCohort2, issuerStorage } = {}) {
  if (configuration.issuerResearch && (env.ONCHAIN_SCAN_URL || configuration.onchainScanUrl))
    throw new TypeError("issuer operation has no subrequest allocation for an onchain hook");
  const outcome = { cron, at: now.toISOString() };
  const step = async (name, work) => {
    try {
      outcome[name] = await work();
    } catch (error2) {
      outcome[name] = { error: error2.message };
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
    if (configuration.issuerResearch) await step("issuerResearch", () => withIssuerSqliteStore(
      issuerStorage,
      configuration.issuerResearch,
      (store) => refreshIssuerResearch(store, configuration.issuerResearch, { now, prepare: prepareIssuerRevenueCohort2 })
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
      const at = Date.now(), commercial = configuration.commercial?.enabled === true || configuration.researchProcurement?.enabled === true || acquisition;
      const acquisitionState = acquisition ? await this.state.storage.get(HASHN_STATE) : null;
      const acquisitionPulseAt = acquisition ? await this.state.storage.get("hashn/next-pulse-at") : null;
      const acquisitionDue = acquisition && !acquisitionState?.terminal && !acquisitionState?.retryBlocked && !(acquisitionState?.nextAttemptAt > at) && !(acquisitionPulseAt > at);
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
              at: new Date(at).toISOString()
            });
          }
        } else await tick(this.env, new Date(slot), { ...this.options, issuerStorage: this.state.storage });
      } finally {
        let alarm = acquisitionOnly ? coreNextAt : commercial ? (Math.floor(at / 45e4) + 1) * 45e4 : nextTick(at);
        if (bootstrap && armed?.id === releaseId && Number.isFinite(armed.previousAlarm))
          alarm = Math.min(alarm, armed.previousAlarm > Date.now() ? armed.previousAlarm : Date.now() + 1e3);
        if (acquisition && !acquisitionOnly) await this.state.storage.put("earning-clock/core-next-at", alarm);
        if (configuration.researchProcurement?.enabled) {
          const pending = await this.state.storage.get(RESEARCH_STATE);
          if (!pending?.terminal && !pending?.retryBlocked && Number.isFinite(pending?.nextAttemptAt))
            alarm = Math.min(alarm, Math.max(Date.now() + 1e3, pending.nextAttemptAt));
        }
        if (acquisition) {
          const pending = await this.state.storage.get(HASHN_STATE);
          const pulseAt = await this.state.storage.get("hashn/next-pulse-at");
          if (!pending?.terminal && !pending?.retryBlocked)
            alarm = Math.min(alarm, Math.max(Date.now() + 1e3, pending?.nextAttemptAt ?? 0, pulseAt ?? 0));
        }
        await this.state.storage.setAlarm(alarm);
      }
    });
  }
  async fetch(request) {
    if (request && new URL(request.url).pathname === "/acquisition.json") {
      const summary = await this.state.storage.get(HASHN_SUMMARY);
      if (!summary) return new Response("not yet observed\n", { status: 404 });
      const fields = ["stage", "requests", "newCashExpenseUsd", "at", "offerId", "knockStatus", "agreementReceived", "deliverySubmitted", "recognizedOutsideRevenue"];
      return Response.json(Object.fromEntries(fields.filter((key) => Object.hasOwn(summary, key)).map((key) => [key, summary[key]])), { headers: { "cache-control": "no-store" } });
    }
    if (request) {
      const response2 = await issuerSqliteResponse(request, this.state.storage, (this.options.configuration ?? operation_default).issuerResearch);
      if (response2) return response2;
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
      return Response.json({
        stage: summary.stage,
        requests: summary.requests,
        newCashExpenseUsd: 0,
        at: summary.at,
        nextTick: alarm ? new Date(alarm).toISOString() : null
      }, { headers: { "cache-control": "no-store" } });
    }
    return this.enqueue(async () => {
      let alarm = await this.state.storage.getAlarm();
      const configuration = this.options.configuration ?? operation_default;
      const at = Date.now(), commercial = configuration.commercial?.enabled || configuration.researchProcurement?.enabled || configuration.hashAcquisition?.enabled;
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
var earning_loops_default = {
  async scheduled(event, env, context) {
    context.waitUntil(run(env, event.cron));
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
