// test/workerd-hashn-worker.mjs
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
  const error = new TypeError(`${code} at ${renderedPath}: ${message}`);
  error.code = code;
  error.path = renderedPath;
  throw error;
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
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  } catch (error) {
    cancel(reader, error);
    if (error instanceof BodyReadError) throw error;
    if (signal?.aborted) throw signal.reason;
    throw new BodyReadError(400, "invalid-body", "could not read request body", {
      cause: error
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
  let bytes = await collectBody(stream, maxEncodedBytes, "request body", signal);
  for (const coding of [
    ...codings
  ].reverse()) bytes = await collectBody(decoder(bytes, coding), maxBytes, "decoded request body", signal);
  if (bytes.byteLength > maxBytes) throw new BodyReadError(413, "body-too-large", `decoded request body exceeded ${maxBytes} bytes`);
  return bytes;
}
function decodeBody(bytes, contentType) {
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
    if ((charset === "ascii" || charset === "us-ascii") && bytes.some((byte) => byte > 127)) throw new BodyReadError(400, "invalid-body", "US-ASCII request body contains a non-ASCII octet");
    return Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
  }
  try {
    return new TextDecoder("utf-8", {
      fatal: true
    }).decode(bytes);
  } catch (cause) {
    throw new BodyReadError(400, "invalid-body", "request body must contain valid UTF-8", {
      cause
    });
  }
}

// node_modules/@red-cup-engineering/http-services-section/src/body/web.mjs
var DEFAULT_BODY_LIMIT = 1024 * 1024;
var decode = (bytes, coding) => {
  let decoder;
  try {
    decoder = new DecompressionStream(coding);
  } catch (cause) {
    throw new BodyReadError(415, "unsupported-content-coding", `unsupported request content-encoding: ${coding}`, {
      cause
    });
  }
  return new Blob([
    bytes
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

// src/hashn-client.mjs
var HASHN_ORIGIN = "https://api.hashn.com";
var UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
var LIMIT = 131072;
var envelope = { ...JSON_RESOURCE_ENVELOPE, maxSourceBytes: LIMIT, maxCanonicalBytes: LIMIT, maxDepth: 20, maxNodes: 12e3 };
var hashnError = (code, status = 0) => Object.assign(new Error(code), { code, status });
function privateHashnReceipt(value, credential) {
  const redact = (v) => {
    if (typeof v === "string") return v.replace(/aw_[A-Za-z0-9._~-]+/g, "[redacted-token]").split(credential?.apiToken || "\0").join("[redacted-token]");
    if (Array.isArray(v)) return v.map(redact);
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, /authorization|token|secret|password|credential/i.test(k) ? "[redacted]" : redact(x)]));
    return v;
  };
  return redact(value);
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
  const allowed = method === "GET" && ["/agents/me", "/knocks"].includes(path) || method === "POST" && (path === "/agents" && !credential || /^\/workspaces\/[a-f0-9-]{36}\/knock$/i.test(path) && credential);
  if (!allowed) throw hashnError("hashn-endpoint-refused");
  const signal = AbortSignal.timeout(15e3);
  let response;
  try {
    response = await fetchImpl(HASHN_ORIGIN + path, {
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
    status: response.status,
    requestId: response.headers.get("x-request-id")?.slice(0, 256) ?? null,
    cfRay: response.headers.get("cf-ray")?.slice(0, 256) ?? null,
    coverage: "headers-only"
  };
  const refuse = (code) => Object.assign(hashnError(code, response.status), { providerReceipt: privateHashnReceipt(receipt, credential) });
  const retry = response.headers.get("retry-after");
  if (retry) {
    const delay = retry.length <= 256 ? retryAfterDelayMs(retry, now()) : null;
    const retryBlocked = retry.length > 256 || delay === null && /^\d+$/.test(retry.trim()) || delay !== null && !Number.isFinite(new Date(now() + delay).getTime());
    if (retryBlocked || delay !== null) await onRetry({ retryBlocked, retryAt: retryBlocked ? null : now() + delay });
  }
  if (Number(response.headers.get("content-length")) > LIMIT) {
    receipt.coverage = "declared-body-too-large";
    void response.body?.cancel().catch(() => {
    });
    throw refuse("hashn-response-too-large");
  }
  let text;
  try {
    text = await readTextBody({ body: response.body, headers: response.headers, signal }, { maxBytes: LIMIT, decodeContentEncoding: false });
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
    if (response.ok) throw refuse("hashn-response-invalid");
  }
  if (!response.ok) throw refuse(response.status >= 300 && response.status < 400 ? "hashn-redirect-refused" : response.status === 402 ? "hashn-payment-refused" : "hashn-provider-refused");
  return { status: response.status, data, providerReceipt: privateHashnReceipt(receipt, credential) };
}

// src/hashn-acquisition.mjs
var HASHN_STATE = "hashn/acquisition";
var HASHN_SUMMARY = "hashn/public-summary";
var AUTH = "hashn/auth";
var SIX_HOURS = 6 * 60 * 60 * 1e3;
var WEEK = 7 * 24 * 60 * 60 * 1e3;
var hash = async (value) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalJson(value)))), (n) => n.toString(16).padStart(2, "0")).join("");
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
    const binding = await hash(bound);
    if (state.binding && state.binding !== binding) return finish("hashn-binding-drift", true);
    const priorAuth = await storage.get(AUTH);
    if (priorAuth && (priorAuth.agentId !== credential.agentId || priorAuth.apiToken !== credential.apiToken)) return finish("hashn-credential-drift", true);
    if (state.terminal) return finish(state.stage, true);
    if (state.retryBlocked || state.nextAttemptAt > now()) return { stage: state.stage, requests: 0, newCashExpenseUsd: 0 };
    if (state.monitoringUntil && now() >= state.monitoringUntil) return finish("hashn-reconciliation-deadline-held", true);
    if (!priorAuth) {
      const { data: data2 } = await wire("/agents/me", { credential });
      if ((data2.agent_id ?? data2.id) !== credential.agentId) return finish("hashn-account-mismatch", true);
      await storage.put(AUTH, credential);
    }
    state.binding ??= binding;
    state.scope ??= bound;
    if (state.intent && !state.reconciliationAttempted) state.reconciliationAttempted = true;
    await storage.put(HASHN_STATE, state);
    const { data } = await wire("/knocks", { credential });
    if (!Array.isArray(data.outgoing)) throw hashnError("hashn-knocks-shape-held");
    if (data.has_more === true || data.next_cursor || data.nextCursor) throw hashnError("hashn-knocks-truncated-held");
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
      payloadSha256: await hash({ note: instance.note }),
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
      [400, 401, 403, 404, 402, 409, 410, 422].includes(e.status) || code === "hashn-redirect-refused",
      state.intent && !state.reconciliationAttempted ? 3e4 : SIX_HOURS
    );
  }
}

// test/workerd-hashn-worker.mjs
var testNativeHashn = { async test() {
  const agentId = "33333333-3333-4333-8333-333333333333", buyerAgentId = "55555555-5555-4555-8555-555555555555";
  const workspaceId = "11111111-1111-4111-8111-111111111111", knockId = "77777777-7777-4777-8777-777777777777";
  const instance = { enabled: true, workspaceId, buyerAgentId, offerId: "fixture", note: "Exact terms before work.", maximumNewCashExpenseUsd: 0, maximumProviderRequestsPerPass: 3, pollIntervalMs: 216e5 };
  let time = Date.parse("2026-10-24T22:00:00Z"), posts = 0, outgoing = [];
  const values = /* @__PURE__ */ new Map(), storage = { async get(k) {
    return structuredClone(values.get(k));
  }, async put(k, v) {
    values.set(k, structuredClone(v));
  } };
  const options = { storage, instance, initialCredential: { agentId, apiToken: "aw_runtime_fixture_only" }, now: () => time, fetchImpl: async (url, init) => {
    if (url.endsWith("/agents/me")) return Response.json({ agent_id: agentId });
    if (url.endsWith("/knocks")) return Response.json({ outgoing });
    assert.equal(values.get(HASHN_STATE).intent.body.note, instance.note);
    assert.equal(init.method, "POST");
    posts++;
    outgoing = [{ knock_id: knockId, workspace_id: workspaceId, from_agent_id: agentId, to_agent_id: buyerAgentId, note: instance.note, status: "pending" }];
    return Response.json({ knock_id: knockId }, { status: 201 });
  } };
  const first = await runHashnAcquisition(options);
  assert.equal(first.requests, 3);
  assert.equal(first.stage, "hashn-knock-sent-readback-pending");
  time += 3e4;
  const next = await runHashnAcquisition(options);
  assert.equal(next.requests, 1);
  assert.equal(next.stage, "hashn-pending");
  assert.equal(posts, 1);
} };
export {
  testNativeHashn
};
