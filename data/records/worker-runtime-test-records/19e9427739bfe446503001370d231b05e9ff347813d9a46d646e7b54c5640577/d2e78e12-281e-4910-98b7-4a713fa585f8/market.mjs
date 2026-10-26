// ../../apps/market.561.group/src/issuer-evidence-store.mjs
function issuerEvidenceReadPlan(configuration) {
  if (configuration == null || configuration.enabled !== true || configuration.resourceAdmission?.status !== "received") return null;
  const { cacheKey, maximumCohortBytes } = configuration;
  if (typeof cacheKey !== "string" || cacheKey.length === 0 || new TextEncoder().encode(cacheKey).byteLength > 256 || cacheKey === "registers/earning-loops/issuer-research.json" || !Number.isSafeInteger(maximumCohortBytes) || maximumCohortBytes <= 0 || maximumCohortBytes > 524288) {
    throw new TypeError("Invalid issuer cache configuration");
  }
  return { objectName: "earning-loops", path: "/issuer-evidence", cacheKey, maximumCohortBytes };
}
function unavailable() {
  const error = new Error("Issuer revenue unavailable");
  error.code = "issuer-revenue-unavailable";
  error.status = 503;
  error.retryable = true;
  return error;
}
async function cancelBody(body) {
  try {
    if (body != null && typeof body.cancel === "function") await body.cancel();
  } catch {
  }
}
function createIssuerEvidenceReadStore(namespace, configuration) {
  const plan = issuerEvidenceReadPlan(configuration);
  if (plan === null) return void 0;
  if (namespace == null || typeof namespace.idFromName !== "function" || typeof namespace.get !== "function") {
    throw new TypeError("Invalid issuer namespace");
  }
  return {
    async get(key) {
      if (key !== plan.cacheKey) throw new TypeError("Invalid issuer cache key");
      try {
        const id = namespace.idFromName(plan.objectName);
        const stub = namespace.get(id);
        const url = new URL(plan.path, "https://issuer-cache.invalid");
        url.search = new URLSearchParams({ key: plan.cacheKey }).toString();
        const response = await stub.fetch(new Request(url, {
          method: "GET",
          redirect: "manual"
        }));
        if (response.status === 404) {
          await cancelBody(response.body);
          return null;
        }
        if (response.status !== 200) {
          await cancelBody(response.body);
          throw unavailable();
        }
        const body = response.body;
        let length;
        let valid = false;
        try {
          const text = response.headers.get("Content-Length");
          length = Number(text);
          valid = body instanceof ReadableStream && typeof text === "string" && /^(0|[1-9][0-9]*)$/.test(text) && Number.isSafeInteger(length) && length >= 0 && String(length) === text && length <= plan.maximumCohortBytes;
        } catch {
          valid = false;
        }
        if (!valid) {
          await cancelBody(body);
          throw unavailable();
        }
        return { body, size: length };
      } catch {
        throw unavailable();
      }
    }
  };
}

// test/workerd-issuer-market.mjs
var cfg = { enabled: true, resourceAdmission: { status: "received" }, cacheKey: "issuer-research/current.json", maximumCohortBytes: 524288 };
var workerd_issuer_market_default = { async fetch(request, env) {
  const store = createIssuerEvidenceReadStore(env.ISSUER_EVIDENCE_CLOCK, cfg);
  const item = await store.get(cfg.cacheKey);
  return item ? new Response(item.body, { headers: { "content-length": String(item.size) } }) : new Response("missing", { status: 404 });
} };
export {
  workerd_issuer_market_default as default
};
