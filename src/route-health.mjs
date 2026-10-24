// Is every listed offer actually buyable? A route is held when an unpaid request in the catalog's own example
// shape answers 402 with an x402 challenge for the catalog's exact amount, in Base USDC. Anything else is a sale
// that cannot happen: a 400 on the documented example, a 5xx, a missing or undecodable challenge, a wrong price.
import { BASE_USDC } from "./settlements.mjs";
import { register, read, put } from "./registers.mjs";

export const CATALOG_URL = "https://market.561.group/v1/catalog";
export const BROKEN_STREAK_FOR_REPAIR = 3;
const id = (offer) => `${offer.method} ${offer.route}`;

export function probeRequest(offer) {
  const example = offer.request?.example;
  const headers = { "user-agent": "coesite-earning-loops/1 (+https://github.com/coesite-operations/operations-services-section)", accept: "application/json" };
  if (offer.method === "GET") return [example?.url ?? offer.url, { method: "GET", headers }];
  const body = example && typeof example === "object" && "body" in example ? example.body : {};
  return [offer.url, { method: offer.method, headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify(body) }];
}

const decode = (header) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(header), (c) => c.charCodeAt(0))));

export function judge(offer, status, challengeHeader, { payTo, resourceUrl } = {}) {
  if (status !== 402) return { held: false, finding: `answered ${status}, not 402, to the catalog's example request` };
  if (!challengeHeader) return { held: false, finding: "402 without a payment-required challenge" };
  let challenge;
  try { challenge = decode(challengeHeader); } catch { return { held: false, finding: "payment-required challenge does not decode" }; }
  if (challenge?.x402Version !== 2 || !Array.isArray(challenge.accepts)) return { held: false, finding: "challenge is not x402 v2" };
  if (resourceUrl && challenge.resource?.url !== resourceUrl) return { held: false, finding: "challenge resource differs from the probed public URL" };
  if (!/^0x[0-9a-f]{40}$/i.test(payTo ?? "")) return { held: false, finding: "merchant receiver has not been configured" };
  const accept = challenge.accepts.find((a) => a?.scheme === "exact" && typeof a.payTo === "string" && a.payTo.toLowerCase() === payTo.toLowerCase() && a.network === "eip155:8453" && typeof a.asset === "string" && a.asset.toLowerCase() === BASE_USDC);
  if (!accept) return { held: false, finding: "challenge offers no exact Base USDC payment to the configured merchant" };
  if (offer.amountAtomic != null && String(accept.amount) !== String(offer.amountAtomic))
    return { held: false, finding: `challenge asks ${accept.amount}, catalog lists ${offer.amountAtomic}` };
  return { held: true, finding: `buyable at ${offer.price}`, amount: String(accept.amount), payTo: accept.payTo?.toLowerCase() ?? null };
}

/** Probe the `limit` stalest listed offers; keep first-listed dates, streaks and repair candidates. */
export async function checkRoutes(env, { now = new Date(), limit = 15, catalogUrl = CATALOG_URL, brokenStreak = BROKEN_STREAK_FOR_REPAIR, repository = env.REPAIR_REPOSITORY, payTo, fetchImpl = fetch } = {}) {
  const key = register("route-health");
  const state = (await read(env.STATE, key)) ?? { routes: {} };
  const response = await fetchImpl(catalogUrl, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(15000), redirect: "manual" });
  if (!response.ok) throw new Error(`catalog answered ${response.status}`);
  const catalog = await response.json();
  const offers = catalog.offers.filter((offer) => offer.listed);
  const at = now.toISOString();
  for (const offer of offers) state.routes[id(offer)] ??= { firstListedAt: at, price: offer.price, amountAtomic: offer.amountAtomic ?? null, heldSince: null, brokenStreak: 0 };
  const listed = new Set(offers.map(id));
  for (const route of Object.keys(state.routes)) if (!listed.has(route)) state.routes[route].delistedAt ??= at;
  const due = offers.sort((a, b) => (state.routes[id(a)].observedAt ?? "").localeCompare(state.routes[id(b)].observedAt ?? "")).slice(0, limit);
  for (const offer of due) {
    const [url, init] = probeRequest(offer);
    let verdict;
    try {
      const response = await fetchImpl(url, { ...init, redirect: "manual", signal: AbortSignal.timeout(15000) });
      verdict = judge(offer, response.status, response.headers.get("payment-required"), { payTo, resourceUrl: url });
      await response.body?.cancel();
    } catch (error) { verdict = { held: false, finding: `request failed: ${error.message}` }; }
    const entry = state.routes[id(offer)];
    Object.assign(entry, verdict, { observedAt: at, price: offer.price, amountAtomic: offer.amountAtomic ?? null, delistedAt: undefined });
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

// Self-healing: ask the market's repository to redeploy or delist through its own workflow. Only the market
// owner's workflow decides and acts; this loop never deploys or edits the catalog itself.
async function dispatchRepair(token, repository, repairs, fetchImpl) {
  await fetchImpl(`https://api.github.com/repos/${repository}/dispatches`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "user-agent": "coesite-earning-loops" },
    body: JSON.stringify({ event_type: "market-route-broken", client_payload: { repairs: repairs.slice(0, 20) } }),
  });
}
