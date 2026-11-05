// The self-adjusting loop: read what buyers revealed at each listed price and propose the next price, following
// the 561 Group's price-an-offer rules and the border-price relation. Every directive names the price it replaces,
// so it can be reverted, and a raise that lost its buyers is reverted automatically.
//
// Rules, in order:
//   - not buyable now: no price directive; the route-health repair comes first;
//   - crossed-range (20+ outside sales in 14 days): raise one step;
//   - a raise applied 14+ days ago whose outside sales fell below half of the 14 days before it: revert;
//   - open-gap at a sub-cent per-call price: raise to USD 0.01, since sub-cent prices signal a toy;
//   - open-gap otherwise: advise changing one thing (name, example, bundle) and never cut by reflex;
//   - exact-match or unobserved: hold.
import { isOutside, preparedDelivery } from "./scorecard.mjs";
import { revealedBorder } from "./border-price.mjs";
import { register, read, put } from "./registers.mjs";

const DAY = 86_400_000;
export const FLOOR_ATOMIC = 10_000n; // USD 0.01 in Base USDC atomic units
export const dollars = (atomic) => `$${+(Number(atomic) / 1e6).toFixed(6)}`;

// One step up the ladder: x1.5, rounded to a whole cent above USD 0.01 and to a tenth of a cent below.
export function stepUp(atomic) {
  const raised = (BigInt(atomic) * 3n) / 2n;
  const unit = raised >= FLOOR_ATOMIC ? 10_000n : 1_000n;
  return ((raised + unit - 1n) / unit) * unit;
}

export function proposeDirectives({ routes, settlements, previous = [] }, { now = new Date(), groupPayers = new Set() } = {}) {
  const at = now.getTime(), issuedAt = now.toISOString();
  // Route-health keys are "METHOD /path"; a witness always carries the path, not always the method.
  const between = (route, start, end) => Object.values(settlements ?? {}).filter((s) => {
    const t = Date.parse(s.recordedAt ?? s.corroboratedAt);
    return s.route === route.slice(route.indexOf(" ") + 1) && isOutside(s, groupPayers) && preparedDelivery(s) && t > start && t <= end;
  }).length;
  const sales = (route, days) => between(route, at - days * DAY, at);
  const lastFor = (route) => previous.filter((d) => d.route === route).at(-1);
  const out = [];
  for (const [route, r] of Object.entries(routes ?? {})) {
    if (r.delistedAt || r.amountAtomic == null) continue;
    if (!r.held) continue;
    const current = BigInt(r.amountAtomic);
    const healthyDays = r.heldSince ? (at - Date.parse(r.heldSince)) / DAY : 0;
    const listedDays = (at - Date.parse(r.firstListedAt)) / DAY;
    const recent = sales(route, 14), relation = revealedBorder({ healthyDays, listedDays, outsideSales: recent });
    const last = lastFor(route);
    const base = { route, from: String(current), relation, evidence: { outsideSales14d: recent, healthyDays: Math.floor(healthyDays), listedDays: Math.floor(listedDays) }, issuedAt, status: "proposed" };
    if (last?.status === "proposed" && last.from === String(current)) continue; // still waiting to be applied
    if (last?.kind === "raise" && last.to === String(current) && last.appliedAt && at - Date.parse(last.appliedAt) >= 14 * DAY) {
      const applied = Date.parse(last.appliedAt), before = between(route, applied - 14 * DAY, applied), after = recent;
      if (before > 0 && after * 2 < before) { out.push({ ...base, kind: "revert", to: last.from, reason: `raise to ${dollars(current)} cut outside sales from ${before} to ${after} in 14 days`, revertOf: last.id }); continue; }
    }
    if (relation === "crossed-range") out.push({ ...base, kind: "raise", to: String(stepUp(current)), reason: `${recent} outside sales in 14 days at ${dollars(current)}: buyers' bids sit at or above the ask` });
    else if (relation === "open-gap" && current < FLOOR_ATOMIC) out.push({ ...base, kind: "raise", to: String(FLOOR_ATOMIC), reason: `buyable and listed ${Math.floor(listedDays)} days at sub-cent ${dollars(current)} with no outside sale; sub-cent prices signal a toy` });
    else if (relation === "open-gap") out.push({ ...base, kind: "change-one-thing", to: String(current), reason: `buyable and listed ${Math.floor(listedDays)} days with no outside sale: change the name, example or bundle before the price` });
  }
  return out.map((d) => ({ id: `${d.route}@${d.issuedAt}`, ...d }));
}

// A directive is applied when the live catalog's price for its route becomes its target. Nobody reports it.
export function markApplied(directives, routes, now = new Date()) {
  for (const d of directives) {
    if (d.status !== "proposed" || d.kind === "change-one-thing") continue;
    const current = routes[d.route]?.amountAtomic;
    if (current != null && String(current) === d.to) Object.assign(d, { status: "applied", appliedAt: now.toISOString() });
    else if (current != null && String(current) !== d.from) Object.assign(d, { status: "superseded", supersededAt: now.toISOString() });
  }
  return directives;
}

export async function writeDirectives(env, { now = new Date(), groupPayers } = {}) {
  const key = register("price-directives");
  const state = (await read(env.STATE, key)) ?? { directives: [] };
  const routes = (await read(env.STATE, register("route-health")))?.routes ?? {};
  markApplied(state.directives, routes, now);
  const fresh = proposeDirectives({
    routes,
    settlements: (await read(env.STATE, register("settlements")))?.settlements,
    previous: state.directives,
  }, { now, groupPayers });
  state.directives.push(...fresh);
  state.at = now.toISOString();
  await put(env.STATE, key, state);
  return { proposed: fresh.length, pending: state.directives.filter((d) => d.status === "proposed").length };
}
