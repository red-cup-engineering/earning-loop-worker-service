#!/usr/bin/env node
// Apply the earning loops' pending price directives to a seller catalog, for the catalog's owner to compile and
// deploy through its own release. Only raise and revert directives are applied, and only where the catalog still
// lists the directive's old amount, so a price someone changed since is never overwritten.
//   node scripts/apply-price-directives.mjs --catalog path/to/catalog.json [--directives URL|path] [--dry-run]
// The Worker marks a directive applied by itself once the live catalog shows its new price.
import { readFileSync, writeFileSync } from "node:fs";

const DIRECTIVES = "https://earning-loops-561-group.561-group.workers.dev/price-directives.json";
const atomic = (price) => Math.round(Number(String(price).replace(/^\$/, "")) * 1e6);
const dollars = (amount) => `$${+(Number(amount) / 1e6).toFixed(6)}`;

export function applyDirectives(catalog, directives) {
  const changes = [];
  for (const d of directives) {
    if (d.status !== "proposed" || !["raise", "revert"].includes(d.kind)) continue;
    const [method, route] = [d.route.slice(0, d.route.indexOf(" ")), d.route.slice(d.route.indexOf(" ") + 1)];
    const offer = catalog.find((o) => o.method === method && o.route === route);
    if (!offer || atomic(offer.price) !== Number(d.from)) continue;
    changes.push({ route: d.route, from: offer.price, to: dollars(d.to), reason: d.reason });
    offer.price = dollars(d.to);
  }
  return changes;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const arg = (name) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : null; };
  const catalogPath = arg("catalog");
  if (!catalogPath) { console.error("--catalog is required"); process.exit(2); }
  const source = arg("directives") ?? DIRECTIVES;
  const register = /^https?:/.test(source) ? await (await fetch(source)).json() : JSON.parse(readFileSync(source, "utf8"));
  const catalog = JSON.parse(readFileSync(catalogPath, "utf8"));
  const changes = applyDirectives(catalog, register.directives ?? []);
  if (!process.argv.includes("--dry-run") && changes.length) writeFileSync(catalogPath, `${JSON.stringify(catalog, null, 2)}\n`);
  for (const c of changes) console.log(`price: ${c.route} ${c.from} -> ${c.to} because ${c.reason}`);
  if (!changes.length) console.log("no applicable price directives");
}
