#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { projectOperation, deploymentMetadata } from "../src/deployment.mjs";
import { buildWorker } from "./build-worker.mjs";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const arg = name => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : null; };
const operationPath = arg("operation"), payersPath = arg("group-payers");
if (!operationPath || !payersPath) throw new TypeError("--operation and --group-payers are required");
const record = JSON.parse(readFileSync(operationPath, "utf8"));
const operation = projectOperation(record);
const payers = JSON.parse(readFileSync(payersPath, "utf8"));
writeFileSync(join(root, "data/operation.mjs"), `// Generated from trusted operation ${record.id}; do not hand-edit.\nexport default ${JSON.stringify(operation, null, 2)};\n`);
writeFileSync(join(root, "data/group-payers.mjs"), `// Generated from Group payer record observed ${payers["observed-on"]}; do not hand-edit.\nexport default ${JSON.stringify(payers.addresses.map(a => a.address.toLowerCase()).sort(), null, 2)};\n`);
const built = await buildWorker({ esbuildRoot: arg("esbuild") });
console.log(`${operation.worker}: ${built.record.artifact.bytes} bundled bytes, composition ${built.record.compositionSha256}, crons ${Object.values(operation.crons).join(" | ")}`);
if (process.argv.includes("--dry-run")) process.exit(0);
const account = process.env.CLOUDFLARE_ACCOUNT_ID, token = process.env.CLOUDFLARE_API_TOKEN;
if (!account || !token) throw new TypeError("CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN are required");
const api = `https://api.cloudflare.com/client/v4/accounts/${account}/workers/scripts/${operation.worker}`;
const call = async (url, init) => {
  const response = await fetch(url, { ...init, headers: { authorization: `Bearer ${token}`, ...init.headers } });
  const body = await response.json();
  if (!body.success) throw new Error(`${init.method} ${url.replace(account, "<account>")}: ${JSON.stringify(body.errors)}`);
  return body.result;
};
// Preserve the actual installed settings, including bindings this caller does
// not understand. Secret values are retained by Cloudflare without readback.
const existing = await call(`${api}/settings`, { method: "GET" });
if (operation.issuerResearch && existing.bindings?.some(b => b.name === "ONCHAIN_SCAN_URL" && b.text))
  throw new TypeError("issuer operation has no subrequest allocation for the installed onchain hook");
const metadata = deploymentMetadata(operation, existing);
const form = new FormData();
form.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
form.append("worker.mjs", new Blob([readFileSync(join(built.directory, "worker.mjs"))], { type: "application/javascript+module" }), "worker.mjs");
let uploaded;
try { uploaded = await call(api, { method: "PUT", body: form }); }
catch (error) {
  if (!metadata.migrations || !/migration/i.test(error.message)) throw error;
  delete metadata.migrations;
  form.set("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
  uploaded = await call(api, { method: "PUT", body: form });
}
await call(`${api}/subdomain`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled: true }) });
const crons = operation.clock === "durable-object-alarm" ? [] : Object.values(operation.crons).map(cron => ({ cron }));
await call(`${api}/schedules`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(crons) });
console.log(`deployed ${operation.worker} (etag ${uploaded.etag?.slice(0, 12) ?? "?"}), clock: ${operation.clock}`);
if (operation.clock === "durable-object-alarm") {
  const subdomain = await call(`https://api.cloudflare.com/client/v4/accounts/${account}/workers/subdomain`, { method: "GET" });
  const armed = await (await fetch(`https://${operation.worker}.${subdomain.subdomain}.workers.dev/clock`)).text();
  console.log(`clock armed: ${armed}`);
}
