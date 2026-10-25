import test from 'node:test';
import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { mkdir, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

test('actual SQLite receives financial client first-writer custody, rollback and original corroboration across Workers', async () => {
  const root = fileURLToPath(new URL('../', import.meta.url)), modules = {};
  for (const name of ['loop', 'market', 'driver']) {
    const built = await build({ absWorkingDir: root, entryPoints: [`test/workerd-issuer-financial-${name}.mjs`],
      bundle: true, format: 'esm', platform: 'browser', conditions: ['workerd', 'worker'],
      target: 'es2022', external: ['node:*'], write: false });
    modules[name] = built.outputFiles[0].contents;
  }
  const digest = createHash('sha256').update('issuer-financial-sqlite-receiving-v1');
  for (const name of Object.keys(modules).sort()) digest.update(modules[name]);
  const identity = digest.digest('hex'), invocation = randomUUID();
  const directory = resolve(root, 'data/records/worker-runtime-test-records', identity, invocation);
  const stateDirectory = resolve(root, 'data/logs/worker-runtime-test-logs', identity, invocation);
  await mkdir(directory, { recursive: true });
  await mkdir(stateDirectory, { recursive: true });
  for (const [name, bytes] of Object.entries(modules)) await writeFile(resolve(directory, name + '.mjs'), bytes);
  const binding = 'durableObjectNamespace = (className = "EarningClock", serviceName = "loop")';
  const config = `using Workerd = import "/workerd/workerd.capnp";
const tests :Workerd.Config = (services = [
 (name = "loop", worker = .loop), (name = "market", worker = .market),
 (name = "main", worker = .driver), (name = "internet", network = (allow = [])),
 (name = "sqlite", disk = (path = ${JSON.stringify(stateDirectory)}, writable = true))
]);
const loop :Workerd.Worker = (
 modules = [(name = "worker", esModule = embed "loop.mjs")],
 compatibilityDate = "2026-09-01", compatibilityFlags = ["nodejs_compat"],
 durableObjectNamespaces = [(className = "EarningClock", uniqueKey = "issuer-financial-receiving", enableSql = true)],
 durableObjectStorage = (localDisk = "sqlite")
);
const market :Workerd.Worker = (
 modules = [(name = "worker", esModule = embed "market.mjs")],
 compatibilityDate = "2026-09-01", compatibilityFlags = ["nodejs_compat"],
 bindings = [(name = "ISSUER_EVIDENCE_CLOCK", ${binding})]
);
const driver :Workerd.Worker = (
 modules = [(name = "worker", esModule = embed "driver.mjs")],
 compatibilityDate = "2026-09-01", compatibilityFlags = ["nodejs_compat"],
 bindings = [(name = "CLOCK", ${binding}), (name = "MARKET", service = "market"), (name = "PUBLIC_LOOP", service = "loop")]
);
`;
  await writeFile(resolve(directory, 'config.capnp'), config);
  const result = spawnSync(resolve(root, 'node_modules/@cloudflare/workerd-linux-64/bin/workerd'),
    ['test', resolve(directory, 'config.capnp')], { encoding: 'utf8', timeout: 30000, maxBuffer: 65536 });
  await writeFile(resolve(directory, 'result.json'), JSON.stringify({ status: result.status, stdout: result.stdout, stderr: result.stderr }, null, 2) + '\n');
  console.log('issuer financial SQLite receiving: ' + directory);
  assert.equal(result.status, 0, result.stdout + '\n' + result.stderr);
});
