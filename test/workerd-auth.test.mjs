import test from 'node:test';
import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

test('actual workerd with deployed compatibility runs fresh-key assertion and shared DPoP', async () => {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const built = await build({ absWorkingDir: root, entryPoints: ['test/workerd-auth-worker.mjs'], bundle: true,
    format: 'esm', platform: 'browser', conditions: ['workerd','worker'], target: 'es2022', external: ['node:*'], write: false });
  const bytes = built.outputFiles[0].contents;
  const directory = resolve(root, 'data/records/worker-runtime-test-records', createHash('sha256').update(bytes).digest('hex'));
  await mkdir(directory, { recursive: true });
  await writeFile(resolve(directory, 'worker.mjs'), bytes);
  await writeFile(resolve(directory, 'config.capnp'), `using Workerd = import "/workerd/workerd.capnp";
const tests :Workerd.Config = (services = [(name = "main", worker = .worker), (name = "internet", network = (allow = []))]);
const worker :Workerd.Worker = (modules = [(name = "worker", esModule = embed "worker.mjs")], compatibilityDate = "2026-09-01", compatibilityFlags = ["nodejs_compat"]);
`);
  const result = spawnSync(resolve(root, 'node_modules/.bin/workerd'), ['test', resolve(directory, 'config.capnp')], { encoding: 'utf8', timeout: 30000 });
  await writeFile(resolve(directory, 'result.json'), JSON.stringify({ status: result.status, stdout: result.stdout, stderr: result.stderr }, null, 2) + '\n');
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
});
