import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { buildWorker } from '../scripts/build-worker.mjs';

function fakeProvider(directory) {
  mkdirSync(join(directory, 'lib'), { recursive: true });
  writeFileSync(join(directory, 'package.json'), JSON.stringify({ name: 'esbuild', version: '0.0.0-test' }));
  writeFileSync(join(directory, 'lib/main.js'), `export const build = async () => ({
    metafile: { inputs: { 'worker/earning-loops.mjs': {} }, outputs: { 'worker.mjs': { imports: [{ external: true, path: 'node:url' }] } } },
    outputFiles: [{ path: '/out/worker.mjs', contents: new TextEncoder().encode('export default {};') }] });`);
}

test('a build returns the bundle and logs its record; nothing is kept under data/records', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'build-worker-'));
  const sourceRoot = join(directory, 'source');
  fakeProvider(join(directory, 'esbuild'));
  mkdirSync(join(sourceRoot, 'worker'), { recursive: true });
  writeFileSync(join(sourceRoot, 'worker/earning-loops.mjs'), 'export default {};');
  const built = await buildWorker({ esbuildRoot: join(directory, 'esbuild'), sourceRoot, at: '2026-10-26T12:00:00.000Z' });
  assert.equal(Buffer.from(built.bytes).toString(), 'export default {};');
  const log = join(sourceRoot, 'data/logs/service-logs/worker-build-service-logs/2026/10/26/2026-10-26-earning-loop-worker-worker-build-service-log.jsonl');
  const entry = JSON.parse(readFileSync(log, 'utf8'));
  assert.equal(entry.entity, built.record.compositionSha256);
  assert.deepEqual(entry.value.externalModules, ['node:url']);
  assert.equal(existsSync(join(sourceRoot, 'data/records')), false);
});
