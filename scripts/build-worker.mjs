import { readFileSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { appendServiceLog } from '@red-cup-engineering/computer-systems-logging-engine/append-service-log';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

// The caller selects the existing native build provider explicitly. No install,
// implicit download, private source copy or post-build bundle replacement occurs.
// The worker bundle is returned to the caller and never kept on disk; the build record is logged.
export async function buildWorker({ esbuildRoot, sourceRoot = root, at = new Date().toISOString() }) {
  if (!esbuildRoot) throw new TypeError('--esbuild must select an installed esbuild package root');
  const provider = JSON.parse(readFileSync(join(esbuildRoot, 'package.json'), 'utf8'));
  const esbuild = await import(pathToFileURL(join(resolve(esbuildRoot), 'lib/main.js')).href);
  const result = await esbuild.build({ absWorkingDir: sourceRoot, entryPoints: ['worker/earning-loops.mjs'],
    outfile: 'worker.mjs', bundle: true, format: 'esm', platform: 'browser', conditions: ['workerd', 'worker'],
    target: 'es2022', external: ['node:*'], alias: { url: 'node:url' }, metafile: true, write: false });
  const inputs = Object.keys(result.metafile.inputs).sort().map(path => {
    const bytes = readFileSync(resolve(sourceRoot, path));
    return { path, bytes: bytes.length, sha256: digest(bytes) };
  });
  const bytes = result.outputFiles.find(file => file.path.endsWith('/worker.mjs')).contents;
  const identity = digest(JSON.stringify({ provider: { name: provider.name, version: provider.version },
    options: { target: 'es2022', platform: 'browser', format: 'esm', conditions: ['workerd', 'worker'], external: ['node:*'], alias: { url: 'node:url' } }, inputs }));
  const record = { kind: 'WorkerBuildRecord', version: 1, compositionSha256: identity,
    provider: { name: provider.name, version: provider.version }, sourceInputs: inputs,
    artifact: { path: 'worker.mjs', bytes: bytes.length, sha256: digest(bytes) },
    externalModules: [...new Set(result.metafile.outputs['worker.mjs'].imports.filter(value => value.external).map(value => value.path))].sort() };
  appendServiceLog({ root: sourceRoot, hirer: 'earning-loop-worker', service: 'worker-build', at,
    entry: { subject: 'earning-loop-worker', entity: identity, attribute: 'worker-built', value: record, time: at } });
  return { bytes, record };
}
