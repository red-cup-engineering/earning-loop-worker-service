import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

// The caller selects the existing native build provider explicitly. No install,
// implicit download, private source copy or post-build bundle replacement occurs.
export async function buildWorker({ esbuildRoot, sourceRoot = root }) {
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
  const directory = join(sourceRoot, 'data/records/worker-build-records', identity);
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, 'worker.mjs'), bytes);
  writeFileSync(join(directory, 'esbuild.metafile.json'), JSON.stringify(result.metafile, null, 2)+'\n');
  const record = { kind: 'WorkerBuildRecord', version: 1, compositionSha256: identity,
    provider: { name: provider.name, version: provider.version }, sourceInputs: inputs,
    artifact: { path: 'worker.mjs', bytes: bytes.length, sha256: digest(bytes) },
    externalModules: [...new Set(result.metafile.outputs['worker.mjs'].imports.filter(value => value.external).map(value => value.path))].sort() };
  writeFileSync(join(directory, 'build.json'), JSON.stringify(record, null, 2)+'\n');
  return { directory, record };
}
