import { sha256Hex } from "@red-cup-engineering/semiotic-content-address-system";
import { existsSync, readFileSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { execGitSync } from '@red-cup-engineering/git-engine/git-process';
import { appendServiceLog } from '@red-cup-engineering/computer-systems-logging-engine/append-service-log';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Where a deploy writes the parameter modules it compiles from the Operations record: machine state, never tracked source. */
export const PARAMETER_STATE = 'data/state/build-state/parameters';
/** The committed parameter modules the Worker imports; a deploy replaces each by its compiled module in PARAMETER_STATE. */
export const PARAMETER_MODULES = Object.freeze(['operation', 'group-payers', 'products', 'research-products']);

/**
 * An esbuild plugin that resolves the Worker's `../data/<parameter>.mjs` imports to the module the deploy compiled
 * into `parameterRoot`, and leaves the committed default where the deploy compiled none.
 */
export function parameterModules({ parameterRoot, sourceRoot = root }) {
  const filter = new RegExp(`/data/(${PARAMETER_MODULES.join('|')})\\.mjs$`, 'u');
  return { name: 'compiled-parameter-modules', setup(build) {
    build.onResolve({ filter }, args => {
      const name = args.path.match(filter)[1];
      const compiled = join(parameterRoot, `${name}.mjs`);
      const committed = resolve(sourceRoot, 'data', `${name}.mjs`);
      return resolve(args.resolveDir, args.path) === committed && existsSync(compiled) ? { path: compiled } : undefined;
    });
  } };
}

// The caller selects the existing native build provider explicitly. No install,
// implicit download, private source copy or post-build bundle replacement occurs.
// The worker bundle is returned to the caller and never kept on disk; the build record, which names the source
// commit and the content address of the bundle rather than holding a copy of it, is logged.
export async function buildWorker({ esbuildRoot, sourceRoot = root, parameterRoot = join(sourceRoot, PARAMETER_STATE), at = new Date().toISOString() }) {
  if (!esbuildRoot) throw new TypeError('--esbuild must select an installed esbuild package root');
  const provider = JSON.parse(readFileSync(join(esbuildRoot, 'package.json'), 'utf8'));
  const esbuild = await import(pathToFileURL(join(resolve(esbuildRoot), 'lib/main.js')).href);
  const result = await esbuild.build({ absWorkingDir: sourceRoot, entryPoints: ['worker/earning-loops.mjs'],
    outfile: 'worker.mjs', bundle: true, format: 'esm', platform: 'browser', conditions: ['workerd', 'worker'],
    target: 'es2022', external: ['node:*'], alias: { url: 'node:url' }, plugins: [parameterModules({ parameterRoot, sourceRoot })], metafile: true, write: false });
  const inputs = Object.keys(result.metafile.inputs).sort().map(path => {
    const bytes = readFileSync(resolve(sourceRoot, path));
    return { path, bytes: bytes.length, sha256: sha256Hex(bytes) };
  });
  const bytes = result.outputFiles.find(file => file.path.endsWith('/worker.mjs')).contents;
  const identity = sha256Hex(JSON.stringify({ provider: { name: provider.name, version: provider.version },
    options: { target: 'es2022', platform: 'browser', format: 'esm', conditions: ['workerd', 'worker'], external: ['node:*'], alias: { url: 'node:url' } }, inputs }));
  const git = (...args) => execGitSync(args, { cwd: sourceRoot, encoding: 'utf8' }).trim();
  const record = { kind: 'WorkerBuildRecord', version: 1, compositionSha256: identity,
    source: { commit: git('rev-parse', 'HEAD'), worktreeClean: git('status', '--porcelain') === '' },
    provider: { name: provider.name, version: provider.version }, sourceInputs: inputs,
    artifact: { path: 'worker.mjs', bytes: bytes.length, sha256: sha256Hex(bytes) },
    externalModules: [...new Set(result.metafile.outputs['worker.mjs'].imports.filter(value => value.external).map(value => value.path))].sort() };
  appendServiceLog({ root: sourceRoot, hirer: 'earning-loop-worker', service: 'worker-build', at,
    entry: { subject: 'earning-loop-worker', entity: identity, attribute: 'worker-built', value: record, time: at } });
  return { bytes, record };
}
