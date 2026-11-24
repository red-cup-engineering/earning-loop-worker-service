import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { PARAMETER_MODULES, PARAMETER_STATE, parameterModules } from "../scripts/build-worker.mjs";

const sourceRoot = mkdtempSync(join(tmpdir(), "earning-loops-"));
after(() => rmSync(sourceRoot, { recursive: true, force: true }));
const parameterRoot = join(sourceRoot, PARAMETER_STATE);
mkdirSync(parameterRoot, { recursive: true });

const resolver = () => {
  let resolve, filter;
  parameterModules({ parameterRoot, sourceRoot }).setup({ onResolve: (options, callback) => { filter = options.filter; resolve = callback; } });
  return (path, resolveDir = join(sourceRoot, "worker")) => (filter.test(path) ? resolve({ path, resolveDir }) : undefined);
};

test("compiled parameter modules live in git-ignored state", () => {
  assert.equal(PARAMETER_STATE, "data/state/build-state/parameters");
  assert.deepEqual([...PARAMETER_MODULES], ["operation", "group-payers", "products", "research-products"]);
});

test("a data import resolves to the compiled module when the deploy compiled one", () => {
  writeFileSync(join(parameterRoot, "operation.mjs"), "export default {};\n");
  assert.deepEqual(resolver()("../data/operation.mjs"), { path: join(parameterRoot, "operation.mjs") });
});

test("a data import keeps the committed default when none was compiled", () => {
  assert.equal(resolver()("../data/products.mjs"), undefined);
});

test("only the Worker's own data modules are redirected", () => {
  writeFileSync(join(parameterRoot, "operation.mjs"), "export default {};\n");
  assert.equal(resolver()("../data/operation.mjs", join(sourceRoot, "elsewhere/deeper")), undefined);
  assert.equal(resolver()("../data/other.mjs"), undefined);
});
