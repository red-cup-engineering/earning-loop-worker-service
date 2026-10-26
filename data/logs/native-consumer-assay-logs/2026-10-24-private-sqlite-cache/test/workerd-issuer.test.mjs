import test from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {mkdir,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
test('actual SQLite DO shares original singleton through private cross-Worker binding without alarm or custody changes',async()=>{
  const root=fileURLToPath(new URL('../',import.meta.url)),modules={};
  for(const [name,entry]of [['loop','test/workerd-issuer-loop.mjs'],['market','test/workerd-issuer-market.mjs'],['driver','test/workerd-issuer-driver.mjs']]){
    const built=await build({absWorkingDir:root,entryPoints:[entry],bundle:true,format:'esm',platform:'browser',conditions:['workerd','worker'],target:'es2022',external:['node:*'],write:false});
    modules[name]=built.outputFiles[0].contents;
  }
  const digest=createHash('sha256');for(const name of Object.keys(modules).sort())digest.update(modules[name]);
  const directory=resolve(root,'data/records/worker-runtime-test-records',digest.digest('hex'));await mkdir(directory,{recursive:true});
  for(const[name,bytes]of Object.entries(modules))await writeFile(resolve(directory,name+'.mjs'),bytes);
  const binding='durableObjectNamespace = (className = "EarningClock", serviceName = "loop")';
  const config="using Workerd = import \"/workerd/workerd.capnp\";\nconst tests :Workerd.Config = (services = [\n (name = \"loop\", worker = .loop), (name = \"market\", worker = .market),\n (name = \"main\", worker = .driver), (name = \"internet\", network = (allow = []))\n]);\nconst loop :Workerd.Worker = (\n modules = [(name = \"worker\", esModule = embed \"loop.mjs\")],\n compatibilityDate = \"2026-09-01\", compatibilityFlags = [\"nodejs_compat\"],\n durableObjectNamespaces = [(className = \"EarningClock\", uniqueKey = \"issuer-cache-receiving\", enableSql = true)],\n durableObjectStorage = (inMemory = void)\n);\nconst market :Workerd.Worker = (\n modules = [(name = \"worker\", esModule = embed \"market.mjs\")],\n compatibilityDate = \"2026-09-01\", compatibilityFlags = [\"nodejs_compat\"],\n bindings = [(name = \"ISSUER_EVIDENCE_CLOCK\", @@BINDING@@)]\n);\nconst driver :Workerd.Worker = (\n modules = [(name = \"worker\", esModule = embed \"driver.mjs\")],\n compatibilityDate = \"2026-09-01\", compatibilityFlags = [\"nodejs_compat\"],\n bindings = [(name = \"CLOCK\", @@BINDING@@), (name = \"MARKET\", service = \"market\")]\n);\n";
  await writeFile(resolve(directory,'config.capnp'),config.replaceAll('@@BINDING@@',binding));
  const result=spawnSync(resolve(root,'node_modules/.bin/workerd'),['test',resolve(directory,'config.capnp')],{encoding:'utf8',timeout:30000,maxBuffer:65536});
  await writeFile(resolve(directory,'result.json'),JSON.stringify({status:result.status,stdout:result.stdout,stderr:result.stderr},null,2)+'\n');
  assert.equal(result.status,0,result.stdout+'\n'+result.stderr);
});

