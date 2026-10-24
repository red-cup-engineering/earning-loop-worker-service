import assert from 'node:assert/strict';
import { runResearchPass, RESEARCH_STATE } from '../src/ln-church-research.mjs';
import { fixture } from './ln-church-fixture.mjs';
export const testNativeResearch = { async test() {
  const f=await fixture();
  const result=await runResearchPass(f.options);
  assert.equal(result.stage,'research-evaluation-pending');assert.equal(result.requests,4);
  const state=await f.storage.get(RESEARCH_STATE);
  assert.equal(state.completionPosts,1);assert.equal(state.receipt.report_sha256,state.reportSha256);
  assert.equal(result.independentlyVerifiedCashAtomic,null);
} };
