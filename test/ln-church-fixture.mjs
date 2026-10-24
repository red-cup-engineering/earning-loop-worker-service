import { canonicalJson } from '@red-cup-engineering/json-services-section/canonical-json';
import { RESEARCH_STATE } from '../src/ln-church-research.mjs';
export const merchant = '0x'+'12'.repeat(20);
export const payer = '0x'+'34'.repeat(20);
export const time = Date.parse('2026-10-24T22:00:00Z');
export const sha = async text => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text))),v=>v.toString(16).padStart(2,'0')).join('');
export async function fixture() {
  const question = 'Select the primary explicitly disclosed operator purpose.';
  const product = { taskId:'task_fixture',taskType:'endpoint_choice_reason.v2',taskDefinitionVersion:'2.3.0',
    taskDefinitionDigest:'a'.repeat(64),termsDigest:'b'.repeat(64),questionSha256:await sha(question),selectedCandidateId:'o04',
    answerReason:'The operator explicitly requested paid work for external customers. This is a test answer, not a paid result.',
    reward:{network:'eip155:8453',asset:'USDC',asset_address:'0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',correct_amount_atomic:'25000',incorrect_amount_atomic:'10000',full_reward_threshold:'0.7',rounding:'FLOOR_ATOMIC'} };
  const instance = {enabled:true,provider:'ln-church',agentId:'fixture-agent',taskId:product.taskId,productId:'operator-purpose-v1',maximumNewCashExpenseUsd:0,maximumProviderRequestsPerPass:12};
  const products = {[instance.productId]:product};
  const terms = {task_type:product.taskType,task_definition_version:product.taskDefinitionVersion,task_definition_digest:product.taskDefinitionDigest,question,
    candidates:[{candidate_id:'o04',url:'https://kari.mayim-mayim.com/example/o04'}],reward:product.reward,
    reveal_correct_set_after_answer:true,evaluation_profile_id:'endpoint-choice-reason-jev-v2_1',plan_id:'C21',registration_amount_atomic:'1000000',capacity_total:21,
    economic_policy_id:'endpoint-choice-reason-economics-terms-v1',capacity_profile_id:'endpoint-choice-reason-rpah.v2_1',evaluation_profile_digest:'f'.repeat(64),
    economic_terms_revision:'fixture-terms',creator_amount_atomic:'100000'};
  const task = {...terms,schema_version:'ln_church.agent_task.endpoint_choice_reason.v2_3',task_id:product.taskId,terms_digest:product.termsDigest,status:'OPEN',capacity_available:9,listing_ends_at:new Date(time+86400000).toISOString()};
  const claim = {...terms,schema_version:'ln_church.agent_task_claim_response.endpoint_choice_reason.v2_3',task_id:product.taskId,terms_digest:product.termsDigest,
    execution_id:'exec_'+'c'.repeat(32),claim_token:'private-fixture-capability',reward_address:merchant,reward_address_control_verified:false,
    claim_accepted_at:new Date(time).toISOString(),report_deadline:new Date(time+600000).toISOString(),terms_snapshot:terms};
  const values = new Map();
  const storage = {async get(k){return values.get(k);},async put(k,v){values.set(k,structuredClone(v));}};
  const base = 'https://kari.mayim-mayim.com/api/agent/tasks/'+product.taskId;
  let calls = [];
  async function receipt() {
    const s=await storage.get(RESEARCH_STATE);
    return {schema_version:'ln_church.task_completion_receipt.endpoint_choice_reason.v2_3',task_id:product.taskId,execution_id:claim.execution_id,
      submission_id:s.submissionId,terms_digest:product.termsDigest,report_sha256:await sha(s.completionBody),receipt_state:'accepted',received_at:new Date(time).toISOString(),
      evaluation_deadline:new Date(time+1800000).toISOString(),status_url:'/api/agent/tasks/'+product.taskId+'/submissions/'+s.submissionId+'/status'};
  }
  async function status() { const r=await receipt(); return {...r,schema_version:'ln_church.task_submission_status.endpoint_choice_reason.v2_3',
    selected_candidate_id:product.selectedCandidateId,answer_reason:product.answerReason,evaluation:{state:'PENDING',approved_amount_atomic:null},
    payout:{state:'pending',transaction_hash:null,confirmed_paid_amount_atomic:null}}; }
  async function fetchImpl(url,init) {
    calls.push({url,...init});
    if(url===base)return Response.json(task);
    if(url===base+'/claim')return Response.json(claim);
    if(url===base+'/completion')return Response.json(await receipt(),{status:202});
    if(url.includes('/submissions/'))return Response.json(await status());
    throw new Error('unexpected external request');
  }
  return {product,instance,products,task,claim,storage,values,base,calls,receipt,status,fetchImpl,
    options:{storage,instance,products,merchant,fetchImpl,now:()=>time},canonicalJson};
}
