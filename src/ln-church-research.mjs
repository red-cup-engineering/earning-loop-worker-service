// One qualified paid research unit. Provider wire contract: endpoint_choice_reason.v2/2.3.0.
// Claim recovery and canonical report replay follow the original ln-church-agent client.
import { canonicalJson, admitCanonicalJson, JSON_RESOURCE_ENVELOPE } from '@red-cup-engineering/json-services-section/canonical-json';
import { retryAfterDelayMs } from '@red-cup-engineering/http-services-section/retry-after';
import { BASE_USDC, BASE_PROVIDERS, corroborate } from './settlements.mjs';

const ORIGIN = 'https://kari.mayim-mayim.com';
export const RESEARCH_STATE = 'ln-church/research';
export const RESEARCH_SUMMARY = 'ln-church/public-summary';
const ID = /^[A-Za-z0-9._~-]{1,128}$/;
const HASH = /^[a-f0-9]{64}$/;
const ADDRESS = /^0x[\da-f]{40}$/i;
const TX = /^0x[\da-f]{64}$/i;
const LIMIT = 131072;
const TERMS = ['task_type','task_definition_version','task_definition_digest','question','candidates','reveal_correct_set_after_answer','evaluation_profile_id','reward','plan_id','registration_amount_atomic','capacity_total','economic_policy_id','capacity_profile_id','evaluation_profile_digest','economic_terms_revision','creator_amount_atomic'];
const ENVELOPE = { ...JSON_RESOURCE_ENVELOPE, maxSourceBytes: LIMIT, maxCanonicalBytes: LIMIT, maxDepth: 24, maxNodes: 12000 };
const equal = (a,b) => canonicalJson(a) === canonicalJson(b);
const hash = async text => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))), n => n.toString(16).padStart(2,'0')).join('');
const error = (code, status = 0) => Object.assign(new Error(code), { code, status });
const finiteDate = value => typeof value === 'string' && Number.isFinite(Date.parse(value));

export function researchProductProblem(instance, product, merchant) {
  if (instance?.enabled !== true) return 'disabled';
  if (instance.provider !== 'ln-church' || !ID.test(instance.taskId ?? '') ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(instance.agentId ?? '') || !ID.test(instance.productId ?? '') ||
      instance.maximumNewCashExpenseUsd !== 0 || instance.maximumProviderRequestsPerPass !== 12 || !ADDRESS.test(merchant ?? '')) return 'research-instance-refused';
  if (!product || product.taskId !== instance.taskId || product.taskType !== 'endpoint_choice_reason.v2' || product.taskDefinitionVersion !== '2.3.0' ||
      ![product.taskDefinitionDigest,product.termsDigest,product.questionSha256].every(v => HASH.test(v ?? '')) ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(product.selectedCandidateId ?? '') ||
      typeof product.answerReason !== 'string' || !product.answerReason.trim() || new TextEncoder().encode(product.answerReason).length > 8192 ||
      product.reward?.network !== 'eip155:8453' || product.reward.asset !== 'USDC' || product.reward.asset_address?.toLowerCase() !== BASE_USDC ||
      product.reward.full_reward_threshold !== '0.7' || product.reward.rounding !== 'FLOOR_ATOMIC' ||
      ![product.reward.correct_amount_atomic,product.reward.incorrect_amount_atomic].every(v => /^[1-9]\d{0,77}$/.test(v ?? '') && BigInt(v) < 2n ** 256n)) return 'research-product-refused';
  try { canonicalJson(product, ENVELOPE); } catch { return 'research-product-refused'; }
  return null;
}

async function matchesTerms(value, product) {
  return value?.task_type === product.taskType && value.task_definition_version === product.taskDefinitionVersion &&
    value.task_definition_digest === product.taskDefinitionDigest && typeof value.question === 'string' &&
    await hash(value.question) === product.questionSha256 && equal(value.reward, product.reward) &&
    Array.isArray(value.candidates) && value.candidates.some(c => c.candidate_id === product.selectedCandidateId);
}

export async function runResearchPass({ storage, instance, products, merchant, groupPayers = new Set(), fetchImpl = fetch, now = () => Date.now() } = {}) {
  const product = products?.[instance?.productId];
  const refusal = researchProductProblem(instance, product, merchant);
  if (refusal) return { stage: refusal, requests: 0, newCashExpenseUsd: 0 };
  let state = await storage.get(RESEARCH_STATE) ?? { stage: 'unclaimed', completionPosts: 0 };
  let calls = 0;
  const base = `/api/agent/tasks/${instance.taskId}`;
  const binding = await hash(canonicalJson({ instance, product, merchant: merchant.toLowerCase() }));
  async function finish(stage, { terminal = false, delay = 30000 } = {}) {
    if (!terminal && Number.isFinite(state.monitoringUntil) && now() >= state.monitoringUntil) {
      state.reconciliationPending = true; stage = 'research-monitoring-held'; terminal = true;
    }
    state.stage = stage; state.observedAt = new Date(now()).toISOString();
    state.terminal = terminal;
    state.nextAttemptAt = terminal || state.retryBlocked ? null : Math.max(now() + delay, state.retryAt ?? 0);
    await storage.put(RESEARCH_STATE, state);
    const summary = { stage, requests: calls, newCashExpenseUsd: 0, at: state.observedAt,
      taskId: instance.taskId, productId: instance.productId, receiptAccepted: !!state.receipt || !!state.status,
      evaluationState: state.status?.evaluation?.state ?? null, approvedAmountAtomic: state.status?.evaluation?.approved_amount_atomic ?? null,
      providerPayoutState: state.status?.payout?.state ?? null, payoutTx: TX.test(state.status?.payout?.transaction_hash ?? '') ? state.status.payout.transaction_hash : null,
      independentlyVerifiedCashAtomic: state.verifiedCashAtomic ?? null, recognizedOutsideRevenue: null };
    await storage.put(RESEARCH_SUMMARY, summary);
    return summary;
  }
  if (state.binding && state.binding !== binding) return finish('research-binding-drift', { terminal: true });
  if (state.terminal) return finish(state.stage, { terminal: true });
  if (Number.isFinite(state.monitoringUntil) && now() >= state.monitoringUntil) {
    state.reconciliationPending = true;
    return finish('research-monitoring-held',{terminal:true});
  }
  if (state.retryBlocked || state.nextAttemptAt > now()) return { stage: state.stage, requests: 0, newCashExpenseUsd: 0 };

  async function wire(path, { method = 'GET', body, headers = {}, rpc = false } = {}) {
    if (calls >= 12) throw error('research-request-budget');
    if (state.retryBlocked || state.retryAt > now()) throw error('research-retry-deferred');
    const statusPath = state.submissionId ? `${base}/submissions/${state.submissionId}/status` : null;
    if (rpc ? !BASE_PROVIDERS.includes(path) : ![base,base+'/claim',base+'/completion',statusPath].includes(path)) throw error('research-endpoint-refused');
    calls++;
    let response;
    try { response = await fetchImpl(rpc ? path : ORIGIN + path, { method, redirect: 'manual', signal: AbortSignal.timeout(15000),
      headers: { accept: 'application/json', ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...headers }, ...(body === undefined ? {} : { body }) }); }
    catch { throw error('research-response-unknown'); }
    const retry = response.headers.get('retry-after');
    if (retry) {
      const delay = retry.length <= 256 ? retryAfterDelayMs(retry, now()) : null;
      state.retryBlocked = retry.length > 256 || delay === null && /^\d+$/.test(retry.trim()) || delay !== null && !Number.isFinite(new Date(now() + delay).getTime());
      if (state.retryBlocked || delay !== null) {
        state.retryAt = state.retryBlocked ? null : now() + delay; state.retryAfter = retry.slice(0,256);
        await storage.put(RESEARCH_STATE, state); // headers govern even a gateway HTML/stream failure
      }
    }
    if (response.status >= 300 && response.status < 400) throw error('research-redirect-refused', response.status);
    if (response.status === 402) throw error('research-payment-refused',402);
    if (Number(response.headers.get('content-length')) > LIMIT) throw error('research-response-too-large',response.status);
    let text = '', bytes = 0;
    try {
      const reader = response.body?.getReader(), decoder = new TextDecoder('utf-8', { fatal: true });
      if (reader) for (;;) { const part = await reader.read(); if (part.done) break; bytes += part.value.byteLength;
        if (bytes > LIMIT) { await reader.cancel(); throw error('research-response-too-large',response.status); }
        text += decoder.decode(part.value,{stream:true}); }
      text += decoder.decode();
    } catch (e) { throw e.code?.startsWith('research-') ? e : error('research-response-read-failed',response.status); }
    let value;
    try { value = admitCanonicalJson(text,ENVELOPE).value; } catch { throw error('research-invalid-response',response.status); }
    if (!response.ok) throw error(response.status === 402 ? 'research-payment-refused' : 'research-provider-refused',response.status);
    return value;
  }
  async function save() { await storage.put(RESEARCH_STATE,state); }
  const pending = async stage => {
    if (Number.isFinite(state.monitoringUntil) && now() >= state.monitoringUntil) {
      state.reconciliationPending = true;
      return finish('research-monitoring-held',{terminal:true});
    }
    return finish(stage);
  };
  const tokenHeaders = () => ({ 'X-LN-Task-Claim-Token': state.claim.claim_token });
  const statusRead = () => wire(`${base}/submissions/${state.submissionId}/status`, { headers: tokenHeaders() });
  async function receiveStatus(status) {
    if (status.schema_version !== 'ln_church.task_submission_status.endpoint_choice_reason.v2_3' ||
        !sameSubmission(status) || status.selected_candidate_id !== product.selectedCandidateId || status.answer_reason !== product.answerReason ||
        !['PENDING','GRADED','COMPENSATED'].includes(status.evaluation?.state) ||
        !(status.evaluation.approved_amount_atomic === null || /^(0|[1-9]\d{0,77})$/.test(status.evaluation.approved_amount_atomic ?? '')) ||
        !['not_applicable','pending','processing','retryable','ambiguous','failed','paid_confirmed'].includes(status.payout?.state) ||
        !validEvaluationTimes(status) || state.monitoring && !equal(state.monitoring,{receivedAt:status.received_at,evaluationDeadline:status.evaluation_deadline})) throw error('research-status-mismatch');
    state.monitoring = {receivedAt:status.received_at,evaluationDeadline:status.evaluation_deadline};
    state.monitoringUntil = Date.parse(status.evaluation_deadline)+30000;
    state.status = status;
    await save(); // recovered native status also owns the finite deadline after a lost receipt
    if (status.payout.state === 'paid_confirmed') {
      const paid = status.payout.confirmed_paid_amount_atomic, approved = status.evaluation.approved_amount_atomic;
      if (!TX.test(status.payout.transaction_hash ?? '') || !/^[1-9]\d{0,77}$/.test(paid ?? '') || paid !== approved ||
          BigInt(paid) > BigInt(product.reward.correct_amount_atomic) && BigInt(paid) > BigInt(product.reward.incorrect_amount_atomic)) throw error('research-payout-mismatch');
      const receipts = [];
      for (const url of BASE_PROVIDERS) {
        if (receipts.length >= 2 || calls >= 12) break;
        try { const data = await wire(url, { rpc: true, method: 'POST', body: canonicalJson({ jsonrpc:'2.0',id:1,method:'eth_getTransactionReceipt',params:[status.payout.transaction_hash] }) });
          if (data.result && !data.error) receipts.push(data.result); } catch (e) { if (state.retryAt > now() || state.retryBlocked) throw e; }
      }
      const topic = '0x' + '0'.repeat(24) + merchant.slice(2).toLowerCase();
      const matching = receipts[0]?.logs?.filter(log => log.address?.toLowerCase() === BASE_USDC && log.topics?.[2]?.toLowerCase() === topic &&
        /^0x0{24}[a-f\d]{40}$/i.test(log.topics?.[1] ?? '') && /^0x[a-f\d]{64}$/i.test(log.data ?? '') && BigInt(log.data).toString() === paid) ?? [];
      if (matching.length === 1) {
        const payer = '0x'+matching[0].topics[1].slice(-40).toLowerCase();
        const checked = corroborate({ transaction: status.payout.transaction_hash, network:'eip155:8453',asset:BASE_USDC,payer,payTo:merchant,amount:paid },receipts);
        if (checked.ok && !groupPayers.has(payer) && payer !== merchant.toLowerCase()) {
          state.verifiedCashAtomic = paid; state.payer = payer; state.blockNumber = checked.receipt.blockNumber; state.logIndex = checked.transfer.logIndex;
          return finish('research-cash-corroborated',{terminal:true});
        }
      }
      return pending('research-provider-paid-unverified');
    }
    if (status.payout.state === 'failed' || status.payout.state === 'not_applicable' && status.evaluation.state !== 'PENDING')
      return finish('research-no-payout',{terminal:true});
    return pending('research-evaluation-pending');
  }
  function sameSubmission(value) {
    return value.task_id === instance.taskId && value.execution_id === state.claim.execution_id && value.submission_id === state.submissionId &&
      value.terms_digest === product.termsDigest && value.report_sha256 === state.reportSha256;
  }
  function validEvaluationTimes(value) {
    return finiteDate(value.received_at) && finiteDate(value.evaluation_deadline) && Date.parse(value.evaluation_deadline)>Date.parse(value.received_at) &&
      Date.parse(value.evaluation_deadline)-Date.parse(value.received_at)<=1800000;
  }
  try {
    if (!state.claim && Number.isFinite(state.claimIntentAt) && now() >= state.claimIntentAt + 600000)
      return finish('research-claim-recovery-held',{terminal:true});
    if (!state.binding) {
      const task = await wire(base);
      if (task.schema_version !== 'ln_church.agent_task.endpoint_choice_reason.v2_3' || task.task_id !== instance.taskId || task.terms_digest !== product.termsDigest ||
          TERMS.some(key=>!Object.hasOwn(task,key)) || !await matchesTerms(task,product)) return finish('research-task-mismatch',{terminal:true});
      if (task.status !== 'OPEN' || !Number.isSafeInteger(task.capacity_available) || task.capacity_available < 1 || !finiteDate(task.listing_ends_at) || Date.parse(task.listing_ends_at) <= now()) return finish('research-unavailable',{terminal:true});
      state.binding = binding; state.task = task;
      state.claimKey = 'claim-'+crypto.randomUUID(); state.submissionId = 'sub_'+crypto.randomUUID().replaceAll('-','');
      state.claimBody = canonicalJson({ schema_version:'ln_church.agent_task_claim_request.v1',agent_id:instance.agentId,reward_address:merchant.toLowerCase() });
      state.stage = 'claim-intent'; state.claimIntentAt = now(); await save();
      state.freshClaim = true;
    }
    if (!state.claim) {
      const fresh = state.freshClaim === true;
      state.freshClaim = false; await save();
      const claim = await wire(base+'/claim', { method:'POST',body:state.claimBody,
        headers:{ 'Idempotency-Key':state.claimKey, ...(fresh ? {} : { 'X-LN-Claim-Recovery':'1' }) } });
      if (claim.schema_version !== 'ln_church.agent_task_claim_response.endpoint_choice_reason.v2_3' || claim.task_id !== instance.taskId ||
          !await matchesTerms(claim,product) || claim.terms_digest !== product.termsDigest ||
          !/^exec_[a-f0-9]{32}$/.test(claim.execution_id ?? '') || !/^[\x21-\x7e]{1,8192}$/.test(claim.claim_token ?? '') ||
          claim.reward_address !== merchant.toLowerCase() || claim.reward_address_control_verified !== false || !finiteDate(claim.report_deadline) ||
          !finiteDate(claim.claim_accepted_at) || Date.parse(claim.report_deadline) <= Date.parse(claim.claim_accepted_at) || Date.parse(claim.report_deadline) - Date.parse(claim.claim_accepted_at) > 600000 ||
          Date.parse(claim.claim_accepted_at) > now()+15000 || !await matchesTerms(claim.terms_snapshot,product) ||
          !equal(claim.terms_snapshot,Object.fromEntries(TERMS.map(key=>[key,state.task[key]]))) || !equal(claim.candidates,state.task.candidates)) throw error('research-claim-mismatch');
      state.claim = claim; state.stage = 'claimed';
      state.completionBody = canonicalJson({schema_version:'ln_church.task_completion.endpoint_choice_reason.v2_3',task_id:instance.taskId,
        task_type:product.taskType,task_definition_version:product.taskDefinitionVersion,task_definition_digest:product.taskDefinitionDigest,
        terms_digest:product.termsDigest,execution_id:claim.execution_id,submission_id:state.submissionId,
        selected_candidate_id:product.selectedCandidateId,answer_reason:product.answerReason});
      if (new TextEncoder().encode(state.completionBody).length > 16384) throw error('research-report-too-large');
      state.reportSha256 = await hash(state.completionBody); await save();
    }
    if (state.receipt || state.completionPosts > 0) {
      try { return await receiveStatus(await statusRead()); }
      catch (e) { if (e.status !== 404 || state.receipt) throw e; }
    }
    if (Date.parse(state.claim.report_deadline) <= now() || state.completionPosts >= 3) return finish('research-report-recovery-held',{terminal:true});
    state.completionPosts++; state.stage = 'completion-intent';
    // Even an entirely lost response/status sequence has a finite episode:
    // reports must arrive by the original Claim deadline; evaluation adds at most 1800s.
    state.monitoringUntil ??= Date.parse(state.claim.report_deadline)+1800000+30000;
    await save();
    const receipt = await wire(base+'/completion',{method:'POST',body:state.completionBody,headers:{...tokenHeaders(),'Idempotency-Key':state.submissionId}});
    if (receipt.schema_version !== 'ln_church.task_completion_receipt.endpoint_choice_reason.v2_3' || !sameSubmission(receipt) || receipt.receipt_state !== 'accepted' ||
        new URL(receipt.status_url,ORIGIN).href !== ORIGIN+`${base}/submissions/${state.submissionId}/status` || !validEvaluationTimes(receipt)) throw error('research-receipt-mismatch');
    state.receipt = receipt; state.monitoring = {receivedAt:receipt.received_at,evaluationDeadline:receipt.evaluation_deadline};
    state.monitoringUntil = Date.parse(receipt.evaluation_deadline)+30000; await save();
    return await receiveStatus(await statusRead());
  } catch (e) {
    const code = /^research-[a-z-]{1,80}$/.test(e.code ?? '') ? e.code : 'research-failure';
    state.lastFailure = code;
    if (Number.isFinite(state.monitoringUntil) && now() >= state.monitoringUntil) {
      state.reconciliationPending = true;
      return finish('research-monitoring-held',{terminal:true});
    }
    const terminal = code.includes('mismatch') || code === 'research-payment-refused' || code === 'research-redirect-refused' || [400,401,403,404,409,410,422].includes(e.status);
    return finish(code,{terminal});
  }
}
