import {createIssuerEvidenceReadStore} from '../../../apps/market.561.group/src/issuer-evidence-store.mjs';
const cfg={enabled:true,resourceAdmission:{status:'received'},cacheKey:'issuer-research/current.json',maximumCohortBytes:524288};
export default {async fetch(request,env){
  const store=createIssuerEvidenceReadStore(env.ISSUER_EVIDENCE_CLOCK,cfg);
  const item=await store.get(cfg.cacheKey);
  return item?new Response(item.body,{headers:{'content-length':String(item.size)}}):new Response('missing',{status:404});
}};

