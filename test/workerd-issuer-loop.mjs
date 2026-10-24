// Local receiving fixture only: no external networking, credentials or installed objects.
import { EarningClock as RuntimeClock } from '../worker/earning-loops.mjs';
import { withIssuerSqliteStore } from '../src/issuer-sqlite-cache.mjs';
const cfg={enabled:true,resourceAdmission:{status:'received'},cacheKey:'issuer-research/current.json',maximumCohortBytes:524288};
export class EarningClock extends RuntimeClock {
  constructor(state,env){super(state,env,{configuration:{issuerResearch:cfg}});}
  async fetch(request){
    const path=new URL(request.url).pathname;
    if(path==='/fixture/seed')return this.enqueue(async()=>{
      this.state.storage.sql.exec('SELECT 1');
      await this.state.storage.put('opentask/auth',{marker:'PRIVATE-TEST-CUSTODY'});
      const alarm=Date.now()+86400000;await this.state.storage.setAlarm(alarm);
      const status={status:'prepared',cacheKey:cfg.cacheKey,at:'2026-10-24T20:00:00.000Z',observedAt:'2026-10-24T20:00:00.000Z',nextAttemptAt:'2026-10-24T20:15:00.000Z'};
      await withIssuerSqliteStore(this.state.storage,cfg,async store=>{
        await store.put(cfg.cacheKey,JSON.stringify({complete:true,marker:'é🙂'}));
        await store.put('registers/earning-loops/issuer-research.json',JSON.stringify(status));
      });
      return Response.json({alarm});
    });
    if(path==='/fixture/failure')return this.enqueue(async()=>{
      try{await withIssuerSqliteStore(this.state.storage,cfg,async store=>{
        await store.put(cfg.cacheKey,'{"partial":true}');throw new Error('refused source');
      });}catch{}
      return new Response('held');
    });
    if(path==='/fixture/inspect')return Response.json({
      auth:await this.state.storage.get('opentask/auth'),alarm:await this.state.storage.getAlarm(),
      keys:[...(await this.state.storage.list()).keys()].sort()
    });
    return super.fetch(request);
  }
}
export default {fetch(){return new Response('not found',{status:404});}};

