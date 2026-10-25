// Local SQLite receiving fixture. Network access is disabled by the harness.
import worker, { EarningClock as RuntimeClock } from '../worker/earning-loops.mjs';
import { issuerSettlementResponse, receiveIssuerSettlements } from '../src/issuer-settlement-custody.mjs';
import { witnessProblem, corroborate, usdc, BASE_PROVIDERS } from '../src/settlements.mjs';
import { configuration, logicalKey, witnessText } from './issuer-financial-fixture.mjs';

export class EarningClock extends RuntimeClock {
  constructor(state, env) { super(state, env, { configuration: { issuerSettlements: configuration } }); }
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === '/fixture/seed') return this.enqueue(async () => {
      this.state.storage.sql.exec('SELECT 1');
      await this.state.storage.put('opentask/auth', { marker: 'PRIVATE-TEST-CUSTODY' });
      await this.state.storage.put('issuer-evidence/cohort', { marker: 'EXISTING-CACHE' });
      const alarm = Date.now() + 86400000;
      await this.state.storage.setAlarm(alarm);
      return Response.json({ alarm });
    });
    if (path === '/fixture/inspect') return this.enqueue(async () => Response.json({
      alarm: await this.state.storage.getAlarm(),
      rows: [...await this.state.storage.list()].sort(([a], [b]) => a.localeCompare(b)),
    }));
    if (path === '/fixture/failed-commit') return this.enqueue(async () => {
      const storage = this.state.storage;
      const refusing = {
        get: storage.get.bind(storage), list: storage.list.bind(storage),
        transaction: work => storage.transaction(async transaction => {
          await work(transaction);
          throw new Error('injected failure before SQLite transaction commit');
        }),
      };
      return issuerSettlementResponse(new Request(
        'https://private.invalid/issuer-settlement-witness?' + new URLSearchParams({ key: logicalKey(9) }),
        { method: 'POST', headers: { 'content-type': 'application/json', 'if-none-match': '*' }, body: witnessText(9) },
      ), refusing, configuration);
    });
    if (path === '/fixture/receive') return this.enqueue(async () => {
      let requests = 0;
      const attempts = new Map();
      const result = await receiveIssuerSettlements(this.state.storage, configuration, {
        witnessProblem, corroborate, usdc, BASE_PROVIDERS: Object.freeze([...BASE_PROVIDERS]),
        groupPayers: new Set(), now: () => Date.parse('2026-10-24T20:07:30.000Z'),
        fetch: async (url, init) => {
          if (init.redirect !== 'manual' || !BASE_PROVIDERS.includes(url)) throw new Error('unadmitted fixture request');
          requests++;
          const transaction = JSON.parse(init.body).params[0];
          const attempt = (attempts.get(transaction) ?? 0) + 1;
          attempts.set(transaction, attempt);
          if (url !== BASE_PROVIDERS[attempt - 1]) throw new Error('unexpected provider order');
          return Response.json({ result: attempt <= 2 ? null : {
            status: '0x1', transactionHash: transaction, blockHash: '0x' + 'd'.repeat(64), blockNumber: '0x10',
            logs: [{ address: configuration.asset,
              topics: ['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
                '0x' + '0'.repeat(24) + 'a'.repeat(40), '0x' + '0'.repeat(24) + configuration.payTo.slice(2)],
              data: '0x' + (50000).toString(16).padStart(64, '0'), logIndex: '0x2' }],
          } });
        },
      });
      return Response.json({ result, requests });
    });
    return super.fetch(request);
  }
}
export default worker;
