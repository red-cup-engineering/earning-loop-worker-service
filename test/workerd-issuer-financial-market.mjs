import { createIssuerSettlementStore } from '../../../apps/market.561.group/src/issuer-settlement-store.mjs';
import { configuration } from './issuer-financial-fixture.mjs';

export default { async fetch(request, env) {
  const store = createIssuerSettlementStore(env.ISSUER_EVIDENCE_CLOCK, configuration);
  try {
    if (request.method === 'POST') {
      const { key, text } = await request.json();
      const result = await store.put(key, text, {
        onlyIf: { etagDoesNotMatch: '*' }, httpMetadata: { contentType: 'application/json' },
      });
      return new Response('', { status: result ? 201 : 412 });
    }
    const value = await store.get(new URL(request.url).searchParams.get('key'));
    return value ? Response.json(await value.json()) : new Response('', { status: 404 });
  } catch {
    return new Response('', { status: 503 });
  }
} };
