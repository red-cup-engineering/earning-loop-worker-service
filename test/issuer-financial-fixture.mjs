// Local receiving data only. No actual transaction, payment or customer claim.
export const configuration = Object.freeze({
  enabled: true, resourceAdmission: { status: 'received' },
  network: 'eip155:8453', asset: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
  payTo: '0x' + 'b'.repeat(40), operation: 'issuer-revenue-comparison',
  method: 'POST', route: '/v1/issuer-revenue-comparison', amount: '50000',
  sku: 'fixture-issuer-sku', gateway: 'fixture-issuer-gateway',
  ledgerAccount: 'Income:Sales:X402:IssuerResearch',
});
export const transaction = n => '0x' + n.toString(16).padStart(64, '0');
export const logicalKey = n => 'settlements/eip155:8453/' + transaction(n) + '.json';
export const witnessText = n => JSON.stringify({
  ...configuration, payer: '0x' + 'a'.repeat(40), transaction: transaction(n),
  recordedAt: '2026-10-24T20:00:00.000Z', marker: 'original é🙂',
}, null, 2);
