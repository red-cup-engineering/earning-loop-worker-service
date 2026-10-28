// Receive market.561.group's x402 sales without a house machine: list the seller's settlement witnesses in R2,
// corroborate each against two independent public Base providers, and classify the payer as outside or Group.
// The rule is Red Cup's confirmSellerWitness (x402-services-section, settlement-derivation): both receipts agree,
// the transaction succeeded, and it holds exactly one USDC transfer from the payer to the seller for the amount.
// A corroborated transfer is cash received; it is not delivery, acceptance or recognized revenue.
import { register, read, put } from "./registers.mjs";
import {
  baseUsdcWitnessProblem, matchingBaseUsdcTransfers, corroborateBaseUsdcReceiptPair,
} from "@red-cup-engineering/x402-services-section/settlement-derivation/base-usdc-receipt";

export const BASE_USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
// Ordered by observed availability of receipts (2026-10-24); the pass reads until two answer.
export const BASE_PROVIDERS = [
  "https://base-rpc.publicnode.com",
  "https://base.drpc.org",
  "https://base-mainnet.public.blastapi.io",
  "https://mainnet.base.org",
];
// One source-owned pure proof; the existing Worker owns RPC acquisition and
// operational settlement persistence, not a second ERC-20 event verifier.
// The exact published supplier must be received before the Worker is deployed.
const PREFIX = "settlements/eip155:8453/";
export const matchingTransfers = matchingBaseUsdcTransfers;
export const witnessProblem = baseUsdcWitnessProblem;
export const corroborate = corroborateBaseUsdcReceiptPair;

export const usdc = (atomic) => Number(BigInt(atomic)) / 1e6;

async function receiptsFor(hash, fetchImpl) {
  const read = async (url) => {
    try {
      const response = await fetchImpl(url, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getTransactionReceipt", params: [hash] }), signal: AbortSignal.timeout(10000) });
      const body = await response.json();
      return response.ok && !body.error && body.result ? body.result : null;
    } catch { return null; }
  };
  const found = [];
  for (const url of BASE_PROVIDERS) {
    if (found.length === 2) break;
    const receipt = await read(url);
    if (receipt) found.push(receipt);
  }
  return found;
}

/** One receiving pass: at most `limit` new witnesses, two provider reads each. */
export async function receiveSettlements(env, { now = new Date(), limit = 8, groupPayers = new Set(), fetchImpl = fetch } = {}) {
  const key = register("settlements");
  const state = (await read(env.STATE, key)) ?? { settlements: {}, refused: {} };
  const seen = new Set([...Object.values(state.settlements).filter((s) => s.evidenceVersion === 2).map((s) => s.witnessKey), ...Object.keys(state.refused).filter((k) => !state.refused[k].retry)]);
  const fresh = [];
  // One bounded page per pass. Persist the opaque continuation after processing
  // the entire page; restart after the end to revisit retriable or new witnesses.
  const page = await env.MARKET_SETTLEMENTS.list({ prefix: PREFIX, cursor: state.scanCursor ?? undefined, limit });
  for (const object of page.objects) if (!seen.has(object.key)) fresh.push(object.key);
  const received = [];
  for (const witnessKey of fresh.slice(0, limit)) {
    const witness = await (await env.MARKET_SETTLEMENTS.get(witnessKey))?.json();
    const problem = witness ? witnessProblem(witness) : "witness-disappeared";
    const checked = problem ? { ok: false, reason: problem } : corroborate(witness, await receiptsFor(witness.transaction, fetchImpl));
    if (!checked.ok) { state.refused[witnessKey] = { reason: checked.reason, retry: !!checked.retry, at: now.toISOString() }; continue; }
    delete state.refused[witnessKey];
    const payer = witness.payer.toLowerCase();
    const sourceId = `evm:eip155:8453:${BASE_USDC}:${witness.payTo.toLowerCase()}:${witness.transaction.toLowerCase()}:${BigInt(checked.transfer.logIndex)}`;
    const settlement = {
      evidenceVersion: 2, sourceId, witnessKey, transactionHash: witness.transaction.toLowerCase(), payer, receiver: witness.payTo.toLowerCase(),
      amount: witness.amount, usd: usdc(witness.amount), payerClass: groupPayers.has(payer) ? "group" : "unclassified",
      paymentObservation: witness.paymentObservation ?? null, deliveryObservation: witness.deliveryObservation ?? null,
      responsePreparation: witness.responsePreparation ?? null, witnessId: witness.witnessId ?? null,
      classificationBasis: groupPayers.has(payer) ? "current Group payer register" : "absence from Group register does not establish outside ownership",
      route: witness.route ?? null, method: witness.method ?? null, gateway: witness.gateway ?? null, sku: witness.sku ?? null,
      ledgerAccount: witness.ledgerAccount ?? null, blockNumber: Number(BigInt(checked.receipt.blockNumber)),
      recordedAt: witness.recordedAt ?? null, corroboratedAt: now.toISOString(),
    };
    state.settlements[sourceId] = settlement;
    received.push(settlement);
  }
  state.at = now.toISOString();
  state.scanCursor = page.truncated ? page.cursor : null;
  await put(env.STATE, key, state);
  return { received, refused: Object.keys(state.refused).length, total: Object.keys(state.settlements).length };
}
